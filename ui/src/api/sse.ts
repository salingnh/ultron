import { getOperatorToken } from './client';

export interface SSEEvent<T = Record<string, unknown>> {
  id: string;
  type: string;
  data: T;
  raw: string;
  timestamp: number;
}

export type SSEConnectionStatus = 'connecting' | 'connected' | 'disconnected' | 'error';

export interface SSEOptions {
  campaignId: string;
  onEvent: (event: SSEEvent) => void;
  onStatusChange?: (status: SSEConnectionStatus) => void;
  lastEventId?: string;
  types?: string[];
  apiBase?: string;
  reconnectDelayMs?: number;
}

export interface SSEConnection {
  close: () => void;
  getLastEventId: () => string | null;
}

const latestSeqByCampaign = new Map<string, string>();

function parsePositiveSeq(id: string | null | undefined): number | null {
  if (!id) return null;
  const trimmed = id.trim();
  if (!/^\d+$/.test(trimmed)) return null;
  const num = Number(trimmed);
  return Number.isSafeInteger(num) && num > 0 ? num : null;
}

export function getLatestCampaignEventId(campaignId: string): string | null {
  return latestSeqByCampaign.get(campaignId) ?? null;
}

export function recordCampaignEventId(campaignId: string, eventId: string | null | undefined): void {
  const nextSeq = parsePositiveSeq(eventId);
  if (nextSeq === null) return;
  const currentSeq = parsePositiveSeq(latestSeqByCampaign.get(campaignId));
  if (currentSeq === null || nextSeq > currentSeq) {
    latestSeqByCampaign.set(campaignId, String(nextSeq));
  }
}

export function clearCampaignEventId(campaignId: string): void {
  latestSeqByCampaign.delete(campaignId);
}

export function clearAllCampaignEventIds(): void {
  latestSeqByCampaign.clear();
}

export interface CoalescedRefresh {
  trigger: () => void;
  cancel: () => void;
}

/**
 * Debounce bursts of SSE events and coalesce overlapping in-flight fetches into O(1) GETs.
 */
export function createCoalescedRefresh(
  fn: () => Promise<void> | void,
  delayMs: number = 250
): CoalescedRefresh {
  let timer: ReturnType<typeof setTimeout> | null = null;
  let inFlight = false;
  let pendingFollowUp = false;
  let cancelled = false;

  const execute = async () => {
    if (cancelled) return;
    if (inFlight) {
      pendingFollowUp = true;
      return;
    }
    inFlight = true;
    try {
      await fn();
    } finally {
      inFlight = false;
      if (pendingFollowUp && !cancelled) {
        pendingFollowUp = false;
        schedule();
      }
    }
  };

  const schedule = () => {
    if (cancelled) return;
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => {
      timer = null;
      void execute();
    }, delayMs);
  };

  return {
    trigger: schedule,
    cancel: () => {
      cancelled = true;
      pendingFollowUp = false;
      if (timer) {
        clearTimeout(timer);
        timer = null;
      }
    },
  };
}

/**
 * Parse a raw SSE message block (separated by double newlines)
 */
export function parseSSEBlock(block: string, fallbackId: string = ''): SSEEvent | null {
  const lines = block.split(/\r?\n/);
  let eventType = 'message';
  let eventId = fallbackId;
  const dataLines: string[] = [];
  let isOnlyComments = true;

  for (const line of lines) {
    if (!line) continue;
    if (line.startsWith(':')) {
      // SSE comment line (e.g., heartbeat or ready signal), ignore payload
      continue;
    }
    isOnlyComments = false;
    if (line.startsWith('event:')) {
      eventType = line.slice(6).trim();
    } else if (line.startsWith('id:')) {
      eventId = line.slice(3).trim();
    } else if (line.startsWith('data:')) {
      dataLines.push(line.slice(5).trim());
    }
  }

  if (isOnlyComments || (dataLines.length === 0 && eventType === 'message')) {
    return null;
  }

  const rawData = dataLines.join('\n');
  let parsedData: Record<string, unknown>;
  try {
    parsedData = JSON.parse(rawData);
  } catch {
    parsedData = { raw: rawData };
  }

  return {
    id: eventId,
    type: eventType,
    data: parsedData,
    raw: rawData,
    timestamp: Date.now(),
  };
}

/**
 * Fetch-based SSE subscriber.
 * Standard EventSource does not support sending Authorization headers or custom Last-Event-ID headers.
 * This client uses fetch() with ReadableStream to support bearer auth and seamless resume.
 */
export function subscribeToCampaignEvents(options: SSEOptions): SSEConnection {
  const {
    campaignId,
    onEvent,
    onStatusChange,
    types,
    apiBase = import.meta.env.VITE_API_BASE || '/api/v2',
    reconnectDelayMs = 1500,
  } = options;

  const normalizedTypes = types && types.length > 0 ? Array.from(new Set(types)) : undefined;
  let currentLastEventId: string | null =
    options.lastEventId || getLatestCampaignEventId(campaignId) || null;
  let isClosed = false;
  let abortController: AbortController | null = null;
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null;

  async function connect() {
    if (isClosed) return;
    onStatusChange?.('connecting');

    abortController = new AbortController();
    const query = new URLSearchParams();
    if (normalizedTypes && normalizedTypes.length > 0) {
      query.set('types', normalizedTypes.join(','));
    }
    const qs = query.toString() ? `?${query.toString()}` : '';
    const url = `${apiBase}/campaigns/${encodeURIComponent(campaignId)}/events${qs}`;
    const headers: Record<string, string> = {
      Accept: 'text/event-stream',
    };

    const token = getOperatorToken();
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }
    if (currentLastEventId) {
      headers['Last-Event-ID'] = currentLastEventId;
    }

    try {
      const response = await fetch(url, {
        headers,
        signal: abortController.signal,
      });

      if (!response.ok) {
        if (response.status === 400 && currentLastEventId) {
          // Stale or cross-generation checkpoint: reset so reconnect starts from current DB log
          currentLastEventId = null;
          clearCampaignEventId(campaignId);
        }
        throw new Error(`SSE stream returned status ${response.status}: ${response.statusText}`);
      }

      if (!response.body) {
        throw new Error('SSE stream response body is null');
      }

      onStatusChange?.('connected');

      const reader = response.body.getReader();
      const decoder = new TextDecoder('utf-8');
      let buffer = '';

      while (!isClosed) {
        const { value, done } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const blocks = buffer.split(/\r?\n\r?\n/);
        // The last segment may be an incomplete frame, preserve it in the buffer
        buffer = blocks.pop() || '';

        for (const block of blocks) {
          const parsed = parseSSEBlock(block, currentLastEventId || '');
          if (parsed) {
            if (parsed.id) {
              currentLastEventId = parsed.id;
              recordCampaignEventId(campaignId, parsed.id);
            }
            if (parsed.type !== 'heartbeat') {
              onEvent(parsed);
            }
          }
        }
      }

      // If stream ended normally without being closed, schedule reconnection
      if (!isClosed) {
        onStatusChange?.('disconnected');
        reconnectTimer = setTimeout(connect, reconnectDelayMs);
      }
    } catch {
      if (isClosed) return;
      onStatusChange?.('error');
      // Reconnect after delay
      reconnectTimer = setTimeout(connect, reconnectDelayMs);
    }
  }

  // Kick off initial connection
  connect();

  return {
    close: () => {
      isClosed = true;
      if (reconnectTimer) {
        clearTimeout(reconnectTimer);
        reconnectTimer = null;
      }
      if (abortController) {
        abortController.abort();
        abortController = null;
      }
      onStatusChange?.('disconnected');
    },
    getLastEventId: () => currentLastEventId,
  };
}
