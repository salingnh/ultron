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
  apiBase?: string;
  reconnectDelayMs?: number;
}

export interface SSEConnection {
  close: () => void;
  getLastEventId: () => string | null;
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
    apiBase = import.meta.env.VITE_API_BASE || '/api/v2',
    reconnectDelayMs = 1500,
  } = options;

  let currentLastEventId: string | null = options.lastEventId || null;
  let isClosed = false;
  let abortController: AbortController | null = null;
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null;

  async function connect() {
    if (isClosed) return;
    onStatusChange?.('connecting');

    abortController = new AbortController();
    const url = `${apiBase}/campaigns/${encodeURIComponent(campaignId)}/events`;
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
