import type {
  Campaign,
  ScanJob,
  CampaignFlow,
  AssetGraphResponse,
  AssetGraphNode,
  AssetGraphEdge,
  AssetHistoryResponse,
  AssetVulnerabilitiesResponse,
  CampaignEventsResponse,
  Asset,
  CapabilitiesResponse,
  CampaignActivityResponse,
  ProvenanceDetail,
  CampaignStatus,
  JobStatus,
  AppError,
  UiError,
  CreateCampaignRequest,
  CreateCampaignResponse,
  UpdateCampaignPolicyRequest,
  UpdateCampaignPolicyResponse,
} from './types';
import { mockHandlers } from '../mock/handlers';
import {
  recordCampaignEventId,
  subscribeToCampaignEvents,
  type SSEConnection,
  type SSEOptions,
} from './sse';

export type { UiError };

export const STORAGE_KEY_TOKEN = 'ultron-operator-token';

export function getOperatorToken(): string {
  if (typeof window !== 'undefined' && window.localStorage) {
    const stored = window.localStorage.getItem(STORAGE_KEY_TOKEN);
    if (stored && stored.trim()) {
      return stored.trim();
    }
  }
  return import.meta.env.VITE_BEARER_TOKEN || '';
}

export function setOperatorToken(token: string): void {
  if (typeof window !== 'undefined' && window.localStorage) {
    const trimmed = token.trim();
    if (trimmed) {
      window.localStorage.setItem(STORAGE_KEY_TOKEN, trimmed);
    } else {
      window.localStorage.removeItem(STORAGE_KEY_TOKEN);
    }
    window.dispatchEvent(new CustomEvent('ultron-token-changed', { detail: { token: trimmed } }));
  }
}

const API_BASE = import.meta.env.VITE_API_BASE || '/api/v2';
let mockOverride: boolean | null = null;

const NETWORK_ERROR_VI =
  'Không thể kết nối tới máy chủ API (lỗi mạng hoặc CORS bị chặn). Kiểm tra API server đang chạy và cấu hình CORS.';

export function isLikelyNetworkError(err: unknown): boolean {
  if (!(err instanceof Error)) return false;
  if (err.name === 'TypeError') return true;
  return /failed to fetch|networkerror|network request failed|load failed|fetch/i.test(err.message);
}

export class ApiError extends Error {
  public code: string;
  public path?: string;
  public isNetworkError: boolean;
  public next_action?: string;
  public next_action_detail?: string;
  public technical_cause?: string;
  public field?: string;
  public trace_id?: string;

  constructor(
    public status: number | undefined,
    public appError?: AppError,
    message?: string,
    path?: string,
    isNetworkError: boolean = false
  ) {
    super(
      message ||
        appError?.message ||
        (isNetworkError
          ? NETWORK_ERROR_VI
          : status !== undefined
          ? `Yêu cầu thất bại với mã HTTP ${status}`
          : 'Lỗi kết nối API')
    );
    this.name = 'ApiError';
    this.path = path;
    this.isNetworkError = isNetworkError;
    this.code =
      appError?.code ||
      (isNetworkError
        ? 'NETWORK_ERROR'
        : status === 401
        ? 'POLICY_DENIED'
        : status === 404
        ? 'INPUT_INVALID'
        : 'INTERNAL_ERROR');
    if (appError) {
      this.next_action = appError.next_action;
      this.next_action_detail = appError.next_action_detail;
      this.technical_cause = appError.technical_cause;
      this.field = appError.field;
      this.trace_id = appError.trace_id;
    } else if (isNetworkError) {
      this.next_action = 'CHECK_PROVIDER';
      this.next_action_detail = 'Kiểm tra kết nối mạng, trạng thái API server và cấu hình CORS.';
    }
  }

  toUiError(): UiError {
    return {
      status: this.status,
      code: this.code,
      path: this.path,
      message: this.message,
      next_action: this.next_action,
      next_action_detail: this.next_action_detail,
      technical_cause: this.technical_cause,
      field: this.field,
      trace_id: this.trace_id,
      isNetworkError: this.isNetworkError,
    };
  }
}

export function toUiError(err: unknown, fallbackPath?: string): UiError {
  if (err instanceof ApiError) {
    const uiErr = err.toUiError();
    if (!uiErr.path && fallbackPath) uiErr.path = fallbackPath;
    return uiErr;
  }
  if (typeof err === 'object' && err !== null && 'code' in err && 'message' in err) {
    const obj = err as UiError;
    return {
      ...obj,
      path: obj.path || fallbackPath,
    };
  }
  if (err instanceof Error) {
    if (isLikelyNetworkError(err)) {
      return {
        code: 'NETWORK_ERROR',
        path: fallbackPath,
        message: NETWORK_ERROR_VI,
        technical_cause: err.message,
        next_action: 'CHECK_PROVIDER',
        next_action_detail: 'Kiểm tra kết nối mạng, trạng thái API server và cấu hình CORS.',
        isNetworkError: true,
      };
    }
    return {
      code: 'ERROR',
      path: fallbackPath,
      message: err.message || 'Đã xảy ra lỗi không xác định',
    };
  }
  return {
    code: 'ERROR',
    path: fallbackPath,
    message: typeof err === 'string' ? err : 'Đã xảy ra lỗi không xác định',
  };
}

export function generateIdempotencyKey(): string {
  if (typeof crypto !== 'undefined' && crypto.randomUUID) {
    return crypto.randomUUID();
  }
  return 'idemp-' + Math.random().toString(36).substring(2, 15) + Date.now().toString(36);
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const url = `${API_BASE}${path}`;
  const headers = new Headers(options.headers || {});
  headers.set('Accept', 'application/json');

  if (options.body && typeof options.body === 'string') {
    headers.set('Content-Type', 'application/json');
  }

  const token = getOperatorToken();
  if (token) {
    headers.set('Authorization', `Bearer ${token}`);
  }

  if (options.method === 'POST' && !headers.has('Idempotency-Key')) {
    headers.set('Idempotency-Key', generateIdempotencyKey());
  }

  let res: Response;
  try {
    res = await fetch(url, { ...options, headers });
  } catch (err: unknown) {
    const netErr = new ApiError(undefined, undefined, NETWORK_ERROR_VI, path, true);
    if (err instanceof Error && err.message) {
      netErr.technical_cause = err.message;
    }
    throw netErr;
  }

  if (!res.ok) {
    let errorData: AppError | undefined;
    try {
      errorData = await res.json();
    } catch {
      // not json error
    }
    throw new ApiError(
      res.status,
      errorData,
      errorData?.message || `Yêu cầu thất bại với mã HTTP ${res.status}`,
      path,
      false
    );
  }

  return res.json();
}

export const apiClient = {
  get isMock(): boolean {
    if (mockOverride !== null) return mockOverride;
    return import.meta.env.VITE_USE_MOCK !== 'false';
  },

  setMock(val: boolean | null) {
    mockOverride = val;
  },

  async listCampaigns(params?: { cursor?: string; limit?: number; status?: CampaignStatus }) {
    if (this.isMock) return mockHandlers.listCampaigns(params);
    const query = new URLSearchParams();
    if (params?.cursor) query.set('cursor', params.cursor);
    if (params?.limit) query.set('limit', String(params.limit));
    if (params?.status) query.set('status', params.status);
    const qs = query.toString() ? `?${query.toString()}` : '';
    return request<{ items: Campaign[]; next_cursor?: string }>(`/campaigns${qs}`);
  },

  async getCampaign(id: string): Promise<Campaign> {
    if (this.isMock) return mockHandlers.getCampaign(id);
    return request<Campaign>(`/campaigns/${encodeURIComponent(id)}`);
  },

  async createCampaign(
    payload: CreateCampaignRequest,
    options?: { idempotencyKey?: string }
  ): Promise<CreateCampaignResponse> {
    const key = options?.idempotencyKey || generateIdempotencyKey();
    if (this.isMock) return mockHandlers.createCampaign(payload, key);
    return request<CreateCampaignResponse>('/campaigns', {
      method: 'POST',
      headers: { 'Idempotency-Key': key },
      body: JSON.stringify(payload),
    });
  },

  async updateCampaignPolicy(
    id: string,
    payload: UpdateCampaignPolicyRequest,
    options?: { idempotencyKey?: string }
  ): Promise<UpdateCampaignPolicyResponse> {
    const key = options?.idempotencyKey || generateIdempotencyKey();
    if (this.isMock) return mockHandlers.updateCampaignPolicy(id, payload, key);
    return request<UpdateCampaignPolicyResponse>(`/campaigns/${encodeURIComponent(id)}/policy`, {
      method: 'POST',
      headers: { 'Idempotency-Key': key },
      body: JSON.stringify(payload),
    });
  },

  async pauseCampaign(id: string, reason?: string): Promise<Campaign> {
    if (this.isMock) return mockHandlers.pauseCampaign(id, reason);
    return request<Campaign>(`/campaigns/${encodeURIComponent(id)}/pause`, {
      method: 'POST',
      body: JSON.stringify({ reason: reason || 'Tạm dừng tác chiến theo yêu cầu điều độ' }),
    });
  },

  async resumeCampaign(id: string, reason?: string): Promise<Campaign> {
    if (this.isMock) return mockHandlers.resumeCampaign(id, reason);
    return request<Campaign>(`/campaigns/${encodeURIComponent(id)}/resume`, {
      method: 'POST',
      body: JSON.stringify({ reason: reason || 'Tiếp tục chiến dịch' }),
    });
  },

  async cancelCampaign(id: string, reason?: string): Promise<Campaign> {
    if (this.isMock) return mockHandlers.cancelCampaign(id, reason);
    return request<Campaign>(`/campaigns/${encodeURIComponent(id)}/cancel`, {
      method: 'POST',
      body: JSON.stringify({ reason: reason || 'Hủy toàn bộ job và dừng chiến dịch' }),
    });
  },

  async getCampaignFlow(id: string): Promise<CampaignFlow> {
    if (this.isMock) return mockHandlers.getCampaignFlow(id);
    return request<CampaignFlow>(`/campaigns/${encodeURIComponent(id)}/flow`);
  },

  async listJobs(params: { campaign_id: string; status?: JobStatus; cursor?: string; limit?: number }) {
    if (this.isMock) return mockHandlers.listJobs(params);
    const query = new URLSearchParams();
    query.set('campaign_id', params.campaign_id);
    if (params.status) query.set('status', params.status);
    if (params.cursor) query.set('cursor', params.cursor);
    if (params.limit) query.set('limit', String(params.limit));
    return request<{ items: ScanJob[]; next_cursor?: string }>(`/jobs?${query.toString()}`);
  },

  async getJob(id: string): Promise<ScanJob> {
    if (this.isMock) return mockHandlers.getJob(id);
    return request<ScanJob>(`/jobs/${encodeURIComponent(id)}`);
  },

  async cancelJob(id: string, reason?: string): Promise<ScanJob> {
    if (this.isMock) return mockHandlers.cancelJob(id, reason);
    return request<ScanJob>(`/jobs/${encodeURIComponent(id)}/cancel`, {
      method: 'POST',
      body: JSON.stringify({ reason: reason || 'Hủy thủ công qua giao diện' }),
    });
  },

  async listAssets(params?: { campaign_id?: string; kind?: string; q?: string; cursor?: string; limit?: number }) {
    if (this.isMock) return mockHandlers.listAssets(params);
    const query = new URLSearchParams();
    if (params?.campaign_id) query.set('campaign_id', params.campaign_id);
    if (params?.kind) query.set('kind', params.kind);
    if (params?.q) query.set('q', params.q);
    if (params?.cursor) query.set('cursor', params.cursor);
    if (params?.limit) query.set('limit', String(params.limit));
    const qs = query.toString() ? `?${query.toString()}` : '';
    try {
      return await request<{ items: Asset[]; next_cursor?: string }>(`/assets${qs}`);
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) {
        // GET /assets is marked deferred in contract (x-aegis-status: deferred)
        return { items: [] };
      }
      throw err;
    }
  },

  async getAssetGraph(
    assetId: string,
    params: { campaign_id: string; max_hops?: number; as_of?: string; limit?: number }
  ): Promise<AssetGraphResponse> {
    if (this.isMock) return mockHandlers.getAssetGraph(assetId, params);
    const query = new URLSearchParams();
    query.set('campaign_id', params.campaign_id);
    if (params.max_hops) query.set('max_hops', String(params.max_hops));
    if (params.as_of) query.set('as_of', params.as_of);
    if (params.limit) query.set('limit', String(params.limit));
    return request<AssetGraphResponse>(`/assets/${encodeURIComponent(assetId)}/graph?${query.toString()}`);
  },

  async getAssetHistory(
    assetId: string,
    params?: { cursor?: string; limit?: number }
  ): Promise<AssetHistoryResponse> {
    if (this.isMock) return mockHandlers.getAssetHistory(assetId, params);
    const query = new URLSearchParams();
    if (params?.cursor) query.set('cursor', params.cursor);
    if (params?.limit) query.set('limit', String(params.limit));
    const qs = query.toString() ? `?${query.toString()}` : '';
    return request<AssetHistoryResponse>(`/assets/${encodeURIComponent(assetId)}/history${qs}`);
  },

  async listAssetVulnerabilities(
    assetId: string,
    params?: { campaign_id?: string; kev_only?: boolean; cursor?: string; limit?: number }
  ): Promise<AssetVulnerabilitiesResponse> {
    if (this.isMock) return mockHandlers.listAssetVulnerabilities(assetId, params);
    const query = new URLSearchParams();
    if (params?.campaign_id) query.set('campaign_id', params.campaign_id);
    if (params?.kev_only !== undefined) query.set('kev_only', String(params.kev_only));
    if (params?.cursor) query.set('cursor', params.cursor);
    if (params?.limit) query.set('limit', String(params.limit));
    const qs = query.toString() ? `?${query.toString()}` : '';
    return request<AssetVulnerabilitiesResponse>(
      `/assets/${encodeURIComponent(assetId)}/vulnerabilities${qs}`
    );
  },

  async listCampaignEvents(
    campaignId: string,
    params?: { cursor?: string; limit?: number; types?: string[] }
  ): Promise<CampaignEventsResponse> {
    if (this.isMock) return mockHandlers.listCampaignEvents(campaignId, params);
    const query = new URLSearchParams();
    if (params?.cursor) query.set('cursor', params.cursor);
    if (params?.limit) query.set('limit', String(params.limit));
    if (params?.types && params.types.length > 0) query.set('types', params.types.join(','));
    const qs = query.toString() ? `?${query.toString()}` : '';
    const res = await request<CampaignEventsResponse>(
      `/campaigns/${encodeURIComponent(campaignId)}/events${qs}`
    );
    if (res.next_cursor) {
      recordCampaignEventId(campaignId, res.next_cursor);
    }
    return res;
  },

  async getCampaignActivity(
    campaignId: string,
    params?: { cursor?: string; limit?: number }
  ): Promise<CampaignActivityResponse> {
    if (this.isMock) return mockHandlers.getCampaignActivity(campaignId, params);
    const query = new URLSearchParams();
    if (params?.cursor) query.set('cursor', params.cursor);
    if (params?.limit) query.set('limit', String(params.limit));
    const qs = query.toString() ? `?${query.toString()}` : '';
    return request<CampaignActivityResponse>(
      `/campaigns/${encodeURIComponent(campaignId)}/activity${qs}`
    );
  },

  async listCapabilities(campaignId?: string): Promise<CapabilitiesResponse> {
    if (this.isMock) return mockHandlers.listCapabilities(campaignId);
    const query = campaignId ? `?campaign_id=${encodeURIComponent(campaignId)}` : '';
    return request<CapabilitiesResponse>(`/capabilities${query}`);
  },

  async getProvenance(
    targetId: string,
    options?: {
      edge?: AssetGraphEdge;
      fallbackAsset?: AssetGraphNode;
    }
  ): Promise<ProvenanceDetail | null> {
    if (this.isMock) {
      return mockHandlers.getProvenance(targetId);
    }

    const edge = options?.edge;
    const fallbackNode = options?.fallbackAsset;

    // UUID regex check (Id in common/ids.v2.schema.json)
    const isUuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(targetId);

    if (isUuid) {
      try {
        const history = await this.getAssetHistory(targetId);
        const latestObs = history.items && history.items.length > 0 ? history.items[0] : null;

        if (latestObs) {
          const tool = latestObs.provider || latestObs.capability || undefined;
          return {
            tool,
            capability: latestObs.capability,
            provider: latestObs.provider,
            jobId: latestObs.scan_id,
            observedAt: latestObs.observed_at,
            predicate: latestObs.predicate,
            polarity: latestObs.polarity,
            evidenceIds: latestObs.evidence_ids,
            confidence: edge?.confidence,
            sourceAsset: history.asset.discovered_from?.[0] || edge?.from,
            targetAsset: history.asset.canonical_key || edge?.to,
          };
        }

        return {
          observedAt: history.asset.last_seen || history.asset.first_seen,
          sourceAsset: history.asset.discovered_from?.[0] || edge?.from,
          targetAsset: history.asset.canonical_key || edge?.to,
        };
      } catch (err) {
        console.warn('Failed to load asset history for provenance:', err);
      }
    }

    if (edge) {
      return {
        jobId: edge.source_job_id,
        observedAt: edge.observed_at || edge.valid_from,
        confidence: edge.confidence,
        sourceAsset: edge.from,
        targetAsset: edge.to,
      };
    }

    if (fallbackNode) {
      return {
        observedAt: fallbackNode.last_seen || fallbackNode.first_seen,
        targetAsset: fallbackNode.canonical_key,
      };
    }

    return null;
  },

  subscribeCampaignEvents(options: SSEOptions): SSEConnection {
    if (this.isMock) {
      return { close: () => {}, getLastEventId: () => null };
    }
    return subscribeToCampaignEvents(options);
  },
};
