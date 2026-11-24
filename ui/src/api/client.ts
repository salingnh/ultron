import type {
  Campaign,
  ScanJob,
  CampaignFlow,
  AssetGraphResponse,
  Asset,
  CapabilitiesResponse,
  ProvenanceDetail,
  CampaignStatus,
  JobStatus,
  AppError,
} from './types';
import { mockHandlers } from '../mock/handlers';
import { subscribeToCampaignEvents, type SSEConnection, type SSEOptions } from './sse';

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

export class ApiError extends Error {
  constructor(
    public status: number,
    public appError?: AppError,
    message?: string
  ) {
    super(message || appError?.message || `API Error: ${status}`);
    this.name = 'ApiError';
  }
}

function generateIdempotencyKey(): string {
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

  const res = await fetch(url, { ...options, headers });

  if (!res.ok) {
    let errorData: AppError | undefined;
    try {
      errorData = await res.json();
    } catch {
      // not json error
    }
    throw new ApiError(res.status, errorData, errorData?.message || `Yêu cầu thất bại với mã ${res.status}`);
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
    return request<{ items: Asset[]; next_cursor?: string }>(`/assets${qs}`);
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

  async listCapabilities(): Promise<CapabilitiesResponse> {
    if (this.isMock) return mockHandlers.listCapabilities();
    return request<CapabilitiesResponse>('/capabilities');
  },

  async getProvenance(targetId: string): Promise<ProvenanceDetail | null> {
    return mockHandlers.getProvenance(targetId);
  },

  subscribeCampaignEvents(options: SSEOptions): SSEConnection {
    return subscribeToCampaignEvents(options);
  },
};
