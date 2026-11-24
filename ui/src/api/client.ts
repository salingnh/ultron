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

const API_BASE = import.meta.env.VITE_API_BASE || '/api/v2';
const BEARER_TOKEN = import.meta.env.VITE_BEARER_TOKEN || '';
// Default to mock when VITE_USE_MOCK is 'true' or undefined in dev/test, but swappable via config
const USE_MOCK = import.meta.env.VITE_USE_MOCK !== 'false';

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

  if (BEARER_TOKEN) {
    headers.set('Authorization', `Bearer ${BEARER_TOKEN}`);
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
  isMock: USE_MOCK,

  async listCampaigns(params?: { cursor?: string; limit?: number; status?: CampaignStatus }) {
    if (USE_MOCK) return mockHandlers.listCampaigns(params);
    const query = new URLSearchParams();
    if (params?.cursor) query.set('cursor', params.cursor);
    if (params?.limit) query.set('limit', String(params.limit));
    if (params?.status) query.set('status', params.status);
    const qs = query.toString() ? `?${query.toString()}` : '';
    return request<{ items: Campaign[]; next_cursor?: string }>(`/campaigns${qs}`);
  },

  async getCampaign(id: string): Promise<Campaign> {
    if (USE_MOCK) return mockHandlers.getCampaign(id);
    return request<Campaign>(`/campaigns/${encodeURIComponent(id)}`);
  },

  async pauseCampaign(id: string, reason?: string): Promise<Campaign> {
    if (USE_MOCK) return mockHandlers.pauseCampaign(id, reason);
    return request<Campaign>(`/campaigns/${encodeURIComponent(id)}/pause`, {
      method: 'POST',
      body: JSON.stringify({ reason }),
    });
  },

  async resumeCampaign(id: string, reason?: string): Promise<Campaign> {
    if (USE_MOCK) return mockHandlers.resumeCampaign(id, reason);
    return request<Campaign>(`/campaigns/${encodeURIComponent(id)}/resume`, {
      method: 'POST',
      body: JSON.stringify({ reason }),
    });
  },

  async cancelCampaign(id: string, reason?: string): Promise<Campaign> {
    if (USE_MOCK) return mockHandlers.cancelCampaign(id, reason);
    return request<Campaign>(`/campaigns/${encodeURIComponent(id)}/cancel`, {
      method: 'POST',
      body: JSON.stringify({ reason }),
    });
  },

  async getCampaignFlow(id: string): Promise<CampaignFlow> {
    if (USE_MOCK) return mockHandlers.getCampaignFlow(id);
    return request<CampaignFlow>(`/campaigns/${encodeURIComponent(id)}/flow`);
  },

  async listJobs(params: { campaign_id: string; status?: JobStatus; cursor?: string; limit?: number }) {
    if (USE_MOCK) return mockHandlers.listJobs(params);
    const query = new URLSearchParams();
    query.set('campaign_id', params.campaign_id);
    if (params.status) query.set('status', params.status);
    if (params.cursor) query.set('cursor', params.cursor);
    if (params.limit) query.set('limit', String(params.limit));
    return request<{ items: ScanJob[]; next_cursor?: string }>(`/jobs?${query.toString()}`);
  },

  async getJob(id: string): Promise<ScanJob> {
    if (USE_MOCK) return mockHandlers.getJob(id);
    return request<ScanJob>(`/jobs/${encodeURIComponent(id)}`);
  },

  async cancelJob(id: string, reason?: string): Promise<ScanJob> {
    if (USE_MOCK) return mockHandlers.cancelJob(id, reason);
    return request<ScanJob>(`/jobs/${encodeURIComponent(id)}/cancel`, {
      method: 'POST',
      body: JSON.stringify({ reason }),
    });
  },

  async listAssets(params?: { campaign_id?: string; kind?: string; q?: string; cursor?: string; limit?: number }) {
    if (USE_MOCK) return mockHandlers.listAssets(params);
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
    if (USE_MOCK) return mockHandlers.getAssetGraph(assetId, params);
    const query = new URLSearchParams();
    query.set('campaign_id', params.campaign_id);
    if (params.max_hops) query.set('max_hops', String(params.max_hops));
    if (params.as_of) query.set('as_of', params.as_of);
    if (params.limit) query.set('limit', String(params.limit));
    return request<AssetGraphResponse>(`/assets/${encodeURIComponent(assetId)}/graph?${query.toString()}`);
  },

  async listCapabilities(): Promise<CapabilitiesResponse> {
    if (USE_MOCK) return mockHandlers.listCapabilities();
    return request<CapabilitiesResponse>('/capabilities');
  },

  async getProvenance(targetId: string): Promise<ProvenanceDetail | null> {
    // In mock mode returns from mock map, in real backend could be resolved from job or result envelope
    return mockHandlers.getProvenance(targetId);
  },
};
