import {
  mockCampaigns,
  mockJobs,
  mockCampaignFlow,
  mockAssets,
  mockAssetGraph,
  mockCapabilities,
  mockProvenanceMap,
} from './fixtures';
import type {
  Campaign,
  ScanJob,
  CampaignFlow,
  AssetGraphResponse,
  CapabilitiesResponse,
  ProvenanceDetail,
  CampaignStatus,
  JobStatus,
} from '../api/types';

// In-memory clones for state mutation during interactive testing
let campaigns: Campaign[] = JSON.parse(JSON.stringify(mockCampaigns));
let jobs: ScanJob[] = JSON.parse(JSON.stringify(mockJobs));
const flow: CampaignFlow = JSON.parse(JSON.stringify(mockCampaignFlow));

export function resetMockData() {
  campaigns = JSON.parse(JSON.stringify(mockCampaigns));
  jobs = JSON.parse(JSON.stringify(mockJobs));
}

export const mockHandlers = {
  async listCampaigns(params?: { cursor?: string; limit?: number; status?: CampaignStatus }) {
    let result = [...campaigns];
    if (params?.status) {
      result = result.filter((c) => c.status === params.status);
    }
    return {
      items: result,
      next_cursor: undefined,
    };
  },

  async getCampaign(id: string): Promise<Campaign> {
    const campaign = campaigns.find((c) => c.campaign_id === id);
    if (!campaign) {
      throw new Error(`Campaign ${id} không tồn tại (404)`);
    }
    return campaign;
  },

  async pauseCampaign(id: string, reason?: string): Promise<Campaign> {
    const campaign = campaigns.find((c) => c.campaign_id === id);
    if (!campaign) throw new Error(`Campaign ${id} không tồn tại`);
    campaign.status = 'PAUSED';
    campaign.status_reason = reason || 'Tạm dừng bởi người vận hành';
    return campaign;
  },

  async resumeCampaign(id: string, reason?: string): Promise<Campaign> {
    const campaign = campaigns.find((c) => c.campaign_id === id);
    if (!campaign) throw new Error(`Campaign ${id} không tồn tại`);
    campaign.status = 'RUNNING';
    campaign.status_reason = reason || 'Tiếp tục bởi người vận hành';
    return campaign;
  },

  async cancelCampaign(id: string, reason?: string): Promise<Campaign> {
    const campaign = campaigns.find((c) => c.campaign_id === id);
    if (!campaign) throw new Error(`Campaign ${id} không tồn tại`);
    campaign.status = 'CANCELLED';
    campaign.status_reason = reason || 'Đã hủy bởi người vận hành';
    return campaign;
  },

  async getCampaignFlow(id: string): Promise<CampaignFlow> {
    const campaign = campaigns.find((c) => c.campaign_id === id);
    if (!campaign) throw new Error(`Campaign ${id} không tồn tại`);
    return flow;
  },

  async listJobs(params: { campaign_id: string; status?: JobStatus; cursor?: string; limit?: number }) {
    let result = jobs.filter((j) => j.campaign_id === params.campaign_id);
    if (params.status) {
      result = result.filter((j) => j.status === params.status);
    }
    return {
      items: result,
      next_cursor: undefined,
    };
  },

  async getJob(id: string): Promise<ScanJob> {
    const job = jobs.find((j) => j.job_id === id);
    if (!job) throw new Error(`Job ${id} không tồn tại`);
    return job;
  },

  async cancelJob(id: string, reason?: string): Promise<ScanJob> {
    const job = jobs.find((j) => j.job_id === id);
    if (!job) throw new Error(`Job ${id} không tồn tại`);
    job.status = 'CANCELLED';
    job.cancel = {
      requested_at: new Date().toISOString(),
      requested_by: { kind: 'operator', id: 'current-operator' },
      reason: reason || 'Hủy thủ công qua giao diện',
    };
    return job;
  },

  async listAssets(params?: { campaign_id?: string; kind?: string; q?: string; cursor?: string; limit?: number }) {
    let result = [...mockAssets];
    if (params?.kind) {
      result = result.filter((a) => a.kind === params.kind);
    }
    if (params?.q) {
      const q = params.q.toLowerCase();
      result = result.filter((a) => a.canonical_key.toLowerCase().includes(q));
    }
    return {
      items: result,
      next_cursor: undefined,
    };
  },

  async getAssetGraph(
    _assetId?: string,
    _params?: { campaign_id: string; max_hops?: number; as_of?: string; limit?: number }
  ): Promise<AssetGraphResponse> {
    return mockAssetGraph;
  },

  async listCapabilities(_campaignId?: string): Promise<CapabilitiesResponse> {
    return mockCapabilities;
  },

  async getProvenance(targetId: string): Promise<ProvenanceDetail | null> {
    return mockProvenanceMap[targetId] || null;
  },
};
