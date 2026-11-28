import {
  mockCampaigns,
  mockJobs,
  mockCampaignFlow,
  mockAssets,
  mockAssetGraph,
  mockAssetHistoryMap,
  mockAssetVulnerabilitiesMap,
  mockCampaignEvents,
  mockCapabilities,
  mockCampaignActivity,
  mockProvenanceMap,
  mockFindings,
  mockFindingCampaignMap,
  mockFindingHistoryMap,
} from './fixtures';
import type {
  Campaign,
  ScanJob,
  CampaignFlow,
  AssetGraphResponse,
  AssetHistoryResponse,
  AssetVulnerabilitiesResponse,
  CampaignEventsResponse,
  CapabilitiesResponse,
  CampaignActivityResponse,
  ProvenanceDetail,
  CampaignStatus,
  JobStatus,
  CreateCampaignRequest,
  CreateCampaignResponse,
  UpdateCampaignPolicyRequest,
  UpdateCampaignPolicyResponse,
  AppError,
  Finding,
  FindingListResponse,
  ListFindingsParams,
  FindingHistoryResponse,
  TransitionFindingRequest,
  FindingStatus,
} from '../api/types';
import { ApiError } from '../api/client';
import { buildBudgetFromPolicy } from '../utils/campaignStats';

// In-memory clones for state mutation during interactive testing
let campaigns: Campaign[] = JSON.parse(JSON.stringify(mockCampaigns));
let jobs: ScanJob[] = JSON.parse(JSON.stringify(mockJobs));
const flow: CampaignFlow = JSON.parse(JSON.stringify(mockCampaignFlow));
let findings: Finding[] = JSON.parse(JSON.stringify(mockFindings));
let findingHistoryMap: Record<string, FindingHistoryResponse> = JSON.parse(
  JSON.stringify(mockFindingHistoryMap)
);
let policySeq = 10;
let campaignSeq = 10;
const idempotencyStore = new Map<string, { fingerprint: string; response: unknown }>();

function makeUuidV7(seq: number): string {
  const tail = seq.toString(16).padStart(12, '0');
  return `01934f6a-0000-7000-8000-${tail}`;
}

function stableStringify(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) =>
    a.localeCompare(b)
  );
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${stableStringify(v)}`).join(',')}}`;
}

function makeError(
  status: number,
  code: AppError['code'],
  message: string,
  nextAction: AppError['next_action'],
  field?: string
): ApiError {
  const err: AppError = {
    code,
    message,
    next_action: nextAction,
    ...(field ? { field } : {}),
  };
  return new ApiError(status, err, message);
}

export function resetMockData() {
  campaigns = JSON.parse(JSON.stringify(mockCampaigns));
  jobs = JSON.parse(JSON.stringify(mockJobs));
  findings = JSON.parse(JSON.stringify(mockFindings));
  findingHistoryMap = JSON.parse(JSON.stringify(mockFindingHistoryMap));
  policySeq = 10;
  campaignSeq = 10;
  idempotencyStore.clear();
}

const ALLOWED_OPERATOR_TRANSITIONS: Record<FindingStatus, FindingStatus[]> = {
  CANDIDATE: ['FALSE_POSITIVE', 'ACCEPTED_RISK'],
  CORROBORATED: ['FALSE_POSITIVE', 'ACCEPTED_RISK'],
  VERIFIED: ['FALSE_POSITIVE', 'ACCEPTED_RISK'],
  REGRESSED: ['FALSE_POSITIVE', 'ACCEPTED_RISK'],
  FALSE_POSITIVE: ['CANDIDATE'],
  ACCEPTED_RISK: ['CANDIDATE'],
  FIXED: [],
};

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

  async createCampaign(
    payload: CreateCampaignRequest,
    idempotencyKey?: string
  ): Promise<CreateCampaignResponse> {
    if (!payload.name?.trim()) {
      throw makeError(400, 'INPUT_INVALID', 'body.name is required', 'FIX_INPUT', '/name');
    }
    if (!payload.objective?.trim()) {
      throw makeError(400, 'INPUT_INVALID', 'body.objective is required', 'FIX_INPUT', '/objective');
    }
    const t = payload.targets as {
      domains?: string[];
      ips?: string[];
      urls?: string[];
      emails?: string[];
      keywords?: string[];
    };
    const hasAnyTarget = Boolean(
      t?.domains?.length || t?.ips?.length || t?.urls?.length || t?.emails?.length || t?.keywords?.length
    );
    if (!hasAnyTarget) {
      throw makeError(
        400,
        'INPUT_INVALID',
        'targets must include at least one non-empty list',
        'FIX_INPUT',
        '/targets'
      );
    }

    const key = idempotencyKey || `mock-${Date.now()}`;
    const storeKey = `POST /campaigns|${key}`;
    const fingerprint = stableStringify(payload);
    const existing = idempotencyStore.get(storeKey);
    if (existing) {
      if (existing.fingerprint !== fingerprint) {
        throw makeError(
          409,
          'IDEMPOTENCY_CONFLICT',
          'Idempotency-Key was already used with a different body (POST /campaigns)',
          'NONE'
        );
      }
      return existing.response as CreateCampaignResponse;
    }

    campaignSeq += 1;
    policySeq += 1;
    const campaignId = makeUuidV7(campaignSeq);
    const scopeId = makeUuidV7(1000 + campaignSeq);
    const policyVersion = `roe-${policySeq}`;

    const clonedPolicy = JSON.parse(JSON.stringify(payload.policy));
    const newCampaign: Campaign = {
      campaign_id: campaignId,
      name: payload.name.trim(),
      objective: payload.objective.trim(),
      status: 'CREATED',
      policy_version: policyVersion,
      scope_id: scopeId,
      created_at: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
      policy: clonedPolicy,
      targets: JSON.parse(JSON.stringify(payload.targets)),
      counters: {
        jobs_by_status: {},
        assets_by_kind: {},
      },
      budget: buildBudgetFromPolicy(clonedPolicy),
    };
    campaigns = [newCampaign, ...campaigns];

    const response: CreateCampaignResponse = {
      campaign_id: campaignId,
      status: 'CREATED',
      policy_version: policyVersion,
      scope_id: scopeId,
    };
    idempotencyStore.set(storeKey, { fingerprint, response });
    return response;
  },

  async updateCampaignPolicy(
    id: string,
    payload: UpdateCampaignPolicyRequest,
    idempotencyKey?: string
  ): Promise<UpdateCampaignPolicyResponse> {
    const campaign = campaigns.find((c) => c.campaign_id === id);
    if (!campaign) {
      throw makeError(404, 'INPUT_INVALID', `campaign ${id} does not exist`, 'FIX_INPUT');
    }
    if (!payload.reason || payload.reason.trim().length < 3) {
      throw makeError(
        400,
        'INPUT_INVALID',
        'body.reason is required and at least 3 characters',
        'FIX_INPUT',
        '/reason'
      );
    }
    if (
      campaign.status === 'COMPLETED' ||
      campaign.status === 'FAILED' ||
      campaign.status === 'CANCELLED'
    ) {
      throw makeError(
        409,
        'INPUT_INVALID',
        `cannot adopt a policy for campaign ${id} in status ${campaign.status}`,
        'NONE'
      );
    }

    const key = idempotencyKey || `mock-policy-${Date.now()}`;
    const storeKey = `POST /campaigns/${id}/policy|${key}`;
    const fingerprint = stableStringify(payload);
    const existing = idempotencyStore.get(storeKey);
    if (existing) {
      if (existing.fingerprint !== fingerprint) {
        throw makeError(
          409,
          'IDEMPOTENCY_CONFLICT',
          'Idempotency-Key was already used with a different body (POST /campaigns/{campaign_id}/policy)',
          'NONE'
        );
      }
      return existing.response as UpdateCampaignPolicyResponse;
    }

    policySeq += 1;
    const version = `roe-${policySeq}`;
    const clonedPolicy = JSON.parse(JSON.stringify(payload.policy));
    campaign.policy = clonedPolicy;
    campaign.policy_version = version;
    campaign.budget = buildBudgetFromPolicy(clonedPolicy, campaign.budget?.used);

    const response: UpdateCampaignPolicyResponse = { policy_version: version };
    idempotencyStore.set(storeKey, { fingerprint, response });
    return response;
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

  async getAssetHistory(
    assetId: string,
    _params?: { cursor?: string; limit?: number }
  ): Promise<AssetHistoryResponse> {
    const asset = mockAssets.find((a) => a.asset_id === assetId) || mockAssets[0];
    const customItems = mockAssetHistoryMap[assetId];
    if (customItems) {
      return {
        asset,
        items: customItems,
      };
    }
    const prov =
      mockProvenanceMap[assetId] ||
      mockProvenanceMap['01934f6a-0000-7000-8000-0000000000f1'];
    return {
      asset,
      items: [
        {
          scan_id: prov?.jobId || '01934f6a-0000-7000-8000-00000000d001',
          capability: prov?.tool === 'subfinder' ? 'recon.subdomains' : 'recon.dns',
          provider: prov ? `${prov.tool}:${prov.version}` : 'subfinder:v2.17.0',
          observed_at: prov?.observedAt || asset.last_seen || new Date().toISOString(),
          predicate: prov?.tool === 'subfinder' ? 'dns.subdomain' : 'dns.record',
          polarity: 'present',
          evidence_ids: ['01934f6a-0000-7000-8000-0000000000e1'],
        },
      ],
    };
  },

  async listAssetVulnerabilities(
    assetId: string,
    params?: { campaign_id?: string; kev_only?: boolean; cursor?: string; limit?: number }
  ): Promise<AssetVulnerabilitiesResponse> {
    const asset = mockAssets.find((a) => a.asset_id === assetId) || mockAssets[0];
    const entry = mockAssetVulnerabilitiesMap[assetId];
    let items = entry ? [...entry.items] : [];
    if (params?.kev_only) {
      items = items.filter((item) => item.kev);
    }
    return {
      asset: entry
        ? entry.asset
        : {
            asset_id: asset.asset_id,
            canonical_key: asset.canonical_key,
            kind: asset.kind,
          },
      items,
    };
  },

  async listCampaignEvents(
    _campaignId: string,
    params?: { cursor?: string; limit?: number; types?: string[] }
  ): Promise<CampaignEventsResponse> {
    let items = [...mockCampaignEvents];
    if (params?.types && params.types.length > 0) {
      const allowed = new Set(params.types);
      items = items.filter((ev) => allowed.has(ev.type));
    }
    return {
      items: params?.limit ? items.slice(0, params.limit) : items,
    };
  },

  async listCapabilities(_campaignId?: string): Promise<CapabilitiesResponse> {
    return mockCapabilities;
  },

  async getCampaignActivity(
    campaignId: string,
    params?: { cursor?: string; limit?: number }
  ): Promise<CampaignActivityResponse> {
    if (!campaigns.some((c) => c.campaign_id === campaignId)) {
      throw makeError(404, 'INPUT_INVALID', `campaign ${campaignId} does not exist`, 'FIX_INPUT');
    }
    const allItems = mockCampaignActivity.items;
    const offset = params?.cursor ? Math.max(0, Number(params.cursor) || 0) : 0;
    const limit = params?.limit ?? 50;
    const pageItems = allItems.slice(offset, offset + limit);
    const hasMore = offset + limit < allItems.length;
    return {
      items: pageItems,
      truncated: hasMore,
      ...(hasMore ? { next_cursor: String(offset + limit) } : {}),
    };
  },

  async getProvenance(targetId: string): Promise<ProvenanceDetail | null> {
    return mockProvenanceMap[targetId] || null;
  },

  async listFindings(params?: ListFindingsParams): Promise<FindingListResponse> {
    let result = [...findings];
    if (params?.campaign_id) {
      result = result.filter((f) => mockFindingCampaignMap[f.finding_id] === params.campaign_id);
    }
    if (params?.asset_id) {
      result = result.filter((f) => f.asset_id === params.asset_id);
    }
    if (params?.status && params.status.length > 0) {
      const allowed = new Set(params.status);
      result = result.filter((f) => allowed.has(f.status));
    }
    if (params?.severity && params.severity.length > 0) {
      const allowed = new Set(params.severity);
      result = result.filter((f) => allowed.has(f.severity));
    }
    if (params?.category) {
      const cat = params.category.trim().toLowerCase();
      result = result.filter((f) => (f.category || '').toLowerCase() === cat);
    }
    if (params?.vulnerability_id) {
      const needle = params.vulnerability_id.trim().toLowerCase();
      result = result.filter(
        (f) =>
          f.vulnerability_ids?.some((v) => v.toLowerCase().includes(needle)) ||
          f.title.toLowerCase().includes(needle) ||
          f.rule_id.toLowerCase().includes(needle)
      );
    }
    if (params?.kev !== undefined) {
      result = result.filter(
        (f) => Boolean(f.severity_assessment?.inputs?.kev?.listed) === params.kev
      );
    }
    if (params?.changed_since) {
      const sinceMs = Date.parse(params.changed_since);
      if (Number.isFinite(sinceMs)) {
        result = result.filter((f) => Date.parse(f.last_seen) >= sinceMs);
      }
    }

    const offset = params?.cursor ? Math.max(0, Number(params.cursor) || 0) : 0;
    const limit = params?.limit ?? 20;
    const pageItems = result.slice(offset, offset + limit);
    const hasMore = offset + limit < result.length;

    return {
      items: JSON.parse(JSON.stringify(pageItems)) as Finding[],
      ...(hasMore ? { next_cursor: String(offset + limit) } : {}),
    };
  },

  async getFinding(findingId: string): Promise<Finding> {
    const found = findings.find((f) => f.finding_id === findingId);
    if (!found) {
      throw makeError(404, 'INPUT_INVALID', `finding ${findingId} does not exist`, 'FIX_INPUT');
    }
    return JSON.parse(JSON.stringify(found)) as Finding;
  },

  async getFindingHistory(findingId: string): Promise<FindingHistoryResponse> {
    const found = findings.find((f) => f.finding_id === findingId);
    if (!found) {
      throw makeError(404, 'INPUT_INVALID', `finding ${findingId} does not exist`, 'FIX_INPUT');
    }
    const history = findingHistoryMap[findingId];
    if (!history) {
      return { runs: [], transitions: [], assessments: [] };
    }
    return JSON.parse(JSON.stringify(history)) as FindingHistoryResponse;
  },

  async transitionFinding(
    findingId: string,
    payload: TransitionFindingRequest,
    idempotencyKey?: string
  ): Promise<Finding> {
    const found = findings.find((f) => f.finding_id === findingId);
    if (!found) {
      throw makeError(404, 'INPUT_INVALID', `finding ${findingId} does not exist`, 'FIX_INPUT');
    }
    if (!payload.reason || payload.reason.trim().length < 3) {
      throw makeError(
        400,
        'INPUT_INVALID',
        'body.reason is required and must be at least 3 characters',
        'FIX_INPUT',
        '/reason'
      );
    }

    const key = idempotencyKey || `mock-transition-${Date.now()}`;
    const storeKey = `POST /findings/${findingId}/transitions|${key}`;
    const fingerprint = stableStringify(payload);
    const existing = idempotencyStore.get(storeKey);
    if (existing) {
      if (existing.fingerprint !== fingerprint) {
        throw makeError(
          409,
          'IDEMPOTENCY_CONFLICT',
          `Idempotency-Key was already used with a different body (POST /findings/${findingId}/transitions)`,
          'NONE'
        );
      }
      return existing.response as Finding;
    }

    const history = findingHistoryMap[findingId] || { runs: [], transitions: [], assessments: [] };
    findingHistoryMap[findingId] = history;
    const currentSeq = history.transitions.reduce((max, t) => Math.max(max, t.seq), 0);
    if (payload.expected_seq !== currentSeq) {
      throw makeError(
        409,
        'INPUT_INVALID',
        `expected_seq ${payload.expected_seq} is stale; current transition seq is ${currentSeq}`,
        'RETRY',
        '/expected_seq'
      );
    }

    const allowedTargets = ALLOWED_OPERATOR_TRANSITIONS[found.status] || [];
    if (!allowedTargets.includes(payload.to)) {
      throw makeError(
        409,
        'INPUT_INVALID',
        `transition from ${found.status} to ${payload.to} is not permitted for operator`,
        'FIX_INPUT',
        '/to'
      );
    }

    const now = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
    const nextSeq = currentSeq + 1;
    const fromStatus = found.status;
    found.status = payload.to;
    found.last_seen = now;
    history.transitions.push({
      seq: nextSeq,
      from_status: fromStatus,
      to_status: payload.to,
      reason: payload.reason.trim(),
      ...(payload.evidence_id ? { evidence_id: payload.evidence_id } : {}),
      actor: { kind: 'operator', id: 'current-operator' },
      cause: 'operator',
      created_at: now,
    });

    const cloned = JSON.parse(JSON.stringify(found)) as Finding;
    idempotencyStore.set(storeKey, { fingerprint, response: cloned });
    return JSON.parse(JSON.stringify(cloned)) as Finding;
  },
};
