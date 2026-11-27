import type { components, operations } from './schema';

// Error types
export type AppError = Omit<components['schemas']['error.v2.schema'], '$defs'> & { $defs?: unknown };
export type ErrorCode = components['schemas']['ErrorCode'];
export type NextAction = components['schemas']['NextAction'];

// Campaign types
export type Campaign = Omit<components['schemas']['campaign.v2.schema'], '$defs' | 'policy'> & {
  $defs?: unknown;
  policy?: Omit<components['schemas']['roe-policy.v2.schema'], '$defs'> & { $defs?: unknown };
};
export type CampaignPage = components['schemas']['CampaignPage'];
export type CampaignStatus = components['schemas']['CampaignStatus'];
export type RoEPolicy = Omit<components['schemas']['roe-policy.v2.schema'], '$defs'> & { $defs?: unknown };
export type Targets = components['schemas']['Targets'];
export type CreateCampaignRequest = Omit<
  components['schemas']['campaign-create.v2.schema'],
  '$defs' | 'policy' | 'targets'
> & {
  policy: RoEPolicy;
  targets: Targets;
};
export type CreateCampaignResponse =
  operations['createCampaign']['responses'][202]['content']['application/json'];
export type UpdateCampaignPolicyRequest = Omit<
  operations['updateCampaignPolicy']['requestBody']['content']['application/json'],
  'policy'
> & {
  policy: RoEPolicy;
};
export type UpdateCampaignPolicyResponse =
  operations['updateCampaignPolicy']['responses'][200]['content']['application/json'];

// Job types
export type ScanJob = Omit<components['schemas']['job.v2.schema'], '$defs' | 'error'> & {
  $defs?: unknown;
  error?: AppError;
};
export type JobStatus = components['schemas']['JobStatus'];
export type WaitReason = components['schemas']['WaitReason'];
export type WaitReasonCode = WaitReason['code'];
export type CancelIntent = components['schemas']['CancelIntent'];

// Graph & Asset types
export type Asset = components['schemas']['Asset'];
export type AssetKind = components['schemas']['AssetKind'];
export type AssetExposure = components['schemas']['Asset']['exposure'];
export type AssetCriticality = components['schemas']['Asset']['criticality'];

export type CampaignFlow = operations['getCampaignFlow']['responses'][200]['content']['application/json'];
export type FlowNode = CampaignFlow['nodes'][number];
export type FlowEdge = CampaignFlow['edges'][number];

export type AssetGraphResponse = operations['getAssetGraph']['responses'][200]['content']['application/json'];
export type AssetGraphNode = AssetGraphResponse['nodes'][number];
export type AssetGraphEdge = AssetGraphResponse['edges'][number];
export type AssetHistoryResponse = operations['getAssetHistory']['responses'][200]['content']['application/json'];
export type AssetHistoryItem = AssetHistoryResponse['items'][number];
export type AssetVulnerabilitiesResponse = Omit<
  operations['listAssetVulnerabilities']['responses'][200]['content']['application/json'],
  '$defs'
>;
export type VulnerabilityCandidate = components['schemas']['Candidate'];

export type EventEnvelope = Omit<components['schemas']['event-envelope.v2.schema'], 'payload'> & {
  payload: Record<string, unknown>;
};
export type CampaignEventsResponse = Omit<
  operations['streamCampaignEvents']['responses'][200]['content']['application/json'],
  'items'
> & {
  items: EventEnvelope[];
};
export type AssetDiscoveredPayload = components['schemas']['asset.discovered.v2.schema'];

// Capability / Tool types
export type CapabilitiesResponse = operations['listCapabilities']['responses'][200]['content']['application/json'];
export type CapabilityItem = CapabilitiesResponse['items'][number];
export type CapabilityProvider = CapabilityItem['providers'][number];
export type ProviderHealth = CapabilityProvider['health'];

// Agent Activity types (PR #85: GET /campaigns/{id}/activity)
export type CampaignActivityResponse = Omit<
  operations['getCampaignActivity']['responses'][200]['content']['application/json'],
  '$defs'
>;
export type ActivityEntry = components['schemas']['Entry'];
export type ActivitySessionStarted = components['schemas']['SessionStarted'];
export type ActivitySessionFinished = components['schemas']['SessionFinished'];
export type ActivityDecision = components['schemas']['Decision'];
export type ActivityIdleCycle = components['schemas']['IdleCycle'];
export type ActivityBlocker = components['schemas']['Blocker'];
export type ActivityBudget = components['schemas']['Budget'];

export interface UiError {
  status?: number;
  code: string;
  path?: string;
  message: string;
  next_action?: string;
  next_action_detail?: string;
  technical_cause?: string;
  field?: string;
  trace_id?: string;
  isNetworkError?: boolean;
}

// Common types
export type Actor = components['schemas']['Actor'];
export type TargetRef = components['schemas']['TargetRef'];
export type Timestamp = components['schemas']['Timestamp'];

// Provenance detail model
export interface ProvenanceDetail {
  tool?: string;
  version?: string;
  adapterVersion?: string;
  jobId?: string;
  observedAt?: string;
  confidence?: number;
  sha256?: string;
  sourceAsset?: string;
  targetAsset?: string;
  evidenceUri?: string;
  rawRef?: string;
  capability?: string;
  provider?: string;
  predicate?: string;
  polarity?: string;
  evidenceIds?: string[];
}

// Service & Vulnerability view models (derived strictly from contract observations & Candidate)
export interface ServiceProductValue {
  product?: string;
  version?: string;
  cpe?: string;
}

export interface AssetEnrichment {
  protocol?: string;
  portState?: string;
  product?: ServiceProductValue;
  technologies: string[];
  tlsSubjectCn?: string;
  tlsSha256?: string;
  httpStatus?: number;
  httpTitle?: string;
}

export interface ServiceRowData {
  asset: Asset;
  host: string;
  port: string;
  transport: string;
  protocol: string;
  product: string;
  version: string;
  cpe: string;
  candidates: VulnerabilityCandidate[];
  candidateCount: number;
  kevCount: number;
  criticalCount?: number;
  highCount?: number;
  truncatedCandidates: boolean;
}

export interface SelectedVulnerabilityState {
  candidate: VulnerabilityCandidate;
  assetKey: string;
  assetId: string;
  siblings?: VulnerabilityCandidate[];
}
