import type { Campaign, RoEPolicy } from '../api/types';

export type CampaignBudget = NonNullable<Campaign['budget']>;
export type CampaignLegacyBudgetRemaining = NonNullable<Campaign['budget_remaining']>;
export type CampaignCounters = NonNullable<Campaign['counters']>;

export interface BudgetDimensionRow {
  key: 'hours' | 'llm_cost_usd' | 'llm_tokens' | 'jobs' | 'agent_sessions';
  label: string;
  usedText: string;
  limitText: string;
  hasLimit: boolean;
  remainingText: string | null;
  usedRatio: number | null;
}

export interface JobCountersSummary {
  hasData: boolean;
  total?: number;
  running?: number;
  succeeded?: number;
  failed?: number;
  byStatus: Array<{ status: string; count: number }>;
}

export interface AssetCountersSummary {
  hasData: boolean;
  total?: number;
  byKind: Array<{ kind: string; count: number }>;
}

const JOB_STATUS_ORDER = [
  'RUNNING',
  'WAITING',
  'DISPATCHED',
  'QUEUED',
  'VALIDATING',
  'APPROVED',
  'PROPOSED',
  'SUCCEEDED',
  'FAILED',
  'CANCELLED',
];

const ASSET_KIND_ORDER = ['domain', 'ip', 'service', 'application', 'vulnerability'];

const ASSET_KIND_LABELS: Record<string, string> = {
  domain: 'domain',
  ip: 'IP',
  service: 'service',
  application: 'app',
  vulnerability: 'CVE',
};

export function assetKindLabel(kind: string): string {
  return ASSET_KIND_LABELS[kind] ?? kind;
}

function clampRatio(used: number | undefined, limit: number | undefined): number | null {
  if (typeof used !== 'number' || typeof limit !== 'number' || limit <= 0) return null;
  return Math.max(0, Math.min(1, used / limit));
}

function formatUsdRemaining(value: number): string {
  if (value > 0 && value < 0.01) return `$${value.toFixed(4)}`;
  return `$${value.toFixed(2)}`;
}

/**
 * Builds normalized display rows for the 5 tracked RoE budget ledger dimensions.
 */
export function buildBudgetDimensions(budget?: Campaign['budget']): BudgetDimensionRow[] {
  if (!budget) return [];
  const limits = budget.limits;
  const used = budget.used;
  const remaining = budget.remaining;
  const maxDurationHours = limits?.max_duration_hours;
  const maxLlmCostUsd = limits?.max_llm_cost_usd;
  const maxLlmTokens = limits?.max_llm_tokens;
  const maxJobs = limits?.max_jobs;
  const maxAgentSessions = limits?.max_agent_sessions;

  return [
    {
      key: 'hours',
      label: 'Thời lượng',
      usedText: typeof used?.hours === 'number' ? `${used.hours.toFixed(2)}h` : '—',
      limitText: typeof maxDurationHours === 'number' ? `${maxDurationHours}h` : 'Không giới hạn',
      hasLimit: typeof maxDurationHours === 'number',
      remainingText: typeof remaining?.hours === 'number' ? `${remaining.hours.toFixed(2)}h` : null,
      usedRatio: clampRatio(used?.hours, maxDurationHours),
    },
    {
      key: 'llm_cost_usd',
      label: 'Chi phí LLM',
      usedText: typeof used?.llm_cost_usd === 'number' ? `$${used.llm_cost_usd.toFixed(4)}` : '—',
      limitText:
        typeof maxLlmCostUsd === 'number' ? `$${maxLlmCostUsd.toFixed(2)}` : 'Không giới hạn',
      hasLimit: typeof maxLlmCostUsd === 'number',
      remainingText:
        typeof remaining?.llm_cost_usd === 'number' ? formatUsdRemaining(remaining.llm_cost_usd) : null,
      usedRatio: clampRatio(used?.llm_cost_usd, maxLlmCostUsd),
    },
    {
      key: 'llm_tokens',
      label: 'Token LLM',
      usedText: typeof used?.llm_tokens === 'number' ? used.llm_tokens.toLocaleString('en-US') : '—',
      limitText:
        typeof maxLlmTokens === 'number'
          ? maxLlmTokens.toLocaleString('en-US')
          : 'Không giới hạn',
      hasLimit: typeof maxLlmTokens === 'number',
      remainingText:
        typeof remaining?.llm_tokens === 'number' ? remaining.llm_tokens.toLocaleString('en-US') : null,
      usedRatio: clampRatio(used?.llm_tokens, maxLlmTokens),
    },
    {
      key: 'jobs',
      label: 'Số Job',
      usedText: typeof used?.jobs === 'number' ? `${used.jobs}` : '—',
      limitText: typeof maxJobs === 'number' ? `${maxJobs}` : 'Không giới hạn',
      hasLimit: typeof maxJobs === 'number',
      remainingText: typeof remaining?.jobs === 'number' ? `${remaining.jobs}` : null,
      usedRatio: clampRatio(used?.jobs, maxJobs),
    },
    {
      key: 'agent_sessions',
      label: 'Phiên Agent',
      usedText: typeof used?.agent_sessions === 'number' ? `${used.agent_sessions}` : '—',
      limitText:
        typeof maxAgentSessions === 'number' ? `${maxAgentSessions}` : 'Không giới hạn',
      hasLimit: typeof maxAgentSessions === 'number',
      remainingText:
        typeof remaining?.agent_sessions === 'number' ? `${remaining.agent_sessions}` : null,
      usedRatio: clampRatio(used?.agent_sessions, maxAgentSessions),
    },
  ];
}

/**
 * Summarizes job counts from contract `counters.jobs_by_status` (or legacy flat counters).
 */
export function summarizeJobCounters(counters?: Campaign['counters']): JobCountersSummary {
  if (!counters) return { hasData: false, byStatus: [] };
  if (counters.jobs_by_status) {
    const entries = Object.entries(counters.jobs_by_status).sort(([a], [b]) => {
      const idxA = JOB_STATUS_ORDER.indexOf(a);
      const idxB = JOB_STATUS_ORDER.indexOf(b);
      if (idxA !== -1 && idxB !== -1) return idxA - idxB;
      if (idxA !== -1) return -1;
      if (idxB !== -1) return 1;
      return a.localeCompare(b);
    });
    const total = entries.reduce((sum, [, count]) => sum + count, 0);
    return {
      hasData: true,
      total,
      running: counters.jobs_by_status.RUNNING ?? 0,
      succeeded: counters.jobs_by_status.SUCCEEDED ?? 0,
      failed: counters.jobs_by_status.FAILED ?? 0,
      byStatus: entries.map(([status, count]) => ({ status, count })),
    };
  }
  if (
    counters.jobs_total !== undefined ||
    counters.jobs_running !== undefined ||
    counters.jobs_failed !== undefined
  ) {
    return {
      hasData: true,
      total: counters.jobs_total,
      running: counters.jobs_running,
      failed: counters.jobs_failed,
      byStatus: [],
    };
  }
  return { hasData: false, byStatus: [] };
}

/**
 * Summarizes asset counts from contract `counters.assets_by_kind` (or legacy flat `assets`).
 */
export function summarizeAssetCounters(counters?: Campaign['counters']): AssetCountersSummary {
  if (!counters) return { hasData: false, byKind: [] };
  if (counters.assets_by_kind) {
    const entries = Object.entries(counters.assets_by_kind).sort(([a], [b]) => {
      const idxA = ASSET_KIND_ORDER.indexOf(a);
      const idxB = ASSET_KIND_ORDER.indexOf(b);
      if (idxA !== -1 && idxB !== -1) return idxA - idxB;
      if (idxA !== -1) return -1;
      if (idxB !== -1) return 1;
      return a.localeCompare(b);
    });
    const total = entries.reduce((sum, [, count]) => sum + count, 0);
    return {
      hasData: true,
      total,
      byKind: entries.map(([kind, count]) => ({ kind, count })),
    };
  }
  if (counters.assets !== undefined) {
    return {
      hasData: true,
      total: counters.assets,
      byKind: [],
    };
  }
  return { hasData: false, byKind: [] };
}

/**
 * Computes a contract-compliant `budget` object from a RoE policy and usage values (for mock state).
 */
export function buildBudgetFromPolicy(
  policy: RoEPolicy,
  used: CampaignBudget['used'] = {
    hours: 0,
    llm_cost_usd: 0,
    llm_tokens: 0,
    jobs: 0,
    agent_sessions: 0,
  }
): CampaignBudget {
  const limits: CampaignBudget['limits'] = {
    max_duration_hours: policy.max_duration_hours,
    ...(policy.budget?.max_llm_cost_usd !== undefined
      ? { max_llm_cost_usd: policy.budget.max_llm_cost_usd }
      : {}),
    ...(policy.budget?.max_llm_tokens !== undefined
      ? { max_llm_tokens: policy.budget.max_llm_tokens }
      : {}),
    ...(policy.budget?.max_jobs !== undefined ? { max_jobs: policy.budget.max_jobs } : {}),
    ...(policy.budget?.max_agent_sessions !== undefined
      ? { max_agent_sessions: policy.budget.max_agent_sessions }
      : {}),
  };

  const remaining: CampaignBudget['remaining'] = {
    hours: Number(Math.max(0, limits.max_duration_hours - used.hours).toFixed(6)),
    ...(limits.max_llm_cost_usd !== undefined
      ? { llm_cost_usd: Number(Math.max(0, limits.max_llm_cost_usd - used.llm_cost_usd).toFixed(6)) }
      : {}),
    ...(limits.max_llm_tokens !== undefined
      ? { llm_tokens: Math.max(0, limits.max_llm_tokens - used.llm_tokens) }
      : {}),
    ...(limits.max_jobs !== undefined ? { jobs: Math.max(0, limits.max_jobs - used.jobs) } : {}),
    ...(limits.max_agent_sessions !== undefined
      ? { agent_sessions: Math.max(0, limits.max_agent_sessions - used.agent_sessions) }
      : {}),
  };

  return { limits, used, remaining };
}
