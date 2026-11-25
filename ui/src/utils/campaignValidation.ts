import type { CreateCampaignRequest, RoEPolicy, Targets } from '../api/types';

export interface FieldValidationResult {
  errors: Record<string, string>;
}

const DOMAIN_LABEL_REGEX = /^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?$/i;
const DOMAIN_LAST_LABEL_REGEX = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;
const CAPABILITY_ID_REGEX = /^[a-z][a-z0-9]*\.[a-z][a-z0-9_]*$/;

export function parseLines(raw: string): string[] {
  return raw
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
}

export function findDuplicates(items: string[]): string[] {
  const seen = new Set<string>();
  const dups = new Set<string>();
  for (const item of items) {
    if (seen.has(item)) dups.add(item);
    seen.add(item);
  }
  return Array.from(dups);
}

/**
 * Mirrors contracts/validation.py::domain_seed for client-side checks.
 * Supports ASCII and IDNA hostnames (via URL punycode conversion in browser/jsdom).
 */
export function isValidDomainSeed(value: string): boolean {
  if (!value || value.length > 253) return false;
  if (/[\s/:@#?\\]/.test(value)) return false;
  const candidate = value.endsWith('.') ? value.slice(0, -1) : value;
  if (!candidate || candidate.length > 253) return false;

  let asciiHost = candidate.toLowerCase();
  if (/[^\x20-\x7e]/.test(asciiHost)) {
    try {
      asciiHost = new URL(`https://${asciiHost}`).hostname.toLowerCase();
    } catch {
      return false;
    }
  }
  if (!asciiHost || asciiHost.length > 253) return false;
  const labels = asciiHost.split('.');
  if (labels.some((label) => label.length === 0)) return false;
  for (let i = 0; i < labels.length - 1; i++) {
    if (!DOMAIN_LABEL_REGEX.test(labels[i])) return false;
  }
  return DOMAIN_LAST_LABEL_REGEX.test(labels[labels.length - 1]);
}

function isValidIpv4(value: string): boolean {
  const parts = value.split('.');
  if (parts.length !== 4) return false;
  return parts.every((part) => {
    if (!/^(?:0|[1-9][0-9]{0,2})$/.test(part)) return false;
    const num = Number(part);
    return num >= 0 && num <= 255;
  });
}

function isValidIpv6(value: string): boolean {
  if (!value || value.includes('%')) return false;
  // Use browser/Node URL parser for full RFC 4291 IPv6 validation (handles :: compression and v4-mapped)
  try {
    const url = new URL(`http://[${value}]`);
    return url.hostname.startsWith('[') && url.hostname.endsWith(']');
  } catch {
    return false;
  }
}

/**
 * Mirrors contracts/validation.py::ip_or_cidr.
 */
export function isValidIpOrCidr(value: string): boolean {
  if (!value || value.length > 64 || value.includes('%')) return false;
  const slashIdx = value.indexOf('/');
  if (slashIdx === -1) {
    return isValidIpv4(value) || isValidIpv6(value);
  }
  if (value.indexOf('/', slashIdx + 1) !== -1) return false;
  const addr = value.slice(0, slashIdx);
  const prefixStr = value.slice(slashIdx + 1);
  if (!/^[0-9]+$/.test(prefixStr)) return false;
  const prefix = Number(prefixStr);
  if (isValidIpv4(addr)) {
    return prefix >= 0 && prefix <= 32;
  }
  if (isValidIpv6(addr)) {
    return prefix >= 0 && prefix <= 128;
  }
  return false;
}

export function isValidCapabilityId(value: string): boolean {
  return CAPABILITY_ID_REGEX.test(value);
}

export interface PolicyFormValues {
  networkProfile: 'lab' | 'internet';
  maxParallelJobs: string;
  maxDurationHours: string;
  requestsPerSecondPerHost: string;
  maxConcurrentConnectionsPerHost: string;
  packetsPerSecond: string;
  jobsPerMinute: string;
  maxLlmCostUsd: string;
  maxLlmTokens: string;
  maxJobs: string;
  maxAgentSessions: string;
  idleCyclesBeforePause: string;
  capabilityDenylistText: string;
  targetDenylistText: string;
  authOwner: string;
  authReference: string;
  authDate: string;
  authSuffixesText: string;
}

export interface CampaignFormValues extends PolicyFormValues {
  name: string;
  objective: string;
  authorizationLabel: string;
  domainsText: string;
  ipsText: string;
  keywordsText: string;
}

export const SAFE_LAB_POLICY_DEFAULTS: PolicyFormValues = {
  networkProfile: 'lab',
  maxParallelJobs: '2',
  maxDurationHours: '2',
  requestsPerSecondPerHost: '2',
  maxConcurrentConnectionsPerHost: '2',
  packetsPerSecond: '100',
  jobsPerMinute: '10',
  maxLlmCostUsd: '5',
  maxLlmTokens: '100000',
  maxJobs: '20',
  maxAgentSessions: '5',
  idleCyclesBeforePause: '3',
  capabilityDenylistText: '',
  targetDenylistText: '',
  authOwner: '',
  authReference: '',
  authDate: '',
  authSuffixesText: '',
};

export function policyToFormValues(policy?: RoEPolicy): PolicyFormValues {
  if (!policy) return { ...SAFE_LAB_POLICY_DEFAULTS };
  return {
    networkProfile: policy.network_profile === 'lab' ? 'lab' : 'internet',
    maxParallelJobs: String(policy.max_parallel_jobs ?? 2),
    maxDurationHours: String(policy.max_duration_hours ?? 2),
    requestsPerSecondPerHost:
      policy.rate_limits?.requests_per_second_per_host !== undefined
        ? String(policy.rate_limits.requests_per_second_per_host)
        : '',
    maxConcurrentConnectionsPerHost:
      policy.rate_limits?.max_concurrent_connections_per_host !== undefined
        ? String(policy.rate_limits.max_concurrent_connections_per_host)
        : '',
    packetsPerSecond:
      policy.rate_limits?.packets_per_second !== undefined
        ? String(policy.rate_limits.packets_per_second)
        : '',
    jobsPerMinute:
      policy.rate_limits?.jobs_per_minute !== undefined
        ? String(policy.rate_limits.jobs_per_minute)
        : '',
    maxLlmCostUsd:
      policy.budget?.max_llm_cost_usd !== undefined ? String(policy.budget.max_llm_cost_usd) : '',
    maxLlmTokens:
      policy.budget?.max_llm_tokens !== undefined ? String(policy.budget.max_llm_tokens) : '',
    maxJobs: policy.budget?.max_jobs !== undefined ? String(policy.budget.max_jobs) : '',
    maxAgentSessions:
      policy.budget?.max_agent_sessions !== undefined
        ? String(policy.budget.max_agent_sessions)
        : '',
    idleCyclesBeforePause:
      policy.budget?.idle_cycles_before_pause !== undefined
        ? String(policy.budget.idle_cycles_before_pause)
        : '3',
    capabilityDenylistText: (policy.capability_denylist || []).join('\n'),
    targetDenylistText: (policy.target_denylist || []).join('\n'),
    authOwner: policy.authorization?.owner ?? '',
    authReference: policy.authorization?.reference ?? '',
    authDate: policy.authorization?.date ?? '',
    authSuffixesText: (policy.authorization?.authorized_suffixes || []).join('\n'),
  };
}

function isValidIsoDate(value: string): boolean {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value);
  if (!m) return false;
  const year = Number(m[1]);
  const month = Number(m[2]);
  const day = Number(m[3]);
  const dt = new Date(Date.UTC(year, month - 1, day));
  return (
    dt.getUTCFullYear() === year &&
    dt.getUTCMonth() === month - 1 &&
    dt.getUTCDate() === day
  );
}

function parseOptionalInt(
  raw: string,
  label: string,
  min: number,
  max: number | undefined,
  required: boolean
): { value?: number; error?: string } {
  const trimmed = raw.trim();
  if (!trimmed) {
    return required ? { error: `${label} là bắt buộc.` } : {};
  }
  const num = Number(trimmed);
  if (!Number.isInteger(num) || num < min || (max !== undefined && num > max)) {
    const range = max !== undefined ? `${min}..${max}` : `>= ${min}`;
    return { error: `${label} phải là số nguyên trong khoảng ${range}.` };
  }
  return { value: num };
}

function parseOptionalNumber(
  raw: string,
  label: string,
  min: number,
  exclusiveMin: boolean,
  max: number | undefined,
  required: boolean
): { value?: number; error?: string } {
  const trimmed = raw.trim();
  if (!trimmed) {
    return required ? { error: `${label} là bắt buộc.` } : {};
  }
  const num = Number(trimmed);
  const minBad = exclusiveMin ? num <= min : num < min;
  if (!Number.isFinite(num) || minBad || (max !== undefined && num > max)) {
    const op = exclusiveMin ? '>' : '>=';
    const range = max !== undefined ? `${op} ${min} và <= ${max}` : `${op} ${min}`;
    return { error: `${label} phải là số hợp lệ (${range}).` };
  }
  return { value: num };
}

export function validatePolicyForm(values: PolicyFormValues): {
  errors: Record<string, string>;
  policy?: RoEPolicy;
} {
  const errors: Record<string, string> = {};
  const isInternet = values.networkProfile === 'internet';

  const maxParallel = parseOptionalInt(values.maxParallelJobs, 'Số job đồng thời tối đa', 1, 50, true);
  if (maxParallel.error) errors.maxParallelJobs = maxParallel.error;

  const maxDuration = parseOptionalInt(values.maxDurationHours, 'Thời lượng tối đa (giờ)', 1, 168, true);
  if (maxDuration.error) errors.maxDurationHours = maxDuration.error;

  const rps = parseOptionalNumber(
    values.requestsPerSecondPerHost,
    'Tốc độ tối đa / host (req/s)',
    0,
    true,
    1000,
    isInternet
  );
  if (rps.error) errors.requestsPerSecondPerHost = rps.error;

  const maxConn = parseOptionalInt(
    values.maxConcurrentConnectionsPerHost,
    'Kết nối đồng thời tối đa / host',
    1,
    100,
    isInternet
  );
  if (maxConn.error) errors.maxConcurrentConnectionsPerHost = maxConn.error;

  const pps = parseOptionalInt(values.packetsPerSecond, 'Gói tin/giây (packets/s)', 1, 100000, false);
  if (pps.error) errors.packetsPerSecond = pps.error;

  const jpm = parseOptionalInt(values.jobsPerMinute, 'Số job/phút', 1, 600, false);
  if (jpm.error) errors.jobsPerMinute = jpm.error;

  const cost = parseOptionalNumber(values.maxLlmCostUsd, 'Chi phí LLM tối đa (USD)', 0, false, undefined, false);
  if (cost.error) errors.maxLlmCostUsd = cost.error;

  const tokens = parseOptionalInt(values.maxLlmTokens, 'Token LLM tối đa', 0, undefined, false);
  if (tokens.error) errors.maxLlmTokens = tokens.error;

  const maxJobs = parseOptionalInt(values.maxJobs, 'Số job tối đa', 1, undefined, false);
  if (maxJobs.error) errors.maxJobs = maxJobs.error;

  const maxSessions = parseOptionalInt(values.maxAgentSessions, 'Số phiên agent tối đa', 1, undefined, false);
  if (maxSessions.error) errors.maxAgentSessions = maxSessions.error;

  const hasAnyBudgetField =
    values.maxLlmCostUsd.trim() !== '' ||
    values.maxLlmTokens.trim() !== '' ||
    values.maxJobs.trim() !== '' ||
    values.maxAgentSessions.trim() !== '' ||
    values.idleCyclesBeforePause.trim() !== '';

  const idleCycles = parseOptionalInt(
    values.idleCyclesBeforePause,
    'Số chu kỳ rỗi trước khi tạm dừng',
    3,
    5,
    hasAnyBudgetField
  );
  if (idleCycles.error) errors.idleCyclesBeforePause = idleCycles.error;

  const capDeny = parseLines(values.capabilityDenylistText);
  const capDups = findDuplicates(capDeny);
  if (capDups.length > 0) {
    errors.capabilityDenylistText = `Capability bị lặp: ${capDups.join(', ')}`;
  } else {
    const badCap = capDeny.find((c) => !isValidCapabilityId(c));
    if (badCap) {
      errors.capabilityDenylistText = `Capability "${badCap}" không đúng định dạng <nhóm>.<hành_động> (ví dụ: network.discover_services).`;
    }
  }

  const targetDeny = parseLines(values.targetDenylistText);
  const targetDenyDups = findDuplicates(targetDeny);
  if (targetDenyDups.length > 0) {
    errors.targetDenylistText = `Mục tiêu loại trừ bị lặp: ${targetDenyDups.join(', ')}`;
  } else if (targetDeny.length > 10000) {
    errors.targetDenylistText = 'Danh sách loại trừ tối đa 10.000 mục.';
  }

  let authPayload: RoEPolicy['authorization'];
  if (isInternet) {
    const authOwner = values.authOwner.trim();
    if (!authOwner) {
      errors.authOwner = 'Chủ sở hữu hợp pháp (authorization.owner) là bắt buộc cho profile internet.';
    } else if (authOwner.length > 200) {
      errors.authOwner = 'Chủ sở hữu tối đa 200 ký tự.';
    }

    const authReference = values.authReference.trim();
    if (authReference.length < 3) {
      errors.authReference = 'Tham chiếu ủy quyền (authorization.reference) tối thiểu 3 ký tự.';
    } else if (authReference.length > 300) {
      errors.authReference = 'Tham chiếu ủy quyền tối đa 300 ký tự.';
    }

    const authDate = values.authDate.trim();
    if (!isValidIsoDate(authDate)) {
      errors.authDate = 'Ngày ủy quyền phải đúng định dạng YYYY-MM-DD.';
    }

    const suffixes = parseLines(values.authSuffixesText);
    const suffixDups = findDuplicates(suffixes);
    if (suffixes.length === 0) {
      errors.authSuffixesText = 'Cần ít nhất một hậu tố tên miền được phép (authorized_suffixes).';
    } else if (suffixDups.length > 0) {
      errors.authSuffixesText = `Hậu tố tên miền bị lặp: ${suffixDups.join(', ')}`;
    } else if (suffixes.length > 100) {
      errors.authSuffixesText = 'Tối đa 100 hậu tố tên miền được phép.';
    } else {
      const badSuffix = suffixes.find((s) => !isValidDomainSeed(s));
      if (badSuffix) {
        errors.authSuffixesText = `Hậu tố tên miền "${badSuffix}" không hợp lệ.`;
      }
    }

    if (!errors.authOwner && !errors.authReference && !errors.authDate && !errors.authSuffixesText) {
      authPayload = {
        owner: authOwner,
        reference: authReference,
        date: authDate,
        authorized_suffixes: suffixes,
      };
    }
  }

  if (Object.keys(errors).length > 0) {
    return { errors };
  }

  const rateLimits: NonNullable<RoEPolicy['rate_limits']> = {};
  if (rps.value !== undefined) rateLimits.requests_per_second_per_host = rps.value;
  if (maxConn.value !== undefined) rateLimits.max_concurrent_connections_per_host = maxConn.value;
  if (pps.value !== undefined) rateLimits.packets_per_second = pps.value;
  if (jpm.value !== undefined) rateLimits.jobs_per_minute = jpm.value;

  const policy: RoEPolicy = {
    network_profile: values.networkProfile,
    max_parallel_jobs: maxParallel.value!,
    max_duration_hours: maxDuration.value!,
  };

  if (Object.keys(rateLimits).length > 0) {
    policy.rate_limits = rateLimits;
  }

  if (hasAnyBudgetField && idleCycles.value !== undefined) {
    const budget: NonNullable<RoEPolicy['budget']> = {
      idle_cycles_before_pause: idleCycles.value,
    };
    if (cost.value !== undefined) budget.max_llm_cost_usd = cost.value;
    if (tokens.value !== undefined) budget.max_llm_tokens = tokens.value;
    if (maxJobs.value !== undefined) budget.max_jobs = maxJobs.value;
    if (maxSessions.value !== undefined) budget.max_agent_sessions = maxSessions.value;
    policy.budget = budget;
  }

  if (capDeny.length > 0) {
    policy.capability_denylist = capDeny;
  }
  if (targetDeny.length > 0) {
    policy.target_denylist = targetDeny;
  }
  if (authPayload) {
    policy.authorization = authPayload;
  }

  return { errors, policy };
}

export function validateCampaignForm(values: CampaignFormValues): {
  errors: Record<string, string>;
  payload?: CreateCampaignRequest;
} {
  const errors: Record<string, string> = {};

  const name = values.name.trim();
  if (!name) {
    errors.name = 'Tên chiến dịch là bắt buộc.';
  } else if (name.length > 200) {
    errors.name = 'Tên chiến dịch tối đa 200 ký tự.';
  }

  const objective = values.objective.trim();
  if (!objective) {
    errors.objective = 'Mục tiêu chiến dịch là bắt buộc.';
  } else if (objective.length > 4000) {
    errors.objective = 'Mục tiêu chiến dịch tối đa 4.000 ký tự.';
  }

  const authLabel = values.authorizationLabel.trim();
  if (authLabel.length > 200) {
    errors.authorizationLabel = 'Tham chiếu ủy quyền (labels.authorization) tối đa 200 ký tự.';
  }

  const domains = parseLines(values.domainsText);
  const ips = parseLines(values.ipsText);
  const keywords = parseLines(values.keywordsText);

  if (domains.length === 0 && ips.length === 0 && keywords.length === 0) {
    errors.targets = 'Cần ít nhất một mục tiêu hợp lệ (domain, IP/CIDR hoặc từ khóa).';
  }

  const domainDups = findDuplicates(domains);
  if (domainDups.length > 0) {
    errors.domainsText = `Tên miền bị lặp: ${domainDups.join(', ')}`;
  } else if (domains.length > 10000) {
    errors.domainsText = 'Tối đa 10.000 tên miền.';
  } else {
    const badDomain = domains.find((d) => !isValidDomainSeed(d));
    if (badDomain) {
      errors.domainsText = `Tên miền "${badDomain}" không hợp lệ (dạng domain thuần, không gồm http:// hay khoảng trắng).`;
    }
  }

  const ipDups = findDuplicates(ips);
  if (ipDups.length > 0) {
    errors.ipsText = `IP / CIDR bị lặp: ${ipDups.join(', ')}`;
  } else if (ips.length > 10000) {
    errors.ipsText = 'Tối đa 10.000 địa chỉ IP/CIDR.';
  } else {
    const badIp = ips.find((ip) => !isValidIpOrCidr(ip));
    if (badIp) {
      errors.ipsText = `IP / CIDR "${badIp}" không hợp lệ (ví dụ: 203.0.113.10 hoặc 10.20.0.0/24).`;
    }
  }

  const kwDups = findDuplicates(keywords);
  if (kwDups.length > 0) {
    errors.keywordsText = `Từ khóa bị lặp: ${kwDups.join(', ')}`;
  } else if (keywords.length > 1000) {
    errors.keywordsText = 'Tối đa 1.000 từ khóa.';
  } else {
    const badKw = keywords.find((k) => k.length < 2 || k.length > 200);
    if (badKw) {
      errors.keywordsText = `Từ khóa "${badKw}" phải có độ dài từ 2 đến 200 ký tự.`;
    }
  }

  const policyValidation = validatePolicyForm(values);
  Object.assign(errors, policyValidation.errors);

  if (Object.keys(errors).length > 0 || !policyValidation.policy) {
    return { errors };
  }

  const targetsObj: { domains?: string[]; ips?: string[]; keywords?: string[] } = {};
  if (domains.length > 0) targetsObj.domains = domains;
  if (ips.length > 0) targetsObj.ips = ips;
  if (keywords.length > 0) targetsObj.keywords = keywords;

  const payload: CreateCampaignRequest = {
    name,
    objective,
    targets: targetsObj as Targets,
    policy: policyValidation.policy,
  };

  if (authLabel) {
    payload.labels = { authorization: authLabel };
  }

  return { errors, payload };
}

/**
 * Maps JSON Pointer `error.v2.field` (both /campaigns and /campaigns/{id}/policy shapes)
 * to UI form field keys so server errors highlight inline on the exact field.
 */
export function mapServerFieldToKey(field?: string): string | null {
  if (!field) return null;
  const clean = field.trim();
  if (clean === '/name') return 'name';
  if (clean === '/objective') return 'objective';
  if (clean === '/reason') return 'reason';
  if (clean === '/labels' || clean.startsWith('/labels/')) return 'authorizationLabel';
  if (clean === '/targets') return 'targets';
  if (clean.startsWith('/targets/domains')) return 'domainsText';
  if (clean.startsWith('/targets/ips')) return 'ipsText';
  if (clean.startsWith('/targets/keywords')) return 'keywordsText';

  // Both `/policy/<x>` (createCampaign) and `/<x>` (updateCampaignPolicy validates roe-policy directly)
  const policyPath = clean.startsWith('/policy/') ? clean.slice('/policy'.length) : clean;
  if (policyPath === '/network_profile') return 'networkProfile';
  if (policyPath === '/max_parallel_jobs') return 'maxParallelJobs';
  if (policyPath === '/max_duration_hours') return 'maxDurationHours';
  if (policyPath === '/rate_limits/requests_per_second_per_host') return 'requestsPerSecondPerHost';
  if (policyPath === '/rate_limits/max_concurrent_connections_per_host')
    return 'maxConcurrentConnectionsPerHost';
  if (policyPath === '/rate_limits/packets_per_second') return 'packetsPerSecond';
  if (policyPath === '/rate_limits/jobs_per_minute') return 'jobsPerMinute';
  if (policyPath === '/budget/max_llm_cost_usd') return 'maxLlmCostUsd';
  if (policyPath === '/budget/max_llm_tokens') return 'maxLlmTokens';
  if (policyPath === '/budget/max_jobs') return 'maxJobs';
  if (policyPath === '/budget/max_agent_sessions') return 'maxAgentSessions';
  if (policyPath === '/budget/idle_cycles_before_pause') return 'idleCyclesBeforePause';
  if (policyPath.startsWith('/capability_denylist')) return 'capabilityDenylistText';
  if (policyPath.startsWith('/target_denylist')) return 'targetDenylistText';
  if (policyPath === '/authorization/owner') return 'authOwner';
  if (policyPath === '/authorization/reference') return 'authReference';
  if (policyPath === '/authorization/date') return 'authDate';
  if (policyPath.startsWith('/authorization/authorized_suffixes')) return 'authSuffixesText';

  return null;
}
