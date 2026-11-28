import type {
  Finding,
  FindingHistoryResponse,
  FindingSeverity,
  FindingStatus,
} from '../api/types';

export type ChipVariant = 'success' | 'warning' | 'accent' | 'danger' | 'neutral';

export const FINDING_STATUS_OPTIONS: readonly FindingStatus[] = [
  'CANDIDATE',
  'CORROBORATED',
  'VERIFIED',
  'FALSE_POSITIVE',
  'ACCEPTED_RISK',
  'FIXED',
  'REGRESSED',
];

export const FINDING_SEVERITY_OPTIONS: readonly FindingSeverity[] = [
  'CRITICAL',
  'HIGH',
  'MEDIUM',
  'LOW',
  'INFO',
  'UNRATED',
];

export const FINDING_STATUS_META: Record<
  FindingStatus,
  { label: string; shortLabel: string; variant: ChipVariant }
> = {
  CANDIDATE: { label: 'Ứng viên (CANDIDATE)', shortLabel: 'CANDIDATE', variant: 'warning' },
  CORROBORATED: { label: 'Đối chứng (CORROBORATED)', shortLabel: 'CORROBORATED', variant: 'accent' },
  VERIFIED: { label: 'Đã xác minh (VERIFIED)', shortLabel: 'VERIFIED', variant: 'success' },
  FALSE_POSITIVE: { label: 'Báo nhầm (FALSE_POSITIVE)', shortLabel: 'FALSE_POSITIVE', variant: 'neutral' },
  ACCEPTED_RISK: { label: 'Chấp nhận rủi ro (ACCEPTED_RISK)', shortLabel: 'ACCEPTED_RISK', variant: 'neutral' },
  FIXED: { label: 'Đã khắc phục (FIXED)', shortLabel: 'FIXED', variant: 'success' },
  REGRESSED: { label: 'Tái phát (REGRESSED)', shortLabel: 'REGRESSED', variant: 'danger' },
};

export const FINDING_SEVERITY_META: Record<
  FindingSeverity,
  { label: string; variant: ChipVariant; rank: number }
> = {
  CRITICAL: { label: 'CRITICAL', variant: 'danger', rank: 5 },
  HIGH: { label: 'HIGH', variant: 'warning', rank: 4 },
  MEDIUM: { label: 'MEDIUM', variant: 'accent', rank: 3 },
  LOW: { label: 'LOW', variant: 'neutral', rank: 2 },
  INFO: { label: 'INFO', variant: 'neutral', rank: 1 },
  UNRATED: { label: 'UNRATED (Chưa đánh giá)', variant: 'neutral', rank: 0 },
};

/**
 * Operator-permitted transitions from contracts/finding/transitions.v2.yaml.
 */
const OPERATOR_TRANSITIONS: Record<FindingStatus, FindingStatus[]> = {
  CANDIDATE: ['FALSE_POSITIVE', 'ACCEPTED_RISK'],
  CORROBORATED: ['FALSE_POSITIVE', 'ACCEPTED_RISK'],
  VERIFIED: ['FALSE_POSITIVE', 'ACCEPTED_RISK'],
  REGRESSED: ['FALSE_POSITIVE', 'ACCEPTED_RISK'],
  FALSE_POSITIVE: ['CANDIDATE'],
  ACCEPTED_RISK: ['CANDIDATE'],
  FIXED: [],
};

export function getAllowedOperatorTransitions(status: FindingStatus): FindingStatus[] {
  return OPERATOR_TRANSITIONS[status] || [];
}

export function getLatestTransitionSeq(
  history: Pick<FindingHistoryResponse, 'transitions'> | null | undefined
): number {
  if (!history || !history.transitions || history.transitions.length === 0) {
    return 0;
  }
  return history.transitions.reduce((max, item) => Math.max(max, item.seq), 0);
}

export function isSafeHttpUrl(url: string | undefined): url is string {
  if (!url) return false;
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

const CAUSE_LABELS: Record<string, string> = {
  scan: 'Quét tự động (scan)',
  intel_revision: 'Cập nhật tri thức CVE (intel_revision)',
  verification: 'Xác minh động (verification)',
  operator: 'Người vận hành (operator)',
  regression_check: 'Kiểm tra tái phát (regression_check)',
};

export function formatTransitionCause(cause: string): string {
  return CAUSE_LABELS[cause] || cause;
}

const TRIGGER_LABELS: Record<string, string> = {
  scan: 'Lần quét (scan)',
  intel_revision: 'Thay đổi feed tri thức (intel_revision)',
  operator_request: 'Yêu cầu vận hành (operator_request)',
  verification: 'Kết quả xác minh (verification)',
};

export function formatAssessmentTrigger(trigger: string): string {
  return TRIGGER_LABELS[trigger] || trigger;
}

export interface ResolvedSourceRefLink {
  type: 'external' | 'anchor';
  href: string;
}

export function resolveSourceRefLink(
  sourceRef: { kind: string; ref: string },
  finding: Pick<Finding, 'evidence'>
): ResolvedSourceRefLink | null {
  const value = sourceRef.ref.trim();
  if (!value) return null;

  if (sourceRef.kind === 'evidence') {
    const matched = finding.evidence.find((ev) => ev.evidence_id === value);
    if (matched) {
      return { type: 'anchor', href: `#finding-evidence-${matched.evidence_id}` };
    }
    return isSafeHttpUrl(value) ? { type: 'external', href: value } : null;
  }

  if (sourceRef.kind === 'intel') {
    const lower = value.toLowerCase();
    const cveMatch = value.match(/(CVE-\d{4}-\d+)/i);
    if (lower.startsWith('kev:')) {
      return {
        type: 'external',
        href: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
      };
    }
    if (lower.startsWith('epss:') && cveMatch) {
      return {
        type: 'external',
        href: `https://api.first.org/data/v1/epss?cve=${encodeURIComponent(cveMatch[1].toUpperCase())}`,
      };
    }
    if (cveMatch) {
      return {
        type: 'external',
        href: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cveMatch[1].toUpperCase())}`,
      };
    }
    return isSafeHttpUrl(value) ? { type: 'external', href: value } : null;
  }

  if (sourceRef.kind === 'finding_run') {
    return { type: 'anchor', href: `#finding-run-${value}` };
  }

  if (sourceRef.kind === 'observation') {
    return { type: 'anchor', href: '#finding-provenance' };
  }

  return null;
}
