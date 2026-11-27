import type { VulnerabilityCandidate } from '../api/types';

export type CandidateSortKey = 'rank' | 'epss' | 'cvss' | 'cve_asc' | 'cve_desc';

export interface CandidateCountSummary {
  total: number;
  kevCount: number;
  criticalCount: number;
  highCount: number;
}

function numericScore(value: number | null | undefined): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : -1;
}

/**
 * Resolves effective CVSS severity label for counting CRITICAL/HIGH candidates.
 * Uses contract `cvss_severity` when present; falls back to CVSS v3 thresholds only when absent.
 */
export function resolveCandidateSeverity(
  candidate: Pick<VulnerabilityCandidate, 'cvss_severity' | 'cvss_base'>
): string | null {
  if (candidate.cvss_severity) {
    return candidate.cvss_severity.toUpperCase();
  }
  if (typeof candidate.cvss_base === 'number' && Number.isFinite(candidate.cvss_base)) {
    if (candidate.cvss_base >= 9.0) return 'CRITICAL';
    if (candidate.cvss_base >= 7.0) return 'HIGH';
    if (candidate.cvss_base >= 4.0) return 'MEDIUM';
    if (candidate.cvss_base > 0) return 'LOW';
    return 'NONE';
  }
  return null;
}

/**
 * Primary operator priority ranking: KEV first, then EPSS desc, then CVSS desc, then CVE ID asc.
 */
export function compareCandidatesByRank(
  a: VulnerabilityCandidate,
  b: VulnerabilityCandidate
): number {
  const kevDiff = Number(Boolean(b.kev)) - Number(Boolean(a.kev));
  if (kevDiff !== 0) return kevDiff;

  const epssDiff = numericScore(b.epss) - numericScore(a.epss);
  if (epssDiff !== 0) return epssDiff;

  const cvssDiff = numericScore(b.cvss_base) - numericScore(a.cvss_base);
  if (cvssDiff !== 0) return cvssDiff;

  return a.vulnerability_id.localeCompare(b.vulnerability_id);
}

/**
 * Returns a new candidate array ordered by KEV -> EPSS -> CVSS -> CVE ID.
 */
export function rankCandidates(
  candidates: readonly VulnerabilityCandidate[]
): VulnerabilityCandidate[] {
  return [...candidates].sort(compareCandidatesByRank);
}

/**
 * Sorts candidate list according to the selected VulnerabilityPanel sort key.
 */
export function sortCandidates(
  candidates: readonly VulnerabilityCandidate[],
  sortKey: CandidateSortKey
): VulnerabilityCandidate[] {
  if (sortKey === 'rank') {
    return rankCandidates(candidates);
  }
  return [...candidates].sort((a, b) => {
    switch (sortKey) {
      case 'epss': {
        const diff = numericScore(b.epss) - numericScore(a.epss);
        return diff !== 0 ? diff : compareCandidatesByRank(a, b);
      }
      case 'cvss': {
        const diff = numericScore(b.cvss_base) - numericScore(a.cvss_base);
        return diff !== 0 ? diff : compareCandidatesByRank(a, b);
      }
      case 'cve_asc':
        return a.vulnerability_id.localeCompare(b.vulnerability_id);
      case 'cve_desc':
        return b.vulnerability_id.localeCompare(a.vulnerability_id);
    }
  });
}

/**
 * Computes total, KEV, CRITICAL, and HIGH candidate counts for a service row.
 */
export function summarizeCandidateCounts(
  candidates: readonly VulnerabilityCandidate[]
): CandidateCountSummary {
  let kevCount = 0;
  let criticalCount = 0;
  let highCount = 0;
  for (const cand of candidates) {
    if (cand.kev) kevCount += 1;
    const sev = resolveCandidateSeverity(cand);
    if (sev === 'CRITICAL') criticalCount += 1;
    else if (sev === 'HIGH') highCount += 1;
  }
  return {
    total: candidates.length,
    kevCount,
    criticalCount,
    highCount,
  };
}
