import React, { useState } from 'react';
import { Server, ShieldAlert, Network } from 'lucide-react';
import type { ServiceRowData, VulnerabilityCandidate } from '../api/types';
import { CopyableId } from './CopyableId';
import {
  rankCandidates,
  resolveCandidateSeverity,
  summarizeCandidateCounts,
} from '../utils/cveCandidates';

const TOP_CVE_CHIP_LIMIT = 5;

function formatCandidateTitle(cand: VulnerabilityCandidate): string {
  const parts = [cand.vulnerability_id];
  if (cand.kev) parts.push('CISA KEV');
  if (typeof cand.epss === 'number') parts.push(`EPSS ${(cand.epss * 100).toFixed(2)}%`);
  if (typeof cand.cvss_base === 'number') {
    parts.push(
      `CVSS ${cand.cvss_base.toFixed(1)}${cand.cvss_severity ? ` (${cand.cvss_severity})` : ''}`
    );
  }
  return `Mở bảng ứng viên ${parts.join(' · ')} (chưa xác minh)`;
}

interface ServiceTableProps {
  rows: ServiceRowData[];
  selectedAssetId?: string;
  selectedCveId?: string;
  onSelectVulnerability: (row: ServiceRowData, candidate: VulnerabilityCandidate) => void;
  onFocusInGraph: (assetId: string) => void;
}

export const ServiceTable: React.FC<ServiceTableProps> = ({
  rows,
  selectedAssetId,
  selectedCveId,
  onSelectVulnerability,
  onFocusInGraph,
}) => {
  const [expandedRows, setExpandedRows] = useState<Record<string, boolean>>({});

  const toggleRowExpanded = (assetId: string) => {
    setExpandedRows((prev) => ({ ...prev, [assetId]: !prev[assetId] }));
  };

  if (rows.length === 0) {
    return (
      <div className="state-box" style={{ padding: '40px 20px' }}>
        <Server size={36} style={{ color: 'var(--muted)', marginBottom: 8 }} />
        <div className="state-title" style={{ fontSize: 'var(--text-base)' }}>
          Chưa phát hiện dịch vụ nào khớp bộ lọc trong chiến dịch
        </div>
        <div className="state-desc" style={{ fontSize: 'var(--text-xs)' }}>
          Bảng dịch vụ tổng hợp các tài sản kind=service cùng thông tin protocol, product/version/CPE và ứng viên CVE từ backend API.
        </div>
      </div>
    );
  }

  const thStyle: React.CSSProperties = { padding: '8px 8px' };
  const tdStyle: React.CSSProperties = { padding: '10px 8px', verticalAlign: 'top' };

  return (
    <div className="table-container">
      <table
        className="data-table"
        aria-label="Bảng dịch vụ theo chiến dịch"
        style={{ fontSize: 'var(--text-xs)' }}
      >
        <thead>
          <tr>
            <th style={thStyle}>Host</th>
            <th style={thStyle}>Port</th>
            <th style={thStyle}>Protocol</th>
            <th style={thStyle}>Product</th>
            <th style={thStyle}>Version</th>
            <th style={thStyle}>CPE</th>
            <th style={thStyle}>#Ứng viên CVE (KEV)</th>
            <th style={{ ...thStyle, textAlign: 'right' }}>Thao tác</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => {
            const isSelected = selectedAssetId === row.asset.asset_id;
            const rankedCandidates = rankCandidates(row.candidates);
            const counts = summarizeCandidateCounts(rankedCandidates);
            const kevCount = row.kevCount ?? counts.kevCount;
            const criticalCount = row.criticalCount ?? counts.criticalCount;
            const highCount = row.highCount ?? counts.highCount;
            const firstCandidate = rankedCandidates[0];
            const firstKevCandidate = rankedCandidates.find((c) => c.kev);
            const firstCriticalCandidate = rankedCandidates.find(
              (c) => resolveCandidateSeverity(c) === 'CRITICAL'
            );
            const firstHighCandidate = rankedCandidates.find(
              (c) => resolveCandidateSeverity(c) === 'HIGH'
            );
            const summaryBadges = [
              {
                key: 'kev',
                count: kevCount,
                label: 'KEV',
                variant: 'danger' as const,
                candidate: firstKevCandidate,
                title: 'Mở ứng viên CVE ưu tiên trong CISA KEV',
              },
              {
                key: 'critical',
                count: criticalCount,
                label: 'Critical',
                variant: 'danger' as const,
                candidate: firstCriticalCandidate,
                title: 'Mở ứng viên CVE mức CRITICAL',
              },
              {
                key: 'high',
                count: highCount,
                label: 'High',
                variant: 'warning' as const,
                candidate: firstHighCandidate,
                title: 'Mở ứng viên CVE mức HIGH',
              },
            ];
            const hasCandidates = rankedCandidates.length > 0;
            const isExpanded = Boolean(expandedRows[row.asset.asset_id]);
            const hiddenCount = Math.max(0, rankedCandidates.length - TOP_CVE_CHIP_LIMIT);
            const visibleCandidates = isExpanded
              ? rankedCandidates
              : rankedCandidates.slice(0, TOP_CVE_CHIP_LIMIT);
            return (
              <tr
                key={row.asset.asset_id}
                onClick={() => {
                  if (firstCandidate) {
                    onSelectVulnerability(row, firstCandidate);
                  }
                }}
                style={{
                  backgroundColor: isSelected ? 'var(--subtle)' : undefined,
                  cursor: hasCandidates ? 'pointer' : undefined,
                }}
              >
                <td style={{ ...tdStyle, maxWidth: 148 }}>
                  <div
                    className="mono"
                    style={{
                      fontWeight: 600,
                      fontSize: 'var(--text-xs)',
                      color: 'var(--ink)',
                      overflowWrap: 'anywhere',
                    }}
                  >
                    {row.host}
                  </div>
                  <div style={{ marginTop: 3 }}>
                    <CopyableId value={row.asset.canonical_key} truncate />
                  </div>
                </td>
                <td style={{ ...tdStyle, whiteSpace: 'nowrap' }}>
                  <span className="mono tabular" style={{ fontWeight: 600 }}>
                    {row.port}
                  </span>
                </td>
                <td style={{ ...tdStyle, whiteSpace: 'nowrap' }}>
                  <span className="brand-badge" style={{ whiteSpace: 'nowrap' }}>
                    {row.protocol}
                  </span>
                </td>
                <td style={{ ...tdStyle, maxWidth: 115, overflowWrap: 'anywhere' }}>
                  {row.product ? (
                    <span style={{ fontWeight: 600, color: 'var(--ink)' }}>{row.product}</span>
                  ) : (
                    <span style={{ color: 'var(--muted)', fontSize: 'var(--text-xs)' }}>Chưa rõ</span>
                  )}
                </td>
                <td style={{ ...tdStyle, whiteSpace: 'nowrap' }}>
                  {row.version ? (
                    <span className="mono tabular">{row.version}</span>
                  ) : (
                    <span style={{ color: 'var(--muted)' }}>—</span>
                  )}
                </td>
                <td style={{ ...tdStyle, maxWidth: 175, wordBreak: 'break-all', fontSize: '11px' }}>
                  {row.cpe ? (
                    <CopyableId value={row.cpe} truncate={false} />
                  ) : (
                    <span style={{ color: 'var(--muted)' }}>—</span>
                  )}
                </td>
                <td style={{ ...tdStyle, minWidth: 210 }}>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                    <div
                      style={{ display: 'flex', alignItems: 'center', gap: 4, flexWrap: 'wrap' }}
                      aria-label={`Tóm tắt ứng viên CVE cho ${row.host}:${row.port}`}
                    >
                      {hasCandidates && firstCandidate ? (
                        <button
                          type="button"
                          className={`status-chip ${
                            kevCount > 0 || criticalCount > 0 ? 'danger' : 'warning'
                          }`}
                          onClick={(e) => {
                            e.stopPropagation();
                            onSelectVulnerability(row, firstCandidate);
                          }}
                          style={{ cursor: 'pointer' }}
                          title="Mở bảng chi tiết ứng viên CVE"
                        >
                          <span className="tabular">
                            {row.candidateCount}
                            {row.truncatedCandidates ? '+' : ''} ứng viên
                          </span>
                        </button>
                      ) : (
                        <span className="status-chip neutral">
                          <span className="tabular">
                            {row.candidateCount}
                            {row.truncatedCandidates ? '+' : ''} ứng viên
                          </span>
                        </span>
                      )}
                      {hasCandidates &&
                        summaryBadges.map((badge) =>
                          badge.count > 0 && badge.candidate ? (
                            <button
                              key={badge.key}
                              type="button"
                              className={`status-chip ${badge.variant}`}
                              onClick={(e) => {
                                e.stopPropagation();
                                onSelectVulnerability(row, badge.candidate!);
                              }}
                              style={{ cursor: 'pointer' }}
                              title={badge.title}
                            >
                              <span className="tabular">
                                {badge.count} {badge.label}
                              </span>
                            </button>
                          ) : (
                            <span key={badge.key} className="status-chip neutral">
                              <span className="tabular">
                                0 {badge.label}
                              </span>
                            </span>
                          )
                        )}
                    </div>
                    {visibleCandidates.length > 0 && (
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                        {visibleCandidates.map((cand) => {
                          const active =
                            isSelected && selectedCveId === cand.vulnerability_id;
                          return (
                            <button
                              key={cand.vulnerability_id}
                              type="button"
                              className="btn btn-sm"
                              onClick={(e) => {
                                e.stopPropagation();
                                onSelectVulnerability(row, cand);
                              }}
                              style={{
                                fontFamily: 'var(--font-mono)',
                                fontSize: '11px',
                                padding: '2px 6px',
                                whiteSpace: 'nowrap',
                                backgroundColor: active ? 'var(--accent-bg)' : undefined,
                                borderColor: active ? 'var(--accent)' : undefined,
                                color: active ? 'var(--accent)' : undefined,
                                fontWeight: active ? 700 : 500,
                              }}
                              title={formatCandidateTitle(cand)}
                            >
                              <ShieldAlert size={11} />
                              <span>{cand.vulnerability_id}</span>
                              {cand.kev ? (
                                <span style={{ color: 'var(--danger)', fontWeight: 700 }}>KEV</span>
                              ) : null}
                            </button>
                          );
                        })}
                        {hiddenCount > 0 && (
                          <button
                            type="button"
                            className="btn btn-sm"
                            aria-expanded={isExpanded}
                            aria-label={
                              isExpanded
                                ? `Thu gọn danh sách ứng viên CVE cho ${row.host}:${row.port}`
                                : `Hiện thêm ${hiddenCount} ứng viên CVE cho ${row.host}:${row.port}`
                            }
                            title={
                              isExpanded
                                ? 'Thu gọn về 5 ứng viên CVE ưu tiên hàng đầu'
                                : `Mở rộng toàn bộ ${rankedCandidates.length} ứng viên CVE`
                            }
                            onClick={(e) => {
                              e.stopPropagation();
                              toggleRowExpanded(row.asset.asset_id);
                            }}
                            style={{
                              fontFamily: 'var(--font-mono)',
                              fontSize: '11px',
                              fontWeight: 600,
                              padding: '2px 8px',
                              whiteSpace: 'nowrap',
                              color: 'var(--accent)',
                              borderColor: 'var(--accent)',
                              backgroundColor: 'var(--accent-bg)',
                            }}
                          >
                            {isExpanded ? 'Thu gọn' : `+${hiddenCount}`}
                          </button>
                        )}
                      </div>
                    )}
                  </div>
                </td>
                <td style={{ ...tdStyle, textAlign: 'right', whiteSpace: 'nowrap' }}>
                  <button
                    type="button"
                    className="btn btn-sm"
                    onClick={(e) => {
                      e.stopPropagation();
                      onFocusInGraph(row.asset.asset_id);
                    }}
                    style={{ whiteSpace: 'nowrap' }}
                    title="Xem dịch vụ này trên đồ thị tài sản"
                  >
                    <Network size={13} /> Đồ thị
                  </button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
};
