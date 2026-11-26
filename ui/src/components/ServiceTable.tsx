import React from 'react';
import { Server, ShieldAlert, Network } from 'lucide-react';
import type { ServiceRowData, VulnerabilityCandidate } from '../api/types';
import { CopyableId } from './CopyableId';

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
            const firstCandidate = row.candidates[0];
            const firstKevCandidate = row.candidates.find((c) => c.kev) || firstCandidate;
            const hasCandidates = row.candidates.length > 0;
            return (
              <tr
                key={row.asset.asset_id}
                onClick={() => {
                  if (firstKevCandidate) {
                    onSelectVulnerability(row, firstKevCandidate);
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
                <td style={{ ...tdStyle, minWidth: 155 }}>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 4, flexWrap: 'wrap' }}>
                      {hasCandidates && firstCandidate ? (
                        <button
                          type="button"
                          className={`status-chip ${
                            row.kevCount > 0 ? 'danger' : row.candidateCount > 0 ? 'warning' : 'neutral'
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
                      {row.kevCount > 0 && firstKevCandidate && (
                        <button
                          type="button"
                          className="status-chip danger"
                          onClick={(e) => {
                            e.stopPropagation();
                            onSelectVulnerability(row, firstKevCandidate);
                          }}
                          style={{ cursor: 'pointer' }}
                          title="Mở bảng chi tiết ứng viên CVE trong CISA KEV"
                        >
                          <span className="tabular">{row.kevCount} KEV</span>
                        </button>
                      )}
                    </div>
                    {row.candidates.length > 0 && (
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                        {row.candidates.map((cand) => {
                          const active =
                            isSelected && selectedCveId === cand.vulnerability_id;
                          return (
                            <button
                              key={cand.vulnerability_id}
                              type="button"
                              className={`btn btn-sm ${active ? 'btn-primary' : ''}`}
                              onClick={(e) => {
                                e.stopPropagation();
                                onSelectVulnerability(row, cand);
                              }}
                              style={{
                                fontFamily: 'var(--font-mono)',
                                fontSize: '11px',
                                padding: '2px 6px',
                                whiteSpace: 'nowrap',
                              }}
                              title={`Mở bảng ứng viên ${cand.vulnerability_id} (chưa xác minh)`}
                            >
                              <ShieldAlert size={11} />
                              <span>{cand.vulnerability_id}</span>
                              {cand.kev ? <span style={{ color: active ? '#fff' : 'var(--danger)', fontWeight: 700 }}>KEV</span> : null}
                            </button>
                          );
                        })}
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
