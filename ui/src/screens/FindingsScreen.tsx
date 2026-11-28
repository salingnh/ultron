import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useParams, useSearchParams } from 'react-router-dom';
import {
  Eye,
  FileCheck2,
  Filter,
  Key,
  Radio,
  RefreshCw,
  RotateCcw,
  ShieldAlert,
} from 'lucide-react';
import { ApiError, apiClient, toUiError } from '../api/client';
import { createCoalescedRefresh } from '../api/sse';
import type {
  Campaign,
  Finding,
  FindingHistoryResponse,
  FindingSeverity,
  FindingStatus,
  ListFindingsParams,
  ProvenanceDetail,
  UiError,
} from '../api/types';
import { CopyableId } from '../components/CopyableId';
import { ErrorDisplay } from '../components/ErrorDisplay';
import { FindingDetailPanel } from '../components/FindingDetailPanel';
import { SeverityChip, StatusChip } from '../components/StatusChip';
import {
  FINDING_SEVERITY_META,
  FINDING_SEVERITY_OPTIONS,
  FINDING_STATUS_META,
  FINDING_STATUS_OPTIONS,
} from '../utils/findings';

const PAGE_LIMIT = 20;
const FINDINGS_SSE_TYPES = ['finding.changed.v2'];

export const FindingsScreen: React.FC = () => {
  const { findingId: routeFindingId } = useParams<{ findingId?: string }>();
  const [searchParams, setSearchParams] = useSearchParams();

  const [campaignList, setCampaignList] = useState<Campaign[]>([]);
  const [campaignFilter, setCampaignFilter] = useState<string>(
    () => searchParams.get('campaign_id') || 'ALL'
  );
  const [statusFilter, setStatusFilter] = useState<string>(
    () => searchParams.get('status') || 'ALL'
  );
  const [severityFilter, setSeverityFilter] = useState<string>(
    () => searchParams.get('severity') || 'ALL'
  );
  const [vulnQuery, setVulnQuery] = useState<string>(() => searchParams.get('q') || '');
  const [kevOnly, setKevOnly] = useState<boolean>(() => searchParams.get('kev') === 'true');

  const [findings, setFindings] = useState<Finding[]>([]);
  const [nextCursor, setNextCursor] = useState<string | undefined>(undefined);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<UiError | null>(null);
  const [errorStatus, setErrorStatus] = useState<number | null>(null);

  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(
    () => routeFindingId || searchParams.get('finding_id') || null
  );

  const [history, setHistory] = useState<FindingHistoryResponse | null>(null);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyError, setHistoryError] = useState<UiError | null>(null);

  const [provenance, setProvenance] = useState<ProvenanceDetail | null>(null);
  const [provenanceLoading, setProvenanceLoading] = useState(false);
  const [provenanceError, setProvenanceError] = useState<UiError | null>(null);

  const [sseConnected, setSseConnected] = useState(false);
  const [lastLiveEvent, setLastLiveEvent] = useState<{ type: string; time: string } | null>(null);

  const mountedRef = useRef(true);
  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  useEffect(() => {
    if (routeFindingId) {
      setSelectedId(routeFindingId);
    }
  }, [routeFindingId]);

  useEffect(() => {
    apiClient
      .listCampaigns()
      .then((res) => {
        if (mountedRef.current) setCampaignList(res.items);
      })
      .catch(() => {
        // Optional dropdown filter options
      });
  }, []);

  const buildQueryParams = useCallback(
    (cursor?: string): ListFindingsParams => {
      const params: ListFindingsParams = { limit: PAGE_LIMIT };
      if (campaignFilter !== 'ALL') params.campaign_id = campaignFilter;
      if (statusFilter !== 'ALL') params.status = [statusFilter as FindingStatus];
      if (severityFilter !== 'ALL') params.severity = [severityFilter as FindingSeverity];
      if (vulnQuery.trim()) params.vulnerability_id = vulnQuery.trim();
      if (kevOnly) params.kev = true;
      if (cursor) params.cursor = cursor;
      return params;
    },
    [campaignFilter, statusFilter, severityFilter, vulnQuery, kevOnly]
  );

  const syncUrlParams = useCallback(
    (next: {
      campaign?: string;
      status?: string;
      severity?: string;
      q?: string;
      kev?: boolean;
      findingId?: string | null;
    }) => {
      const sp = new URLSearchParams();
      const c = next.campaign ?? campaignFilter;
      const st = next.status ?? statusFilter;
      const sv = next.severity ?? severityFilter;
      const q = next.q ?? vulnQuery;
      const kv = next.kev ?? kevOnly;
      const fid = next.findingId === undefined ? selectedId : next.findingId;
      if (c && c !== 'ALL') sp.set('campaign_id', c);
      if (st && st !== 'ALL') sp.set('status', st);
      if (sv && sv !== 'ALL') sp.set('severity', sv);
      if (q.trim()) sp.set('q', q.trim());
      if (kv) sp.set('kev', 'true');
      if (fid && !routeFindingId) sp.set('finding_id', fid);
      setSearchParams(sp, { replace: true });
    },
    [campaignFilter, statusFilter, severityFilter, vulnQuery, kevOnly, selectedId, routeFindingId, setSearchParams]
  );

  const loadFindings = useCallback(
    async (showLoading: boolean = true) => {
      const params = buildQueryParams();
      try {
        if (showLoading) setLoading(true);
        setError(null);
        setErrorStatus(null);
        const res = await apiClient.listFindings(params);
        if (!mountedRef.current) return;
        setFindings(res.items);
        setNextCursor(res.next_cursor);
      } catch (err: unknown) {
        if (!mountedRef.current) return;
        if (err instanceof ApiError) {
          setErrorStatus(err.status ?? null);
        }
        setError(toUiError(err, '/findings'));
      } finally {
        if (showLoading && mountedRef.current) setLoading(false);
      }
    },
    [buildQueryParams]
  );

  useEffect(() => {
    void loadFindings(true);
  }, [loadFindings]);

  useEffect(() => {
    const handleTokenChanged = () => {
      void loadFindings(true);
    };
    window.addEventListener('ultron-token-changed', handleTokenChanged);
    return () => {
      window.removeEventListener('ultron-token-changed', handleTokenChanged);
    };
  }, [loadFindings]);

  const loadMore = async () => {
    if (!nextCursor || loadingMore) return;
    const params = buildQueryParams(nextCursor);
    try {
      setLoadingMore(true);
      setError(null);
      const res = await apiClient.listFindings(params);
      if (!mountedRef.current) return;
      setFindings((prev) => {
        const seen = new Set(prev.map((item) => item.finding_id));
        const appended = res.items.filter((item) => !seen.has(item.finding_id));
        return [...prev, ...appended];
      });
      setNextCursor(res.next_cursor);
    } catch (err: unknown) {
      if (!mountedRef.current) return;
      setError(toUiError(err, '/findings'));
    } finally {
      if (mountedRef.current) setLoadingMore(false);
    }
  };

  const loadFindingDetailAndHistory = useCallback(async (findingId: string) => {
    setHistoryLoading(true);
    setHistoryError(null);
    setProvenanceLoading(true);
    setProvenanceError(null);

    try {
      const [detailRes, historyRes] = await Promise.allSettled([
        apiClient.getFinding(findingId),
        apiClient.getFindingHistory(findingId),
      ]);

      if (!mountedRef.current) return;

      let activeAssetId: string | null = null;
      if (detailRes.status === 'fulfilled') {
        setSelectedFinding(detailRes.value);
        activeAssetId = detailRes.value.asset_id;
        setFindings((prev) =>
          prev.map((item) => (item.finding_id === detailRes.value.finding_id ? detailRes.value : item))
        );
      }

      if (historyRes.status === 'fulfilled') {
        setHistory(historyRes.value);
      } else {
        setHistory(null);
        setHistoryError(toUiError(historyRes.reason, `/findings/${findingId}/history`));
      }
      setHistoryLoading(false);

      if (activeAssetId) {
        try {
          const prov = await apiClient.getProvenance(activeAssetId);
          if (!mountedRef.current) return;
          setProvenance(prov);
        } catch (provErr: unknown) {
          if (!mountedRef.current) return;
          setProvenance(null);
          setProvenanceError(toUiError(provErr, `/assets/${activeAssetId}/history`));
        } finally {
          if (mountedRef.current) setProvenanceLoading(false);
        }
      } else {
        setProvenanceLoading(false);
      }
    } catch (err: unknown) {
      if (!mountedRef.current) return;
      setHistoryLoading(false);
      setProvenanceLoading(false);
      setHistoryError(toUiError(err, `/findings/${findingId}/history`));
    }
  }, []);

  useEffect(() => {
    if (!selectedId) {
      setSelectedFinding(null);
      setHistory(null);
      setHistoryError(null);
      setProvenance(null);
      setProvenanceError(null);
      return;
    }

    const fromList = findings.find((f) => f.finding_id === selectedId) || null;
    if (fromList) {
      setSelectedFinding(fromList);
    }
    void loadFindingDetailAndHistory(selectedId);
    // Intentionally keyed on selectedId so list updates do not loop detail fetches
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedId]);

  const loadFindingsRef = useRef(loadFindings);
  loadFindingsRef.current = loadFindings;
  const loadDetailRef = useRef(loadFindingDetailAndHistory);
  loadDetailRef.current = loadFindingDetailAndHistory;
  const selectedIdRef = useRef(selectedId);
  selectedIdRef.current = selectedId;

  // Live SSE updates when a campaign is selected (refetch on reconnect as well)
  useEffect(() => {
    if (campaignFilter === 'ALL') {
      setSseConnected(false);
      return;
    }

    let hadDisconnect = false;
    const refresher = createCoalescedRefresh(() => {
      void loadFindingsRef.current(false);
      if (selectedIdRef.current) {
        void loadDetailRef.current(selectedIdRef.current);
      }
    }, 250);

    const sub = apiClient.subscribeCampaignEvents({
      campaignId: campaignFilter,
      types: FINDINGS_SSE_TYPES,
      onEvent: (event) => {
        setLastLiveEvent({
          type: event.type,
          time: new Date().toLocaleTimeString('vi-VN'),
        });
        refresher.trigger();
      },
      onStatusChange: (status) => {
        const connected = status === 'connected';
        setSseConnected(connected);
        if (status === 'disconnected' || status === 'error') {
          hadDisconnect = true;
        } else if (connected && hadDisconnect) {
          hadDisconnect = false;
          refresher.trigger();
        }
      },
    });

    return () => {
      refresher.cancel();
      sub.close();
    };
  }, [campaignFilter]);

  const handleSelectFinding = (finding: Finding) => {
    setSelectedId(finding.finding_id);
    setSelectedFinding(finding);
    syncUrlParams({ findingId: finding.finding_id });
  };

  const handleCloseDetail = () => {
    setSelectedId(null);
    setSelectedFinding(null);
    syncUrlParams({ findingId: null });
  };

  const handleTransitionSuccess = (updated: Finding) => {
    setSelectedFinding(updated);
    setFindings((prev) =>
      prev.map((item) => (item.finding_id === updated.finding_id ? updated : item))
    );
    void loadFindingDetailAndHistory(updated.finding_id);
  };

  const hasActiveFilters =
    campaignFilter !== 'ALL' ||
    statusFilter !== 'ALL' ||
    severityFilter !== 'ALL' ||
    vulnQuery.trim().length > 0 ||
    kevOnly;

  const resetFilters = () => {
    setCampaignFilter('ALL');
    setStatusFilter('ALL');
    setSeverityFilter('ALL');
    setVulnQuery('');
    setKevOnly(false);
    syncUrlParams({
      campaign: 'ALL',
      status: 'ALL',
      severity: 'ALL',
      q: '',
      kev: false,
    });
  };

  const severityCounts = useMemo(() => {
    const counts: Record<string, number> = { CRITICAL: 0, HIGH: 0, UNRATED: 0 };
    for (const f of findings) {
      if (f.severity in counts) counts[f.severity] += 1;
    }
    return counts;
  }, [findings]);

  return (
    <div>
      <div className="filter-bar">
        <div>
          <h1 style={{ fontSize: 'var(--text-xl)', fontWeight: 700, color: 'var(--ink)' }}>
            Quản lý Findings &amp; Bằng chứng
          </h1>
          <p style={{ fontSize: 'var(--text-sm)', color: 'var(--muted)', marginTop: 2 }}>
            Danh sách finding đã tổng hợp, đánh giá mức nghiêm trọng, nguồn cung cấp, bằng chứng SHA-256 và lịch sử trạng thái.
          </p>
        </div>

        <div className="filter-group">
          {campaignFilter !== 'ALL' && (
            <span
              className={`status-chip ${sseConnected ? 'success' : 'neutral'}`}
              title={
                lastLiveEvent
                  ? `Sự kiện gần nhất: ${lastLiveEvent.type} lúc ${lastLiveEvent.time}`
                  : 'Theo dõi finding.changed.v2 theo chiến dịch'
              }
            >
              <Radio size={12} /> {sseConnected ? 'SSE finding.changed' : 'SSE chờ kết nối'}
            </span>
          )}
          <button
            type="button"
            className="btn btn-sm"
            onClick={() => void loadFindings(true)}
            disabled={loading}
          >
            <RefreshCw size={13} /> Làm mới
          </button>
        </div>
      </div>

      {/* Filters bar */}
      <div className="card" style={{ padding: '12px 14px', marginBottom: 14 }}>
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 10,
            flexWrap: 'wrap',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 'var(--text-xs)', color: 'var(--muted)', fontWeight: 600 }}>
            <Filter size={13} />
            <span>Bộ lọc:</span>
          </div>

          <select
            className="input-search"
            style={{ minWidth: 180 }}
            value={campaignFilter}
            onChange={(e) => {
              const val = e.target.value;
              setCampaignFilter(val);
              syncUrlParams({ campaign: val });
            }}
            aria-label="Lọc theo chiến dịch"
          >
            <option value="ALL">Tất cả chiến dịch</option>
            {campaignList.map((c) => (
              <option key={c.campaign_id} value={c.campaign_id}>
                {c.name} ({c.status})
              </option>
            ))}
          </select>

          <select
            className="input-search"
            style={{ minWidth: 165 }}
            value={statusFilter}
            onChange={(e) => {
              const val = e.target.value;
              setStatusFilter(val);
              syncUrlParams({ status: val });
            }}
            aria-label="Lọc theo trạng thái finding"
          >
            <option value="ALL">Tất cả trạng thái</option>
            {FINDING_STATUS_OPTIONS.map((st) => (
              <option key={st} value={st}>
                {FINDING_STATUS_META[st].label}
              </option>
            ))}
          </select>

          <select
            className="input-search"
            style={{ minWidth: 155 }}
            value={severityFilter}
            onChange={(e) => {
              const val = e.target.value;
              setSeverityFilter(val);
              syncUrlParams({ severity: val });
            }}
            aria-label="Lọc theo mức nghiêm trọng"
          >
            <option value="ALL">Tất cả mức nghiêm trọng</option>
            {FINDING_SEVERITY_OPTIONS.map((sev) => (
              <option key={sev} value={sev}>
                {FINDING_SEVERITY_META[sev].label}
              </option>
            ))}
          </select>

          <input
            type="search"
            className="input-search"
            style={{ minWidth: 170 }}
            value={vulnQuery}
            onChange={(e) => {
              const val = e.target.value;
              setVulnQuery(val);
              syncUrlParams({ q: val });
            }}
            placeholder="Lọc mã CVE (vd CVE-2021-41773)..."
            aria-label="Tìm theo mã CVE"
          />

          <label
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 6,
              fontSize: 'var(--text-xs)',
              color: 'var(--ink)',
              cursor: 'pointer',
              userSelect: 'none',
            }}
          >
            <input
              type="checkbox"
              checked={kevOnly}
              onChange={(e) => {
                const checked = e.target.checked;
                setKevOnly(checked);
                syncUrlParams({ kev: checked });
              }}
            />
            <span>Chỉ CISA KEV</span>
          </label>

          {hasActiveFilters && (
            <button type="button" className="btn btn-sm" onClick={resetFilters}>
              <RotateCcw size={12} /> Đặt lại
            </button>
          )}
        </div>

        {/* Summary strip */}
        {!loading && !error && (
          <div
            style={{
              marginTop: 10,
              paddingTop: 8,
              borderTop: '1px solid var(--line)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              gap: 10,
              flexWrap: 'wrap',
              fontSize: 'var(--text-xs)',
              color: 'var(--muted)',
            }}
          >
            <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center' }}>
              <span className="tabular">
                Đang hiển thị <strong style={{ color: 'var(--ink)' }}>{findings.length}</strong> finding
                {nextCursor ? ' (còn dữ liệu theo cursor)' : ''}
              </span>
              {severityCounts.CRITICAL > 0 && (
                <span className="status-chip danger">CRITICAL: {severityCounts.CRITICAL}</span>
              )}
              {severityCounts.HIGH > 0 && (
                <span className="status-chip warning">HIGH: {severityCounts.HIGH}</span>
              )}
              {severityCounts.UNRATED > 0 && (
                <span className="status-chip neutral">UNRATED: {severityCounts.UNRATED}</span>
              )}
            </div>
          </div>
        )}
      </div>

      {error && (
        <div style={{ marginBottom: 16 }}>
          <ErrorDisplay error={error} onRetry={() => void loadFindings(true)} />
          {errorStatus === 401 && (
            <div style={{ marginTop: 8 }}>
              <button
                type="button"
                className="btn btn-sm btn-primary"
                onClick={() => window.dispatchEvent(new CustomEvent('ultron-open-token-modal'))}
              >
                <Key size={13} /> Mở cấu hình Operator Token
              </button>
            </div>
          )}
        </div>
      )}

      {loading ? (
        <div className="card" aria-label="Đang nạp danh sách findings">
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
            <ShieldAlert size={18} style={{ color: 'var(--accent)' }} />
            <span className="state-title" style={{ fontSize: 'var(--text-base)' }}>
              Đang nạp danh sách findings...
            </span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            <div className="skeleton-line" style={{ width: '100%', height: 22 }} />
            <div className="skeleton-line" style={{ width: '92%', height: 22 }} />
            <div className="skeleton-line" style={{ width: '96%', height: 22 }} />
          </div>
        </div>
      ) : findings.length === 0 ? (
        <div className="state-box">
          <FileCheck2 size={32} style={{ color: 'var(--muted)' }} />
          <div className="state-title">
            {hasActiveFilters ? 'Không tìm thấy finding khớp bộ lọc' : 'Chưa có finding nào được ghi nhận'}
          </div>
          <div className="state-desc">
            {hasActiveFilters
              ? 'Thử xóa bớt bộ lọc trạng thái, mức nghiêm trọng hoặc mã CVE để xem thêm kết quả.'
              : 'Khi chiến dịch phát hiện lỗ hổng hoặc cấu hình sai được nâng thành finding từ M20, danh sách sẽ hiển thị tại đây.'}
          </div>
          {hasActiveFilters && (
            <button type="button" className="btn btn-sm" onClick={resetFilters}>
              <RotateCcw size={12} /> Xóa bộ lọc
            </button>
          )}
        </div>
      ) : (
        <div className="split-panel-layout">
          <div style={{ flex: 1, minWidth: 0, width: '100%' }}>
            <div className="table-container">
              <table className="data-table findings-table" aria-label="Bảng danh sách findings">
                <thead>
                  <tr>
                    <th>Finding &amp; Tài sản</th>
                    <th>Mức độ &amp; Trạng thái</th>
                    <th>CVE &amp; Nguồn</th>
                    <th>Bằng chứng &amp; Lần cuối</th>
                    <th style={{ textAlign: 'right' }}>Thao tác</th>
                  </tr>
                </thead>
                <tbody>
                  {findings.map((f) => {
                    const isSelected = selectedFinding?.finding_id === f.finding_id;
                    return (
                      <tr
                        key={f.finding_id}
                        style={
                          isSelected
                            ? { backgroundColor: 'var(--accent-bg)' }
                            : undefined
                        }
                      >
                        <td style={{ maxWidth: 270 }}>
                          <button
                            type="button"
                            onClick={() => handleSelectFinding(f)}
                            style={{
                              background: 'none',
                              border: 'none',
                              padding: 0,
                              textAlign: 'left',
                              cursor: 'pointer',
                              font: 'inherit',
                              fontWeight: 600,
                              color: 'var(--ink)',
                              wordBreak: 'break-word',
                            }}
                          >
                            {f.title}
                          </button>
                          <div
                            className="mono"
                            style={{ fontSize: 'var(--text-xs)', color: 'var(--muted)', marginTop: 3, wordBreak: 'break-all' }}
                          >
                            {f.asset_key}
                          </div>
                          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center', marginTop: 4 }}>
                            {f.category && <span className="brand-badge">{f.category}</span>}
                            <CopyableId value={f.finding_id} prefix="ID" />
                          </div>
                        </td>
                        <td>
                          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-start', gap: 5 }}>
                            <SeverityChip severity={f.severity} />
                            <StatusChip status={f.status} kind="finding" />
                            {f.severity_assessment?.failure && (
                              <div style={{ fontSize: '11px', color: 'var(--warning)' }}>
                                Fallback: {f.severity_assessment.failure.code}
                              </div>
                            )}
                          </div>
                        </td>
                        <td>
                          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                            {f.vulnerability_ids && f.vulnerability_ids.length > 0 ? (
                              <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                                {f.vulnerability_ids.map((v) => (
                                  <span key={v} className="brand-badge" style={{ color: 'var(--ink)' }}>
                                    {v}
                                  </span>
                                ))}
                              </div>
                            ) : (
                              <span style={{ fontSize: 'var(--text-xs)', color: 'var(--muted)' }}>—</span>
                            )}
                            {f.providers && f.providers.length > 0 && (
                              <div style={{ fontSize: '11px', color: 'var(--muted)' }}>
                                Nguồn: {f.providers.join(', ')}
                              </div>
                            )}
                          </div>
                        </td>
                        <td>
                          <div className="tabular" style={{ fontSize: 'var(--text-xs)' }}>
                            <strong>{f.evidence.length}</strong> bằng chứng
                          </div>
                          <div
                            className="mono"
                            style={{ fontSize: '11px', color: 'var(--muted)', marginTop: 2, whiteSpace: 'nowrap' }}
                          >
                            {new Date(f.last_seen).toLocaleString('vi-VN')}
                          </div>
                        </td>
                        <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                          <button
                            type="button"
                            className={`btn btn-sm ${isSelected ? 'btn-primary' : ''}`}
                            onClick={() => handleSelectFinding(f)}
                            aria-pressed={isSelected}
                          >
                            <Eye size={13} /> Chi tiết
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {/* Cursor pagination footer */}
            {nextCursor && (
              <div
                style={{
                  marginTop: 12,
                  padding: '10px 14px',
                  backgroundColor: 'var(--surface)',
                  border: '1px solid var(--line)',
                  borderRadius: 'var(--radius-md)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  gap: 10,
                  flexWrap: 'wrap',
                  fontSize: 'var(--text-xs)',
                  color: 'var(--muted)',
                }}
              >
                <span>
                  Danh sách phân trang theo cursor (chưa hiển thị toàn bộ finding).
                </span>
                <button
                  type="button"
                  className="btn btn-sm btn-primary"
                  onClick={() => void loadMore()}
                  disabled={loadingMore}
                >
                  {loadingMore ? 'Đang tải thêm...' : 'Tải thêm finding'}
                </button>
              </div>
            )}
          </div>

          {selectedFinding && (
            <FindingDetailPanel
              finding={selectedFinding}
              history={history}
              historyLoading={historyLoading}
              historyError={historyError}
              provenance={provenance}
              provenanceLoading={provenanceLoading}
              provenanceError={provenanceError}
              campaignId={campaignFilter !== 'ALL' ? campaignFilter : undefined}
              onRetryHistory={() => void loadFindingDetailAndHistory(selectedFinding.finding_id)}
              onRefreshFinding={() => void loadFindingDetailAndHistory(selectedFinding.finding_id)}
              onTransitionSuccess={handleTransitionSuccess}
              onClose={handleCloseDetail}
            />
          )}
        </div>
      )}
    </div>
  );
};
