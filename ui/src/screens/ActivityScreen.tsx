import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Clock,
  DollarSign,
  Filter,
  GitBranch,
  PauseCircle,
  PlayCircle,
  Radio,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  XCircle,
} from 'lucide-react';
import { apiClient, toUiError } from '../api/client';
import { createCoalescedRefresh } from '../api/sse';
import type { ActivityEntry, Campaign, UiError } from '../api/types';
import { CopyableId } from '../components/CopyableId';
import { ErrorDisplay } from '../components/ErrorDisplay';
import { StatusChip } from '../components/StatusChip';
import { TruncatedBanner } from '../components/TruncatedBanner';

const STOP_REASON_LABELS: Record<string, string> = {
  objective_met: 'Đạt mục tiêu',
  no_new_evidence: 'Không có bằng chứng mới',
  budget_exhausted: 'Hết ngân sách',
  step_limit: 'Đạt giới hạn bước',
  blocked: 'Bị chặn',
  operator: 'Người vận hành dừng',
};

const SESSION_DECISION_LABELS: Record<string, string> = {
  continue: 'Tiếp tục (continue)',
  wait: 'Chờ (wait)',
  stop: 'Dừng (stop)',
};

function formatTargetRef(ref: { seed_id: string } | { canonical_key: string }): string {
  return 'canonical_key' in ref ? ref.canonical_key : `seed:${ref.seed_id}`;
}

const ACTIVITY_SSE_TYPES = ['job.started.v2', 'job.completed.v2', 'policy.denied.v2'];
const ACTIVITY_SSE_TYPE_SET = new Set(ACTIVITY_SSE_TYPES);

export const ActivityScreen: React.FC = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const urlCampaignId = searchParams.get('campaign_id');

  const [campaignList, setCampaignList] = useState<Campaign[]>([]);
  const [activeCampaignId, setActiveCampaignId] = useState<string>(urlCampaignId || '');

  const [items, setItems] = useState<ActivityEntry[]>([]);
  const [nextCursor, setNextCursor] = useState<string | undefined>(undefined);
  const [truncated, setTruncated] = useState(false);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<UiError | null>(null);

  const [kindFilter, setKindFilter] = useState<string>('ALL');
  const [decisionFilter, setDecisionFilter] = useState<string>('ALL');
  const [sseConnected, setSseConnected] = useState(false);
  const [lastLiveEvent, setLastLiveEvent] = useState<{ type: string; time: string } | null>(null);
  const [lastSyncedAt, setLastSyncedAt] = useState<string | null>(null);

  const mountedRef = useRef(true);
  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  useEffect(() => {
    apiClient
      .listCampaigns()
      .then((res) => {
        if (!mountedRef.current) return;
        setCampaignList(res.items);
        if (!urlCampaignId) {
          if (res.items.length > 0) {
            setActiveCampaignId(res.items[0].campaign_id);
          } else if (apiClient.isMock) {
            setActiveCampaignId('01934f6a-0000-7000-8000-000000000001');
          }
        }
      })
      .catch(() => {
        if (!urlCampaignId && apiClient.isMock && mountedRef.current) {
          setActiveCampaignId('01934f6a-0000-7000-8000-000000000001');
        }
      });
  }, [urlCampaignId]);

  const effectiveCampaignId =
    activeCampaignId || urlCampaignId || (apiClient.isMock ? '01934f6a-0000-7000-8000-000000000001' : '');

  const selectedCampaign = useMemo(
    () => campaignList.find((c) => c.campaign_id === effectiveCampaignId),
    [campaignList, effectiveCampaignId]
  );

  const loadActivity = useCallback(
    async (showLoading: boolean = true) => {
      if (!effectiveCampaignId) {
        setLoading(false);
        return;
      }
      const reqPath = `/campaigns/${encodeURIComponent(effectiveCampaignId)}/activity?limit=50`;
      try {
        if (showLoading) setLoading(true);
        setError(null);
        const res = await apiClient.getCampaignActivity(effectiveCampaignId, { limit: 50 });
        if (!mountedRef.current) return;
        setItems(res.items);
        setNextCursor(res.next_cursor);
        setTruncated(res.truncated);
        setLastSyncedAt(new Date().toLocaleTimeString('vi-VN'));
      } catch (err: unknown) {
        if (!mountedRef.current) return;
        setError(toUiError(err, reqPath));
      } finally {
        if (showLoading && mountedRef.current) setLoading(false);
      }
    },
    [effectiveCampaignId]
  );

  const loadActivityRef = useRef(loadActivity);
  loadActivityRef.current = loadActivity;

  const loadMore = async () => {
    if (!effectiveCampaignId || !nextCursor || loadingMore) return;
    const reqPath = `/campaigns/${encodeURIComponent(effectiveCampaignId)}/activity?cursor=${encodeURIComponent(nextCursor)}&limit=50`;
    try {
      setLoadingMore(true);
      setError(null);
      const res = await apiClient.getCampaignActivity(effectiveCampaignId, {
        cursor: nextCursor,
        limit: 50,
      });
      if (!mountedRef.current) return;
      setItems((prev) => {
        const seen = new Set(prev.map((entry) => entry.entry_id));
        const appended = res.items.filter((entry) => !seen.has(entry.entry_id));
        return [...prev, ...appended];
      });
      setNextCursor(res.next_cursor);
      setTruncated(res.truncated);
    } catch (err: unknown) {
      if (!mountedRef.current) return;
      setError(toUiError(err, reqPath));
    } finally {
      if (mountedRef.current) setLoadingMore(false);
    }
  };

  useEffect(() => {
    loadActivity(true);
  }, [loadActivity]);

  // Listen to campaign SSE events to trigger debounced/coalesced refresh of activity timeline
  // (openapi.v2: GET /campaigns/{id}/activity has no dedicated outbox stream, so SSE + polling keeps it fresh)
  useEffect(() => {
    if (!effectiveCampaignId) return;

    const refresher = createCoalescedRefresh(() => loadActivityRef.current(false), 250);
    const sub = apiClient.subscribeCampaignEvents({
      campaignId: effectiveCampaignId,
      types: ACTIVITY_SSE_TYPES,
      onEvent: (event) => {
        setLastLiveEvent({
          type: event.type,
          time: new Date().toLocaleTimeString('vi-VN'),
        });
        if (ACTIVITY_SSE_TYPE_SET.has(event.type)) {
          refresher.trigger();
        }
      },
      onStatusChange: (status) => {
        setSseConnected(status === 'connected');
      },
    });

    return () => {
      refresher.cancel();
      sub.close();
    };
  }, [effectiveCampaignId]);

  // Poll every 5s while selected campaign is active (CREATED / RUNNING / WAITING)
  useEffect(() => {
    if (!effectiveCampaignId) return;
    const isActive =
      selectedCampaign?.status === 'CREATED' ||
      selectedCampaign?.status === 'RUNNING' ||
      selectedCampaign?.status === 'WAITING';
    if (!isActive) return;

    const timer = setInterval(() => {
      loadActivity(false);
    }, 5000);
    return () => clearInterval(timer);
  }, [effectiveCampaignId, selectedCampaign?.status, loadActivity]);

  const filteredItems = useMemo(() => {
    return items.filter((entry) => {
      if (kindFilter === 'decision' && entry.kind !== 'decision') return false;
      if (kindFilter === 'session' && entry.kind !== 'session_started' && entry.kind !== 'session_finished') {
        return false;
      }
      if (kindFilter === 'budget' && entry.kind !== 'budget') return false;
      if (kindFilter === 'blocker' && entry.kind !== 'blocker' && entry.kind !== 'idle_cycle') {
        return false;
      }
      if (decisionFilter !== 'ALL') {
        if (entry.kind !== 'decision') return false;
        if (entry.decision !== decisionFilter) return false;
      }
      return true;
    });
  }, [items, kindFilter, decisionFilter]);

  const summary = useMemo(() => {
    let approved = 0;
    let denied = 0;
    let sessions = 0;
    let blockers = 0;
    for (const item of items) {
      if (item.kind === 'decision') {
        if (item.decision === 'approved') approved += 1;
        else denied += 1;
      } else if (item.kind === 'session_started') {
        sessions += 1;
      } else if (item.kind === 'blocker') {
        blockers += 1;
      }
    }
    return { approved, denied, sessions, blockers };
  }, [items]);

  return (
    <div>
      <div className="filter-bar">
        <div>
          <h1 style={{ fontSize: 'var(--text-xl)', fontWeight: 700, color: 'var(--ink)' }}>
            Nhật ký Hoạt động Agent (Activity)
          </h1>
          <p style={{ fontSize: 'var(--text-sm)', color: 'var(--muted)', marginTop: 2 }}>
            Dòng thời gian có cấu trúc: phiên agent, lý do dừng, quyết định policy (duyệt/từ chối), job liên kết và ngân sách phiên.
          </p>
        </div>

        <div className="filter-group" style={{ flexWrap: 'wrap' }}>
          {campaignList.length > 0 && (
            <select
              className="input-search"
              style={{ minWidth: 210 }}
              value={effectiveCampaignId}
              onChange={(e) => {
                setActiveCampaignId(e.target.value);
                setSearchParams({ campaign_id: e.target.value });
              }}
              aria-label="Chọn chiến dịch"
            >
              {campaignList.map((c) => (
                <option key={c.campaign_id} value={c.campaign_id}>
                  {c.name} ({c.status})
                </option>
              ))}
            </select>
          )}

          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              padding: '4px 8px',
              borderRadius: 'var(--radius-sm)',
              backgroundColor: sseConnected ? 'var(--success-bg)' : 'var(--subtle)',
              color: sseConnected ? 'var(--success)' : 'var(--muted)',
              border: `1px solid ${sseConnected ? 'var(--success)' : 'var(--line)'}`,
              fontSize: 'var(--text-xs)',
            }}
            title="API /activity đọc theo cursor (polling); UI tự làm mới khi có SSE từ /events của chiến dịch"
          >
            <Radio size={12} className={sseConnected ? 'pulse-icon' : ''} />
            <span style={{ fontWeight: 600 }}>
              {sseConnected ? 'SSE + Auto-refresh' : 'Polling (REST)'}
            </span>
            {lastLiveEvent && (
              <span style={{ fontSize: '11px', color: 'var(--ink)' }}>
                ({lastLiveEvent.type})
              </span>
            )}
          </div>

          <button
            type="button"
            className="btn btn-sm"
            onClick={() => loadActivity(true)}
            disabled={loading}
            title={lastSyncedAt ? `Đồng bộ gần nhất: ${lastSyncedAt}` : 'Làm mới dòng thời gian'}
          >
            <RefreshCw size={13} /> Làm mới
          </button>
        </div>
      </div>

      {/* Filters & Summary Strip */}
      <div
        className="card"
        style={{
          padding: '12px 16px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: 12,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 'var(--text-xs)', color: 'var(--muted)' }}>
            <Filter size={14} />
            <span>Loại mục:</span>
          </div>
          <select
            className="input-search"
            style={{ minWidth: 180 }}
            value={kindFilter}
            onChange={(e) => {
              setKindFilter(e.target.value);
              if (e.target.value !== 'ALL' && e.target.value !== 'decision') {
                setDecisionFilter('ALL');
              }
            }}
            aria-label="Lọc loại hoạt động"
          >
            <option value="ALL">Tất cả mục ({items.length})</option>
            <option value="decision">Quyết định Policy (Decision)</option>
            <option value="session">Phiên Agent (Session)</option>
            <option value="budget">Ngân sách phiên (Budget)</option>
            <option value="blocker">Cảnh báo / Chu kỳ rỗi</option>
          </select>

          <select
            className="input-search"
            style={{ minWidth: 165 }}
            value={decisionFilter}
            onChange={(e) => setDecisionFilter(e.target.value)}
            aria-label="Lọc trạng thái quyết định"
          >
            <option value="ALL">Mọi quyết định</option>
            <option value="approved">Đã duyệt (Approved)</option>
            <option value="denied">Bị từ chối (Denied)</option>
          </select>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', fontSize: 'var(--text-xs)' }}>
          <span className="status-chip success tabular">
            <ShieldCheck size={12} /> {summary.approved} duyệt
          </span>
          <span className={`status-chip ${summary.denied > 0 ? 'danger' : 'neutral'} tabular`}>
            <XCircle size={12} /> {summary.denied} từ chối
          </span>
          <span className="status-chip accent tabular">
            <PlayCircle size={12} /> {summary.sessions} phiên
          </span>
          {summary.blockers > 0 && (
            <span className="status-chip warning tabular">
              <AlertTriangle size={12} /> {summary.blockers} blocker
            </span>
          )}
        </div>
      </div>

      {error && (
        <div style={{ marginBottom: 16 }}>
          <ErrorDisplay error={error} onRetry={() => loadActivity(true)} />
        </div>
      )}

      {truncated && (
        <TruncatedBanner
          truncated={truncated}
          customMessage="Dòng thời gian đang hiển thị trang mới nhất (còn mục cũ hơn ở trang kế tiếp). Nhấn 'Tải thêm mục cũ hơn' ở cuối danh sách."
        />
      )}

      {loading ? (
        <div className="state-box">
          <Activity size={28} className="pulse-icon" style={{ color: 'var(--accent)' }} />
          <div className="state-title">Đang nạp nhật ký hoạt động agent...</div>
          <div className="state-desc">Đang truy vấn GET /campaigns/{'{id}'}/activity</div>
        </div>
      ) : !effectiveCampaignId ? (
        <div className="state-box">
          <div className="state-title">Chưa chọn chiến dịch</div>
          <div className="state-desc">Vui lòng chọn một chiến dịch để xem dòng thời gian hoạt động agent.</div>
        </div>
      ) : filteredItems.length === 0 ? (
        <div className="state-box">
          <Activity size={32} style={{ color: 'var(--muted)' }} />
          <div className="state-title">Chưa có hoạt động agent phù hợp</div>
          <div className="state-desc">
            {items.length === 0
              ? 'Chiến dịch này chưa ghi nhận phiên agent, quyết định policy hay mục ledger nào.'
              : 'Không có mục nào khớp với bộ lọc hiện tại.'}
          </div>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {filteredItems.map((entry) => {
            const timeText = new Date(entry.at).toLocaleString('vi-VN');

            if (entry.kind === 'decision') {
              const isApproved = entry.decision === 'approved';
              return (
                <article
                  key={entry.entry_id}
                  className="card"
                  style={{
                    marginBottom: 0,
                    borderLeft: `3px solid ${isApproved ? 'var(--success)' : 'var(--danger)'}`,
                  }}
                >
                  <div
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'flex-start',
                      gap: 10,
                      flexWrap: 'wrap',
                      marginBottom: 8,
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                      <span className={`status-chip ${isApproved ? 'success' : 'danger'}`}>
                        {isApproved ? <CheckCircle2 size={12} /> : <ShieldAlert size={12} />}
                        {isApproved ? 'Đã duyệt (Approved)' : 'Bị từ chối (Denied)'}
                      </span>
                      <strong className="mono" style={{ fontSize: 'var(--text-sm)', color: 'var(--ink)' }}>
                        {entry.capability}
                      </strong>
                      {entry.provider && <span className="brand-badge">{entry.provider}</span>}
                      <span className="brand-badge">RoE: {entry.policy_version}</span>
                    </div>
                    <span className="mono tabular" style={{ fontSize: 'var(--text-xs)', color: 'var(--muted)' }}>
                      {timeText}
                    </span>
                  </div>

                  {!isApproved && entry.reason && (
                    <div
                      style={{
                        padding: '8px 10px',
                        backgroundColor: 'var(--danger-bg)',
                        border: '1px solid var(--danger)',
                        borderRadius: 'var(--radius-sm)',
                        fontSize: 'var(--text-xs)',
                        color: 'var(--ink)',
                        marginBottom: 8,
                        display: 'flex',
                        alignItems: 'center',
                        gap: 8,
                        flexWrap: 'wrap',
                      }}
                    >
                      <span className="mono" style={{ fontWeight: 700, color: 'var(--danger)' }}>
                        Lý do từ chối: {entry.reason.code}
                      </span>
                      {entry.reason.rule && (
                        <span className="brand-badge" style={{ borderColor: 'var(--danger)', color: 'var(--danger)' }}>
                          Luật: {entry.reason.rule}
                        </span>
                      )}
                    </div>
                  )}

                  <div
                    style={{
                      display: 'flex',
                      flexWrap: 'wrap',
                      gap: 12,
                      alignItems: 'center',
                      fontSize: 'var(--text-xs)',
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
                      <span style={{ color: 'var(--muted)' }}>Khởi tạo (requested_by):</span>
                      <span className="brand-badge">
                        {entry.requested_by.kind}:{entry.requested_by.id}
                      </span>
                    </div>

                    {entry.proposed_by && (
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
                        <span style={{ color: 'var(--muted)' }}>Đề xuất (proposed_by):</span>
                        <CopyableId value={entry.proposed_by.id} prefix="agent" />
                      </div>
                    )}

                    {entry.targets.length > 0 && (
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
                        <span style={{ color: 'var(--muted)' }}>Mục tiêu:</span>
                        {entry.targets.map((t, idx) => (
                          <CopyableId key={idx} value={formatTargetRef(t)} />
                        ))}
                      </div>
                    )}

                    {entry.job_id && (
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
                        <span style={{ color: 'var(--muted)' }}>Job liên kết:</span>
                        <CopyableId value={entry.job_id} prefix="Job" />
                        <Link
                          to={`/jobs?campaign_id=${effectiveCampaignId}&job_id=${entry.job_id}`}
                          className="btn btn-sm"
                          style={{ whiteSpace: 'nowrap' }}
                        >
                          <GitBranch size={12} /> Xem Job
                        </Link>
                      </div>
                    )}
                  </div>
                </article>
              );
            }

            if (entry.kind === 'session_started') {
              return (
                <article
                  key={entry.entry_id}
                  className="card"
                  style={{ marginBottom: 0, borderLeft: '3px solid var(--accent)' }}
                >
                  <div
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      gap: 8,
                      flexWrap: 'wrap',
                      marginBottom: 6,
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                      <span className="status-chip accent">
                        <PlayCircle size={12} /> Mở phiên (Session Started)
                      </span>
                      <span className="brand-badge">RoE: {entry.policy_version}</span>
                      <span className="brand-badge tabular">Graph rev: {entry.revision_from}</span>
                    </div>
                    <span className="mono tabular" style={{ fontSize: 'var(--text-xs)', color: 'var(--muted)' }}>
                      {timeText}
                    </span>
                  </div>
                  <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center' }}>
                    <CopyableId value={entry.session_id} prefix="Session" />
                    {entry.objective_id && <CopyableId value={entry.objective_id} prefix="Objective" />}
                  </div>
                </article>
              );
            }

            if (entry.kind === 'session_finished') {
              return (
                <article
                  key={entry.entry_id}
                  className="card"
                  style={{
                    marginBottom: 0,
                    borderLeft: `3px solid ${entry.status === 'SUCCEEDED' ? 'var(--success)' : 'var(--warning)'}`,
                  }}
                >
                  <div
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      gap: 8,
                      flexWrap: 'wrap',
                      marginBottom: 6,
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                      <span className="status-chip neutral">
                        <PauseCircle size={12} /> Kết thúc phiên (Session Finished)
                      </span>
                      <StatusChip status={entry.status} kind="job" />
                      <span className="brand-badge">
                        {SESSION_DECISION_LABELS[entry.decision] || entry.decision}
                      </span>
                      {entry.stop_reason && (
                        <span className="status-chip warning">
                          Lý do dừng: {STOP_REASON_LABELS[entry.stop_reason] || entry.stop_reason} ({entry.stop_reason})
                        </span>
                      )}
                    </div>
                    <span className="mono tabular" style={{ fontSize: 'var(--text-xs)', color: 'var(--muted)' }}>
                      {timeText}
                    </span>
                  </div>
                  <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', alignItems: 'center', fontSize: 'var(--text-xs)' }}>
                    <CopyableId value={entry.session_id} prefix="Session" />
                    <span className="tabular" style={{ color: 'var(--muted)' }}>
                      Số bước model đã dùng: <strong>{entry.steps_used}</strong> / 30
                    </span>
                  </div>
                </article>
              );
            }

            if (entry.kind === 'budget') {
              return (
                <article
                  key={entry.entry_id}
                  className="card"
                  style={{ marginBottom: 0, borderLeft: '3px solid var(--muted)' }}
                >
                  <div
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      gap: 8,
                      flexWrap: 'wrap',
                      marginBottom: 6,
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                      <span className="status-chip neutral">
                        <DollarSign size={12} /> Ngân sách phiên (Budget)
                      </span>
                      <span className="tabular" style={{ fontSize: 'var(--text-xs)', fontWeight: 600 }}>
                        Đã dùng: {entry.sent_tokens.toLocaleString('en-US')} tokens · ${entry.sent_cost_usd.toFixed(4)}
                      </span>
                      {(entry.remaining_cost_usd !== undefined || entry.remaining_tokens !== undefined) && (
                        <span className="tabular" style={{ fontSize: 'var(--text-xs)', color: 'var(--muted)' }}>
                          (Còn lại:{' '}
                          {entry.remaining_cost_usd !== undefined ? `$${entry.remaining_cost_usd.toFixed(4)}` : ''}
                          {entry.remaining_cost_usd !== undefined && entry.remaining_tokens !== undefined ? ' · ' : ''}
                          {entry.remaining_tokens !== undefined
                            ? `${entry.remaining_tokens.toLocaleString('en-US')} tok`
                            : ''}
                          )
                        </span>
                      )}
                    </div>
                    <span className="mono tabular" style={{ fontSize: 'var(--text-xs)', color: 'var(--muted)' }}>
                      {timeText}
                    </span>
                  </div>
                  <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
                    {entry.session_id && <CopyableId value={entry.session_id} prefix="Session" />}
                    {entry.models && entry.models.length > 0 && (
                      <span className="brand-badge">Models: {entry.models.join(', ')}</span>
                    )}
                  </div>
                </article>
              );
            }

            if (entry.kind === 'blocker') {
              return (
                <article
                  key={entry.entry_id}
                  className="card"
                  style={{ marginBottom: 0, borderLeft: '3px solid var(--warning)' }}
                >
                  <div
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      gap: 8,
                      flexWrap: 'wrap',
                      marginBottom: 6,
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                      <span className="status-chip warning">
                        <AlertTriangle size={12} /> Bị chặn (Blocker): {entry.code}
                      </span>
                      {entry.context && <span className="brand-badge">{entry.context}</span>}
                    </div>
                    <span className="mono tabular" style={{ fontSize: 'var(--text-xs)', color: 'var(--muted)' }}>
                      {timeText}
                    </span>
                  </div>
                  {entry.session_id && <CopyableId value={entry.session_id} prefix="Session" />}
                </article>
              );
            }

            // idle_cycle
            return (
              <article
                key={entry.entry_id}
                className="card"
                style={{ marginBottom: 0, borderLeft: '3px solid var(--line)' }}
              >
                <div
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    gap: 8,
                    flexWrap: 'wrap',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                    <span className="status-chip neutral">
                      <Clock size={12} /> Chu kỳ rỗi (Idle Cycle)
                    </span>
                    {entry.cycle !== undefined && (
                      <span className="brand-badge tabular">Chu kỳ #{entry.cycle}</span>
                    )}
                    {entry.session_id && <CopyableId value={entry.session_id} prefix="Session" />}
                  </div>
                  <span className="mono tabular" style={{ fontSize: 'var(--text-xs)', color: 'var(--muted)' }}>
                    {timeText}
                  </span>
                </div>
              </article>
            );
          })}

          {nextCursor && (
            <div style={{ display: 'flex', justifyContent: 'center', marginTop: 8 }}>
              <button
                type="button"
                className="btn btn-primary"
                onClick={loadMore}
                disabled={loadingMore}
              >
                {loadingMore ? 'Đang tải thêm...' : 'Tải thêm mục cũ hơn (next_cursor)'}
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
