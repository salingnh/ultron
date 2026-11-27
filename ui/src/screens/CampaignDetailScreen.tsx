import React, { useEffect, useState, useCallback, useRef } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  Pause,
  Play,
  XCircle,
  GitBranch,
  Network,
  Shield,
  Target,
  BarChart3,
  ChevronLeft,
  Radio,
  Edit3,
  CheckCircle2,
  Activity,
} from 'lucide-react';
import { ApiError, apiClient, generateIdempotencyKey, toUiError } from '../api/client';
import { createCoalescedRefresh } from '../api/sse';
import type { AppError, Campaign, CapabilityItem, RoEPolicy, UiError } from '../api/types';
import { StatusChip } from '../components/StatusChip';
import { CopyableId } from '../components/CopyableId';
import { ErrorDisplay, InlineFieldError } from '../components/ErrorDisplay';
import { RoEPolicyFields } from '../components/RoEPolicyFields';
import { InternetConfirmModal } from '../components/InternetConfirmModal';
import {
  mapServerFieldToKey,
  policyToFormValues,
  validatePolicyForm,
  type PolicyFormValues,
} from '../utils/campaignValidation';
import {
  assetKindLabel,
  buildBudgetDimensions,
  summarizeAssetCounters,
  summarizeJobCounters,
} from '../utils/campaignStats';

const CAMPAIGN_DETAIL_SSE_TYPES = [
  'job.started.v2',
  'job.completed.v2',
  'policy.denied.v2',
  'asset.discovered.v2',
  'knowledge.delta.v2',
];
const CAMPAIGN_DETAIL_SSE_TYPE_SET = new Set(CAMPAIGN_DETAIL_SSE_TYPES);

export const CampaignDetailScreen: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [campaign, setCampaign] = useState<Campaign | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<UiError | null>(null);
  const [actionLoading, setActionLoading] = useState(false);
  const [actionError, setActionError] = useState<UiError | null>(null);
  const [modalAction, setModalAction] = useState<'pause' | 'resume' | 'cancel' | null>(null);
  const [actionReason, setActionReason] = useState('');
  const [sseConnected, setSseConnected] = useState(false);
  const [lastLiveEvent, setLastLiveEvent] = useState<{ type: string; time: string } | null>(null);

  // Policy adoption editor state
  const [isEditingPolicy, setIsEditingPolicy] = useState(false);
  const [policyValues, setPolicyValues] = useState<PolicyFormValues>(() => policyToFormValues());
  const [policyReason, setPolicyReason] = useState('');
  const [policyIdempKey, setPolicyIdempKey] = useState<string>(() => generateIdempotencyKey());
  const [policyClientErrors, setPolicyClientErrors] = useState<Record<string, string>>({});
  const [policyServerErrors, setPolicyServerErrors] = useState<Record<string, AppError | undefined>>(
    {}
  );
  const [policyTopError, setPolicyTopError] = useState<UiError | null>(null);
  const [policySubmitting, setPolicySubmitting] = useState(false);
  const [policySuccessMsg, setPolicySuccessMsg] = useState<string | null>(null);
  const [pendingInternetPolicy, setPendingInternetPolicy] = useState<{
    policy: RoEPolicy;
    reason: string;
  } | null>(null);
  const [capabilities, setCapabilities] = useState<CapabilityItem[]>([]);

  const loadCampaign = useCallback(async (campaignId: string, showLoading: boolean = true) => {
    try {
      if (showLoading) setLoading(true);
      setError(null);
      const data = await apiClient.getCampaign(campaignId);
      setCampaign(data);
    } catch (err: unknown) {
      setError(toUiError(err, `/campaigns/${campaignId}`));
    } finally {
      if (showLoading) setLoading(false);
    }
  }, []);

  const loadCampaignRef = useRef(loadCampaign);
  loadCampaignRef.current = loadCampaign;

  useEffect(() => {
    if (id) loadCampaign(id, true);
  }, [id, loadCampaign]);

  useEffect(() => {
    let mounted = true;
    if (isEditingPolicy && capabilities.length === 0) {
      apiClient
        .listCapabilities()
        .then((res) => {
          if (mounted) setCapabilities(res.items);
        })
        .catch(() => {
          // Optional capability quick-select chips
        });
    }
    return () => {
      mounted = false;
    };
  }, [isEditingPolicy, capabilities.length]);

  // Subscribe to SSE events for real-time live updates (<2s), coalescing historical bursts into O(1) GETs
  useEffect(() => {
    if (!id) return;

    const refresher = createCoalescedRefresh(() => loadCampaignRef.current(id, false), 250);
    const sub = apiClient.subscribeCampaignEvents({
      campaignId: id,
      types: CAMPAIGN_DETAIL_SSE_TYPES,
      onEvent: (event) => {
        setLastLiveEvent({
          type: event.type,
          time: new Date().toLocaleTimeString('vi-VN'),
        });

        const payload = (event.data as { payload?: Record<string, unknown> })?.payload;
        if (payload && typeof payload === 'object') {
          const newStatus = payload.status as Campaign['status'] | undefined;
          const statusReason = payload.status_reason as string | undefined;

          if (newStatus) {
            setCampaign((prev) =>
              prev ? { ...prev, status: newStatus, status_reason: statusReason ?? prev.status_reason } : null
            );
          }
        }

        if (CAMPAIGN_DETAIL_SSE_TYPE_SET.has(event.type)) {
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
  }, [id]);

  // Poll every 3s while campaign is non-terminal because campaign.status transitions
  // (e.g. RUNNING -> COMPLETED after final M03 session) emit no dedicated outbox SSE event.
  const campaignStatus = campaign?.status;
  useEffect(() => {
    if (!id || !campaignStatus) return;
    const isActive =
      campaignStatus === 'CREATED' ||
      campaignStatus === 'RUNNING' ||
      campaignStatus === 'WAITING';
    if (!isActive) return;

    const timer = setInterval(() => {
      loadCampaign(id, false);
    }, 3000);
    return () => clearInterval(timer);
  }, [id, campaignStatus, loadCampaign]);

  const handleExecuteAction = async () => {
    if (!campaign || !modalAction) return;
    try {
      setActionLoading(true);
      setActionError(null);
      let updated: Campaign;
      const reason = actionReason || (
        modalAction === 'pause'
          ? 'Tạm dừng tác chiến theo yêu cầu điều độ'
          : modalAction === 'resume'
          ? 'Tiếp tục chiến dịch'
          : 'Hủy toàn bộ job và dừng chiến dịch'
      );
      if (modalAction === 'pause') {
        updated = await apiClient.pauseCampaign(campaign.campaign_id, reason);
      } else if (modalAction === 'resume') {
        updated = await apiClient.resumeCampaign(campaign.campaign_id, reason);
      } else {
        updated = await apiClient.cancelCampaign(campaign.campaign_id, reason);
      }
      setCampaign(updated);
      setModalAction(null);
      setActionReason('');
    } catch (err: unknown) {
      setActionError(
        toUiError(err, `/campaigns/${campaign.campaign_id}/${modalAction}`)
      );
    } finally {
      setActionLoading(false);
    }
  };

  const openPolicyEditor = () => {
    if (!campaign) return;
    setPolicyValues(policyToFormValues(campaign.policy));
    setPolicyReason('');
    setPolicyClientErrors({});
    setPolicyServerErrors({});
    setPolicyTopError(null);
    setPolicySuccessMsg(null);
    setPolicyIdempKey(generateIdempotencyKey());
    setIsEditingPolicy(true);
  };

  const updatePolicyValues = (patch: Partial<PolicyFormValues>) => {
    setPolicyValues((prev) => ({ ...prev, ...patch }));
    setPolicyIdempKey(generateIdempotencyKey());
    setPolicyTopError(null);
    const changed = Object.keys(patch);
    setPolicyClientErrors((prev) => {
      const next = { ...prev };
      changed.forEach((k) => delete next[k]);
      return next;
    });
    setPolicyServerErrors((prev) => {
      const next = { ...prev };
      changed.forEach((k) => delete next[k]);
      return next;
    });
  };

  const executeAdoptPolicy = async (policy: RoEPolicy, reason: string) => {
    if (!campaign) return;
    try {
      setPolicySubmitting(true);
      setPolicyTopError(null);
      setPolicyServerErrors({});
      const res = await apiClient.updateCampaignPolicy(
        campaign.campaign_id,
        { policy, reason },
        { idempotencyKey: policyIdempKey }
      );
      setPendingInternetPolicy(null);
      setIsEditingPolicy(false);
      setPolicySuccessMsg(`Đã tạo và kích hoạt bản chụp RoE mới: ${res.policy_version}`);
      await loadCampaign(campaign.campaign_id, false);
    } catch (err: unknown) {
      setPendingInternetPolicy(null);
      setPolicyTopError(
        toUiError(err, `/campaigns/${campaign.campaign_id}/policy`)
      );
      if (err instanceof ApiError && err.appError) {
        const key = mapServerFieldToKey(err.appError.field);
        if (key) {
          setPolicyServerErrors({ [key]: err.appError });
        }
      }
    } finally {
      setPolicySubmitting(false);
    }
  };

  const handleSubmitPolicy = async (e: React.FormEvent) => {
    e.preventDefault();
    const { errors, policy } = validatePolicyForm(policyValues);
    const trimmedReason = policyReason.trim();
    if (trimmedReason.length < 3) {
      errors.reason = 'Lý do cập nhật RoE là bắt buộc (tối thiểu 3 ký tự).';
    }
    setPolicyClientErrors(errors);
    setPolicyServerErrors({});
    setPolicyTopError(null);

    if (Object.keys(errors).length > 0 || !policy) {
      return;
    }

    if (policy.network_profile === 'internet') {
      setPendingInternetPolicy({ policy, reason: trimmedReason });
      return;
    }

    await executeAdoptPolicy(policy, trimmedReason);
  };

  if (loading) {
    return (
      <div className="state-box">
        <div className="state-title">Đang nạp chi tiết chiến dịch...</div>
      </div>
    );
  }

  if (error || !campaign) {
    return (
      <div>
        <Link to="/campaigns" className="btn btn-sm" style={{ marginBottom: 16 }}>
          <ChevronLeft size={14} /> Quay lại danh sách
        </Link>
        <ErrorDisplay error={error || 'Không tìm thấy chiến dịch'} onRetry={() => id && loadCampaign(id)} />
      </div>
    );
  }

  const targets = campaign.targets as
    | { domains?: string[]; ips?: string[]; keywords?: string[]; urls?: string[]; emails?: string[] }
    | undefined;
  const hasDomains = Boolean(targets?.domains && targets.domains.length > 0);
  const hasIps = Boolean(targets?.ips && targets.ips.length > 0);
  const hasKeywords = Boolean(targets?.keywords && targets.keywords.length > 0);
  const hasUrls = Boolean(targets?.urls && targets.urls.length > 0);
  const hasEmails = Boolean(targets?.emails && targets.emails.length > 0);
  const hasAnyTargets = hasDomains || hasIps || hasKeywords || hasUrls || hasEmails;
  const isTerminal =
    campaign.status === 'COMPLETED' ||
    campaign.status === 'FAILED' ||
    campaign.status === 'CANCELLED';
  const canPause =
    campaign.status === 'CREATED' ||
    campaign.status === 'RUNNING' ||
    campaign.status === 'WAITING';
  const canCancel = canPause || campaign.status === 'PAUSED';

  return (
    <div>
      <div style={{ marginBottom: 16 }}>
        <Link to="/campaigns" className="btn btn-sm" style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
          <ChevronLeft size={14} /> Quay lại danh sách chiến dịch
        </Link>
      </div>

      {/* Top Header Card */}
      <div className="card">
        <div className="card-header" style={{ alignItems: 'flex-start' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
              <h1 style={{ fontSize: 'var(--text-xl)', fontWeight: 700, color: 'var(--ink)' }}>
                {campaign.name}
              </h1>
              <StatusChip status={campaign.status} size="md" />
              <span className="brand-badge">RoE: {campaign.policy_version}</span>
              <div
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 5,
                  padding: '2px 8px',
                  borderRadius: 'var(--radius-sm)',
                  backgroundColor: sseConnected ? 'var(--success-bg)' : 'var(--subtle)',
                  color: sseConnected ? 'var(--success)' : 'var(--muted)',
                  border: `1px solid ${sseConnected ? 'var(--success)' : 'var(--line)'}`,
                  fontSize: '11px',
                }}
              >
                <Radio size={11} className={sseConnected ? 'pulse-icon' : ''} />
                <span>{sseConnected ? 'SSE Live' : 'SSE Đang kết nối'}</span>
                {lastLiveEvent && (
                  <span style={{ fontSize: '10.5px', color: 'var(--ink)' }}>
                    ({lastLiveEvent.type} @ {lastLiveEvent.time})
                  </span>
                )}
              </div>
            </div>
            <p style={{ color: 'var(--muted)', marginTop: 4, fontSize: 'var(--text-sm)' }}>
              {campaign.objective || 'Chưa thiết lập mục tiêu'}
            </p>
            <div style={{ display: 'flex', gap: 12, marginTop: 8, flexWrap: 'wrap' }}>
              <CopyableId value={campaign.campaign_id} prefix="Campaign ID" />
              {campaign.scope_id && <CopyableId value={campaign.scope_id} prefix="Scope ID" />}
            </div>
          </div>

          {/* Action buttons with disable during submitting */}
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            {canPause && (
              <button
                type="button"
                className="btn btn-warning"
                disabled={actionLoading}
                onClick={() => {
                  setActionError(null);
                  setActionReason('Tạm dừng tác chiến theo yêu cầu điều độ');
                  setModalAction('pause');
                }}
              >
                <Pause size={14} /> Tạm dừng (Pause)
              </button>
            )}

            {campaign.status === 'PAUSED' && (
              <button
                type="button"
                className="btn btn-primary"
                disabled={actionLoading}
                onClick={() => {
                  setActionError(null);
                  setActionReason('Tiếp tục chiến dịch');
                  setModalAction('resume');
                }}
              >
                <Play size={14} /> Tiếp tục (Resume)
              </button>
            )}

            {canCancel && (
              <button
                type="button"
                className="btn btn-danger"
                disabled={actionLoading}
                onClick={() => {
                  setActionError(null);
                  setActionReason('Hủy toàn bộ job và dừng chiến dịch');
                  setModalAction('cancel');
                }}
              >
                <XCircle size={14} /> Hủy chiến dịch (Cancel)
              </button>
            )}

            <Link to={`/jobs?campaign_id=${campaign.campaign_id}`} className="btn">
              <GitBranch size={14} /> Xem Luồng Job
            </Link>
            <Link to={`/activity?campaign_id=${campaign.campaign_id}`} className="btn">
              <Activity size={14} /> Nhật ký Agent
            </Link>
            <Link to={`/assets?campaign_id=${campaign.campaign_id}`} className="btn">
              <Network size={14} /> Xem Đồ thị Tài sản
            </Link>
          </div>
        </div>

        {campaign.status_reason && (
          <div
            style={{
              padding: '8px 12px',
              backgroundColor: 'var(--subtle)',
              borderLeft: '3px solid var(--warning)',
              borderRadius: 'var(--radius-sm)',
              fontSize: 'var(--text-xs)',
              marginTop: 10,
            }}
          >
            <strong>Lý do trạng thái:</strong> {campaign.status_reason}
          </div>
        )}

        {actionError && (
          <div style={{ marginTop: 10 }}>
            <ErrorDisplay error={actionError} />
          </div>
        )}
      </div>

      {/* Grid of details */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 340px), 1fr))', gap: 16 }}>
        {/* Targets & Scope */}
        <div className="card">
          <div className="card-title">
            <Target size={18} style={{ color: 'var(--accent)' }} />
            <span>Mục tiêu đầu vào (Target Seeds)</span>
          </div>
          <div style={{ fontSize: 'var(--text-sm)', color: 'var(--muted)', marginBottom: 8 }}>
            Tập hạt giống phân quyền theo quy chuẩn RoE.
          </div>
          {hasAnyTargets ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {hasDomains &&
                targets!.domains!.map((dom) => (
                  <div
                    key={dom}
                    style={{
                      padding: '8px 10px',
                      backgroundColor: 'var(--subtle)',
                      borderRadius: 'var(--radius-md)',
                      border: '1px solid var(--line)',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: 6,
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      <span className="brand-badge">domain</span>
                      <strong style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)' }}>{dom}</strong>
                    </div>
                    <div style={{ width: '100%' }}>
                      <CopyableId value={`dns:${dom}`} prefix="Target" truncate={false} className="full-width" />
                    </div>
                  </div>
                ))}
              {hasIps &&
                targets!.ips!.map((ip) => (
                  <div
                    key={ip}
                    style={{
                      padding: '8px 10px',
                      backgroundColor: 'var(--subtle)',
                      borderRadius: 'var(--radius-md)',
                      border: '1px solid var(--line)',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: 6,
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      <span className="brand-badge">ip/cidr</span>
                      <strong style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)' }}>{ip}</strong>
                    </div>
                    <div style={{ width: '100%' }}>
                      <CopyableId value={`ip:${ip}`} prefix="Target" truncate={false} className="full-width" />
                    </div>
                  </div>
                ))}
              {hasKeywords &&
                targets!.keywords!.map((kw) => (
                  <div
                    key={kw}
                    style={{
                      padding: '8px 10px',
                      backgroundColor: 'var(--subtle)',
                      borderRadius: 'var(--radius-md)',
                      border: '1px solid var(--line)',
                      display: 'flex',
                      alignItems: 'center',
                      gap: 6,
                    }}
                  >
                    <span className="brand-badge">keyword</span>
                    <strong style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)' }}>{kw}</strong>
                  </div>
                ))}
              {hasUrls &&
                targets!.urls!.map((u) => (
                  <div
                    key={u}
                    style={{
                      padding: '8px 10px',
                      backgroundColor: 'var(--subtle)',
                      borderRadius: 'var(--radius-md)',
                      border: '1px solid var(--line)',
                      display: 'flex',
                      alignItems: 'center',
                      gap: 6,
                    }}
                  >
                    <span className="brand-badge">url</span>
                    <strong style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', wordBreak: 'break-all' }}>{u}</strong>
                  </div>
                ))}
              {hasEmails &&
                targets!.emails!.map((em) => (
                  <div
                    key={em}
                    style={{
                      padding: '8px 10px',
                      backgroundColor: 'var(--subtle)',
                      borderRadius: 'var(--radius-md)',
                      border: '1px solid var(--line)',
                      display: 'flex',
                      alignItems: 'center',
                      gap: 6,
                    }}
                  >
                    <span className="brand-badge">email</span>
                    <strong style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)' }}>{em}</strong>
                  </div>
                ))}
            </div>
          ) : (
            <div style={{ color: 'var(--muted)', fontSize: 'var(--text-sm)' }}>Không có seed đầu vào</div>
          )}

          {campaign.policy?.target_denylist?.length ? (
            <div style={{ marginTop: 12 }}>
              <div style={{ fontSize: 'var(--text-xs)', fontWeight: 600, color: 'var(--danger)', marginBottom: 4 }}>
                Danh sách mục tiêu loại trừ (Denylist):
              </div>
              {campaign.policy.target_denylist.map((item, idx) => (
                <span key={idx} className="mono" style={{ fontSize: '11.5px', color: 'var(--danger)', display: 'block' }}>
                  • {item}
                </span>
              ))}
            </div>
          ) : null}
        </div>

        {/* RoE Policy Rules */}
        <div className="card">
          <div className="card-header" style={{ marginBottom: 10 }}>
            <div className="card-title">
              <Shield size={18} style={{ color: 'var(--accent)' }} />
              <span>Chính sách Thực thi RoE (Policy)</span>
            </div>
            {!isTerminal && !isEditingPolicy && campaign.policy && (
              <button
                type="button"
                className="btn btn-sm btn-primary"
                onClick={openPolicyEditor}
              >
                <Edit3 size={13} /> Tạo bản chụp RoE mới
              </button>
            )}
          </div>

          {policySuccessMsg && (
            <div
              role="status"
              style={{
                padding: '8px 10px',
                backgroundColor: 'var(--success-bg)',
                border: '1px solid var(--success)',
                borderRadius: 'var(--radius-sm)',
                color: 'var(--success)',
                fontSize: 'var(--text-xs)',
                display: 'flex',
                alignItems: 'center',
                gap: 6,
                marginBottom: 10,
              }}
            >
              <CheckCircle2 size={14} />
              <span>{policySuccessMsg}</span>
            </div>
          )}

          {isTerminal && (
            <div
              style={{
                padding: '8px 10px',
                backgroundColor: 'var(--subtle)',
                border: '1px solid var(--line)',
                borderRadius: 'var(--radius-sm)',
                color: 'var(--muted)',
                fontSize: 'var(--text-xs)',
                marginBottom: 10,
              }}
            >
              Chiến dịch đã kết thúc ({campaign.status}) — API chỉ cho phép tạo bản chụp RoE mới khi chưa kết thúc.
            </div>
          )}

          {!isEditingPolicy ? (
            campaign.policy ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 'var(--text-xs)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--line)', paddingBottom: 6 }}>
                  <span style={{ color: 'var(--muted)' }}>Phiên bản RoE hiện hành:</span>
                  <span className="brand-badge">{campaign.policy_version}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--line)', paddingBottom: 6 }}>
                  <span style={{ color: 'var(--muted)' }}>Profile mạng (network_profile):</span>
                  <span
                    className={`status-chip ${
                      campaign.policy.network_profile === 'lab' ? 'accent' : 'warning'
                    }`}
                  >
                    {campaign.policy.network_profile || 'internet (mặc định hợp đồng)'}
                  </span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--line)', paddingBottom: 6 }}>
                  <span style={{ color: 'var(--muted)' }}>Job đồng thời tối đa:</span>
                  <strong className="tabular">{campaign.policy.max_parallel_jobs} jobs</strong>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--line)', paddingBottom: 6 }}>
                  <span style={{ color: 'var(--muted)' }}>Thời lượng quét tối đa:</span>
                  <strong className="tabular">{campaign.policy.max_duration_hours} giờ</strong>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--line)', paddingBottom: 6 }}>
                  <span style={{ color: 'var(--muted)' }}>Tốc độ / host:</span>
                  <span className="tabular">
                    {campaign.policy.rate_limits?.requests_per_second_per_host !== undefined
                      ? `${campaign.policy.rate_limits.requests_per_second_per_host} req/s`
                      : 'Chưa thiết lập'}
                  </span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--line)', paddingBottom: 6 }}>
                  <span style={{ color: 'var(--muted)' }}>Kết nối đồng thời / host:</span>
                  <span className="tabular">
                    {campaign.policy.rate_limits?.max_concurrent_connections_per_host !== undefined
                      ? `${campaign.policy.rate_limits.max_concurrent_connections_per_host} kết nối`
                      : 'Chưa thiết lập'}
                  </span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--line)', paddingBottom: 6 }}>
                  <span style={{ color: 'var(--muted)' }}>Gói tin / giây &amp; Job / phút:</span>
                  <span className="tabular">
                    {campaign.policy.rate_limits?.packets_per_second ?? '—'} pps /{' '}
                    {campaign.policy.rate_limits?.jobs_per_minute ?? '—'} jobs/phút
                  </span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--line)', paddingBottom: 6 }}>
                  <span style={{ color: 'var(--muted)' }}>Ngân sách &amp; Chu kỳ rỗi:</span>
                  <span className="tabular" style={{ textAlign: 'right' }}>
                    {campaign.policy.budget
                      ? `${campaign.policy.budget.max_jobs ?? '∞'} jobs · $${
                          campaign.policy.budget.max_llm_cost_usd ?? '∞'
                        } · ${campaign.policy.budget.max_llm_tokens ?? '∞'} tok · ${
                          campaign.policy.budget.max_agent_sessions ?? '∞'
                        } phiên · idle ${campaign.policy.budget.idle_cycles_before_pause}`
                      : 'Không giới hạn'}
                  </span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, borderBottom: '1px solid var(--line)', paddingBottom: 6 }}>
                  <span style={{ color: 'var(--muted)' }}>Capability loại trừ:</span>
                  <span className="mono" style={{ textAlign: 'right' }}>
                    {campaign.policy.capability_denylist?.length
                      ? campaign.policy.capability_denylist.join(', ')
                      : 'Không có'}
                  </span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, borderBottom: campaign.policy.authorization ? '1px solid var(--line)' : undefined, paddingBottom: campaign.policy.authorization ? 6 : 0 }}>
                  <span style={{ color: 'var(--muted)' }}>Mục tiêu loại trừ:</span>
                  <span className="mono" style={{ textAlign: 'right' }}>
                    {campaign.policy.target_denylist?.length
                      ? campaign.policy.target_denylist.join(', ')
                      : 'Không có'}
                  </span>
                </div>
                {campaign.policy.authorization && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}>
                      <span style={{ color: 'var(--muted)' }}>Ủy quyền internet (owner / ngày):</span>
                      <span style={{ textAlign: 'right' }}>
                        <strong>{campaign.policy.authorization.owner}</strong> ·{' '}
                        <span className="tabular">{campaign.policy.authorization.date}</span>
                      </span>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}>
                      <span style={{ color: 'var(--muted)' }}>Tham chiếu &amp; hậu tố được phép:</span>
                      <span className="mono" style={{ textAlign: 'right' }}>
                        {campaign.policy.authorization.reference} ({campaign.policy.authorization.authorized_suffixes.join(', ')})
                      </span>
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div style={{ color: 'var(--muted)' }}>Không có bản chụp RoE</div>
            )
          ) : (
            <form onSubmit={handleSubmitPolicy} noValidate>
              <div
                style={{
                  fontSize: 'var(--text-xs)',
                  color: 'var(--muted)',
                  marginBottom: 10,
                  display: 'flex',
                  justifyContent: 'space-between',
                  flexWrap: 'wrap',
                  gap: 6,
                }}
              >
                <span>
                  Bản chụp cũ (<code className="mono">{campaign.policy_version}</code>) được giữ nguyên bất biến.
                </span>
                <span className="brand-badge">Idempotency-Key: {policyIdempKey}</span>
              </div>

              {policyTopError && (
                <div style={{ marginBottom: 12 }}>
                  <ErrorDisplay error={policyTopError} />
                </div>
              )}

              <div className="form-field">
                <label className="form-label" htmlFor="policy-adopt-reason">
                  Lý do cập nhật RoE (reason, tối thiểu 3 ký tự) *
                </label>
                <input
                  id="policy-adopt-reason"
                  type="text"
                  className="form-input"
                  placeholder="Ví dụ: Điều chỉnh giới hạn tốc độ và song song theo vận hành"
                  value={policyReason}
                  disabled={policySubmitting}
                  aria-invalid={Boolean(policyClientErrors.reason || policyServerErrors.reason)}
                  onChange={(e) => {
                    setPolicyReason(e.target.value);
                    setPolicyIdempKey(generateIdempotencyKey());
                    setPolicyTopError(null);
                    setPolicyClientErrors((prev) => {
                      const next = { ...prev };
                      delete next.reason;
                      return next;
                    });
                    setPolicyServerErrors((prev) => {
                      const next = { ...prev };
                      delete next.reason;
                      return next;
                    });
                  }}
                />
                <InlineFieldError
                  clientError={policyClientErrors.reason}
                  serverError={policyServerErrors.reason}
                />
              </div>

              <RoEPolicyFields
                idPrefix="adopt-policy"
                values={policyValues}
                onChange={updatePolicyValues}
                clientErrors={policyClientErrors}
                serverErrors={policyServerErrors}
                capabilities={capabilities}
                disabled={policySubmitting}
              />

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 14 }}>
                <button
                  type="button"
                  className="btn"
                  disabled={policySubmitting}
                  onClick={() => setIsEditingPolicy(false)}
                >
                  Hủy
                </button>
                <button type="submit" className="btn btn-primary" disabled={policySubmitting}>
                  {policySubmitting ? 'Đang tạo bản chụp...' : 'Lưu & Kích hoạt RoE mới'}
                </button>
              </div>
            </form>
          )}
        </div>

        {/* Budget & Counters */}
        <div className="card">
          <div className="card-title">
            <BarChart3 size={18} style={{ color: 'var(--accent)' }} />
            <span>Ngân sách &amp; Bộ đếm Tác chiến</span>
          </div>
          {campaign.budget ? (
            <div style={{ marginBottom: 16 }}>
              <div
                style={{
                  fontSize: 'var(--text-xs)',
                  fontWeight: 600,
                  color: 'var(--muted)',
                  textTransform: 'uppercase',
                  marginBottom: 8,
                }}
              >
                Ngân sách thực thi (Đã dùng / Giới hạn &amp; Còn lại)
              </div>
              <div className="stats-grid-2">
                {buildBudgetDimensions(campaign.budget).map((row) => (
                  <div
                    key={row.key}
                    style={{
                      padding: 10,
                      backgroundColor: 'var(--subtle)',
                      borderRadius: 'var(--radius-md)',
                      border: '1px solid var(--line)',
                      minWidth: 0,
                    }}
                  >
                    <div
                      style={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        fontSize: 'var(--text-xs)',
                        color: 'var(--muted)',
                        marginBottom: 4,
                      }}
                    >
                      <span>{row.label}</span>
                      {row.usedRatio !== null && (
                        <span className="tabular mono">{Math.round(row.usedRatio * 100)}%</span>
                      )}
                    </div>
                    <div className="tabular" style={{ fontSize: 'var(--text-sm)', fontWeight: 700, color: 'var(--ink)' }}>
                      {row.usedText}{' '}
                      <span style={{ fontWeight: 500, color: 'var(--muted)' }}>/ {row.limitText}</span>
                    </div>
                    {row.usedRatio !== null && (
                      <div
                        role="progressbar"
                        aria-valuenow={Math.round(row.usedRatio * 100)}
                        aria-valuemin={0}
                        aria-valuemax={100}
                        aria-label={`${row.label} đã dùng`}
                        style={{
                          height: 4,
                          borderRadius: 999,
                          backgroundColor: 'var(--line)',
                          marginTop: 6,
                          overflow: 'hidden',
                        }}
                      >
                        <div
                          style={{
                            width: `${Math.round(row.usedRatio * 100)}%`,
                            height: '100%',
                            backgroundColor: row.usedRatio >= 0.9 ? 'var(--warning)' : 'var(--accent)',
                          }}
                        />
                      </div>
                    )}
                    <div style={{ fontSize: '11px', color: 'var(--muted)', marginTop: 4 }} className="tabular">
                      {row.remainingText !== null
                        ? `Còn lại: ${row.remainingText}`
                        : row.hasLimit
                          ? 'Còn lại: —'
                          : 'Không giới hạn trần RoE'}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ) : campaign.budget_remaining &&
            (campaign.budget_remaining.llm_cost_usd !== undefined ||
              campaign.budget_remaining.llm_tokens !== undefined ||
              campaign.budget_remaining.jobs !== undefined ||
              campaign.budget_remaining.hours !== undefined) ? (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, marginBottom: 14 }}>
              {campaign.budget_remaining.llm_cost_usd !== undefined && (
                <div style={{ padding: 10, backgroundColor: 'var(--subtle)', borderRadius: 'var(--radius-md)' }}>
                  <div style={{ fontSize: 'var(--text-xs)', color: 'var(--muted)' }}>Chi phí LLM còn lại</div>
                  <div className="tabular" style={{ fontSize: 'var(--text-lg)', fontWeight: 700, color: 'var(--ink)' }}>
                    ${campaign.budget_remaining.llm_cost_usd.toFixed(2)}
                  </div>
                </div>
              )}
              {campaign.budget_remaining.llm_tokens !== undefined && (
                <div style={{ padding: 10, backgroundColor: 'var(--subtle)', borderRadius: 'var(--radius-md)' }}>
                  <div style={{ fontSize: 'var(--text-xs)', color: 'var(--muted)' }}>Token LLM còn lại</div>
                  <div className="tabular" style={{ fontSize: 'var(--text-lg)', fontWeight: 700, color: 'var(--ink)' }}>
                    {campaign.budget_remaining.llm_tokens.toLocaleString('en-US')}
                  </div>
                </div>
              )}
              {campaign.budget_remaining.jobs !== undefined && (
                <div style={{ padding: 10, backgroundColor: 'var(--subtle)', borderRadius: 'var(--radius-md)' }}>
                  <div style={{ fontSize: 'var(--text-xs)', color: 'var(--muted)' }}>Số job còn lại</div>
                  <div className="tabular" style={{ fontSize: 'var(--text-lg)', fontWeight: 700, color: 'var(--ink)' }}>
                    {campaign.budget_remaining.jobs}
                  </div>
                </div>
              )}
              {campaign.budget_remaining.hours !== undefined && (
                <div style={{ padding: 10, backgroundColor: 'var(--subtle)', borderRadius: 'var(--radius-md)' }}>
                  <div style={{ fontSize: 'var(--text-xs)', color: 'var(--muted)' }}>Thời lượng còn lại</div>
                  <div className="tabular" style={{ fontSize: 'var(--text-lg)', fontWeight: 700, color: 'var(--ink)' }}>
                    {campaign.budget_remaining.hours.toFixed(1)}h
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div style={{ color: 'var(--muted)', fontSize: 'var(--text-sm)', marginBottom: 14 }}>
              Chưa có dữ liệu ngân sách
            </div>
          )}

          {(() => {
            const jobSummary = summarizeJobCounters(campaign.counters);
            const assetSummary = summarizeAssetCounters(campaign.counters);
            const hasCounters = Boolean(campaign.counters && (jobSummary.hasData || assetSummary.hasData));
            if (!hasCounters || !campaign.counters) {
              return (
                <div style={{ color: 'var(--muted)', fontSize: 'var(--text-xs)' }}>
                  Chưa có dữ liệu bộ đếm
                </div>
              );
            }
            return (
              <div>
                <div
                  style={{
                    fontSize: 'var(--text-xs)',
                    fontWeight: 600,
                    color: 'var(--muted)',
                    textTransform: 'uppercase',
                    marginBottom: 8,
                  }}
                >
                  Bộ đếm Job &amp; Tài sản
                </div>
                <div className="stats-grid-2">
                  <div
                    style={{
                      padding: 10,
                      backgroundColor: 'var(--subtle)',
                      borderRadius: 'var(--radius-md)',
                      border: '1px solid var(--line)',
                    }}
                  >
                    <div style={{ fontSize: 'var(--text-xs)', color: 'var(--muted)' }}>Tổng số Job theo trạng thái</div>
                    <div className="tabular" style={{ fontSize: 'var(--text-lg)', fontWeight: 700, color: 'var(--accent)' }}>
                      {jobSummary.total ?? '—'}
                    </div>
                    {jobSummary.byStatus.length > 0 ? (
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginTop: 6 }}>
                        {jobSummary.byStatus.map(({ status, count }) => (
                          <span key={status} className="brand-badge tabular">
                            {status}: {count}
                          </span>
                        ))}
                      </div>
                    ) : (
                      <div style={{ fontSize: '11px', color: 'var(--muted)', marginTop: 4 }}>
                        {campaign.counters.jobs_by_status ? 'Chưa có job nào' : '—'}
                      </div>
                    )}
                  </div>

                  <div
                    style={{
                      padding: 10,
                      backgroundColor: 'var(--subtle)',
                      borderRadius: 'var(--radius-md)',
                      border: '1px solid var(--line)',
                    }}
                  >
                    <div style={{ fontSize: 'var(--text-xs)', color: 'var(--muted)' }}>Tổng tài sản theo loại</div>
                    <div className="tabular" style={{ fontSize: 'var(--text-lg)', fontWeight: 700, color: 'var(--success)' }}>
                      {assetSummary.total ?? '—'}
                    </div>
                    {assetSummary.byKind.length > 0 ? (
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginTop: 6 }}>
                        {assetSummary.byKind.map(({ kind, count }) => (
                          <span key={kind} className="brand-badge tabular">
                            {assetKindLabel(kind)}: {count}
                          </span>
                        ))}
                      </div>
                    ) : (
                      <div style={{ fontSize: '11px', color: 'var(--muted)', marginTop: 4 }}>
                        {campaign.counters.assets_by_kind ? 'Chưa có tài sản nào' : '—'}
                      </div>
                    )}
                  </div>

                  {campaign.counters.jobs_failed !== undefined && (
                    <div style={{ padding: 10, backgroundColor: 'var(--subtle)', borderRadius: 'var(--radius-md)' }}>
                      <div style={{ fontSize: 'var(--text-xs)', color: 'var(--muted)' }}>Job thất bại / Từ chối policy</div>
                      <div className="tabular" style={{ fontSize: 'var(--text-base)', fontWeight: 600, color: 'var(--ink)' }}>
                        {campaign.counters.jobs_failed} failed · {campaign.counters.policy_denials ?? 0} denied
                      </div>
                    </div>
                  )}
                  {campaign.counters.agent_sessions !== undefined && (
                    <div style={{ padding: 10, backgroundColor: 'var(--subtle)', borderRadius: 'var(--radius-md)' }}>
                      <div style={{ fontSize: 'var(--text-xs)', color: 'var(--muted)' }}>Phiên Agent / Graph rev</div>
                      <div className="tabular" style={{ fontSize: 'var(--text-base)', fontWeight: 600, color: 'var(--ink)' }}>
                        {campaign.counters.agent_sessions} phiên · rev {campaign.counters.graph_revision ?? '—'}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            );
          })()}
        </div>
      </div>

      {/* Confirmation Modal */}
      {modalAction && (
        <div className="modal-overlay" role="dialog" aria-modal="true">
          <div className="modal-content">
            <h3 style={{ fontSize: 'var(--text-lg)', fontWeight: 600, color: 'var(--ink)', marginBottom: 8 }}>
              Xác nhận {modalAction === 'pause' ? 'Tạm dừng' : modalAction === 'resume' ? 'Tiếp tục' : 'Hủy'} Chiến dịch
            </h3>
            <p style={{ fontSize: 'var(--text-sm)', color: 'var(--muted)', marginBottom: 12 }}>
              Vui lòng nhập lý do vận hành. Thao tác sẽ được kiểm định và gửi tín hiệu điều khiển tới Temporal Workflow.
            </p>

            <textarea
              className="input-search"
              style={{ width: '100%', minHeight: 80, padding: 8, resize: 'vertical', marginBottom: 14 }}
              placeholder="Nhập lý do thực hiện..."
              value={actionReason}
              onChange={(e) => setActionReason(e.target.value)}
              aria-label="Lý do thao tác"
            />

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
              <button
                type="button"
                className="btn"
                disabled={actionLoading}
                onClick={() => setModalAction(null)}
              >
                Đóng
              </button>
              <button
                type="button"
                className={`btn ${modalAction === 'cancel' ? 'btn-danger' : modalAction === 'pause' ? 'btn-warning' : 'btn-primary'}`}
                disabled={actionLoading}
                onClick={handleExecuteAction}
              >
                {actionLoading ? 'Đang gửi tín hiệu...' : 'Xác nhận thực hiện'}
              </button>
            </div>
          </div>
        </div>
      )}

      <InternetConfirmModal
        isOpen={pendingInternetPolicy !== null}
        policy={pendingInternetPolicy?.policy ?? null}
        reason={pendingInternetPolicy?.reason}
        submitting={policySubmitting}
        onCancel={() => setPendingInternetPolicy(null)}
        onConfirm={() =>
          pendingInternetPolicy &&
          executeAdoptPolicy(pendingInternetPolicy.policy, pendingInternetPolicy.reason)
        }
      />
    </div>
  );
};
