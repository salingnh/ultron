import React, { useEffect, useState, useCallback } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  Pause,
  Play,
  XCircle,
  GitBranch,
  Network,
  Clock,
  Shield,
  Target,
  BarChart3,
  ChevronLeft,
  Radio,
} from 'lucide-react';
import { apiClient } from '../api/client';
import type { Campaign } from '../api/types';
import { StatusChip } from '../components/StatusChip';
import { CopyableId } from '../components/CopyableId';
import { ErrorDisplay } from '../components/ErrorDisplay';

export const CampaignDetailScreen: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [campaign, setCampaign] = useState<Campaign | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionLoading, setActionLoading] = useState(false);
  const [modalAction, setModalAction] = useState<'pause' | 'resume' | 'cancel' | null>(null);
  const [actionReason, setActionReason] = useState('');
  const [sseConnected, setSseConnected] = useState(false);
  const [lastLiveEvent, setLastLiveEvent] = useState<{ type: string; time: string } | null>(null);

  const loadCampaign = useCallback(async (campaignId: string, showLoading: boolean = true) => {
    try {
      if (showLoading) setLoading(true);
      setError(null);
      const data = await apiClient.getCampaign(campaignId);
      setCampaign(data);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Không thể tải thông tin chiến dịch');
    } finally {
      if (showLoading) setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (id) loadCampaign(id, true);
  }, [id, loadCampaign]);

  // Subscribe to SSE events for real-time live updates (<2s)
  useEffect(() => {
    if (!id) return;

    const sub = apiClient.subscribeCampaignEvents({
      campaignId: id,
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

        // Silent background authoritative sync
        loadCampaign(id, false);
      },
      onStatusChange: (status) => {
        setSseConnected(status === 'connected');
      },
    });

    return () => {
      sub.close();
    };
  }, [id, loadCampaign]);

  const handleExecuteAction = async () => {
    if (!campaign || !modalAction) return;
    try {
      setActionLoading(true);
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
      alert(err instanceof Error ? err.message : 'Thao tác thất bại');
    } finally {
      setActionLoading(false);
    }
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

  const targets = campaign.targets;
  const hasDomains = targets && 'domains' in targets && Array.isArray(targets.domains) && targets.domains.length > 0;
  const hasIps = targets && 'ips' in targets && Array.isArray(targets.ips) && targets.ips.length > 0;

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
              <CopyableId value={campaign.scope_id} prefix="Scope ID" />
            </div>
          </div>

          {/* Action buttons with disable during submitting */}
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            {campaign.status === 'RUNNING' && (
              <button
                type="button"
                className="btn btn-warning"
                disabled={actionLoading}
                onClick={() => {
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
                  setActionReason('Tiếp tục chiến dịch');
                  setModalAction('resume');
                }}
              >
                <Play size={14} /> Tiếp tục (Resume)
              </button>
            )}

            {(campaign.status === 'RUNNING' || campaign.status === 'PAUSED') && (
              <button
                type="button"
                className="btn btn-danger"
                disabled={actionLoading}
                onClick={() => {
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
      </div>

      {/* Grid of details */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))', gap: 16 }}>
        {/* Targets & Scope */}
        <div className="card">
          <div className="card-title">
            <Target size={18} style={{ color: 'var(--accent)' }} />
            <span>Mục tiêu đầu vào (Target Seeds)</span>
          </div>
          <div style={{ fontSize: 'var(--text-sm)', color: 'var(--muted)', marginBottom: 8 }}>
            Tập hạt giống phân quyền theo quy chuẩn RoE.
          </div>
          {hasDomains || hasIps ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {hasDomains &&
                (targets as { domains: string[] }).domains.map((dom) => (
                  <div
                    key={dom}
                    style={{
                      padding: '8px 10px',
                      backgroundColor: 'var(--subtle)',
                      borderRadius: 'var(--radius-md)',
                      border: '1px solid var(--line)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                    }}
                  >
                    <div>
                      <span className="brand-badge" style={{ marginRight: 6 }}>domain</span>
                      <strong style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)' }}>{dom}</strong>
                    </div>
                    <CopyableId value={`dns:${dom}`} prefix="Target" />
                  </div>
                ))}
              {hasIps &&
                (targets as { ips: string[] }).ips.map((ip) => (
                  <div
                    key={ip}
                    style={{
                      padding: '8px 10px',
                      backgroundColor: 'var(--subtle)',
                      borderRadius: 'var(--radius-md)',
                      border: '1px solid var(--line)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                    }}
                  >
                    <div>
                      <span className="brand-badge" style={{ marginRight: 6 }}>ip/cidr</span>
                      <strong style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)' }}>{ip}</strong>
                    </div>
                    <CopyableId value={`ip:${ip}`} prefix="Target" />
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
          <div className="card-title">
            <Shield size={18} style={{ color: 'var(--accent)' }} />
            <span>Chính sách Thực thi RoE (Policy)</span>
          </div>
          {campaign.policy ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 'var(--text-sm)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--line)', paddingBottom: 6 }}>
                <span style={{ color: 'var(--muted)' }}>Job đồng thời tối đa:</span>
                <strong>{campaign.policy.max_parallel_jobs} jobs</strong>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--line)', paddingBottom: 6 }}>
                <span style={{ color: 'var(--muted)' }}>Thời lượng quét tối đa:</span>
                <strong>{campaign.policy.max_duration_hours} giờ</strong>
              </div>
              {campaign.policy.rate_limits && (
                <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--line)', paddingBottom: 6 }}>
                  <span style={{ color: 'var(--muted)' }}>Giới hạn tốc độ:</span>
                  <span className="tabular">{campaign.policy.rate_limits.requests_per_second_per_host || 10} req/s/host</span>
                </div>
              )}
              {campaign.policy.allowed_windows?.length ? (
                <div>
                  <span style={{ color: 'var(--muted)', display: 'block', marginBottom: 4 }}>
                    Khung giờ cho phép (Allowed Windows):
                  </span>
                  {campaign.policy.allowed_windows.map((win, idx) => (
                    <div
                      key={idx}
                      style={{
                        padding: '6px 8px',
                        backgroundColor: 'var(--subtle)',
                        borderRadius: 'var(--radius-sm)',
                        fontSize: 'var(--text-xs)',
                      }}
                    >
                      <Clock size={12} style={{ display: 'inline', verticalAlign: -1, marginRight: 4 }} />
                      <span>
                        {win.start} - {win.end} ({win.timezone}) [{win.days.join(', ')}]
                      </span>
                    </div>
                  ))}
                </div>
              ) : (
                <div style={{ color: 'var(--muted)', fontSize: 'var(--text-xs)' }}>
                  Cho phép quét mọi khung giờ trong tuần
                </div>
              )}
            </div>
          ) : (
            <div style={{ color: 'var(--muted)' }}>Không có bản chụp RoE</div>
          )}
        </div>

        {/* Budget & Counters */}
        <div className="card">
          <div className="card-title">
            <BarChart3 size={18} style={{ color: 'var(--accent)' }} />
            <span>Ngân sách & Bộ đếm Tác chiến</span>
          </div>
          {campaign.budget_remaining && (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, marginBottom: 14 }}>
              <div style={{ padding: 10, backgroundColor: 'var(--subtle)', borderRadius: 'var(--radius-md)' }}>
                <div style={{ fontSize: 'var(--text-xs)', color: 'var(--muted)' }}>Chi phí LLM còn lại</div>
                <div style={{ fontSize: 'var(--text-lg)', fontWeight: 700, color: 'var(--ink)' }}>
                  ${campaign.budget_remaining.llm_cost_usd?.toFixed(2)}
                </div>
              </div>
              <div style={{ padding: 10, backgroundColor: 'var(--subtle)', borderRadius: 'var(--radius-md)' }}>
                <div style={{ fontSize: 'var(--text-xs)', color: 'var(--muted)' }}>Thời lượng còn lại</div>
                <div style={{ fontSize: 'var(--text-lg)', fontWeight: 700, color: 'var(--ink)' }}>
                  {campaign.budget_remaining.hours?.toFixed(1)}h
                </div>
              </div>
            </div>
          )}

          {campaign.counters && (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
              <div style={{ padding: 10, backgroundColor: 'var(--subtle)', borderRadius: 'var(--radius-md)' }}>
                <div style={{ fontSize: 'var(--text-xs)', color: 'var(--muted)' }}>Tài sản phát hiện</div>
                <div style={{ fontSize: 'var(--text-lg)', fontWeight: 700, color: 'var(--success)' }}>
                  {campaign.counters.assets}
                </div>
              </div>
              <div style={{ padding: 10, backgroundColor: 'var(--subtle)', borderRadius: 'var(--radius-md)' }}>
                <div style={{ fontSize: 'var(--text-xs)', color: 'var(--muted)' }}>Job đang chạy / Tổng</div>
                <div style={{ fontSize: 'var(--text-lg)', fontWeight: 700, color: 'var(--accent)' }}>
                  {campaign.counters.jobs_running} / {campaign.counters.jobs_total}
                </div>
              </div>
            </div>
          )}
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
    </div>
  );
};
