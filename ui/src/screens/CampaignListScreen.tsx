import React, { useEffect, useState, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { Eye, Plus, Layers, Filter, Clock, DollarSign, Activity, Key } from 'lucide-react';
import { ApiError, apiClient, toUiError } from '../api/client';
import type { Campaign, CampaignStatus, UiError } from '../api/types';
import { StatusChip } from '../components/StatusChip';
import { CopyableId } from '../components/CopyableId';
import { ErrorDisplay } from '../components/ErrorDisplay';

export const CampaignListScreen: React.FC = () => {
  const [campaigns, setCampaigns] = useState<Campaign[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<UiError | null>(null);
  const [errorStatus, setErrorStatus] = useState<number | null>(null);
  const [statusFilter, setStatusFilter] = useState<string>('ALL');

  const loadCampaigns = useCallback(async () => {
    const qs = statusFilter !== 'ALL' ? `?status=${encodeURIComponent(statusFilter)}` : '';
    try {
      setLoading(true);
      setError(null);
      setErrorStatus(null);
      const params = statusFilter !== 'ALL' ? { status: statusFilter as CampaignStatus } : undefined;
      const res = await apiClient.listCampaigns(params);
      setCampaigns(res.items);
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        setErrorStatus(err.status ?? null);
      }
      setError(toUiError(err, `/campaigns${qs}`));
    } finally {
      setLoading(false);
    }
  }, [statusFilter]);

  useEffect(() => {
    loadCampaigns();
  }, [loadCampaigns]);

  useEffect(() => {
    const handleTokenChanged = () => {
      loadCampaigns();
    };
    window.addEventListener('ultron-token-changed', handleTokenChanged);
    return () => {
      window.removeEventListener('ultron-token-changed', handleTokenChanged);
    };
  }, [loadCampaigns]);

  return (
    <div>
      <div className="filter-bar">
        <div>
          <h1 style={{ fontSize: 'var(--text-xl)', fontWeight: 700, color: 'var(--ink)' }}>
            Quản lý Chiến dịch (Campaigns)
          </h1>
          <p style={{ fontSize: 'var(--text-sm)', color: 'var(--muted)', marginTop: 2 }}>
            Danh sách chiến dịch rà soát bề mặt tấn công, cấu hình RoE và trạng thái vận hành.
          </p>
        </div>

        <div className="filter-group">
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 'var(--text-xs)', color: 'var(--muted)' }}>
            <Filter size={14} />
            <span>Lọc trạng thái:</span>
          </div>
          <select
            className="input-search"
            style={{ minWidth: 160 }}
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            aria-label="Lọc theo trạng thái"
          >
            <option value="ALL">Tất cả trạng thái</option>
            <option value="CREATED">Mới tạo (CREATED)</option>
            <option value="RUNNING">Đang thực thi (RUNNING)</option>
            <option value="WAITING">Đang chờ (WAITING)</option>
            <option value="PAUSED">Tạm dừng (PAUSED)</option>
            <option value="COMPLETED">Hoàn thành (COMPLETED)</option>
            <option value="FAILED">Thất bại (FAILED)</option>
            <option value="CANCELLED">Đã hủy (CANCELLED)</option>
          </select>

          <Link
            to="/campaigns/new"
            className="btn btn-primary"
            title="Tạo chiến dịch mới tuân thủ Idempotency-Key và RoE Policy"
          >
            <Plus size={15} /> Tạo chiến dịch
          </Link>
        </div>
      </div>

      {error && (
        <div style={{ marginBottom: 16 }}>
          <ErrorDisplay error={error} onRetry={loadCampaigns} />
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
        <div className="state-box">
          <Activity size={28} className="pulse-icon" style={{ color: 'var(--accent)' }} />
          <div className="state-title">Đang nạp danh sách chiến dịch...</div>
          <div className="state-desc">Đang truy vấn dữ liệu từ API /campaigns</div>
        </div>
      ) : campaigns.length === 0 ? (
        <div className="state-box">
          <Layers size={32} style={{ color: 'var(--muted)' }} />
          <div className="state-title">Chưa có chiến dịch nào</div>
          <div className="state-desc">Không tìm thấy chiến dịch nào khớp với bộ lọc hiện tại.</div>
        </div>
      ) : (
        <div className="table-container">
          <table className="data-table" aria-label="Bảng danh sách chiến dịch">
            <thead>
              <tr>
                <th>Chiến dịch</th>
                <th>Trạng thái</th>
                <th>Phiên bản RoE</th>
                <th>Ngân sách còn lại</th>
                <th>Bộ đếm tài sản & Job</th>
                <th>Thời điểm tạo</th>
                <th style={{ textAlign: 'right' }}>Thao tác</th>
              </tr>
            </thead>
            <tbody>
              {campaigns.map((camp) => (
                <tr key={camp.campaign_id}>
                  <td>
                    <div style={{ fontWeight: 600, color: 'var(--ink)' }}>{camp.name}</div>
                    <div style={{ fontSize: 'var(--text-xs)', color: 'var(--muted)', marginTop: 2 }}>
                      {camp.objective || 'Chưa thiết lập mục tiêu'}
                    </div>
                    <div style={{ marginTop: 4 }}>
                      <CopyableId value={camp.campaign_id} prefix="ID" />
                    </div>
                  </td>
                  <td>
                    <StatusChip status={camp.status} />
                    {camp.status_reason && (
                      <div style={{ fontSize: '11px', color: 'var(--muted)', marginTop: 4, maxWidth: 200 }}>
                        {camp.status_reason}
                      </div>
                    )}
                  </td>
                  <td>
                    <span className="brand-badge">{camp.policy_version}</span>
                  </td>
                  <td>
                    {camp.budget_remaining &&
                    (camp.budget_remaining.llm_cost_usd !== undefined ||
                      camp.budget_remaining.llm_tokens !== undefined ||
                      camp.budget_remaining.hours !== undefined ||
                      camp.budget_remaining.jobs !== undefined) ? (
                      <div style={{ fontSize: 'var(--text-xs)', display: 'flex', flexDirection: 'column', gap: 2 }}>
                        {camp.budget_remaining.llm_cost_usd !== undefined && (
                          <span className="tabular">
                            <DollarSign size={11} style={{ display: 'inline', verticalAlign: -1 }} />
                            {camp.budget_remaining.llm_cost_usd.toFixed(2)} USD
                          </span>
                        )}
                        {(camp.budget_remaining.hours !== undefined || camp.budget_remaining.jobs !== undefined) && (
                          <span className="tabular" style={{ color: 'var(--muted)' }}>
                            <Clock size={11} style={{ display: 'inline', verticalAlign: -1 }} />
                            {camp.budget_remaining.hours !== undefined
                              ? `${camp.budget_remaining.hours.toFixed(1)}h`
                              : '—'}
                            {camp.budget_remaining.jobs !== undefined
                              ? ` / ${camp.budget_remaining.jobs} jobs`
                              : ''}
                          </span>
                        )}
                        {camp.budget_remaining.llm_tokens !== undefined && (
                          <span className="tabular" style={{ color: 'var(--muted)' }}>
                            {camp.budget_remaining.llm_tokens.toLocaleString('en-US')} tok
                          </span>
                        )}
                      </div>
                    ) : (
                      <span style={{ color: 'var(--muted)', fontSize: 'var(--text-xs)' }}>
                        Chưa có dữ liệu ngân sách
                      </span>
                    )}
                  </td>
                  <td>
                    {camp.counters ? (
                      <div style={{ fontSize: 'var(--text-xs)', display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                        <span title="Tổng số job / đang chạy" className="tabular">
                          <strong>{camp.counters.jobs_running ?? '—'}</strong> running /{' '}
                          {camp.counters.jobs_total ?? '—'} total
                        </span>
                        <span style={{ color: 'var(--muted)' }}>•</span>
                        <span title="Số tài sản phát hiện" className="tabular" style={{ color: 'var(--success)', fontWeight: 600 }}>
                          {camp.counters.assets ?? '—'} assets
                        </span>
                      </div>
                    ) : (
                      <span style={{ color: 'var(--muted)', fontSize: 'var(--text-xs)' }}>Chưa có bộ đếm</span>
                    )}
                  </td>
                  <td>
                    <span className="mono" style={{ fontSize: 'var(--text-xs)', color: 'var(--muted)', whiteSpace: 'nowrap' }}>
                      {new Date(camp.created_at).toLocaleDateString('vi-VN')}
                    </span>
                  </td>
                  <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                    <Link
                      to={`/campaigns/${camp.campaign_id}`}
                      className="btn btn-sm"
                      style={{ display: 'inline-flex', alignItems: 'center', gap: 4, whiteSpace: 'nowrap', flexShrink: 0 }}
                    >
                      <Eye size={13} /> Chi tiết
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};
