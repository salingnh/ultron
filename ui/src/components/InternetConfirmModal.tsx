import React, { useState } from 'react';
import { AlertTriangle, ShieldAlert } from 'lucide-react';
import type { RoEPolicy, Targets } from '../api/types';

interface InternetConfirmModalProps {
  isOpen: boolean;
  policy: RoEPolicy | null;
  targets?: Targets;
  authorizationLabel?: string;
  reason?: string;
  submitting: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}

export const InternetConfirmModal: React.FC<InternetConfirmModalProps> = ({
  isOpen,
  policy,
  targets,
  authorizationLabel,
  reason,
  submitting,
  onCancel,
  onConfirm,
}) => {
  const [acknowledged, setAcknowledged] = useState(false);

  if (!isOpen || !policy) return null;

  const targetObj = targets as
    | { domains?: string[]; ips?: string[]; keywords?: string[] }
    | undefined;
  const allTargets = [
    ...(targetObj?.domains || []).map((d) => `domain: ${d}`),
    ...(targetObj?.ips || []).map((ip) => `ip/cidr: ${ip}`),
    ...(targetObj?.keywords || []).map((k) => `keyword: ${k}`),
  ];

  return (
    <div className="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="internet-confirm-title">
      <div className="modal-content" style={{ maxWidth: 560 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
          <div
            style={{
              width: 38,
              height: 38,
              borderRadius: 'var(--radius-md)',
              backgroundColor: 'var(--warning-bg)',
              color: 'var(--warning)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              flexShrink: 0,
            }}
          >
            <ShieldAlert size={20} />
          </div>
          <div>
            <h3 id="internet-confirm-title" style={{ fontSize: 'var(--text-lg)', fontWeight: 700, color: 'var(--ink)' }}>
              Xác nhận cấu hình Internet Egress
            </h3>
            <p style={{ fontSize: 'var(--text-xs)', color: 'var(--muted)' }}>
              Kiểm tra phạm vi ủy quyền và giới hạn an toàn trước khi gửi tới API.
            </p>
          </div>
        </div>

        <div
          role="alert"
          style={{
            padding: '10px 12px',
            backgroundColor: 'var(--warning-bg)',
            border: '1px solid var(--warning)',
            borderRadius: 'var(--radius-md)',
            color: 'var(--warning)',
            fontSize: 'var(--text-sm)',
            fontWeight: 600,
            display: 'flex',
            alignItems: 'center',
            gap: 8,
            marginBottom: 14,
          }}
        >
          <AlertTriangle size={18} style={{ flexShrink: 0 }} />
          <span>Quét chủ động ra internet — chỉ trên tài sản bạn sở hữu/được ủy quyền</span>
        </div>

        <div
          style={{
            padding: 12,
            backgroundColor: 'var(--subtle)',
            border: '1px solid var(--line)',
            borderRadius: 'var(--radius-md)',
            fontSize: 'var(--text-xs)',
            marginBottom: 14,
            display: 'flex',
            flexDirection: 'column',
            gap: 6,
          }}
        >
          <div style={{ fontWeight: 700, color: 'var(--ink)', marginBottom: 2 }}>
            Tóm tắt giới hạn an toàn (Caps &amp; RoE)
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between' }}>
            <span style={{ color: 'var(--muted)' }}>Profile mạng:</span>
            <strong className="mono">{policy.network_profile}</strong>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between' }}>
            <span style={{ color: 'var(--muted)' }}>Job đồng thời / Thời lượng tối đa:</span>
            <strong className="tabular">
              {policy.max_parallel_jobs} jobs / {policy.max_duration_hours} giờ
            </strong>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between' }}>
            <span style={{ color: 'var(--muted)' }}>Tốc độ tối đa / host:</span>
            <strong className="tabular">
              {policy.rate_limits?.requests_per_second_per_host ?? '—'} req/s
            </strong>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between' }}>
            <span style={{ color: 'var(--muted)' }}>Kết nối đồng thời tối đa / host:</span>
            <strong className="tabular">
              {policy.rate_limits?.max_concurrent_connections_per_host ?? '—'} kết nối
            </strong>
          </div>
          {policy.rate_limits?.packets_per_second !== undefined && (
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--muted)' }}>Gói tin / giây:</span>
              <strong className="tabular">{policy.rate_limits.packets_per_second} pps</strong>
            </div>
          )}
          {policy.rate_limits?.jobs_per_minute !== undefined && (
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--muted)' }}>Job / phút:</span>
              <strong className="tabular">{policy.rate_limits.jobs_per_minute} jobs/phút</strong>
            </div>
          )}
          {policy.budget && (
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--muted)' }}>Ngân sách / Chu kỳ rỗi:</span>
              <strong className="tabular">
                {policy.budget.max_jobs ?? '∞'} jobs, ${policy.budget.max_llm_cost_usd ?? '∞'}, idle{' '}
                {policy.budget.idle_cycles_before_pause}
              </strong>
            </div>
          )}
          {policy.authorization && (
            <div style={{ borderTop: '1px solid var(--line)', paddingTop: 6, marginTop: 2, display: 'flex', flexDirection: 'column', gap: 4 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}>
                <span style={{ color: 'var(--muted)' }}>Chủ sở hữu (authorization.owner):</span>
                <strong>{policy.authorization.owner}</strong>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}>
                <span style={{ color: 'var(--muted)' }}>Tham chiếu (authorization.reference):</span>
                <strong style={{ textAlign: 'right' }}>{policy.authorization.reference}</strong>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}>
                <span style={{ color: 'var(--muted)' }}>Ngày ủy quyền:</span>
                <strong className="tabular">{policy.authorization.date}</strong>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}>
                <span style={{ color: 'var(--muted)' }}>Hậu tố tên miền được phép:</span>
                <strong className="mono" style={{ textAlign: 'right' }}>
                  {policy.authorization.authorized_suffixes.join(', ')}
                </strong>
              </div>
            </div>
          )}
          {authorizationLabel !== undefined && (
            <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}>
              <span style={{ color: 'var(--muted)' }}>Tham chiếu ủy quyền (labels.authorization):</span>
              <strong className="mono" style={{ textAlign: 'right' }}>
                {authorizationLabel.trim() || 'Chưa khai báo'}
              </strong>
            </div>
          )}
          {reason && (
            <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}>
              <span style={{ color: 'var(--muted)' }}>Lý do cập nhật:</span>
              <span style={{ textAlign: 'right', color: 'var(--ink)' }}>{reason}</span>
            </div>
          )}
          {allTargets.length > 0 && (
            <div style={{ borderTop: '1px solid var(--line)', paddingTop: 6, marginTop: 2 }}>
              <span style={{ color: 'var(--muted)', display: 'block', marginBottom: 4 }}>
                Mục tiêu ({allTargets.length}):
              </span>
              <div className="mono" style={{ maxHeight: 84, overflowY: 'auto', color: 'var(--ink)' }}>
                {allTargets.join(', ')}
              </div>
            </div>
          )}
        </div>

        <label
          style={{
            display: 'flex',
            alignItems: 'flex-start',
            gap: 8,
            fontSize: 'var(--text-xs)',
            color: 'var(--ink)',
            marginBottom: 16,
            cursor: 'pointer',
          }}
        >
          <input
            type="checkbox"
            checked={acknowledged}
            disabled={submitting}
            onChange={(e) => setAcknowledged(e.target.checked)}
            style={{ marginTop: 2 }}
          />
          <span>
            Tôi xác nhận các mục tiêu trên thuộc tài sản tôi sở hữu hoặc đã được ủy quyền hợp pháp và chấp nhận các giới hạn tốc độ đã khai báo.
          </span>
        </label>

        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
          <button
            type="button"
            className="btn"
            disabled={submitting}
            onClick={() => {
              setAcknowledged(false);
              onCancel();
            }}
          >
            Quay lại chỉnh sửa
          </button>
          <button
            type="button"
            className="btn btn-warning"
            disabled={submitting || !acknowledged}
            onClick={onConfirm}
          >
            {submitting ? 'Đang gửi yêu cầu...' : 'Xác nhận & Thực thi'}
          </button>
        </div>
      </div>
    </div>
  );
};
