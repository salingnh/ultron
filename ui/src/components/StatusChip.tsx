import React from 'react';
import type { JobStatus, CampaignStatus, ProviderHealth, WaitReason } from '../api/types';

interface StatusChipProps {
  status: JobStatus | CampaignStatus | ProviderHealth | string;
  waitReason?: WaitReason | { code: string; detail?: string } | null;
  kind?: 'job' | 'campaign' | 'health';
  size?: 'sm' | 'md';
}

const waitReasonLabels: Record<string, string> = {
  DEPENDENCY_PENDING: 'Chờ phụ thuộc (DEPENDENCY_PENDING)',
  DEPENDENCY_FAILED: 'Phụ thuộc thất bại (DEPENDENCY_FAILED)',
  CAMPAIGN_PAUSED: 'Chiến dịch tạm dừng (CAMPAIGN_PAUSED)',
  BUDGET_EXHAUSTED: 'Hết ngân sách (BUDGET_EXHAUSTED)',
  WINDOW_CLOSED: 'Ngoài khung giờ (WINDOW_CLOSED)',
  RATE_LIMITED: 'Giới hạn tốc độ (RATE_LIMITED)',
  CONCURRENCY_LIMIT: 'Giới hạn đồng thời (CONCURRENCY_LIMIT)',
};

const statusConfig: Record<string, { label: string; variant: 'success' | 'warning' | 'accent' | 'danger' | 'neutral' }> = {
  // JobStatus (job.v2.schema.json: QUEUED, VALIDATING, DISPATCHED, RUNNING, COLLECTING, SUCCEEDED, FAILED, CANCELLED)
  QUEUED: { label: 'Đang chờ (Queued)', variant: 'neutral' },
  VALIDATING: { label: 'Kiểm định (Validating)', variant: 'accent' },
  DISPATCHED: { label: 'Đã điều phối (Dispatched)', variant: 'accent' },
  RUNNING: { label: 'Đang chạy (Running)', variant: 'accent' },
  COLLECTING: { label: 'Thu thập (Collecting)', variant: 'accent' },
  SUCCEEDED: { label: 'Thành công (Succeeded)', variant: 'success' },
  FAILED: { label: 'Thất bại (Failed)', variant: 'danger' },
  CANCELLED: { label: 'Đã hủy (Cancelled)', variant: 'warning' },

  // CampaignStatus (campaign.v2.schema.json: CREATED, RUNNING, WAITING, PAUSED, COMPLETED, FAILED, CANCELLED)
  CREATED: { label: 'Khởi tạo (Created)', variant: 'neutral' },
  PAUSED: { label: 'Tạm dừng (Paused)', variant: 'warning' },
  COMPLETED: { label: 'Hoàn thành (Completed)', variant: 'success' },
  WAITING: { label: 'Đang chờ duyệt (Waiting)', variant: 'warning' },

  // Health
  healthy: { label: 'Khỏe mạnh (Healthy)', variant: 'success' },
  degraded: { label: 'Suy giảm (Degraded)', variant: 'warning' },
  unavailable: { label: 'Không khả dụng', variant: 'danger' },
};

export const StatusChip: React.FC<StatusChipProps> = ({ status, waitReason, size = 'sm' }) => {
  // If job is QUEUED and has a wait_reason, map from contract values without inventing status values
  if (status === 'QUEUED' && waitReason) {
    const label = waitReasonLabels[waitReason.code] || `Đang chờ: ${waitReason.code}`;
    const style: React.CSSProperties = {
      fontSize: size === 'sm' ? 'var(--text-xs)' : 'var(--text-sm)',
      padding: size === 'sm' ? '2px 8px' : '4px 10px',
    };
    return (
      <span className="status-chip warning" style={style} title={waitReason.detail || label}>
        <span
          style={{
            width: 6,
            height: 6,
            borderRadius: '50%',
            backgroundColor: 'currentColor',
            display: 'inline-block',
          }}
        />
        {label}
      </span>
    );
  }

  const config = statusConfig[status] || {
    label: status,
    variant: 'neutral' as const,
  };

  const style: React.CSSProperties = {
    fontSize: size === 'sm' ? 'var(--text-xs)' : 'var(--text-sm)',
    padding: size === 'sm' ? '2px 8px' : '4px 10px',
  };

  return (
    <span className={`status-chip ${config.variant}`} style={style}>
      <span
        style={{
          width: 6,
          height: 6,
          borderRadius: '50%',
          backgroundColor: 'currentColor',
          display: 'inline-block',
        }}
      />
      {config.label}
    </span>
  );
};
