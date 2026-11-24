import React from 'react';
import type { JobStatus, CampaignStatus, ProviderHealth } from '../api/types';

interface StatusChipProps {
  status: JobStatus | CampaignStatus | ProviderHealth | string;
  kind?: 'job' | 'campaign' | 'health';
  size?: 'sm' | 'md';
}

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

  // Flow Decision status
  approved: { label: 'Đã duyệt (Approved)', variant: 'success' },
  rejected: { label: 'Từ chối (Rejected)', variant: 'danger' },

  // Health (G1.5a M05 manifest registry contract: healthy = manifest re-admittable + pin match)
  healthy: { label: 'Khớp Manifest (Healthy)', variant: 'success' },
  degraded: { label: 'Suy giảm (Degraded)', variant: 'warning' },
  unavailable: { label: 'Không khả dụng', variant: 'danger' },
};

const healthTooltips: Record<string, string> = {
  healthy: 'healthy = manifest re-admittable + pin match (not a runtime probe)',
  degraded: 'degraded: manifest suy giảm hoặc không thể đọc lại đầy đủ',
  unavailable: 'unavailable: không đọc lại được manifest hoặc không khớp pin',
};

export const StatusChip: React.FC<StatusChipProps> = ({ status, kind, size = 'sm' }) => {
  const config = statusConfig[status] || {
    label: status,
    variant: 'neutral' as const,
  };

  const tooltip = (kind === 'health' || status in healthTooltips)
    ? (healthTooltips[status] || config.label)
    : config.label;

  const style: React.CSSProperties = {
    fontSize: size === 'sm' ? 'var(--text-xs)' : 'var(--text-sm)',
    padding: size === 'sm' ? '2px 8px' : '4px 10px',
  };

  return (
    <span className={`status-chip ${config.variant}`} style={style} title={tooltip}>
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
