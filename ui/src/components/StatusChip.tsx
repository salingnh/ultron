import React from 'react';
import type { JobStatus, CampaignStatus, ProviderHealth } from '../api/types';

interface StatusChipProps {
  status: JobStatus | CampaignStatus | ProviderHealth | string;
  kind?: 'job' | 'campaign' | 'health';
  size?: 'sm' | 'md';
}

const statusConfig: Record<string, { label: string; variant: 'success' | 'warning' | 'accent' | 'danger' | 'neutral' }> = {
  // JobStatus
  QUEUED: { label: 'Đang chờ (Queued)', variant: 'neutral' },
  VALIDATING: { label: 'Kiểm định (Validating)', variant: 'accent' },
  DISPATCHED: { label: 'Đã điều phối (Dispatched)', variant: 'accent' },
  RUNNING: { label: 'Đang chạy (Running)', variant: 'accent' },
  COLLECTING: { label: 'Thu thập (Collecting)', variant: 'accent' },
  SUCCEEDED: { label: 'Thành công (Succeeded)', variant: 'success' },
  FAILED: { label: 'Thất bại (Failed)', variant: 'danger' },
  CANCELLED: { label: 'Đã hủy (Cancelled)', variant: 'warning' },

  // CampaignStatus
  CREATED: { label: 'Khởi tạo (Created)', variant: 'neutral' },
  WAITING: { label: 'Đang chờ (Waiting)', variant: 'warning' },
  PAUSED: { label: 'Tạm dừng (Paused)', variant: 'warning' },
  COMPLETED: { label: 'Hoàn thành (Completed)', variant: 'success' },

  // Health
  healthy: { label: 'Khỏe mạnh (Healthy)', variant: 'success' },
  degraded: { label: 'Suy giảm (Degraded)', variant: 'warning' },
  unavailable: { label: 'Không khả dụng', variant: 'danger' },
};

export const StatusChip: React.FC<StatusChipProps> = ({ status, size = 'sm' }) => {
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
