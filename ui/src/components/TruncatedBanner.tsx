import React from 'react';
import { AlertTriangle } from 'lucide-react';

interface TruncatedBannerProps {
  truncated?: boolean;
  limitsApplied?: {
    max_hops?: number;
    limit?: number;
    timeout_ms?: number;
  };
  customMessage?: string;
}

export const TruncatedBanner: React.FC<TruncatedBannerProps> = ({
  truncated,
  limitsApplied,
  customMessage,
}) => {
  if (!truncated && !limitsApplied) return null;

  return (
    <div className="truncated-banner" role="alert">
      <AlertTriangle size={18} style={{ flexShrink: 0 }} />
      <div style={{ flex: 1 }}>
        <strong>Dữ liệu đồ thị bị giới hạn:</strong>{' '}
        {customMessage ||
          'Kết quả truy vấn đã được cắt bớt để đảm bảo hiệu năng và giới hạn hợp đồng. Đồ thị không thể hiện toàn bộ tập tài sản.'}
        {limitsApplied && (
          <span style={{ marginLeft: 8, fontFamily: 'var(--font-mono)', fontSize: '11.5px' }}>
            [Áp dụng: Giới hạn {limitsApplied.limit || 50} node, tối đa {limitsApplied.max_hops || 1} bước nhảy
            {limitsApplied.timeout_ms ? `, hết hạn ${limitsApplied.timeout_ms}ms` : ''}]
          </span>
        )}
      </div>
    </div>
  );
};
