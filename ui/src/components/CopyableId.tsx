import React, { useState } from 'react';
import { Copy, Check } from 'lucide-react';

interface CopyableIdProps {
  value: string;
  truncate?: boolean;
  prefix?: string;
  className?: string;
}

export const CopyableId: React.FC<CopyableIdProps> = ({ value, truncate = true, prefix, className = '' }) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = (e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(value);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const displayValue = truncate && value.length > 20
    ? `${value.substring(0, 10)}...${value.substring(value.length - 8)}`
    : value;

  return (
    <span className={`copyable-field ${className}`} title={value}>
      {prefix && <span style={{ color: 'var(--muted)', marginRight: 2 }}>{prefix}:</span>}
      <span className="mono">{displayValue}</span>
      <button
        type="button"
        onClick={handleCopy}
        className="copy-btn"
        title={copied ? 'Đã sao chép!' : 'Sao chép giá trị đầy đủ'}
        aria-label="Sao chép"
      >
        {copied ? <Check size={12} style={{ color: 'var(--success)' }} /> : <Copy size={12} />}
      </button>
    </span>
  );
};
