import React from 'react';
import { ShieldCheck, X, FileText, CheckCircle2 } from 'lucide-react';
import type { ProvenanceDetail } from '../api/types';
import { CopyableId } from './CopyableId';

interface ProvenancePanelProps {
  data: ProvenanceDetail | null;
  onClose: () => void;
}

export const ProvenancePanel: React.FC<ProvenancePanelProps> = ({ data, onClose }) => {
  if (!data) return null;

  return (
    <aside className="provenance-panel" aria-label="Bảng điều khiển nguồn gốc">
      <div className="provenance-header">
        <div className="provenance-title">
          <ShieldCheck size={18} style={{ color: 'var(--accent)' }} />
          <span>Nguồn gốc & Bằng chứng</span>
        </div>
        <button
          type="button"
          onClick={onClose}
          className="btn btn-sm"
          style={{ padding: '2px 6px', border: 'none', background: 'transparent' }}
          aria-label="Đóng bảng nguồn gốc"
        >
          <X size={16} />
        </button>
      </div>

      <div className="provenance-item">
        <span className="provenance-label">Công cụ & Phiên bản (Tool/Version)</span>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <span style={{ fontWeight: 600, color: 'var(--ink)' }}>{data.tool}</span>
          <span className="brand-badge">{data.version}</span>
          {data.adapterVersion && <span className="brand-badge">adapter {data.adapterVersion}</span>}
        </div>
      </div>

      <div className="provenance-item">
        <span className="provenance-label">Job tạo ra (Job ID)</span>
        <CopyableId value={data.jobId} truncate={false} />
      </div>

      {data.sourceAsset && (
        <div className="provenance-item">
          <span className="provenance-label">Tài sản nguồn (Source Asset)</span>
          <CopyableId value={data.sourceAsset} truncate={false} />
        </div>
      )}

      {data.targetAsset && (
        <div className="provenance-item">
          <span className="provenance-label">Tài sản đích (Target Asset)</span>
          <CopyableId value={data.targetAsset} truncate={false} />
        </div>
      )}

      <div className="provenance-item">
        <span className="provenance-label">Thời điểm quan sát (Observed At)</span>
        <span className="mono" style={{ fontSize: 'var(--text-sm)', color: 'var(--ink)' }}>
          {new Date(data.observedAt).toLocaleString('vi-VN')}
        </span>
      </div>

      <div className="provenance-item">
        <span className="provenance-label">Độ tin cậy (Confidence)</span>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <div
            style={{
              flex: 1,
              height: 8,
              backgroundColor: 'var(--subtle)',
              borderRadius: 'var(--radius-sm)',
              overflow: 'hidden',
              border: '1px solid var(--line)',
            }}
          >
            <div
              style={{
                width: `${data.confidence * 100}%`,
                height: '100%',
                backgroundColor: data.confidence >= 0.8 ? 'var(--success)' : 'var(--warning)',
              }}
            />
          </div>
          <span className="mono" style={{ fontSize: 'var(--text-xs)', fontWeight: 600 }}>
            {(data.confidence * 100).toFixed(0)}%
          </span>
        </div>
      </div>

      <div className="provenance-item">
        <span className="provenance-label">Bằng chứng SHA-256 (Evidence SHA-256)</span>
        <div style={{ marginTop: 2 }}>
          <CopyableId value={data.sha256} truncate={false} />
        </div>
        <span style={{ fontSize: '11.5px', color: 'var(--muted)', marginTop: 4 }}>
          Giá trị hash đầy đủ (unmasked) xác thực kết quả thực thi theo AGENTS & DESIGN.
        </span>
      </div>

      {data.evidenceUri && (
        <div className="provenance-item">
          <span className="provenance-label">URI Bằng chứng (Storage URI)</span>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <FileText size={14} style={{ color: 'var(--muted)' }} />
            <span className="mono" style={{ fontSize: '12px', wordBreak: 'break-all' }}>
              {data.evidenceUri}
            </span>
          </div>
        </div>
      )}

      <div
        style={{
          marginTop: 10,
          padding: 10,
          backgroundColor: 'var(--subtle)',
          borderRadius: 'var(--radius-md)',
          fontSize: 'var(--text-xs)',
          color: 'var(--muted)',
          display: 'flex',
          gap: 6,
        }}
      >
        <CheckCircle2 size={16} style={{ color: 'var(--success)', flexShrink: 0 }} />
        <span>Kết quả đã qua kiểm định chữ ký ApprovedTask và xác thực phong bì ResultEnvelope.</span>
      </div>
    </aside>
  );
};
