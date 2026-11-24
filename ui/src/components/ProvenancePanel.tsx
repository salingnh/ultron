import React from 'react';
import { ShieldCheck, X, FileText } from 'lucide-react';
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

      {data.tool && (
        <div className="provenance-item">
          <span className="provenance-label">Công cụ / Năng lực (Tool / Capability)</span>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span style={{ fontWeight: 600, color: 'var(--ink)' }}>{data.tool}</span>
            {data.version && <span className="brand-badge">{data.version}</span>}
            {data.adapterVersion && <span className="brand-badge">adapter {data.adapterVersion}</span>}
          </div>
        </div>
      )}

      {data.jobId && (
        <div className="provenance-item">
          <span className="provenance-label">Job tạo ra (Job ID / Scan ID)</span>
          <div style={{ maxWidth: '100%' }}>
            <CopyableId value={data.jobId} truncate={false} />
          </div>
        </div>
      )}

      {data.sourceAsset && (
        <div className="provenance-item">
          <span className="provenance-label">Tài sản nguồn (Source Asset)</span>
          <div style={{ maxWidth: '100%' }}>
            <CopyableId value={data.sourceAsset} truncate={false} />
          </div>
        </div>
      )}

      {data.targetAsset && (
        <div className="provenance-item">
          <span className="provenance-label">Tài sản đích (Target Asset)</span>
          <div style={{ maxWidth: '100%' }}>
            <CopyableId value={data.targetAsset} truncate={false} />
          </div>
        </div>
      )}

      {data.predicate && (
        <div className="provenance-item">
          <span className="provenance-label">Vị từ & Trạng thái (Predicate & Polarity)</span>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span className="mono" style={{ fontSize: 'var(--text-xs)', color: 'var(--ink)' }}>{data.predicate}</span>
            {data.polarity && <span className="brand-badge">{data.polarity}</span>}
          </div>
        </div>
      )}

      {data.observedAt && (
        <div className="provenance-item">
          <span className="provenance-label">Thời điểm quan sát (Observed At)</span>
          <span className="mono" style={{ fontSize: 'var(--text-sm)', color: 'var(--ink)' }}>
            {new Date(data.observedAt).toLocaleString('vi-VN')}
          </span>
        </div>
      )}

      {typeof data.confidence === 'number' && (
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
      )}

      {data.evidenceIds && data.evidenceIds.length > 0 && (
        <div className="provenance-item">
          <span className="provenance-label">Mã bằng chứng (Evidence ID)</span>
          <div style={{ marginTop: 2, maxWidth: '100%' }}>
            <CopyableId value={data.evidenceIds[0]} truncate={false} />
          </div>
        </div>
      )}

      {data.sha256 && (
        <div className="provenance-item">
          <span className="provenance-label">Bằng chứng SHA-256 (Evidence SHA-256)</span>
          <div style={{ marginTop: 2, maxWidth: '100%' }}>
            <CopyableId value={data.sha256} truncate={false} />
          </div>
        </div>
      )}

      {data.evidenceUri && (
        <div className="provenance-item">
          <span className="provenance-label">URI Bằng chứng (Storage URI)</span>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, maxWidth: '100%' }}>
            <FileText size={14} style={{ color: 'var(--muted)', flexShrink: 0 }} />
            <span className="mono" style={{ fontSize: '12px', wordBreak: 'break-all', overflowWrap: 'anywhere' }}>
              {data.evidenceUri}
            </span>
          </div>
        </div>
      )}

      {!data.tool && !data.jobId && !data.sha256 && !(data.evidenceIds && data.evidenceIds.length > 0) && (
        <div className="provenance-item" style={{ color: 'var(--muted)', fontSize: 'var(--text-xs)' }}>
          Chưa có quan sát ghi nhận từ công cụ (No tool observations recorded)
        </div>
      )}
    </aside>
  );
};
