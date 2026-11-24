import React, { useEffect, useState } from 'react';
import {
  Wrench,
  Shield,
  FileCode,
  Box,
} from 'lucide-react';
import { apiClient } from '../api/client';
import type { CapabilityItem } from '../api/types';
import { StatusChip } from '../components/StatusChip';
import { ErrorDisplay } from '../components/ErrorDisplay';

export const ToolCatalogueScreen: React.FC = () => {
  const [capabilities, setCapabilities] = useState<CapabilityItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadCapabilities();
  }, []);

  const loadCapabilities = async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await apiClient.listCapabilities();
      setCapabilities(res.items);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Không thể nạp danh mục công cụ');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <div className="filter-bar">
        <div>
          <h1 style={{ fontSize: 'var(--text-xl)', fontWeight: 700, color: 'var(--ink)' }}>
            Danh mục Công cụ & Bộ điều hợp (Tool Catalogue)
          </h1>
          <p style={{ fontSize: 'var(--text-sm)', color: 'var(--muted)', marginTop: 2 }}>
            Đăng ký năng lực (Capabilities Registry M05), bộ điều hợp (Adapters), phiên bản và trạng thái sức khỏe vận hành.
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span className="brand-badge" style={{ backgroundColor: 'var(--accent-bg)', color: 'var(--accent)' }}>
            G1 Foundation Tools: Subfinder, DNSx
          </span>
        </div>
      </div>

      {error && <ErrorDisplay error={error} onRetry={loadCapabilities} />}

      {loading ? (
        <div className="state-box">
          <div className="state-title">Đang nạp danh mục công cụ...</div>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {/* Card list of capabilities */}
          {capabilities.map((item) => (
            <div key={item.capability} className="card">
              <div className="card-header" style={{ marginBottom: 10 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <div
                    style={{
                      width: 36,
                      height: 36,
                      borderRadius: 'var(--radius-md)',
                      backgroundColor: 'var(--accent-bg)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      color: 'var(--accent)',
                    }}
                  >
                    <Wrench size={18} />
                  </div>
                  <div>
                    <h2 style={{ fontSize: 'var(--text-base)', fontWeight: 700, color: 'var(--ink)' }}>
                      {item.capability}
                    </h2>
                    {item.input_schema_ref && (
                      <div style={{ display: 'flex', alignItems: 'center', gap: 4, marginTop: 2 }}>
                        <FileCode size={12} style={{ color: 'var(--muted)' }} />
                        <span className="mono" style={{ fontSize: '11.5px', color: 'var(--muted)' }}>
                          Hợp đồng: {item.input_schema_ref}
                        </span>
                      </div>
                    )}
                  </div>
                </div>

                <span className="brand-badge">M05 Registry Validated</span>
              </div>

              {/* Providers under this capability */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 12 }}>
                {item.providers.map((p) => (
                  <div
                    key={p.name}
                    style={{
                      padding: 12,
                      borderRadius: 'var(--radius-md)',
                      backgroundColor: 'var(--subtle)',
                      border: '1px solid var(--line)',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: 8,
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                        <Box size={16} style={{ color: 'var(--accent)' }} />
                        <strong style={{ fontSize: 'var(--text-sm)', color: 'var(--ink)' }}>{p.name}</strong>
                        <span className="brand-badge">{p.version}</span>
                      </div>
                      <StatusChip status={p.health} />
                    </div>

                    {p.module && (
                      <div style={{ fontSize: 'var(--text-xs)' }}>
                        <span style={{ color: 'var(--muted)' }}>Điểm vào (Entrypoint): </span>
                        <code className="mono" style={{ color: 'var(--ink)', backgroundColor: 'var(--surface)', padding: '2px 4px', borderRadius: 3 }}>
                          {p.module}
                        </code>
                      </div>
                    )}

                    {/* Sandbox specs per G0.2 / AGENTS */}
                    <div
                      style={{
                        padding: '6px 8px',
                        backgroundColor: 'var(--surface)',
                        borderRadius: 'var(--radius-sm)',
                        border: '1px solid var(--line)',
                        fontSize: '11px',
                        display: 'flex',
                        flexDirection: 'column',
                        gap: 2,
                        color: 'var(--muted)',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: 4, fontWeight: 600, color: 'var(--ink)' }}>
                        <Shield size={12} style={{ color: 'var(--success)' }} />
                        <span>Môi trường Sandbox Podman (G0.2):</span>
                      </div>
                      <div>• Quyền hạn: cap-drop ALL, no-new-privileges, rootless</div>
                      <div>• Mạng: Cách ly hạ tầng điều khiển/dữ liệu, chặn loopback/link-local</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
