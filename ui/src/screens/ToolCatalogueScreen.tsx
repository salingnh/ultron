import React, { useEffect, useState, useCallback } from 'react';
import {
  Wrench,
  Shield,
  FileCode,
  Box,
  Filter,
  CheckCircle2,
} from 'lucide-react';
import { apiClient, toUiError } from '../api/client';
import type { CapabilityItem, Campaign, UiError } from '../api/types';
import { StatusChip } from '../components/StatusChip';
import { ErrorDisplay } from '../components/ErrorDisplay';

export const ToolCatalogueScreen: React.FC = () => {
  const [capabilities, setCapabilities] = useState<CapabilityItem[]>([]);
  const [campaigns, setCampaigns] = useState<Campaign[]>([]);
  const [selectedCampaignId, setSelectedCampaignId] = useState<string>('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<UiError | null>(null);

  const loadCapabilities = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await apiClient.listCapabilities(selectedCampaignId || undefined);
      setCapabilities(res.items);
    } catch (err: unknown) {
      const path = selectedCampaignId
        ? `/capabilities?campaign_id=${encodeURIComponent(selectedCampaignId)}`
        : '/capabilities';
      setError(toUiError(err, path));
    } finally {
      setLoading(false);
    }
  }, [selectedCampaignId]);

  useEffect(() => {
    loadCapabilities();
  }, [loadCapabilities]);

  // Load campaigns for RoE denylist filter dropdown
  useEffect(() => {
    let mounted = true;
    apiClient
      .listCampaigns()
      .then((res) => {
        if (mounted) setCampaigns(res.items);
      })
      .catch(() => {
        // non-blocking
      });
    return () => {
      mounted = false;
    };
  }, []);

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

        <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
          {/* Campaign RoE Denylist filter */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <Filter size={14} style={{ color: 'var(--muted)' }} />
            <label htmlFor="campaign-filter" style={{ fontSize: 'var(--text-xs)', color: 'var(--muted)', fontWeight: 600 }}>
              Lọc theo RoE:
            </label>
            <select
              id="campaign-filter"
              value={selectedCampaignId}
              onChange={(e) => setSelectedCampaignId(e.target.value)}
              style={{
                fontSize: 'var(--text-xs)',
                padding: '4px 8px',
                borderRadius: 'var(--radius-sm)',
                backgroundColor: 'var(--surface)',
                border: '1px solid var(--line)',
                color: 'var(--ink)',
              }}
            >
              <option value="">Tất cả (Không lọc)</option>
              {campaigns.map((c) => (
                <option key={c.campaign_id} value={c.campaign_id}>
                  {c.name} ({c.status})
                </option>
              ))}
            </select>
          </div>

          <span className="brand-badge" style={{ backgroundColor: 'var(--accent-bg)', color: 'var(--accent)' }}>
            M05 Registry Validated (GET /capabilities)
          </span>
        </div>
      </div>

      {error && <ErrorDisplay error={error} onRetry={loadCapabilities} />}

      {loading ? (
        <div className="state-box">
          <div className="state-title">Đang nạp danh mục công cụ...</div>
        </div>
      ) : capabilities.length === 0 ? (
        <div className="state-box" style={{ marginTop: 24, padding: '40px 24px' }}>
          <Wrench size={40} style={{ color: 'var(--muted)', marginBottom: 12 }} />
          <div className="state-title" style={{ fontSize: 'var(--text-base)', marginBottom: 6 }}>
            Không có capability nào phù hợp
          </div>
          <div className="state-desc" style={{ maxWidth: 500, margin: '0 auto', fontSize: 'var(--text-xs)' }}>
            {selectedCampaignId
              ? 'Chiến dịch được chọn có thể đã cấm các capability qua capability_denylist trong RoE, hoặc chưa có công cụ nào được đăng ký trong Registry M05.'
              : 'Hiện chưa có manifest công cụ nào được tiếp nhận vào Registry M05.'}
          </div>
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

                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <CheckCircle2 size={14} style={{ color: 'var(--success)' }} />
                  <span className="brand-badge" style={{ fontSize: '11px' }}>
                    {item.providers.length} Provider
                  </span>
                </div>
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
                      <StatusChip status={p.health} kind="health" />
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
