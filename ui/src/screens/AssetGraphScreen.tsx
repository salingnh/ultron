import React, { useEffect, useState, useCallback } from 'react';
import {
  Network,
  Table as TableIcon,
  Search,
  Globe,
  Server,
  Shield,
  Info,
} from 'lucide-react';
import { apiClient } from '../api/client';
import type {
  Asset,
  AssetGraphResponse,
  AssetGraphNode,
  AssetGraphEdge,
  ProvenanceDetail,
} from '../api/types';
import { TruncatedBanner } from '../components/TruncatedBanner';
import { ProvenancePanel } from '../components/ProvenancePanel';
import { CopyableId } from '../components/CopyableId';
import { ErrorDisplay } from '../components/ErrorDisplay';

export const AssetGraphScreen: React.FC = () => {
  const [viewMode, setViewMode] = useState<'graph' | 'table'>('graph');
  const [graphData, setGraphData] = useState<AssetGraphResponse | null>(null);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [kindFilter, setKindFilter] = useState('ALL');

  // Selected item for Provenance Panel
  const [selectedItem, setSelectedItem] = useState<{ id: string; type: 'node' | 'edge' } | null>(null);
  const [provenanceData, setProvenanceData] = useState<ProvenanceDetail | null>(null);

  const handleSelectNode = useCallback(async (node: AssetGraphNode) => {
    setSelectedItem({ id: node.asset_id, type: 'node' });
    const prov = await apiClient.getProvenance(node.asset_id);
    setProvenanceData(prov);
  }, []);

  const handleSelectEdge = useCallback(async (edge: AssetGraphEdge) => {
    const edgeKey = `edge-${edge.from}-${edge.to}`;
    setSelectedItem({ id: edgeKey, type: 'edge' });
    const prov = await apiClient.getProvenance(edgeKey);
    setProvenanceData(
      prov || {
        tool: 'dnsx',
        version: 'v1.2.3',
        jobId: edge.source_job_id,
        observedAt: edge.observed_at || new Date().toISOString(),
        confidence: edge.confidence,
        sha256: 'c40410bc4028e0f824a02514e702e70dfe0e5f67fbcf250803c7403d1da8ca57',
        sourceAsset: edge.from,
        targetAsset: edge.to,
      }
    );
  }, []);

  const loadData = useCallback(async () => {
    if (!apiClient.isMock) {
      setLoading(false);
      return;
    }
    try {
      setLoading(true);
      setError(null);
      const [assetsRes, graphRes] = await Promise.all([
        apiClient.listAssets({
          kind: kindFilter !== 'ALL' ? kindFilter : undefined,
          q: searchQuery || undefined,
        }),
        apiClient.getAssetGraph('01934f6a-0000-7000-8000-0000000000f1', {
          campaign_id: '01934f6a-0000-7000-8000-000000000001',
          max_hops: 1,
          limit: 50,
        }),
      ]);
      setAssets(assetsRes.items);
      setGraphData(graphRes);
      // Auto select the first node to showcase the provenance panel initially
      if (graphRes.nodes.length > 0 && !selectedItem) {
        handleSelectNode(graphRes.nodes[0]);
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Không thể tải đồ thị tài sản');
    } finally {
      setLoading(false);
    }
  }, [kindFilter, searchQuery, selectedItem, handleSelectNode]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  if (!apiClient.isMock) {
    return (
      <div>
        <div className="filter-bar">
          <div>
            <h1 style={{ fontSize: 'var(--text-xl)', fontWeight: 700, color: 'var(--ink)' }}>
              Đồ thị Tri thức & Nguồn gốc Tài sản
            </h1>
            <p style={{ fontSize: 'var(--text-sm)', color: 'var(--muted)', marginTop: 2 }}>
              Khảo sát quan hệ giữa các tài sản số. Nhấp vào bất kỳ Node hoặc Edge để mở bảng điều khiển nguồn gốc & bằng chứng SHA-256.
            </p>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span className="status-chip warning" style={{ fontSize: '11px', padding: '2px 8px' }}>
              Chưa có API (Đang chờ G1.4b)
            </span>
          </div>
        </div>

        <div className="state-box" style={{ marginTop: 32, padding: '48px 24px' }}>
          <Network size={44} style={{ color: 'var(--muted)', marginBottom: 14 }} />
          <div className="state-title" style={{ fontSize: 'var(--text-lg)', marginBottom: 6 }}>
            Chưa có API backend cho Đồ thị Tài sản
          </div>
          <div className="state-desc" style={{ maxWidth: 540, margin: '0 auto', lineHeight: 1.6 }}>
            Endpoint <code>/assets</code> và đồ thị tri thức quan hệ tài sản đang thuộc kế hoạch phát triển của thẻ G1.4b.
            Trong chế độ Real API, giao diện tuân thủ nguyên tắc trung thực dữ liệu (Data Honesty), không hiển thị dữ liệu giả lập (mock).
          </div>
        </div>
      </div>
    );
  }

  return (
    <div>
      <div className="filter-bar">
        <div>
          <h1 style={{ fontSize: 'var(--text-xl)', fontWeight: 700, color: 'var(--ink)' }}>
            Đồ thị Tri thức & Nguồn gốc Tài sản
          </h1>
          <p style={{ fontSize: 'var(--text-sm)', color: 'var(--muted)', marginTop: 2 }}>
            Khảo sát quan hệ giữa các tài sản số. Nhấp vào bất kỳ Node hoặc Edge để mở bảng điều khiển nguồn gốc & bằng chứng SHA-256.
          </p>
        </div>

        <div className="filter-group">
          {/* Switcher */}
          <div
            style={{
              display: 'flex',
              backgroundColor: 'var(--subtle)',
              padding: 2,
              borderRadius: 'var(--radius-md)',
              border: '1px solid var(--line)',
            }}
          >
            <button
              type="button"
              className={`btn btn-sm ${viewMode === 'graph' ? 'btn-primary' : ''}`}
              style={{ border: 'none' }}
              onClick={() => setViewMode('graph')}
            >
              <Network size={14} /> Đồ thị (Graph)
            </button>
            <button
              type="button"
              className={`btn btn-sm ${viewMode === 'table' ? 'btn-primary' : ''}`}
              style={{ border: 'none' }}
              onClick={() => setViewMode('table')}
            >
              <TableIcon size={14} /> Bảng Tài sản
            </button>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 6, position: 'relative' }}>
            <Search size={14} style={{ position: 'absolute', left: 10, color: 'var(--muted)' }} />
            <input
              type="text"
              className="input-search"
              style={{ paddingLeft: 30, minWidth: 220 }}
              placeholder="Tìm canonical key (dns:*, ip:*)..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && loadData()}
              aria-label="Tìm kiếm canonical key"
            />
          </div>

          <select
            className="input-search"
            style={{ minWidth: 140 }}
            value={kindFilter}
            onChange={(e) => setKindFilter(e.target.value)}
            aria-label="Lọc loại tài sản"
          >
            <option value="ALL">Tất cả loại (Kind)</option>
            <option value="domain">Tên miền (Domain)</option>
            <option value="ip">Địa chỉ IP</option>
          </select>
        </div>
      </div>

      {error && <ErrorDisplay error={error} onRetry={loadData} />}

      {/* Truncated banner when graph query is truncated */}
      {graphData?.truncated && (
        <TruncatedBanner
          truncated={graphData.truncated}
          limitsApplied={graphData.limits_applied}
          customMessage="Dữ liệu đồ thị tài sản đã được giới hạn số bước nhảy và số đỉnh theo hợp đồng MCP graph queries."
        />
      )}

      {loading ? (
        <div className="state-box">
          <div className="state-title">Đang nạp dữ liệu đồ thị tài sản...</div>
        </div>
      ) : (
        /* Main Layout: Graph/Table on left, ProvenancePanel on right */
        <div style={{ display: 'flex', gap: 16, alignItems: 'flex-start' }}>
          <div style={{ flex: 1, minWidth: 0 }}>
            {viewMode === 'graph' ? (
              <div className="graph-container" style={{ height: 600 }}>
                {/* SVG-based interactive graph representation */}
                <svg width="100%" height="100%" viewBox="0 0 920 600" style={{ cursor: 'grab' }}>
                  <defs>
                    <marker
                      id="arrowhead"
                      markerWidth="8"
                      markerHeight="6"
                      refX="7"
                      refY="3"
                      orient="auto"
                    >
                      <polygon points="0 0, 8 3, 0 6" fill="var(--muted)" />
                    </marker>
                    <marker
                      id="arrowhead-active"
                      markerWidth="8"
                      markerHeight="6"
                      refX="7"
                      refY="3"
                      orient="auto"
                    >
                      <polygon points="0 0, 8 3, 0 6" fill="var(--accent)" />
                    </marker>
                  </defs>

                  {/* Edges */}
                  {graphData?.edges.map((edge, idx) => {
                    // Precomputed coordinates for pleasant graph layout
                    const coords: Record<string, { x: number; y: number }> = {
                      'dns:internal.example': { x: 460, y: 110 },
                      'dns:vpn.internal.example': { x: 190, y: 290 },
                      'ip:203.0.113.10': { x: 190, y: 470 },
                      'dns:app.internal.example': { x: 460, y: 320 },
                      'dns:auth.internal.example': { x: 730, y: 290 },
                    };

                    const fromPt = coords[edge.from] || { x: 200 + idx * 80, y: 200 };
                    const toPt = coords[edge.to] || { x: 460, y: 120 };

                    const edgeKey = `edge-${edge.from}-${edge.to}`;
                    const isSelected = selectedItem?.id === edgeKey;

                    const midX = (fromPt.x + toPt.x) / 2;
                    const midY = (fromPt.y + toPt.y) / 2;

                    return (
                      <g
                        key={edgeKey}
                        onClick={() => handleSelectEdge(edge)}
                        style={{ cursor: 'pointer' }}
                        role="button"
                        aria-label={`Cạnh ${edge.type} từ ${edge.from} tới ${edge.to}`}
                      >
                        <title>{`${edge.type}: ${edge.from} -> ${edge.to}`}</title>
                        <line
                          x1={fromPt.x}
                          y1={fromPt.y}
                          x2={toPt.x}
                          y2={toPt.y}
                          stroke={isSelected ? 'var(--accent)' : 'var(--line)'}
                          strokeWidth={isSelected ? 3 : 2}
                          markerEnd={isSelected ? 'url(#arrowhead-active)' : 'url(#arrowhead)'}
                        />
                        <rect
                          x={midX - 52}
                          y={midY - 10}
                          width={104}
                          height={20}
                          rx={4}
                          fill="var(--surface)"
                          stroke={isSelected ? 'var(--accent)' : 'var(--line)'}
                        />
                        <text
                          x={midX}
                          y={midY + 4}
                          textAnchor="middle"
                          fontSize="10"
                          fill={isSelected ? 'var(--accent)' : 'var(--muted)'}
                          fontWeight="600"
                        >
                          {edge.type}
                        </text>
                      </g>
                    );
                  })}

                  {/* Nodes */}
                  {graphData?.nodes.map((node, idx) => {
                    const coords: Record<string, { x: number; y: number }> = {
                      'dns:internal.example': { x: 460, y: 110 },
                      'dns:vpn.internal.example': { x: 190, y: 290 },
                      'ip:203.0.113.10': { x: 190, y: 470 },
                      'dns:app.internal.example': { x: 460, y: 320 },
                      'dns:auth.internal.example': { x: 730, y: 290 },
                    };

                    const pt = coords[node.canonical_key] || { x: 150 + idx * 140, y: 250 };
                    const isSelected = selectedItem?.id === node.asset_id;

                    const displayKey = node.canonical_key.length > 26
                      ? node.canonical_key.substring(0, 24) + '…'
                      : node.canonical_key;

                    return (
                      <g
                        key={node.asset_id}
                        transform={`translate(${pt.x - 115}, ${pt.y - 34})`}
                        onClick={() => handleSelectNode(node)}
                        style={{ cursor: 'pointer' }}
                        role="button"
                        aria-label={`Tài sản ${node.canonical_key}`}
                      >
                        <title>{`${node.canonical_key} (${node.asset_id})`}</title>
                        <rect
                          width={230}
                          height={68}
                          rx={8}
                          fill="var(--surface)"
                          stroke={isSelected ? 'var(--accent)' : 'var(--line)'}
                          strokeWidth={isSelected ? 2.5 : 1}
                          filter="drop-shadow(0px 2px 4px rgba(0,0,0,0.08))"
                        />
                        {/* Kind icon indicator */}
                        <circle
                          cx={22}
                          cy={22}
                          r={10}
                          fill={node.kind === 'domain' ? 'var(--accent-bg)' : 'var(--success-bg)'}
                        />
                        <text
                          x={22}
                          y={26}
                          textAnchor="middle"
                          fontSize="11"
                          fontWeight="bold"
                          fill={node.kind === 'domain' ? 'var(--accent)' : 'var(--success)'}
                        >
                          {node.kind === 'domain' ? 'D' : 'IP'}
                        </text>

                        {/* Canonical key */}
                        <text
                          x={40}
                          y={26}
                          fontSize="11"
                          fontWeight="600"
                          fontFamily="var(--font-mono)"
                          fill="var(--ink)"
                        >
                          <title>{node.canonical_key}</title>
                          {displayKey}
                        </text>

                        {/* Kind label */}
                        <text x={20} y={50} fontSize="10" fill="var(--muted)">
                          Loại: <tspan fontWeight="bold">{node.kind}</tspan>
                        </text>

                        {/* Exposure badge */}
                        <rect
                          x={110}
                          y={40}
                          width={58}
                          height={18}
                          rx={3}
                          fill="var(--subtle)"
                          stroke="var(--line)"
                        />
                        <text
                          x={139}
                          y={53}
                          fontSize="9.5"
                          textAnchor="middle"
                          fill="var(--ink)"
                          fontWeight="500"
                        >
                          internal
                        </text>
                      </g>
                    );
                  })}
                </svg>

                <div
                  style={{
                    position: 'absolute',
                    bottom: 12,
                    left: 12,
                    backgroundColor: 'var(--surface)',
                    padding: '6px 10px',
                    borderRadius: 'var(--radius-md)',
                    border: '1px solid var(--line)',
                    fontSize: 'var(--text-xs)',
                    color: 'var(--muted)',
                    display: 'flex',
                    alignItems: 'center',
                    gap: 8,
                  }}
                >
                  <Info size={14} style={{ color: 'var(--accent)' }} />
                  <span>Nhấp vào node hoặc liên kết để kiểm tra Provenance & Bằng chứng SHA-256</span>
                </div>
              </div>
            ) : (
              <div className="table-container">
                <table className="data-table" aria-label="Bảng tài sản số">
                  <thead>
                    <tr>
                      <th>Khóa chuẩn (Canonical Key)</th>
                      <th>Loại</th>
                      <th>Môi trường (Exposure)</th>
                      <th>Mức quan trọng</th>
                      <th>Quan sát lần đầu</th>
                      <th>Quan sát gần nhất</th>
                      <th style={{ textAlign: 'right' }}>Nguồn gốc</th>
                    </tr>
                  </thead>
                  <tbody>
                    {assets.map((asset) => (
                      <tr
                        key={asset.asset_id}
                        style={{
                          backgroundColor: selectedItem?.id === asset.asset_id ? 'var(--subtle)' : undefined,
                        }}
                      >
                        <td>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                            {asset.kind === 'domain' ? (
                              <Globe size={15} style={{ color: 'var(--accent)' }} />
                            ) : (
                              <Server size={15} style={{ color: 'var(--success)' }} />
                            )}
                            <strong className="mono" style={{ fontSize: 'var(--text-xs)' }}>
                              {asset.canonical_key}
                            </strong>
                          </div>
                          <div style={{ marginTop: 2 }}>
                            <CopyableId value={asset.asset_id} prefix="ID" />
                          </div>
                        </td>
                        <td>
                          <span className="brand-badge">{asset.kind}</span>
                        </td>
                        <td>
                          <span
                            className={`status-chip ${asset.exposure === 'internet' ? 'warning' : 'neutral'}`}
                          >
                            {asset.exposure || 'unknown'}
                          </span>
                        </td>
                        <td>
                          <span className="brand-badge">{asset.criticality || 'unknown'}</span>
                        </td>
                        <td>
                          <span className="mono" style={{ fontSize: 'var(--text-xs)', color: 'var(--muted)' }}>
                            {new Date(asset.first_seen).toLocaleDateString('vi-VN')}
                          </span>
                        </td>
                        <td>
                          <span className="mono" style={{ fontSize: 'var(--text-xs)', color: 'var(--muted)' }}>
                            {new Date(asset.last_seen).toLocaleDateString('vi-VN')}
                          </span>
                        </td>
                        <td style={{ textAlign: 'right' }}>
                          <button
                            type="button"
                            className="btn btn-sm"
                            onClick={() => handleSelectNode(asset as unknown as AssetGraphNode)}
                          >
                            <Shield size={13} /> Nguồn gốc
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* Provenance Panel Drawer on the right */}
          {provenanceData && (
            <ProvenancePanel
              data={provenanceData}
              onClose={() => setProvenanceData(null)}
            />
          )}
        </div>
      )}
    </div>
  );
};
