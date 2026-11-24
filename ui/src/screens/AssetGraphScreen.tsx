import React, { useEffect, useState, useCallback, useRef, useMemo } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  Network,
  Table as TableIcon,
  Search,
  Globe,
  Server,
  Shield,
  Info,
  Clock,
  GitFork,
  RefreshCw,
} from 'lucide-react';
import { apiClient } from '../api/client';
import type {
  Campaign,
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
  const [searchParams, setSearchParams] = useSearchParams();
  const urlCampaignId = searchParams.get('campaign_id');
  const urlAssetId = searchParams.get('asset_id');

  const [campaignList, setCampaignList] = useState<Campaign[]>([]);
  const [activeCampaignId, setActiveCampaignId] = useState<string>(urlCampaignId || '');

  const [viewMode, setViewMode] = useState<'graph' | 'table'>('graph');
  const [graphData, setGraphData] = useState<AssetGraphResponse | null>(null);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [searchQuery, setSearchQuery] = useState('');
  const [kindFilter, setKindFilter] = useState('ALL');
  const [maxHops, setMaxHops] = useState<number>(1);
  const [asOf, setAsOf] = useState<string>('');

  // Selected item for Provenance Panel
  const [selectedItem, setSelectedItem] = useState<{ id: string; type: 'node' | 'edge' } | null>(null);
  const [provenanceData, setProvenanceData] = useState<ProvenanceDetail | null>(null);
  const initialSelectedRef = useRef(false);

  // Load campaigns on mount
  useEffect(() => {
    apiClient
      .listCampaigns()
      .then((res) => {
        setCampaignList(res.items);
        if (!urlCampaignId) {
          if (res.items.length > 0) {
            setActiveCampaignId(res.items[0].campaign_id);
          } else if (apiClient.isMock) {
            setActiveCampaignId('01934f6a-0000-7000-8000-000000000001');
          }
        }
      })
      .catch((err) => {
        console.warn('Không thể tải danh sách chiến dịch:', err);
      });
  }, [urlCampaignId]);

  const effectiveCampaignId = activeCampaignId || urlCampaignId || '';

  const handleSelectNode = useCallback(async (node: AssetGraphNode) => {
    setSelectedItem({ id: node.asset_id, type: 'node' });
    const prov = await apiClient.getProvenance(node.asset_id, { fallbackAsset: node });
    setProvenanceData(prov);
  }, []);

  const handleSelectEdge = useCallback(
    async (edge: AssetGraphEdge) => {
      const edgeKey = `edge-${edge.from}-${edge.to}`;
      setSelectedItem({ id: edgeKey, type: 'edge' });
      const relatedNode = graphData?.nodes.find(
        (n) => n.canonical_key === edge.to || n.canonical_key === edge.from
      );
      const prov = await apiClient.getProvenance(
        relatedNode ? relatedNode.asset_id : edge.source_job_id,
        { edge }
      );
      setProvenanceData(prov);
    },
    [graphData?.nodes]
  );

  const loadData = useCallback(async () => {
    if (!effectiveCampaignId) {
      setLoading(false);
      return;
    }
    try {
      setLoading(true);
      setError(null);

      // 1. Fetch asset list (if /assets endpoint available)
      let loadedAssets: Asset[] = [];
      try {
        const assetsRes = await apiClient.listAssets({
          campaign_id: effectiveCampaignId,
          kind: kindFilter !== 'ALL' ? kindFilter : undefined,
          q: searchQuery || undefined,
        });
        loadedAssets = assetsRes.items || [];
      } catch {
        // GET /assets is marked deferred in contract; fallback to graph nodes
      }

      // 2. Resolve focal asset ID
      let focalAssetId = urlAssetId || (loadedAssets.length > 0 ? loadedAssets[0].asset_id : '');
      if (!focalAssetId && apiClient.isMock) {
        focalAssetId = '01934f6a-0000-7000-8000-0000000000f1';
      }

      // 3. Load graph if focal asset is known
      if (focalAssetId) {
        const graphRes = await apiClient.getAssetGraph(focalAssetId, {
          campaign_id: effectiveCampaignId,
          max_hops: maxHops,
          as_of: asOf.trim() || undefined,
          limit: 50,
        });
        setGraphData(graphRes);

        // If listAssets returned 0 (deferred endpoint), synthesize assets from graph nodes for table view
        if (loadedAssets.length === 0 && graphRes.nodes.length > 0) {
          loadedAssets = graphRes.nodes.map((n) => ({
            asset_id: n.asset_id,
            canonical_key: n.canonical_key,
            kind: n.kind,
            exposure:
              n.kind === 'domain' && n.canonical_key.includes('internal') ? 'internal' : 'internet',
            criticality: 'medium',
            first_seen: n.first_seen || new Date().toISOString(),
            last_seen: n.last_seen || new Date().toISOString(),
          }));
        }

        // Auto select the first node initially once
        if (graphRes.nodes.length > 0 && !initialSelectedRef.current) {
          initialSelectedRef.current = true;
          handleSelectNode(graphRes.nodes[0]);
        }
      } else {
        setGraphData(null);
      }

      setAssets(loadedAssets);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Không thể tải đồ thị tài sản');
    } finally {
      setLoading(false);
    }
  }, [effectiveCampaignId, urlAssetId, kindFilter, searchQuery, maxHops, asOf, handleSelectNode]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // Dynamic layout calculation for nodes in SVG
  const nodePositions = useMemo(() => {
    const positions: Record<string, { x: number; y: number }> = {};
    if (!graphData?.nodes || graphData.nodes.length === 0) return positions;

    const nodes = graphData.nodes;
    const count = nodes.length;

    if (count === 1) {
      positions[nodes[0].canonical_key] = { x: 460, y: 280 };
      return positions;
    }

    // Focal / root node at upper center
    const focalNode = nodes[0];
    positions[focalNode.canonical_key] = { x: 460, y: 130 };

    const otherNodes = nodes.slice(1);
    const otherCount = otherNodes.length;

    if (otherCount <= 4) {
      otherNodes.forEach((node, i) => {
        const spreadX = 640;
        const step = otherCount > 1 ? spreadX / (otherCount - 1) : 0;
        const x = otherCount === 1 ? 460 : 140 + i * step;
        const y = 330 + (i % 2 === 1 ? 90 : 0);
        positions[node.canonical_key] = {
          x: Math.max(130, Math.min(790, x)),
          y: Math.max(80, Math.min(510, y)),
        };
      });
    } else {
      const radiusX = Math.min(360, 200 + otherCount * 12);
      const radiusY = Math.min(200, 140 + otherCount * 8);
      const centerX = 460;
      const centerY = 330;

      otherNodes.forEach((node, i) => {
        const angle = (2 * Math.PI * i) / otherCount;
        const x = Math.round(centerX + radiusX * Math.cos(angle));
        const y = Math.round(centerY + radiusY * Math.sin(angle));
        positions[node.canonical_key] = {
          x: Math.max(130, Math.min(790, x)),
          y: Math.max(80, Math.min(510, y)),
        };
      });
    }

    return positions;
  }, [graphData?.nodes]);

  // Filtered assets for table view
  const filteredAssets = useMemo(() => {
    return assets.filter((asset) => {
      const matchesKind = kindFilter === 'ALL' || asset.kind === kindFilter;
      const matchesSearch =
        !searchQuery ||
        asset.canonical_key.toLowerCase().includes(searchQuery.toLowerCase()) ||
        asset.asset_id.toLowerCase().includes(searchQuery.toLowerCase());
      return matchesKind && matchesSearch;
    });
  }, [assets, kindFilter, searchQuery]);

  return (
    <div>
      {/* Top Filter and Controls Bar */}
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
          {/* Campaign Selector */}
          {campaignList.length > 0 && (
            <select
              className="input-search"
              style={{ minWidth: 200 }}
              value={effectiveCampaignId}
              onChange={(e) => {
                setActiveCampaignId(e.target.value);
                setSearchParams({ campaign_id: e.target.value });
              }}
              aria-label="Chọn chiến dịch"
            >
              {campaignList.map((c) => (
                <option key={c.campaign_id} value={c.campaign_id}>
                  {c.name} ({c.status})
                </option>
              ))}
            </select>
          )}

          {/* View Mode Switcher */}
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

          {/* Search Input */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, position: 'relative' }}>
            <Search size={14} style={{ position: 'absolute', left: 10, color: 'var(--muted)' }} />
            <input
              type="text"
              className="input-search"
              style={{ paddingLeft: 30, minWidth: 200 }}
              placeholder="Tìm canonical key..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              aria-label="Tìm kiếm canonical key"
            />
          </div>

          {/* Kind Filter */}
          <select
            className="input-search"
            style={{ minWidth: 130 }}
            value={kindFilter}
            onChange={(e) => setKindFilter(e.target.value)}
            aria-label="Lọc loại tài sản"
          >
            <option value="ALL">Tất cả loại</option>
            <option value="domain">Tên miền (Domain)</option>
            <option value="ip">Địa chỉ IP</option>
          </select>

          {/* Max Hops Toggle */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 4 }} title="Số bước nhảy lân cận (max_hops: 1 hoặc 2)">
            <GitFork size={14} style={{ color: 'var(--muted)' }} />
            <select
              className="input-search"
              style={{ minWidth: 85 }}
              value={maxHops}
              onChange={(e) => setMaxHops(Number(e.target.value))}
              aria-label="Số bước nhảy"
            >
              <option value={1}>1 hop</option>
              <option value={2}>2 hops</option>
            </select>
          </div>

          {/* As-Of History Filter */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 4, position: 'relative' }} title="Thời điểm lịch sử (as_of timestamp)">
            <Clock size={14} style={{ position: 'absolute', left: 8, color: 'var(--muted)' }} />
            <input
              type="text"
              className="input-search"
              style={{ paddingLeft: 26, minWidth: 150, fontSize: '11.5px' }}
              placeholder="as_of (RFC 3339)..."
              value={asOf}
              onChange={(e) => setAsOf(e.target.value)}
              aria-label="Thời điểm lịch sử (as_of)"
            />
          </div>

          {/* Reload Button */}
          <button
            type="button"
            className="btn btn-sm"
            onClick={loadData}
            title="Tải lại dữ liệu đồ thị"
            aria-label="Tải lại đồ thị"
          >
            <RefreshCw size={14} />
          </button>
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
        <div className="state-box" style={{ marginTop: 32, padding: '48px 24px' }}>
          <div className="state-title">Đang nạp dữ liệu đồ thị tài sản...</div>
        </div>
      ) : !graphData || graphData.nodes.length === 0 ? (
        /* Empty state when no graph data is available */
        <div className="state-box" style={{ marginTop: 32, padding: '48px 24px' }}>
          <Network size={44} style={{ color: 'var(--muted)', marginBottom: 14 }} />
          <div className="state-title" style={{ fontSize: 'var(--text-lg)', marginBottom: 6 }}>
            Chưa có dữ liệu đồ thị tài sản cho chiến dịch này
          </div>
          <div className="state-desc" style={{ maxWidth: 540, margin: '0 auto', lineHeight: 1.6 }}>
            Đồ thị tri thức M23 được cập nhật tự động khi các tác vụ trinh sát (Subfinder, DNSx) hoàn tất
            và dữ liệu quan sát được chuyển thành các đỉnh/cạnh quan hệ.
          </div>
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
                  {graphData.edges.map((edge) => {
                    const fromPt = nodePositions[edge.from] || { x: 200, y: 330 };
                    const toPt = nodePositions[edge.to] || { x: 460, y: 130 };

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
                  {graphData.nodes.map((node) => {
                    const pt = nodePositions[node.canonical_key] || { x: 460, y: 300 };
                    const isSelected = selectedItem?.id === node.asset_id;

                    const displayKey =
                      node.canonical_key.length > 26
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

                        {/* Status badge */}
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
                          {node.stale ? 'cũ (stale)' : 'hiệu lực'}
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
                  <span>Nhấp vào node hoặc cạnh liên kết để kiểm tra Provenance & Bằng chứng SHA-256</span>
                </div>
              </div>
            ) : (
              <div className="table-container">
                {filteredAssets.length === 0 ? (
                  <div className="state-box" style={{ padding: '36px 20px' }}>
                    <Search size={36} style={{ color: 'var(--muted)', marginBottom: 10 }} />
                    <div className="state-title" style={{ fontSize: 'var(--text-base)', marginBottom: 4 }}>
                      Không tìm thấy tài sản nào phù hợp
                    </div>
                    <div className="state-desc" style={{ fontSize: 'var(--text-xs)' }}>
                      Thử thay đổi từ khóa tìm kiếm hoặc chọn "Tất cả loại".
                    </div>
                  </div>
                ) : (
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
                      {filteredAssets.map((asset) => (
                        <tr
                          key={asset.asset_id}
                          style={{
                            backgroundColor:
                              selectedItem?.id === asset.asset_id ? 'var(--subtle)' : undefined,
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
                              className={`status-chip ${
                                asset.exposure === 'internet' ? 'warning' : 'neutral'
                              }`}
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
                )}
              </div>
            )}
          </div>

          {/* Provenance Panel Drawer on the right */}
          {provenanceData && (
            <ProvenancePanel data={provenanceData} onClose={() => setProvenanceData(null)} />
          )}
        </div>
      )}
    </div>
  );
};
