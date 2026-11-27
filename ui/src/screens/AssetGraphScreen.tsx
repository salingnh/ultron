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
  Layers,
} from 'lucide-react';
import { apiClient, toUiError } from '../api/client';
import type {
  Campaign,
  Asset,
  AssetDiscoveredPayload,
  AssetGraphResponse,
  AssetGraphNode,
  AssetGraphEdge,
  AssetHistoryItem,
  AssetEnrichment,
  VulnerabilityCandidate,
  ServiceRowData,
  SelectedVulnerabilityState,
  ProvenanceDetail,
  UiError,
} from '../api/types';
import { TruncatedBanner } from '../components/TruncatedBanner';
import { ProvenancePanel } from '../components/ProvenancePanel';
import { VulnerabilityPanel } from '../components/VulnerabilityPanel';
import { ServiceTable } from '../components/ServiceTable';
import { CopyableId } from '../components/CopyableId';
import { ErrorDisplay } from '../components/ErrorDisplay';
import { rankCandidates, summarizeCandidateCounts } from '../utils/cveCandidates';

interface GraphVulnerabilityNode {
  id: string;
  key: string;
  kind: 'vulnerability';
  candidate: VulnerabilityCandidate;
  sourceAssetId: string;
  sourceAssetKey: string;
}

interface GraphVulnerabilityEdge {
  id: string;
  type: 'AFFECTED_BY';
  from: string;
  to: string;
  candidate: VulnerabilityCandidate;
  sourceAssetId: string;
}

function parseServiceCanonicalKey(key: string): { host: string; port: string; transport: string } {
  // Format: service:<ip>:<port>/<tcp|udp> or service:[<ipv6>]:<port>/<tcp|udp>
  const body = key.startsWith('service:') ? key.slice('service:'.length) : key;
  const slashIdx = body.lastIndexOf('/');
  const transport = slashIdx >= 0 ? body.slice(slashIdx + 1) : '';
  const hostPort = slashIdx >= 0 ? body.slice(0, slashIdx) : body;
  const colonIdx = hostPort.lastIndexOf(':');
  if (colonIdx < 0) {
    return { host: hostPort, port: '—', transport: transport || '—' };
  }
  const rawHost = hostPort.slice(0, colonIdx);
  const port = hostPort.slice(colonIdx + 1);
  return {
    host: rawHost.replace(/^\[|\]$/g, ''),
    port: port || '—',
    transport: transport || '—',
  };
}

function extractEnrichment(items: AssetHistoryItem[]): AssetEnrichment {
  const enrichment: AssetEnrichment = { technologies: [] };
  // History items are ordered newest-first; take newest observation per predicate
  for (const item of items) {
    if (item.polarity !== 'present') continue;
    const val = item.value;
    if (item.predicate === 'service.protocol' && !enrichment.protocol && typeof val === 'string') {
      enrichment.protocol = val;
    } else if (item.predicate === 'net.port_state' && !enrichment.portState && typeof val === 'string') {
      enrichment.portState = val;
    } else if (item.predicate === 'service.product' && !enrichment.product && val && typeof val === 'object') {
      const obj = val as Record<string, unknown>;
      enrichment.product = {
        product: typeof obj.product === 'string' ? obj.product : undefined,
        version: typeof obj.version === 'string' ? obj.version : undefined,
        cpe: typeof obj.cpe === 'string' ? obj.cpe : undefined,
      };
    } else if (item.predicate === 'http.technology' && enrichment.technologies.length === 0 && Array.isArray(val)) {
      enrichment.technologies = val.filter((entry): entry is string => typeof entry === 'string');
    } else if (item.predicate === 'tls.certificate' && !enrichment.tlsSubjectCn && val && typeof val === 'object') {
      const obj = val as Record<string, unknown>;
      if (typeof obj.subject_cn === 'string') enrichment.tlsSubjectCn = obj.subject_cn;
      if (typeof obj.sha256 === 'string') enrichment.tlsSha256 = obj.sha256;
    } else if (item.predicate === 'http.status' && enrichment.httpStatus === undefined && typeof val === 'number') {
      enrichment.httpStatus = val;
    } else if (item.predicate === 'http.title' && !enrichment.httpTitle && typeof val === 'string') {
      enrichment.httpTitle = val;
    }
  }
  return enrichment;
}

function truncateText(value: string, max: number): string {
  return value.length > max ? `${value.slice(0, max - 1)}…` : value;
}

export const AssetGraphScreen: React.FC = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const urlCampaignId = searchParams.get('campaign_id');
  const urlAssetId = searchParams.get('asset_id');

  const [campaignList, setCampaignList] = useState<Campaign[]>([]);
  const [activeCampaignId, setActiveCampaignId] = useState<string>(urlCampaignId || '');
  const [selectedFocalAssetId, setSelectedFocalAssetId] = useState<string>(urlAssetId || '');
  const [resolvedFocalAssetId, setResolvedFocalAssetId] = useState<string>(urlAssetId || '');

  const [viewMode, setViewMode] = useState<'graph' | 'services' | 'table'>('graph');
  const [graphData, setGraphData] = useState<AssetGraphResponse | null>(null);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [eventsTruncated, setEventsTruncated] = useState(false);

  const [enrichments, setEnrichments] = useState<Record<string, AssetEnrichment>>({});
  const [vulnerabilitiesByAsset, setVulnerabilitiesByAsset] = useState<
    Record<string, { items: VulnerabilityCandidate[]; truncated: boolean }>
  >({});

  const [loading, setLoading] = useState(true);
  const [assetsError, setAssetsError] = useState<UiError | null>(null);
  const [graphError, setGraphError] = useState<UiError | null>(null);

  const [searchQuery, setSearchQuery] = useState('');
  const [kindFilter, setKindFilter] = useState('ALL');
  const [maxHops, setMaxHops] = useState<number>(2);
  const [asOf, setAsOf] = useState<string>('');

  // Right-side drawer: either ProvenancePanel or VulnerabilityPanel
  const [selectedItem, setSelectedItem] = useState<{
    id: string;
    type: 'node' | 'edge' | 'vulnerability';
  } | null>(null);
  const [provenanceData, setProvenanceData] = useState<ProvenanceDetail | null>(null);
  const [selectedVulnerability, setSelectedVulnerability] =
    useState<SelectedVulnerabilityState | null>(null);
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
    setSelectedVulnerability(null);
    setSelectedItem({ id: node.asset_id, type: 'node' });
    const prov = await apiClient.getProvenance(node.asset_id, { fallbackAsset: node });
    setProvenanceData(prov);
  }, []);

  const handleSelectEdge = useCallback(
    async (edge: AssetGraphEdge) => {
      setSelectedVulnerability(null);
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

  const handleSelectVulnerability = useCallback(
    (
      candidate: VulnerabilityCandidate,
      assetId: string,
      assetKey: string,
      siblings?: VulnerabilityCandidate[]
    ) => {
      setProvenanceData(null);
      setSelectedItem({ id: `vuln-${assetId}-${candidate.vulnerability_id}`, type: 'vulnerability' });
      setSelectedVulnerability({ candidate, assetId, assetKey, siblings });
    },
    []
  );

  const loadData = useCallback(async () => {
    if (!effectiveCampaignId) {
      setLoading(false);
      return;
    }
    try {
      setLoading(true);
      setAssetsError(null);
      setGraphError(null);
      setEventsTruncated(false);

      // 1. Fetch campaign assets: try GET /assets (works in mock or if implemented),
      //    else derive from cursor-paginated GET /campaigns/{id}/events?types=asset.discovered.v2
      let loadedAssets: Asset[] = [];
      try {
        const assetsRes = await apiClient.listAssets({
          campaign_id: effectiveCampaignId,
          limit: 200,
        });
        loadedAssets = assetsRes.items || [];
      } catch (err) {
        setAssetsError(toUiError(err, `/assets?campaign_id=${effectiveCampaignId}`));
      }

      if (loadedAssets.length === 0) {
        try {
          const eventsRes = await apiClient.listCampaignEvents(effectiveCampaignId, {
            types: ['asset.discovered.v2'],
            limit: 200,
          });
          setEventsTruncated(Boolean(eventsRes.next_cursor));
          const byId = new Map<string, Asset>();
          for (const ev of eventsRes.items || []) {
            if (ev.type !== 'asset.discovered.v2') continue;
            const payload = ev.payload as unknown as AssetDiscoveredPayload;
            if (!payload?.asset_id || !payload?.canonical_key || !payload?.kind) continue;
            const existing = byId.get(payload.asset_id);
            if (!existing) {
              byId.set(payload.asset_id, {
                asset_id: payload.asset_id,
                canonical_key: payload.canonical_key,
                kind: payload.kind,
                first_seen: payload.first_seen || ev.occurred_at,
                last_seen: ev.occurred_at || payload.first_seen,
                discovered_from: payload.discovered_from,
              });
            }
          }
          loadedAssets = Array.from(byId.values());
          setAssetsError(null);
        } catch (err) {
          setAssetsError(
            toUiError(err, `/campaigns/${effectiveCampaignId}/events?types=asset.discovered.v2`)
          );
        }
      }

      // 2. Enrich service & application assets with real history (observations) and candidate CVEs
      const serviceAndAppAssets = loadedAssets.filter(
        (a) => a.kind === 'service' || a.kind === 'application'
      );
      const enrichmentMap: Record<string, AssetEnrichment> = {};
      const vulnMap: Record<string, { items: VulnerabilityCandidate[]; truncated: boolean }> = {};

      await Promise.all(
        serviceAndAppAssets.map(async (asset) => {
          const [historyResult, vulnResult] = await Promise.allSettled([
            apiClient.getAssetHistory(asset.asset_id, { limit: 50 }),
            apiClient.listAssetVulnerabilities(asset.asset_id, {
              campaign_id: effectiveCampaignId,
              limit: 200,
            }),
          ]);
          if (historyResult.status === 'fulfilled') {
            enrichmentMap[asset.asset_id] = extractEnrichment(historyResult.value.items || []);
          }
          if (vulnResult.status === 'fulfilled') {
            vulnMap[asset.asset_id] = {
              items: vulnResult.value.items || [],
              truncated: Boolean(vulnResult.value.next_cursor),
            };
          }
        })
      );

      // 2b. Commit campaign assets, enrichments, and vulnerabilities before graph query
      setEnrichments(enrichmentMap);
      setVulnerabilitiesByAsset(vulnMap);
      setAssets(loadedAssets);

      // 3. Resolve focal asset ID (prefer explicit selection, else an asset with CVEs / IP / service)
      let focalAssetId = urlAssetId || selectedFocalAssetId;
      if (focalAssetId && !loadedAssets.some((a) => a.asset_id === focalAssetId) && !urlAssetId) {
        focalAssetId = '';
      }
      if (!focalAssetId) {
        const assetWithVulns = serviceAndAppAssets.find(
          (a) => (vulnMap[a.asset_id]?.items.length || 0) > 0
        );
        const firstIp = loadedAssets.find((a) => a.kind === 'ip');
        const firstService = loadedAssets.find((a) => a.kind === 'service');
        focalAssetId =
          assetWithVulns?.asset_id ||
          firstIp?.asset_id ||
          firstService?.asset_id ||
          (loadedAssets.length > 0 ? loadedAssets[0].asset_id : '');
      }
      if (!focalAssetId && apiClient.isMock) {
        focalAssetId = '01934f6a-0000-7000-8000-0000000000f3';
      }
      setResolvedFocalAssetId(focalAssetId);

      // 4. Load graph around focal asset (isolated error scope so service/asset tables stay clean)
      if (focalAssetId) {
        const graphPath = `/assets/${encodeURIComponent(focalAssetId)}/graph?campaign_id=${encodeURIComponent(effectiveCampaignId)}&max_hops=${maxHops}&limit=100`;
        try {
          const graphRes = await apiClient.getAssetGraph(focalAssetId, {
            campaign_id: effectiveCampaignId,
            max_hops: maxHops,
            as_of: asOf.trim() || undefined,
            limit: 100,
          });
          setGraphData(graphRes);

          // Also ensure any service/application node present in graphRes has enrichment & vulns loaded
          const missingGraphAssets = graphRes.nodes.filter(
            (n) =>
              (n.kind === 'service' || n.kind === 'application') &&
              (!enrichmentMap[n.asset_id] || !vulnMap[n.asset_id])
          );
          if (missingGraphAssets.length > 0) {
            await Promise.all(
              missingGraphAssets.map(async (node) => {
                const [historyResult, vulnResult] = await Promise.allSettled([
                  apiClient.getAssetHistory(node.asset_id, { limit: 50 }),
                  apiClient.listAssetVulnerabilities(node.asset_id, {
                    campaign_id: effectiveCampaignId,
                    limit: 200,
                  }),
                ]);
                if (historyResult.status === 'fulfilled') {
                  enrichmentMap[node.asset_id] = extractEnrichment(historyResult.value.items || []);
                }
                if (vulnResult.status === 'fulfilled') {
                  vulnMap[node.asset_id] = {
                    items: vulnResult.value.items || [],
                    truncated: Boolean(vulnResult.value.next_cursor),
                  };
                }
              })
            );
            setEnrichments({ ...enrichmentMap });
            setVulnerabilitiesByAsset({ ...vulnMap });
          }

          if (loadedAssets.length === 0 && graphRes.nodes.length > 0) {
            loadedAssets = graphRes.nodes.map((n) => ({
              asset_id: n.asset_id,
              canonical_key: n.canonical_key,
              kind: n.kind,
              first_seen: n.first_seen || new Date().toISOString(),
              last_seen: n.last_seen || new Date().toISOString(),
            }));
            setAssets(loadedAssets);
          }

          if (graphRes.nodes.length > 0 && !initialSelectedRef.current) {
            initialSelectedRef.current = true;
            handleSelectNode(graphRes.nodes[0]);
          }
        } catch (err: unknown) {
          setGraphData(null);
          setGraphError(toUiError(err, graphPath));
        }
      } else {
        setGraphData(null);
      }
    } finally {
      setLoading(false);
    }
  }, [effectiveCampaignId, urlAssetId, selectedFocalAssetId, maxHops, asOf, handleSelectNode]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // Build Vulnerability nodes & AFFECTED_BY edges for the graph from real API results
  const { vulnNodes, vulnEdges } = useMemo(() => {
    const vNodes: GraphVulnerabilityNode[] = [];
    const vEdges: GraphVulnerabilityEdge[] = [];
    if (!graphData?.nodes) return { vulnNodes: vNodes, vulnEdges: vEdges };

    for (const node of graphData.nodes) {
      if (node.kind !== 'service' && node.kind !== 'application') continue;
      const entry = vulnerabilitiesByAsset[node.asset_id];
      if (!entry?.items?.length) continue;
      for (const candidate of entry.items) {
        const vKey = `vuln:${node.asset_id}:${candidate.vulnerability_id}`;
        vNodes.push({
          id: vKey,
          key: vKey,
          kind: 'vulnerability',
          candidate,
          sourceAssetId: node.asset_id,
          sourceAssetKey: node.canonical_key,
        });
        vEdges.push({
          id: `affected-${node.canonical_key}-${candidate.vulnerability_id}`,
          type: 'AFFECTED_BY',
          from: node.canonical_key,
          to: vKey,
          candidate,
          sourceAssetId: node.asset_id,
        });
      }
    }
    return { vulnNodes: vNodes, vulnEdges: vEdges };
  }, [graphData?.nodes, vulnerabilitiesByAsset]);

  // Filter nodes by kindFilter and searchQuery
  const { visibleAssetNodes, visibleVulnNodes, visibleAssetEdges, visibleVulnEdges } = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    const assetNodes = (graphData?.nodes || []).filter((node) => {
      const matchesKind = kindFilter === 'ALL' || node.kind === kindFilter;
      if (!matchesKind) return false;
      if (!q) return true;
      const enr = enrichments[node.asset_id];
      const textBlob = [
        node.canonical_key,
        node.kind,
        enr?.protocol || '',
        enr?.product?.product || '',
        enr?.product?.version || '',
        enr?.product?.cpe || '',
        ...(enr?.technologies || []),
      ]
        .join(' ')
        .toLowerCase();
      return textBlob.includes(q);
    });

    const filteredVulnNodes = vulnNodes.filter((vn) => {
      const matchesKind = kindFilter === 'ALL' || kindFilter === 'vulnerability';
      if (!matchesKind) return false;
      if (!q) return true;
      return (
        vn.candidate.vulnerability_id.toLowerCase().includes(q) ||
        vn.sourceAssetKey.toLowerCase().includes(q)
      );
    });

    const visibleAssetKeys = new Set(assetNodes.map((n) => n.canonical_key));
    const visibleVulnKeys = new Set(filteredVulnNodes.map((v) => v.key));

    const inScopeEdges = (graphData?.edges || []).filter(
      (e) => visibleAssetKeys.has(e.from) && visibleAssetKeys.has(e.to)
    );
    // Avoid drawing redundant DISCOVERED_FROM directly on top of a primary semantic edge (EXPOSES, SERVES, RESOLVES_TO, SUBDOMAIN_OF)
    const primaryPairs = new Set(
      inScopeEdges
        .filter((e) => e.type !== 'DISCOVERED_FROM')
        .flatMap((e) => [`${e.from}->${e.to}`, `${e.to}->${e.from}`])
    );
    const assetEdges = inScopeEdges.filter(
      (e) => e.type !== 'DISCOVERED_FROM' || !primaryPairs.has(`${e.from}->${e.to}`)
    );
    const vEdges = vulnEdges.filter(
      (e) => visibleAssetKeys.has(e.from) && visibleVulnKeys.has(e.to)
    );

    return {
      visibleAssetNodes: assetNodes,
      visibleVulnNodes: filteredVulnNodes,
      visibleAssetEdges: assetEdges,
      visibleVulnEdges: vEdges,
    };
  }, [graphData?.nodes, graphData?.edges, vulnNodes, vulnEdges, kindFilter, searchQuery, enrichments]);

  // Layered layout calculation: Domain -> IP -> Service -> Application -> Vulnerability
  const { nodePositions, svgWidth, svgHeight } = useMemo(() => {
    const positions: Record<string, { x: number; y: number; width: number; height: number }> = {};

    const domains = visibleAssetNodes.filter((n) => n.kind === 'domain');
    const ips = visibleAssetNodes.filter((n) => n.kind === 'ip');
    const services = visibleAssetNodes.filter((n) => n.kind === 'service');
    const applications = visibleAssetNodes.filter((n) => n.kind === 'application');
    const others = visibleAssetNodes.filter(
      (n) =>
        n.kind !== 'domain' &&
        n.kind !== 'ip' &&
        n.kind !== 'service' &&
        n.kind !== 'application'
    );

    const layers: Array<{
      items: Array<{ key: string; width: number; height: number }>;
    }> = [];

    if (domains.length > 0) {
      layers.push({
        items: domains.map((n) => ({ key: n.canonical_key, width: 205, height: 68 })),
      });
    }
    if (ips.length > 0) {
      layers.push({
        items: ips.map((n) => ({ key: n.canonical_key, width: 186, height: 68 })),
      });
    }
    if (services.length > 0) {
      layers.push({
        items: services.map((n) => ({ key: n.canonical_key, width: 256, height: 96 })),
      });
    }
    if (applications.length > 0) {
      layers.push({
        items: applications.map((n) => ({ key: n.canonical_key, width: 248, height: 96 })),
      });
    }
    if (others.length > 0) {
      layers.push({
        items: others.map((n) => ({ key: n.canonical_key, width: 210, height: 72 })),
      });
    }
    if (visibleVulnNodes.length > 0) {
      layers.push({
        items: visibleVulnNodes.map((v) => ({ key: v.key, width: 238, height: 86 })),
      });
    }

    const colGap = 76;
    const rowGap = 24;
    const marginX = 24;
    const marginY = 36;

    let maxColHeight = 480;
    for (const layer of layers) {
      const colHeight =
        layer.items.reduce((sum, item) => sum + item.height, 0) +
        Math.max(0, layer.items.length - 1) * rowGap;
      if (colHeight + marginY * 2 > maxColHeight) {
        maxColHeight = colHeight + marginY * 2;
      }
    }

    let currentX = marginX;
    for (const layer of layers) {
      const maxWidth = Math.max(...layer.items.map((item) => item.width));
      const totalHeight =
        layer.items.reduce((sum, item) => sum + item.height, 0) +
        Math.max(0, layer.items.length - 1) * rowGap;
      let currentY = Math.max(marginY, Math.round((maxColHeight - totalHeight) / 2));

      for (const item of layer.items) {
        positions[item.key] = {
          x: currentX + maxWidth / 2,
          y: currentY + item.height / 2,
          width: item.width,
          height: item.height,
        };
        currentY += item.height + rowGap;
      }

      currentX += maxWidth + colGap;
    }

    const totalWidth = Math.max(920, currentX - colGap + marginX);
    return { nodePositions: positions, svgWidth: totalWidth, svgHeight: maxColHeight };
  }, [visibleAssetNodes, visibleVulnNodes]);

  // Build Service Table rows per campaign
  const serviceRows = useMemo<ServiceRowData[]>(() => {
    const q = searchQuery.trim().toLowerCase();
    return assets
      .filter((a) => a.kind === 'service')
      .map((asset) => {
        const parsed = parseServiceCanonicalKey(asset.canonical_key);
        const enr = enrichments[asset.asset_id];
        const vulnEntry = vulnerabilitiesByAsset[asset.asset_id];
        const candidates = rankCandidates(vulnEntry?.items || []);
        const counts = summarizeCandidateCounts(candidates);
        const protocol = enr?.protocol
          ? `${enr.protocol} (${parsed.transport})`
          : parsed.transport;

        return {
          asset,
          host: parsed.host,
          port: parsed.port,
          transport: parsed.transport,
          protocol,
          product: enr?.product?.product || '',
          version: enr?.product?.version || '',
          cpe: enr?.product?.cpe || '',
          candidates,
          candidateCount: candidates.length,
          kevCount: counts.kevCount,
          criticalCount: counts.criticalCount,
          highCount: counts.highCount,
          truncatedCandidates: Boolean(vulnEntry?.truncated),
        };
      })
      .filter((row) => {
        if (!q) return true;
        const haystack = [
          row.host,
          row.port,
          row.protocol,
          row.product,
          row.version,
          row.cpe,
          row.asset.canonical_key,
          ...row.candidates.map((c) => c.vulnerability_id),
        ]
          .join(' ')
          .toLowerCase();
        return haystack.includes(q);
      });
  }, [assets, enrichments, vulnerabilitiesByAsset, searchQuery]);

  // Filtered assets for Asset Table view
  const filteredAssets = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return assets.filter((asset) => {
      const matchesKind = kindFilter === 'ALL' || asset.kind === kindFilter;
      const matchesSearch =
        !q ||
        asset.canonical_key.toLowerCase().includes(q) ||
        asset.asset_id.toLowerCase().includes(q);
      return matchesKind && matchesSearch;
    });
  }, [assets, kindFilter, searchQuery]);

  // Focal options for switching subgraphs in a multi-IP campaign
  const focalOptions = useMemo(
    () =>
      assets.filter(
        (a) => a.kind === 'ip' || a.kind === 'service' || a.kind === 'domain'
      ),
    [assets]
  );

  return (
    <div>
      {/* Top Filter and Controls Bar */}
      <div className="filter-bar">
        <div>
          <h1 style={{ fontSize: 'var(--text-xl)', fontWeight: 700, color: 'var(--ink)' }}>
            Đồ thị Tri thức & Dịch vụ Tài sản
          </h1>
          <p style={{ fontSize: 'var(--text-sm)', color: 'var(--muted)', marginTop: 2 }}>
            Chuỗi IP → Service → Application/Technology → Ứng viên CVE. Nhấp node hoặc cạnh để xem nguồn gốc hoặc chi tiết ứng viên.
          </p>
        </div>

        <div className="filter-group" style={{ flexWrap: 'wrap' }}>
          {/* Campaign Selector */}
          {campaignList.length > 0 && (
            <select
              className="input-search"
              style={{ minWidth: 200 }}
              value={effectiveCampaignId}
              onChange={(e) => {
                setActiveCampaignId(e.target.value);
                setSelectedFocalAssetId('');
                initialSelectedRef.current = false;
                setProvenanceData(null);
                setSelectedVulnerability(null);
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
              className={`btn btn-sm ${viewMode === 'services' ? 'btn-primary' : ''}`}
              style={{ border: 'none' }}
              onClick={() => setViewMode('services')}
            >
              <Layers size={14} /> Bảng Dịch vụ ({serviceRows.length})
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
              style={{ paddingLeft: 30, minWidth: 190 }}
              placeholder="Tìm key, product, CPE, CVE..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              aria-label="Tìm kiếm tài sản hoặc CVE"
            />
          </div>

          {/* Kind Filter */}
          <select
            className="input-search"
            style={{ minWidth: 145 }}
            value={kindFilter}
            onChange={(e) => setKindFilter(e.target.value)}
            aria-label="Lọc loại tài sản"
          >
            <option value="ALL">Tất cả loại</option>
            <option value="domain">Tên miền (Domain)</option>
            <option value="ip">Địa chỉ IP</option>
            <option value="service">Dịch vụ (Service)</option>
            <option value="application">Ứng dụng (Application)</option>
            <option value="vulnerability">Ứng viên CVE</option>
          </select>

          {/* Focal Asset Selector for Graph */}
          {viewMode === 'graph' && focalOptions.length > 0 && (
            <select
              className="input-search"
              style={{ minWidth: 185, fontFamily: 'var(--font-mono)', fontSize: '12px' }}
              value={urlAssetId || selectedFocalAssetId || resolvedFocalAssetId || focalOptions[0]?.asset_id || ''}
              onChange={(e) => {
                setSelectedFocalAssetId(e.target.value);
                setSearchParams({
                  campaign_id: effectiveCampaignId,
                  asset_id: e.target.value,
                });
              }}
              aria-label="Chọn nút gốc đồ thị"
              title="Nút trung tâm (focal asset) cho truy vấn vùng lân cận"
            >
              {focalOptions.map((a) => (
                <option key={a.asset_id} value={a.asset_id}>
                  {a.canonical_key}
                </option>
              ))}
            </select>
          )}

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
              style={{ paddingLeft: 26, minWidth: 145, fontSize: '11.5px' }}
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

      {assetsError && <ErrorDisplay error={assetsError} onRetry={loadData} />}

      {/* Truncated banner when graph query or campaign event list is truncated */}
      {(viewMode === 'graph' ? graphData?.truncated || eventsTruncated : eventsTruncated) && (
        <TruncatedBanner
          truncated={Boolean(viewMode === 'graph' ? graphData?.truncated || eventsTruncated : eventsTruncated)}
          limitsApplied={viewMode === 'graph' ? graphData?.limits_applied : undefined}
          customMessage={
            eventsTruncated
              ? 'Danh sách tài sản của chiến dịch đã chạm trần phân trang 200 bản ghi; đồ thị vùng lân cận cũng áp dụng giới hạn bước nhảy và đỉnh.'
              : 'Dữ liệu đồ thị tài sản đã được giới hạn số bước nhảy và số đỉnh theo hợp đồng MCP graph queries.'
          }
        />
      )}

      {loading ? (
        <div className="state-box" style={{ marginTop: 32, padding: '48px 24px' }}>
          <div className="state-title">Đang nạp dữ liệu đồ thị tài sản...</div>
        </div>
      ) : viewMode === 'services' ? (
        <div className="split-panel-layout">
          <div style={{ flex: 1, minWidth: 0 }}>
            <ServiceTable
              rows={serviceRows}
              selectedAssetId={selectedVulnerability?.assetId}
              selectedCveId={selectedVulnerability?.candidate.vulnerability_id}
              onSelectVulnerability={(row, candidate) =>
                handleSelectVulnerability(
                  candidate,
                  row.asset.asset_id,
                  row.asset.canonical_key,
                  row.candidates
                )
              }
              onFocusInGraph={(assetId) => {
                setSelectedFocalAssetId(assetId);
                setSearchParams({
                  campaign_id: effectiveCampaignId,
                  asset_id: assetId,
                });
                setViewMode('graph');
              }}
            />
          </div>
          {selectedVulnerability && (
            <VulnerabilityPanel
              data={selectedVulnerability}
              onSelectCandidate={(cand) =>
                handleSelectVulnerability(
                  cand,
                  selectedVulnerability.assetId,
                  selectedVulnerability.assetKey,
                  selectedVulnerability.siblings
                )
              }
              onClose={() => setSelectedVulnerability(null)}
            />
          )}
          {provenanceData && !selectedVulnerability && (
            <ProvenancePanel data={provenanceData} onClose={() => setProvenanceData(null)} />
          )}
        </div>
      ) : viewMode === 'table' ? (
        <div style={{ display: 'flex', gap: 16, alignItems: 'flex-start' }}>
          <div style={{ flex: 1, minWidth: 0 }}>
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
                          {asset.exposure ? (
                            <span
                              className={`status-chip ${
                                asset.exposure === 'internet' ? 'warning' : 'neutral'
                              }`}
                            >
                              {asset.exposure}
                            </span>
                          ) : (
                            <span style={{ color: 'var(--muted)' }}>—</span>
                          )}
                        </td>
                        <td>
                          {asset.criticality ? (
                            <span className="brand-badge">{asset.criticality}</span>
                          ) : (
                            <span style={{ color: 'var(--muted)' }}>—</span>
                          )}
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
          </div>
          {provenanceData && !selectedVulnerability && (
            <ProvenancePanel data={provenanceData} onClose={() => setProvenanceData(null)} />
          )}
        </div>
      ) : !graphData || graphData.nodes.length === 0 ? (
        /* Graph view error or empty state */
        <div>
          {graphError && (
            <div style={{ marginBottom: 16 }}>
              <ErrorDisplay error={graphError} onRetry={loadData} />
            </div>
          )}
          <div className="state-box" style={{ marginTop: graphError ? 0 : 32, padding: '48px 24px' }}>
            <Network size={44} style={{ color: 'var(--muted)', marginBottom: 14 }} />
            <div className="state-title" style={{ fontSize: 'var(--text-lg)', marginBottom: 6 }}>
              {graphError
                ? 'Không thể tải đồ thị tài sản cho chiến dịch này'
                : 'Chưa có dữ liệu đồ thị tài sản cho chiến dịch này'}
            </div>
            <div className="state-desc" style={{ maxWidth: 540, margin: '0 auto', lineHeight: 1.6 }}>
              {graphError
                ? 'Bạn vẫn có thể xem Bảng Dịch vụ và Bảng Tài sản ở các tab phía trên trong khi đồ thị đang lỗi.'
                : 'Đồ thị tri thức M23 được cập nhật tự động khi các tác vụ trinh sát (Subfinder, DNSx, Naabu, Fingerprintx, HTTPx) hoàn tất và dữ liệu quan sát được chuyển thành các đỉnh/cạnh quan hệ.'}
            </div>
          </div>
        </div>
      ) : (
        <div>
          {graphError && (
            <div style={{ marginBottom: 16 }}>
              <ErrorDisplay error={graphError} onRetry={loadData} />
            </div>
          )}
        /* Main Layout: Graph/Table on left, ProvenancePanel or VulnerabilityPanel on right */
        <div style={{ display: 'flex', gap: 16, alignItems: 'flex-start' }}>
          <div style={{ flex: 1, minWidth: 0 }}>
            {viewMode === 'graph' ? (
              <div
                className="graph-container"
                style={{ height: Math.max(540, Math.min(680, svgHeight + 48)) }}
              >
                <svg
                  width="100%"
                  height="100%"
                  viewBox={`0 0 ${svgWidth} ${svgHeight}`}
                  preserveAspectRatio="xMidYMid meet"
                  style={{ display: 'block' }}
                >
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
                    <marker
                      id="arrowhead-vuln"
                      markerWidth="8"
                      markerHeight="6"
                      refX="7"
                      refY="3"
                      orient="auto"
                    >
                      <polygon points="0 0, 8 3, 0 6" fill="var(--warning)" />
                    </marker>
                  </defs>

                  {/* Asset -> Asset Edges */}
                  {visibleAssetEdges.map((edge) => {
                    const fromPt = nodePositions[edge.from];
                    const toPt = nodePositions[edge.to];
                    if (!fromPt || !toPt) return null;

                    const edgeKey = `edge-${edge.from}-${edge.to}`;
                    const isSelected = selectedItem?.id === edgeKey;
                    const x1 = fromPt.x + (toPt.x > fromPt.x ? fromPt.width / 2 : toPt.x < fromPt.x ? -fromPt.width / 2 : 0);
                    const y1 = fromPt.y;
                    const x2 = toPt.x + (toPt.x > fromPt.x ? -toPt.width / 2 : toPt.x < fromPt.x ? toPt.width / 2 : 0);
                    const y2 = toPt.y;
                    const midX = (x1 + x2) / 2;
                    const midY = (y1 + y2) / 2;
                    const labelWidth = Math.max(88, edge.type.length * 7 + 16);

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
                          x1={x1}
                          y1={y1}
                          x2={x2}
                          y2={y2}
                          stroke={isSelected ? 'var(--accent)' : 'var(--line)'}
                          strokeWidth={isSelected ? 2.5 : 1.75}
                          markerEnd={isSelected ? 'url(#arrowhead-active)' : 'url(#arrowhead)'}
                        />
                        <rect
                          x={midX - labelWidth / 2}
                          y={midY - 10}
                          width={labelWidth}
                          height={20}
                          rx={4}
                          fill="var(--surface)"
                          stroke={isSelected ? 'var(--accent)' : 'var(--line)'}
                        />
                        <text
                          x={midX}
                          y={midY + 3.5}
                          textAnchor="middle"
                          fontSize="10"
                          fontFamily="var(--font-mono)"
                          fill={isSelected ? 'var(--accent)' : 'var(--muted)'}
                          fontWeight="600"
                        >
                          {edge.type}
                        </text>
                      </g>
                    );
                  })}

                  {/* Asset -> Vulnerability AFFECTED_BY Edges */}
                  {visibleVulnEdges.map((edge) => {
                    const fromPt = nodePositions[edge.from];
                    const toPt = nodePositions[edge.to];
                    if (!fromPt || !toPt) return null;

                    const isSelected =
                      selectedItem?.id === `vuln-${edge.sourceAssetId}-${edge.candidate.vulnerability_id}`;
                    const x1 = fromPt.x + fromPt.width / 2;
                    const y1 = fromPt.y;
                    const x2 = toPt.x - toPt.width / 2;
                    const y2 = toPt.y;
                    const ctrlX = (x1 + x2) / 2;
                    const ctrlY = Math.min(y1, y2) - (Math.abs(x2 - x1) > 300 ? 135 : 0);
                    const midX = 0.25 * x1 + 0.5 * ctrlX + 0.25 * x2;
                    const midY = 0.25 * y1 + 0.5 * ctrlY + 0.25 * y2;

                    return (
                      <g
                        key={edge.id}
                        onClick={() =>
                          handleSelectVulnerability(
                            edge.candidate,
                            edge.sourceAssetId,
                            edge.from,
                            rankCandidates(vulnerabilitiesByAsset[edge.sourceAssetId]?.items || [])
                          )
                        }
                        style={{ cursor: 'pointer' }}
                        role="button"
                        aria-label={`Cạnh AFFECTED_BY từ ${edge.from} tới ${edge.candidate.vulnerability_id}`}
                      >
                        <title>{`AFFECTED_BY (${edge.candidate.match_method}): ${edge.from} -> ${edge.candidate.vulnerability_id}`}</title>
                        <path
                          d={`M ${x1} ${y1} Q ${ctrlX} ${ctrlY} ${x2} ${y2}`}
                          fill="none"
                          stroke={isSelected ? 'var(--danger)' : 'var(--warning)'}
                          strokeWidth={isSelected ? 2.5 : 1.75}
                          strokeDasharray="5 3"
                          markerEnd="url(#arrowhead-vuln)"
                        />
                        <rect
                          x={midX - 48}
                          y={midY - 10}
                          width={96}
                          height={20}
                          rx={4}
                          fill="var(--warning-bg)"
                          stroke="var(--warning)"
                        />
                        <text
                          x={midX}
                          y={midY + 3.5}
                          textAnchor="middle"
                          fontSize="10"
                          fontFamily="var(--font-mono)"
                          fill="var(--warning)"
                          fontWeight="600"
                        >
                          AFFECTED_BY
                        </text>
                      </g>
                    );
                  })}

                  {/* Asset Nodes (Domain, IP, Service, Application) */}
                  {visibleAssetNodes.map((node) => {
                    const pt = nodePositions[node.canonical_key];
                    if (!pt) return null;
                    const isSelected = selectedItem?.id === node.asset_id;
                    const enr = enrichments[node.asset_id];

                    if (node.kind === 'service') {
                      const parsed = parseServiceCanonicalKey(node.canonical_key);
                      const protoLabel = enr?.protocol
                        ? `${parsed.port}/${parsed.transport} · ${enr.protocol}`
                        : `${parsed.port}/${parsed.transport}`;
                      const productLine = enr?.product?.product
                        ? `${enr.product.product}${enr.product.version ? ` ${enr.product.version}` : ''}`
                        : 'Chưa nhận diện sản phẩm';
                      const cpeLine = enr?.product?.cpe ? truncateText(enr.product.cpe, 34) : 'Không có CPE';

                      return (
                        <g
                          key={node.asset_id}
                          transform={`translate(${pt.x - pt.width / 2}, ${pt.y - pt.height / 2})`}
                          onClick={() => handleSelectNode(node)}
                          style={{ cursor: 'pointer' }}
                          role="button"
                          aria-label={`Dịch vụ ${node.canonical_key}`}
                        >
                          <title>{`${node.canonical_key}\n${productLine}\n${enr?.product?.cpe || ''}`}</title>
                          <rect
                            width={pt.width}
                            height={pt.height}
                            rx={8}
                            fill="var(--surface)"
                            stroke={isSelected ? 'var(--accent)' : 'var(--line)'}
                            strokeWidth={isSelected ? 2.5 : 1}
                            filter="drop-shadow(0px 2px 4px rgba(0,0,0,0.06))"
                          />
                          <rect x={12} y={10} width={34} height={18} rx={4} fill="var(--accent-bg)" />
                          <text
                            x={29}
                            y={22.5}
                            textAnchor="middle"
                            fontSize="10"
                            fontWeight="700"
                            fontFamily="var(--font-mono)"
                            fill="var(--accent)"
                          >
                            SVC
                          </text>
                          <text
                            x={52}
                            y={23}
                            fontSize="11"
                            fontWeight="700"
                            fontFamily="var(--font-mono)"
                            fill="var(--ink)"
                          >
                            {truncateText(`${parsed.host}:${protoLabel}`, 28)}
                          </text>
                          <text
                            x={12}
                            y={46}
                            fontSize="12"
                            fontWeight="600"
                            fill={enr?.product?.product ? 'var(--ink)' : 'var(--muted)'}
                          >
                            {truncateText(productLine, 32)}
                          </text>
                          <text
                            x={12}
                            y={66}
                            fontSize="10.5"
                            fontFamily="var(--font-mono)"
                            fill="var(--muted)"
                          >
                            {cpeLine}
                          </text>
                          <text x={12} y={84} fontSize="10" fill="var(--muted)">
                            {node.stale ? 'cũ (stale)' : 'hiệu lực'}
                          </text>
                        </g>
                      );
                    }

                    if (node.kind === 'application') {
                      const appLabel = node.canonical_key.replace(/^app:/, '');
                      const techLine =
                        enr && enr.technologies.length > 0
                          ? enr.technologies.join(', ')
                          : enr?.httpTitle || 'Web application';
                      const subLine = enr?.product?.cpe
                        ? enr.product.cpe
                        : enr?.tlsSubjectCn
                        ? `TLS CN: ${enr.tlsSubjectCn}`
                        : enr?.httpStatus !== undefined
                        ? `HTTP ${enr.httpStatus}`
                        : 'application';

                      return (
                        <g
                          key={node.asset_id}
                          transform={`translate(${pt.x - pt.width / 2}, ${pt.y - pt.height / 2})`}
                          onClick={() => handleSelectNode(node)}
                          style={{ cursor: 'pointer' }}
                          role="button"
                          aria-label={`Ứng dụng ${node.canonical_key}`}
                        >
                          <title>{`${node.canonical_key}\n${techLine}\n${subLine}`}</title>
                          <rect
                            width={pt.width}
                            height={pt.height}
                            rx={8}
                            fill="var(--surface)"
                            stroke={isSelected ? 'var(--accent)' : 'var(--line)'}
                            strokeWidth={isSelected ? 2.5 : 1}
                            filter="drop-shadow(0px 2px 4px rgba(0,0,0,0.06))"
                          />
                          <rect x={12} y={10} width={34} height={18} rx={4} fill="var(--success-bg)" />
                          <text
                            x={29}
                            y={22.5}
                            textAnchor="middle"
                            fontSize="10"
                            fontWeight="700"
                            fontFamily="var(--font-mono)"
                            fill="var(--success)"
                          >
                            APP
                          </text>
                          <text
                            x={54}
                            y={23}
                            fontSize="11.5"
                            fontWeight="600"
                            fontFamily="var(--font-mono)"
                            fill="var(--ink)"
                          >
                            {truncateText(appLabel, 25)}
                          </text>
                          <text x={12} y={47} fontSize="11.5" fontWeight="600" fill="var(--ink)">
                            {truncateText(techLine, 32)}
                          </text>
                          <text
                            x={12}
                            y={67}
                            fontSize="10.5"
                            fontFamily="var(--font-mono)"
                            fill="var(--muted)"
                          >
                            {truncateText(subLine, 34)}
                          </text>
                          <text x={12} y={84} fontSize="10" fill="var(--muted)">
                            {node.stale ? 'cũ (stale)' : 'hiệu lực'}
                          </text>
                        </g>
                      );
                    }

                    // Domain, IP, or other Asset nodes
                    const badgeLabel =
                      node.kind === 'domain' ? 'DNS' : node.kind === 'ip' ? 'IP' : node.kind.toUpperCase().slice(0, 3);
                    const badgeBg = node.kind === 'domain' ? 'var(--accent-bg)' : 'var(--success-bg)';
                    const badgeInk = node.kind === 'domain' ? 'var(--accent)' : 'var(--success)';

                    return (
                      <g
                        key={node.asset_id}
                        transform={`translate(${pt.x - pt.width / 2}, ${pt.y - pt.height / 2})`}
                        onClick={() => handleSelectNode(node)}
                        style={{ cursor: 'pointer' }}
                        role="button"
                        aria-label={`Tài sản ${node.canonical_key}`}
                      >
                        <title>{`${node.canonical_key} (${node.asset_id})`}</title>
                        <rect
                          width={pt.width}
                          height={pt.height}
                          rx={8}
                          fill="var(--surface)"
                          stroke={isSelected ? 'var(--accent)' : 'var(--line)'}
                          strokeWidth={isSelected ? 2.5 : 1}
                          filter="drop-shadow(0px 2px 4px rgba(0,0,0,0.06))"
                        />
                        <rect x={12} y={12} width={32} height={18} rx={4} fill={badgeBg} />
                        <text
                          x={28}
                          y={24.5}
                          textAnchor="middle"
                          fontSize="10"
                          fontWeight="700"
                          fontFamily="var(--font-mono)"
                          fill={badgeInk}
                        >
                          {badgeLabel}
                        </text>
                        <text
                          x={50}
                          y={25}
                          fontSize="11"
                          fontWeight="600"
                          fontFamily="var(--font-mono)"
                          fill="var(--ink)"
                        >
                          {truncateText(node.canonical_key, 24)}
                        </text>
                        <text x={12} y={50} fontSize="10.5" fill="var(--muted)">
                          Loại: <tspan fontWeight="700">{node.kind}</tspan>
                        </text>
                        <rect
                          x={pt.width - 78}
                          y={38}
                          width={66}
                          height={18}
                          rx={3}
                          fill="var(--subtle)"
                          stroke="var(--line)"
                        />
                        <text
                          x={pt.width - 45}
                          y={50.5}
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

                  {/* Vulnerability Nodes (Candidate CVEs) */}
                  {visibleVulnNodes.map((vn) => {
                    const pt = nodePositions[vn.key];
                    if (!pt) return null;
                    const { candidate } = vn;
                    const isSelected =
                      selectedItem?.id === `vuln-${vn.sourceAssetId}-${candidate.vulnerability_id}`;
                    const cvssText =
                      candidate.cvss_base !== null && candidate.cvss_base !== undefined
                        ? `CVSS ${candidate.cvss_base.toFixed(1)}`
                        : 'CVSS —';
                    const epssText =
                      candidate.epss !== null && candidate.epss !== undefined
                        ? `EPSS ${(candidate.epss * 100).toFixed(1)}%`
                        : 'EPSS —';

                    return (
                      <g
                        key={vn.id}
                        transform={`translate(${pt.x - pt.width / 2}, ${pt.y - pt.height / 2})`}
                        onClick={() =>
                          handleSelectVulnerability(
                            candidate,
                            vn.sourceAssetId,
                            vn.sourceAssetKey,
                            rankCandidates(vulnerabilitiesByAsset[vn.sourceAssetId]?.items || [])
                          )
                        }
                        style={{ cursor: 'pointer' }}
                        role="button"
                        aria-label={`Ứng viên CVE ${candidate.vulnerability_id}`}
                      >
                        <title>{`${candidate.vulnerability_id} — Ứng viên (chưa xác minh)\n${cvssText} | ${epssText} | KEV: ${candidate.kev ? 'Có' : 'Không'}`}</title>
                        <rect
                          width={pt.width}
                          height={pt.height}
                          rx={8}
                          fill="var(--surface)"
                          stroke={isSelected ? 'var(--accent)' : candidate.kev ? 'var(--danger)' : 'var(--warning)'}
                          strokeWidth={isSelected ? 2.5 : 1.5}
                          filter="drop-shadow(0px 2px 4px rgba(0,0,0,0.06))"
                        />
                        <rect x={12} y={10} width={36} height={18} rx={4} fill="var(--warning-bg)" />
                        <text
                          x={30}
                          y={22.5}
                          textAnchor="middle"
                          fontSize="10"
                          fontWeight="700"
                          fontFamily="var(--font-mono)"
                          fill="var(--warning)"
                        >
                          CVE
                        </text>
                        <text
                          x={56}
                          y={23}
                          fontSize="12"
                          fontWeight="700"
                          fontFamily="var(--font-mono)"
                          fill="var(--ink)"
                        >
                          {candidate.vulnerability_id}
                        </text>

                        {/* CVSS & KEV badges */}
                        <rect
                          x={12}
                          y={36}
                          width={74}
                          height={20}
                          rx={4}
                          fill="var(--subtle)"
                          stroke="var(--line)"
                        />
                        <text
                          x={49}
                          y={49.5}
                          textAnchor="middle"
                          fontSize="10.5"
                          fontWeight="600"
                          fontFamily="var(--font-mono)"
                          fill="var(--ink)"
                        >
                          {cvssText}
                        </text>

                        {candidate.kev && (
                          <>
                            <rect
                              x={92}
                              y={36}
                              width={42}
                              height={20}
                              rx={4}
                              fill="var(--danger-bg)"
                              stroke="var(--danger)"
                            />
                            <text
                              x={113}
                              y={49.5}
                              textAnchor="middle"
                              fontSize="10"
                              fontWeight="700"
                              fontFamily="var(--font-mono)"
                              fill="var(--danger)"
                            >
                              KEV
                            </text>
                          </>
                        )}

                        <text
                          x={candidate.kev ? 142 : 94}
                          y={49.5}
                          fontSize="10.5"
                          fontWeight="600"
                          fontFamily="var(--font-mono)"
                          fill="var(--muted)"
                        >
                          {epssText}
                        </text>

                        <text x={12} y={74} fontSize="10" fontWeight="600" fill="var(--warning)">
                          Ứng viên (chưa xác minh)
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
                  <span>
                    Nhấp vào tài sản/cạnh để mở Provenance, hoặc nhấp vào nút CVE để mở bảng Ứng viên (chưa xác minh)
                  </span>
                </div>
              </div>
            ) : null}
          </div>

          {/* Right Panel: VulnerabilityPanel or ProvenancePanel */}
          {selectedVulnerability && (
            <VulnerabilityPanel
              data={selectedVulnerability}
              onSelectCandidate={(cand) =>
                handleSelectVulnerability(
                  cand,
                  selectedVulnerability.assetId,
                  selectedVulnerability.assetKey,
                  selectedVulnerability.siblings
                )
              }
              onClose={() => setSelectedVulnerability(null)}
            />
          )}
          {provenanceData && !selectedVulnerability && (
            <ProvenancePanel data={provenanceData} onClose={() => setProvenanceData(null)} />
          )}
        </div>
        </div>
      )}
    </div>
  );
};
