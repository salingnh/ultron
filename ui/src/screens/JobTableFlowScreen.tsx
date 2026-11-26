import React, { useEffect, useState, useMemo, useCallback, useRef } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  type Node,
  type Edge,
  type NodeProps,
  type NodeTypes,
  Position,
  Handle,
  useReactFlow,
  ReactFlowProvider,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import {
  GitBranch,
  Table,
  Filter,
  Clock,
  XCircle,
  Radio,
  Maximize2,
} from 'lucide-react';
import { apiClient, toUiError } from '../api/client';
import type { ScanJob, JobStatus, CampaignFlow, FlowNode, Campaign, UiError } from '../api/types';
import { StatusChip } from '../components/StatusChip';
import { CopyableId } from '../components/CopyableId';
import { ErrorDisplay } from '../components/ErrorDisplay';

// Human readable translations for WaitReason codes
const waitReasonLabels: Record<string, string> = {
  DEPENDENCY_PENDING: 'Chờ job tiền nhiệm (Pending)',
  DEPENDENCY_FAILED: 'Job tiền nhiệm thất bại (Failed)',
  CAMPAIGN_PAUSED: 'Chiến dịch đang tạm dừng',
  BUDGET_EXHAUSTED: 'Hết hạn mức ngân sách',
  CONCURRENCY_LIMIT: 'Đạt trần job đồng thời',
  RATE_LIMITED: 'Giới hạn tốc độ yêu cầu',
  PROVIDER_UNAVAILABLE: 'Công cụ chưa sẵn sàng',
  MANUAL_HOLD: 'Giữ thủ công bởi vận hành',
};

interface JobNodeData extends FlowNode {
  [key: string]: unknown;
}

// Custom React Flow Node for Campaign, Decision, and Jobs
const CustomJobNode: React.FC<NodeProps<Node<JobNodeData>>> = ({ data }) => {
  const isJob = data.type === 'job';
  const isDecision = data.type === 'decision';

  let borderColor = 'var(--line)';
  if (data.status === 'FAILED' || data.status === 'rejected') borderColor = 'var(--danger)';
  else if (data.status === 'RUNNING') borderColor = 'var(--accent)';
  else if (data.status === 'SUCCEEDED' || data.status === 'approved') borderColor = 'var(--success)';
  else if (data.status === 'CANCELLED') borderColor = 'var(--warning)';

  return (
    <div
      style={{
        padding: '10px 14px',
        borderRadius: 'var(--radius-md)',
        backgroundColor: 'var(--surface)',
        border: `2px solid ${borderColor}`,
        color: 'var(--ink)',
        fontSize: 'var(--text-xs)',
        width: 250,
        boxShadow: 'var(--shadow-md)',
      }}
    >
      <Handle type="target" position={Position.Top} style={{ background: 'var(--line)' }} />
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          gap: 6,
          flexWrap: 'wrap',
          marginBottom: 6,
        }}
      >
        <span style={{ fontWeight: 700, textTransform: 'uppercase', fontSize: '11px', color: 'var(--muted)' }}>
          {data.type}
        </span>
        <StatusChip status={data.status} size="sm" kind={isJob ? 'job' : 'campaign'} />
      </div>

      <div
        title={data.label}
        style={{
          fontWeight: 600,
          fontSize: 'var(--text-sm)',
          color: 'var(--ink)',
          marginBottom: 4,
          wordBreak: 'break-word',
          display: '-webkit-box',
          WebkitLineClamp: 4,
          WebkitBoxOrient: 'vertical',
          overflow: 'hidden',
        }}
      >
        {data.label}
      </div>

      {isJob && (
        <div style={{ display: 'flex', gap: 6, marginTop: 4, flexWrap: 'wrap' }}>
          <span className="brand-badge">Lần thử: #{data.attempt || 1}</span>
          <span className="brand-badge">Thế hệ: G{data.generation || 1}</span>
        </div>
      )}

      {isDecision && data.started_at && (
        <div style={{ fontSize: '11px', color: 'var(--muted)', marginTop: 4 }}>
          Duyệt: {new Date(data.started_at).toLocaleTimeString('vi-VN')}
        </div>
      )}

      {data.wait_reason && (
        <div
          style={{
            marginTop: 6,
            padding: '4px 6px',
            backgroundColor: 'var(--warning-bg)',
            color: 'var(--warning)',
            borderRadius: 'var(--radius-sm)',
            border: '1px solid var(--warning)',
            fontSize: '11px',
            display: 'flex',
            alignItems: 'center',
            gap: 4,
          }}
        >
          <Clock size={11} />
          <span>{waitReasonLabels[data.wait_reason.code] || data.wait_reason.code}</span>
        </div>
      )}

      <Handle type="source" position={Position.Bottom} style={{ background: 'var(--line)' }} />
    </div>
  );
};

// Flow view subcomponent wrapped in ReactFlowProvider to use useReactFlow
const FlowGraphView: React.FC<{
  nodes: Node[];
  edges: Edge[];
  nodeTypes: NodeTypes;
  onNodeSelect: (id: string) => void;
}> = ({ nodes, edges, nodeTypes, onNodeSelect }) => {
  const { fitView } = useReactFlow();
  const containerRef = useRef<HTMLDivElement | null>(null);

  const handleFit = useCallback(() => {
    fitView({ padding: 0.12, maxZoom: 1.0, minZoom: 0.2 });
  }, [fitView]);

  useEffect(() => {
    if (nodes.length === 0) return;
    const raf = requestAnimationFrame(() => {
      fitView({ padding: 0.12, maxZoom: 1.0, minZoom: 0.2 });
    });
    return () => cancelAnimationFrame(raf);
  }, [nodes, fitView]);

  useEffect(() => {
    const el = containerRef.current;
    if (!el || typeof ResizeObserver === 'undefined') return;
    const observer = new ResizeObserver(() => {
      if (nodes.length > 0) {
        fitView({ padding: 0.12, maxZoom: 1.0, minZoom: 0.2 });
      }
    });
    observer.observe(el);
    return () => observer.disconnect();
  }, [nodes.length, fitView]);

  return (
    <div
      ref={containerRef}
      className="flow-container"
      style={{ height: 680, width: '100%', maxWidth: '100%', position: 'relative', overflow: 'hidden' }}
      aria-label="Luồng phụ thuộc React Flow"
    >
      <div
        style={{
          position: 'absolute',
          top: 12,
          right: 12,
          zIndex: 5,
          display: 'flex',
          gap: 6,
        }}
      >
        <button
          type="button"
          className="btn btn-sm"
          style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--line)', boxShadow: 'var(--shadow-sm)' }}
          onClick={handleFit}
          title="Thu phóng vừa vặn khung hình (Fit View)"
        >
          <Maximize2 size={13} /> Vừa khung
        </button>
      </div>

      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        fitView
        fitViewOptions={{ padding: 0.12, maxZoom: 1.0, minZoom: 0.2 }}
        minZoom={0.2}
        maxZoom={1.5}
        style={{ width: '100%', height: '100%' }}
        onNodeClick={(_event, node) => onNodeSelect(node.id)}
      >
        <Background color="var(--line)" gap={16} />
        <Controls />
        <MiniMap
          className="flow-minimap"
          nodeColor={(node) => {
            const data = node.data as unknown as JobNodeData | undefined;
            if (data?.status === 'FAILED' || data?.status === 'rejected') return '#ef4444';
            if (data?.status === 'RUNNING') return '#3b82f6';
            if (data?.status === 'SUCCEEDED' || data?.status === 'approved') return '#22c55e';
            if (data?.status === 'CANCELLED') return '#f59e0b';
            return '#64748b';
          }}
          nodeStrokeColor="var(--line)"
          nodeStrokeWidth={1}
          nodeBorderRadius={4}
          maskColor="rgba(0, 0, 0, 0.15)"
          style={{
            background: 'var(--surface)',
            border: '1px solid var(--line)',
            borderRadius: 'var(--radius-md)',
            width: 160,
            height: 100,
          }}
        />
      </ReactFlow>
    </div>
  );
};

export const JobTableFlowScreen: React.FC = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const urlCampaignId = searchParams.get('campaign_id');
  const urlJobId = searchParams.get('job_id');

  const [campaignList, setCampaignList] = useState<Campaign[]>([]);
  const [activeCampaignId, setActiveCampaignId] = useState<string>(urlCampaignId || '');

  const [viewMode, setViewMode] = useState<'table' | 'flow'>('table');
  const [jobs, setJobs] = useState<ScanJob[]>([]);
  const [flowData, setFlowData] = useState<CampaignFlow | null>(null);
  const [loading, setLoading] = useState(true);
  const [jobsError, setJobsError] = useState<UiError | null>(null);
  const [flowError, setFlowError] = useState<UiError | null>(null);
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [selectedJob, setSelectedJob] = useState<ScanJob | null>(null);

  // SSE Live indicator state
  const [sseConnected, setSseConnected] = useState(false);
  const [lastLiveEvent, setLastLiveEvent] = useState<{ type: string; time: string; id: string } | null>(null);

  const nodeTypes = useMemo(() => ({ jobNode: CustomJobNode }), []);

  // Fetch campaigns to resolve default campaign ID and provide campaign switcher
  useEffect(() => {
    apiClient.listCampaigns().then((res) => {
      setCampaignList(res.items);
      if (!urlCampaignId) {
        if (res.items.length > 0) {
          setActiveCampaignId(res.items[0].campaign_id);
        } else if (apiClient.isMock) {
          setActiveCampaignId('01934f6a-0000-7000-8000-000000000001');
        }
      }
    }).catch(() => {
      if (!urlCampaignId && apiClient.isMock) {
        setActiveCampaignId('01934f6a-0000-7000-8000-000000000001');
      }
    });
  }, [urlCampaignId]);

  const effectiveCampaignId = activeCampaignId || urlCampaignId || (apiClient.isMock ? '01934f6a-0000-7000-8000-000000000001' : '');

  const loadData = useCallback(async (showLoading: boolean = true) => {
    if (!effectiveCampaignId) {
      setLoading(false);
      return;
    }
    try {
      if (showLoading) setLoading(true);
      setJobsError(null);
      setFlowError(null);
      const params = {
        campaign_id: effectiveCampaignId,
        status: statusFilter !== 'ALL' ? (statusFilter as JobStatus) : undefined,
      };
      const [jobsResult, flowResult] = await Promise.allSettled([
        apiClient.listJobs(params),
        apiClient.getCampaignFlow(effectiveCampaignId),
      ]);
      if (jobsResult.status === 'fulfilled') {
        setJobs(jobsResult.value.items);
        if (urlJobId) {
          const matched = jobsResult.value.items.find((j) => j.job_id === urlJobId);
          if (matched) setSelectedJob(matched);
        }
      } else {
        setJobsError(toUiError(jobsResult.reason, `/jobs?campaign_id=${effectiveCampaignId}`));
      }
      if (flowResult.status === 'fulfilled') {
        setFlowData(flowResult.value);
      } else {
        setFlowError(toUiError(flowResult.reason, `/campaigns/${effectiveCampaignId}/flow`));
      }
    } finally {
      if (showLoading) setLoading(false);
    }
  }, [effectiveCampaignId, statusFilter, urlJobId]);

  useEffect(() => {
    loadData(true);
  }, [loadData]);

  // Subscribe to SSE events for real-time live updates (<2s)
  useEffect(() => {
    if (!effectiveCampaignId) return;

    const sub = apiClient.subscribeCampaignEvents({
      campaignId: effectiveCampaignId,
      onEvent: (event) => {
        setLastLiveEvent({
          type: event.type,
          time: new Date().toLocaleTimeString('vi-VN'),
          id: event.id,
        });

        // Fast path: optimistic local updates from SSE payload
        const payload = (event.data as { payload?: Record<string, unknown> })?.payload;
        if (payload && typeof payload === 'object') {
          const jobId = payload.job_id as string | undefined;
          const newStatus = payload.status as JobStatus | undefined;

          if (jobId && newStatus) {
            setJobs((prevJobs) =>
              prevJobs.map((j) =>
                j.job_id === jobId
                  ? {
                      ...j,
                      status: newStatus,
                      finished_at: (payload.finished_at as string) || j.finished_at,
                      started_at: (payload.started_at as string) || j.started_at,
                      wait_reason: newStatus === 'RUNNING' || newStatus === 'SUCCEEDED' ? undefined : j.wait_reason,
                    }
                  : j
              )
            );

            setFlowData((prevFlow) => {
              if (!prevFlow) return null;
              return {
                ...prevFlow,
                nodes: prevFlow.nodes.map((node) =>
                  node.id === jobId
                    ? {
                        ...node,
                        status: newStatus,
                        wait_reason: newStatus === 'RUNNING' || newStatus === 'SUCCEEDED' ? undefined : node.wait_reason,
                      }
                    : node
                ),
              };
            });
          }
        }

        // Silent background authoritative sync
        loadData(false);
      },
      onStatusChange: (status) => {
        setSseConnected(status === 'connected');
      },
    });

    return () => {
      sub.close();
    };
  }, [effectiveCampaignId, loadData]);

  const handleCancelJob = async (jobId: string) => {
    const reason = prompt('Nhập lý do hủy job:', 'Hủy thủ công qua giao diện');
    if (!reason) return;
    try {
      await apiClient.cancelJob(jobId, reason);
      loadData(false);
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'Hủy job thất bại');
    }
  };

  // Convert flowData to React Flow Nodes & Edges with hierarchical DAG layout
  const { flowNodes, flowEdges } = useMemo(() => {
    if (!flowData?.nodes) return { flowNodes: [], flowEdges: [] };

    // Compute in-degree and adjacency for topological DAG ranking
    const inDegree: Record<string, number> = {};
    const adj: Record<string, string[]> = {};
    for (const node of flowData.nodes) {
      inDegree[node.id] = 0;
      adj[node.id] = [];
    }
    for (const edge of flowData.edges) {
      if (inDegree[edge.to] !== undefined) {
        inDegree[edge.to] = (inDegree[edge.to] || 0) + 1;
      }
      if (adj[edge.from]) {
        adj[edge.from].push(edge.to);
      }
    }

    // Assign rank/level using topological traversal
    const ranks: Record<string, number> = {};
    const queue: string[] = [];
    for (const node of flowData.nodes) {
      if (inDegree[node.id] === 0) {
        ranks[node.id] = 0;
        queue.push(node.id);
      }
    }

    while (queue.length > 0) {
      const curr = queue.shift()!;
      const currRank = ranks[curr] || 0;
      for (const next of adj[curr] || []) {
        ranks[next] = Math.max(ranks[next] || 0, currRank + 1);
        inDegree[next]--;
        if (inDegree[next] === 0) {
          queue.push(next);
        }
      }
    }

    // Group nodes by rank
    const rankGroups: Record<number, FlowNode[]> = {};
    for (const node of flowData.nodes) {
      const r = ranks[node.id] ?? 0;
      if (!rankGroups[r]) rankGroups[r] = [];
      rankGroups[r].push(node);
    }

    const calculatedNodes: Node[] = [];
    const nodeWidth = 250;
    const nodeGapX = 40;
    const rankGapY = 60;
    const centerX = 500;

    const estimateNodeHeight = (n: FlowNode): number => {
      const lines = Math.min(4, Math.max(1, Math.ceil((n.label?.length || 1) / 26)));
      const headerHeight = 56;
      const bodyHeight = lines * 20 + 16;
      const footerHeight =
        (n.type === 'job' ? 32 : 0) +
        (n.type === 'decision' && n.started_at ? 22 : 0) +
        (n.wait_reason ? 36 : 0);
      return headerHeight + bodyHeight + footerHeight;
    };

    const sortedRanks = Object.keys(rankGroups)
      .map((r) => parseInt(r, 10))
      .sort((a, b) => a - b);

    let currentY = 30;
    for (const r of sortedRanks) {
      const nodesInRank = rankGroups[r];
      const count = nodesInRank.length;
      const totalWidth = count * nodeWidth + (count - 1) * nodeGapX;
      const startX = centerX - totalWidth / 2;
      const maxRankHeight = Math.max(...nodesInRank.map(estimateNodeHeight));

      nodesInRank.forEach((n, idx) => {
        const x = startX + idx * (nodeWidth + nodeGapX);
        calculatedNodes.push({
          id: n.id,
          type: 'jobNode',
          position: { x, y: currentY },
          width: 250,
          style: { width: 250 },
          data: {
            ...n,
            type: n.type,
          },
        });
      });
      currentY += maxRankHeight + rankGapY;
    }

    const calculatedEdges: Edge[] = flowData.edges.map((e, idx) => ({
      id: `edge-${e.from}-${e.to}-${idx}`,
      source: e.from,
      target: e.to,
      type: 'smoothstep',
      label: e.kind,
      animated: e.kind === 'depends_on',
      style: { stroke: 'var(--accent)', strokeWidth: 2 },
      labelStyle: {
        fill: 'var(--ink)',
        fontWeight: 600,
        fontSize: 11,
        fontFamily: 'var(--font-mono)',
      },
      labelBgStyle: {
        fill: 'var(--surface)',
        stroke: 'var(--line)',
        strokeWidth: 1,
      },
      labelBgPadding: [8, 4] as [number, number],
      labelBgBorderRadius: 4,
    }));

    return { flowNodes: calculatedNodes, flowEdges: calculatedEdges };
  }, [flowData]);

  return (
    <div>
      <div className="filter-bar">
        <div>
          <h1 style={{ fontSize: 'var(--text-xl)', fontWeight: 700, color: 'var(--ink)' }}>
            Kế hoạch & Luồng thực thi Job
          </h1>
          <p style={{ fontSize: 'var(--text-sm)', color: 'var(--muted)', marginTop: 2 }}>
            Theo dõi trạng thái, chuỗi phụ thuộc (depends_on), lý do chờ (wait_reason) và cập nhật trực tiếp qua SSE.
          </p>
        </div>

        <div className="filter-group">
          {/* Campaign Selector if multiple campaigns available */}
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

          {/* SSE Live Status indicator */}
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              padding: '4px 8px',
              borderRadius: 'var(--radius-sm)',
              backgroundColor: sseConnected ? 'var(--success-bg)' : 'var(--subtle)',
              color: sseConnected ? 'var(--success)' : 'var(--muted)',
              border: `1px solid ${sseConnected ? 'var(--success)' : 'var(--line)'}`,
              fontSize: 'var(--text-xs)',
            }}
          >
            <Radio size={12} className={sseConnected ? 'pulse-icon' : ''} />
            <span style={{ fontWeight: 600 }}>{sseConnected ? 'SSE Live' : 'SSE Đang kết nối'}</span>
            {lastLiveEvent && (
              <span style={{ fontSize: '11px', color: 'var(--ink)' }}>
                ({lastLiveEvent.type})
              </span>
            )}
          </div>

          {/* View switcher */}
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
              className={`btn btn-sm ${viewMode === 'table' ? 'btn-primary' : ''}`}
              style={{ border: 'none' }}
              onClick={() => setViewMode('table')}
            >
              <Table size={14} /> Danh sách Bảng
            </button>
            <button
              type="button"
              className={`btn btn-sm ${viewMode === 'flow' ? 'btn-primary' : ''}`}
              style={{ border: 'none' }}
              onClick={() => setViewMode('flow')}
            >
              <GitBranch size={14} /> Đồ thị Luồng (React Flow)
            </button>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 'var(--text-xs)', color: 'var(--muted)' }}>
            <Filter size={14} />
            <span>Lọc:</span>
          </div>
          <select
            className="input-search"
            style={{ minWidth: 160 }}
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            aria-label="Lọc trạng thái job"
          >
            <option value="ALL">Tất cả trạng thái</option>
            <option value="QUEUED">Đang chờ (QUEUED)</option>
            <option value="RUNNING">Đang chạy (RUNNING)</option>
            <option value="SUCCEEDED">Thành công (SUCCEEDED)</option>
            <option value="FAILED">Thất bại (FAILED)</option>
            <option value="CANCELLED">Đã hủy (CANCELLED)</option>
          </select>
        </div>
      </div>

      {viewMode === 'table' && jobsError && (
        <div style={{ marginBottom: 16 }}>
          <ErrorDisplay error={jobsError} onRetry={() => loadData(true)} />
        </div>
      )}
      {viewMode === 'flow' && flowError && (
        <div style={{ marginBottom: 16 }}>
          <ErrorDisplay error={flowError} onRetry={() => loadData(true)} />
        </div>
      )}

      {loading ? (
        <div className="state-box">
          <div className="state-title">Đang nạp danh sách job...</div>
        </div>
      ) : !effectiveCampaignId ? (
        <div className="state-box">
          <div className="state-title">Chưa chọn chiến dịch</div>
          <div className="state-desc">Vui lòng tạo hoặc chọn một chiến dịch để theo dõi danh sách job.</div>
        </div>
      ) : viewMode === 'flow' ? (
        <ReactFlowProvider>
          <FlowGraphView
            nodes={flowNodes}
            edges={flowEdges}
            nodeTypes={nodeTypes}
            onNodeSelect={(nodeId) => {
              const matchedJob = jobs.find((j) => j.job_id === nodeId);
              if (matchedJob) setSelectedJob(matchedJob);
            }}
          />
        </ReactFlowProvider>
      ) : (
        <div className="table-container">
          <table className="data-table" aria-label="Bảng chi tiết Job">
            <thead>
              <tr>
                <th>Job & Công cụ</th>
                <th>Trạng thái</th>
                <th>Ưu tiên & Fencing</th>
                <th>Lý do chờ / Chặn điều phối</th>
                <th>Phụ thuộc (depends_on)</th>
                <th>Thời điểm</th>
                <th style={{ textAlign: 'right' }}>Thao tác</th>
              </tr>
            </thead>
            <tbody>
              {jobs.length === 0 ? (
                <tr>
                  <td colSpan={7} style={{ textAlign: 'center', padding: 24, color: 'var(--muted)' }}>
                    Chưa có job nào trong chiến dịch này.
                  </td>
                </tr>
              ) : (
                jobs.map((job) => (
                  <tr key={job.job_id}>
                    <td>
                      <div style={{ fontWeight: 600, color: 'var(--ink)' }}>{job.capability}</div>
                      <div style={{ fontSize: 'var(--text-xs)', color: 'var(--muted)' }}>
                        Công cụ: <strong>{job.provider}</strong> ({job.provider_version || 'n/a'})
                      </div>
                      <div style={{ marginTop: 4 }}>
                        <CopyableId value={job.job_id} prefix="Job ID" />
                      </div>
                    </td>
                    <td>
                      <StatusChip status={job.status} kind="job" />
                      {job.error && (
                        <div style={{ marginTop: 4 }}>
                          <span className="brand-badge" style={{ color: 'var(--danger)', borderColor: 'var(--danger)' }}>
                            Lỗi: {job.error.code}
                          </span>
                          <div style={{ fontSize: '11px', color: 'var(--muted)', marginTop: 2 }}>
                            {job.error.next_action}
                          </div>
                        </div>
                      )}
                      {job.cancel && (
                        <div style={{ marginTop: 4, fontSize: '11px', color: 'var(--warning)' }}>
                          Ý định hủy: {job.cancel.reason}
                        </div>
                      )}
                    </td>
                    <td>
                      <div style={{ fontSize: 'var(--text-xs)' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                          <span style={{ color: 'var(--muted)' }}>Ưu tiên:</span>
                          <strong className="tabular">{job.priority} / 100</strong>
                        </div>
                        <div style={{ display: 'flex', gap: 4, marginTop: 4 }}>
                          <span className="brand-badge">Lần thử: #{job.attempt}</span>
                          <span className="brand-badge">Gen: G{job.generation}</span>
                        </div>
                      </div>
                    </td>
                    <td>
                      {/* Reason text only for a QUEUED job with a wait_reason; show '—' otherwise */}
                      {job.status === 'QUEUED' && job.wait_reason ? (
                        <div>
                          {job.wait_reason ? (
                            <div
                              style={{
                                padding: '6px 8px',
                                backgroundColor: 'var(--warning-bg)',
                                border: '1px solid var(--warning)',
                                borderRadius: 'var(--radius-sm)',
                                fontSize: 'var(--text-xs)',
                                maxWidth: 280,
                              }}
                            >
                              <div style={{ fontWeight: 600, color: 'var(--warning)', display: 'flex', alignItems: 'center', gap: 4 }}>
                                <Clock size={12} />
                                <span>{waitReasonLabels[job.wait_reason.code] || job.wait_reason.code}</span>
                              </div>
                              {job.wait_reason.detail && (
                                <div style={{ fontSize: '11px', color: 'var(--ink)', marginTop: 2 }}>
                                  {job.wait_reason.detail}
                                </div>
                              )}
                              {job.wait_reason.blocking_job_ids?.length ? (
                                <div style={{ marginTop: 4, fontSize: '10.5px', color: 'var(--muted)' }}>
                                  Chặn bởi: {job.wait_reason.blocking_job_ids.join(', ')}
                                </div>
                              ) : null}
                            </div>
                          ) : null}


                        </div>
                      ) : (
                        <span style={{ color: 'var(--muted)', fontSize: 'var(--text-xs)' }}>—</span>
                      )}
                    </td>
                    <td>
                      {job.depends_on?.length ? (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                          {job.depends_on.map((depId, idx) => (
                            <CopyableId key={idx} value={depId} prefix="Dep" />
                          ))}
                        </div>
                      ) : (
                        <span style={{ color: 'var(--muted)', fontSize: 'var(--text-xs)' }}>Không phụ thuộc</span>
                      )}
                    </td>
                    <td>
                      <span className="mono" style={{ fontSize: 'var(--text-xs)', color: 'var(--muted)' }}>
                        Tạo: {new Date(job.created_at).toLocaleTimeString('vi-VN')}
                      </span>
                      {job.finished_at && (
                        <div className="mono" style={{ fontSize: '11px', color: 'var(--success)' }}>
                          Xong: {new Date(job.finished_at).toLocaleTimeString('vi-VN')}
                        </div>
                      )}
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      {(job.status === 'QUEUED' || job.status === 'RUNNING') && (
                        <button
                          type="button"
                          className="btn btn-sm btn-danger"
                          onClick={() => handleCancelJob(job.job_id)}
                          title="Hủy job này"
                        >
                          <XCircle size={13} /> Hủy Job
                        </button>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* Selected Job Drawer if clicked in Flow view */}
      {selectedJob && (
        <div className="modal-overlay" onClick={() => setSelectedJob(null)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ maxWidth: 540 }}>
            <h3 style={{ fontSize: 'var(--text-lg)', fontWeight: 600, marginBottom: 8, display: 'flex', alignItems: 'center', gap: 8 }}>
              <span>Chi tiết Job: {selectedJob.capability}</span>
              <StatusChip status={selectedJob.status} />
            </h3>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 'var(--text-sm)', margin: '14px 0' }}>
              <div>
                <span style={{ color: 'var(--muted)' }}>Job ID:</span>
                <CopyableId value={selectedJob.job_id} truncate={false} />
              </div>
              <div>
                <span style={{ color: 'var(--muted)' }}>Fingerprint SHA-256:</span>
                <CopyableId value={selectedJob.job_fingerprint} truncate={false} />
              </div>
              <div>
                <span style={{ color: 'var(--muted)' }}>Công cụ:</span>{' '}
                <strong>{selectedJob.provider}</strong> (phiên bản {selectedJob.provider_version || 'n/a'}, adapter {selectedJob.adapter_version})
              </div>
              <div>
                <span style={{ color: 'var(--muted)' }}>Fencing token:</span> Lần thử #{selectedJob.attempt}, Thế hệ G{selectedJob.generation}
              </div>
              {selectedJob.status === 'QUEUED' && selectedJob.wait_reason && (
                <div style={{ padding: 10, backgroundColor: 'var(--warning-bg)', borderRadius: 'var(--radius-sm)' }}>
                  <div style={{ fontWeight: 600, color: 'var(--warning)' }}>
                    Lý do chờ: {waitReasonLabels[selectedJob.wait_reason.code] || selectedJob.wait_reason.code}
                  </div>
                  <div style={{ fontSize: 'var(--text-xs)', marginTop: 4 }}>
                    {selectedJob.wait_reason.detail}
                  </div>
                </div>
              )}
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
              <button type="button" className="btn" onClick={() => setSelectedJob(null)}>
                Đóng
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
