import React, { useEffect, useState, useMemo, useCallback } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  type Node,
  type Edge,
  Position,
  Handle,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import {
  GitBranch,
  Table,
  Filter,
  Clock,
  AlertTriangle,
  XCircle,
  ShieldAlert,
} from 'lucide-react';
import { apiClient } from '../api/client';
import type { ScanJob, JobStatus, CampaignFlow, FlowNode } from '../api/types';
import { StatusChip } from '../components/StatusChip';
import { CopyableId } from '../components/CopyableId';
import { ErrorDisplay } from '../components/ErrorDisplay';

// Human readable translations for WaitReason codes
const waitReasonLabels: Record<string, string> = {
  DEPENDENCY_PENDING: 'Chờ job tiền nhiệm (Pending)',
  DEPENDENCY_FAILED: 'Job tiền nhiệm thất bại (Failed)',
  CAMPAIGN_PAUSED: 'Chiến dịch đang tạm dừng',
  BUDGET_EXHAUSTED: 'Hết hạn mức ngân sách',
  WINDOW_CLOSED: 'Ngoài khung giờ cho phép',
  CONCURRENCY_LIMIT: 'Đạt trần job đồng thời',
  RATE_LIMITED: 'Giới hạn tốc độ yêu cầu',
  PROVIDER_UNAVAILABLE: 'Công cụ chưa sẵn sàng',
  MANUAL_HOLD: 'Giữ thủ công bởi vận hành',
};

interface JobNodeData extends FlowNode {
  dispatch_block_reasons?: string[];
}

// Custom React Flow Node for Jobs
const CustomJobNode: React.FC<{ data: JobNodeData }> = ({ data }) => {
  const isJob = data.type === 'job';
  return (
    <div
      style={{
        padding: '10px 14px',
        borderRadius: 'var(--radius-md)',
        backgroundColor: 'var(--surface)',
        border: `2px solid ${data.status === 'FAILED' ? 'var(--danger)' : data.status === 'RUNNING' ? 'var(--accent)' : data.status === 'SUCCEEDED' ? 'var(--success)' : 'var(--line)'}`,
        color: 'var(--ink)',
        fontSize: 'var(--text-xs)',
        minWidth: 220,
        boxShadow: 'var(--shadow-md)',
      }}
    >
      <Handle type="target" position={Position.Top} style={{ background: 'var(--line)' }} />
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
        <span style={{ fontWeight: 700, textTransform: 'uppercase', fontSize: '11px', color: 'var(--muted)' }}>
          {data.type}
        </span>
        <StatusChip status={data.status} waitReason={data.wait_reason} size="sm" kind={isJob ? 'job' : 'campaign'} />
      </div>

      <div style={{ fontWeight: 600, fontSize: 'var(--text-sm)', color: 'var(--ink)', marginBottom: 4 }}>
        {data.label}
      </div>

      {isJob && (
        <div style={{ display: 'flex', gap: 6, marginTop: 4, flexWrap: 'wrap' }}>
          <span className="brand-badge">Lần thử: #{data.attempt || 1}</span>
          <span className="brand-badge">Thế hệ: G{data.generation || 1}</span>
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

      {data.dispatch_block_reasons?.length ? (
        <div
          style={{
            marginTop: 6,
            padding: '4px 6px',
            backgroundColor: 'var(--danger-bg)',
            color: 'var(--danger)',
            borderRadius: 'var(--radius-sm)',
            border: '1px solid var(--danger)',
            fontSize: '11px',
            display: 'flex',
            alignItems: 'center',
            gap: 4,
          }}
        >
          <AlertTriangle size={11} />
          <span>Chặn dispatch: {data.dispatch_block_reasons[0]}</span>
        </div>
      ) : null}

      <Handle type="source" position={Position.Bottom} style={{ background: 'var(--line)' }} />
    </div>
  );
};

export const JobTableFlowScreen: React.FC = () => {
  const [searchParams] = useSearchParams();
  const campaignId = searchParams.get('campaign_id') || '01934f6a-0000-7000-8000-000000000001';

  const [viewMode, setViewMode] = useState<'table' | 'flow'>('table');
  const [jobs, setJobs] = useState<ScanJob[]>([]);
  const [flowData, setFlowData] = useState<CampaignFlow | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [selectedJob, setSelectedJob] = useState<ScanJob | null>(null);

  const nodeTypes = useMemo(() => ({ jobNode: CustomJobNode }), []);

  const loadData = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const params = {
        campaign_id: campaignId,
        status: statusFilter !== 'ALL' ? (statusFilter as JobStatus) : undefined,
      };
      const [jobsRes, flowRes] = await Promise.all([
        apiClient.listJobs(params),
        apiClient.getCampaignFlow(campaignId),
      ]);
      setJobs(jobsRes.items);
      setFlowData(flowRes);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Không thể tải dữ liệu Job hoặc Flow');
    } finally {
      setLoading(false);
    }
  }, [campaignId, statusFilter]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleCancelJob = async (jobId: string) => {
    const reason = prompt('Nhập lý do hủy job:', 'Hủy thủ công qua giao diện');
    if (!reason) return;
    try {
      await apiClient.cancelJob(jobId, reason);
      loadData();
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
    const nodeWidth = 260;
    const nodeGapX = 80;
    const levelHeight = 170;
    const startY = 40;
    const centerX = 500;

    for (const [rankStr, nodesInRank] of Object.entries(rankGroups)) {
      const r = parseInt(rankStr, 10);
      const count = nodesInRank.length;
      const totalWidth = count * nodeWidth + (count - 1) * nodeGapX;
      const startX = centerX - totalWidth / 2;

      nodesInRank.forEach((n, idx) => {
        const x = startX + idx * (nodeWidth + nodeGapX);
        const y = startY + r * levelHeight;
        calculatedNodes.push({
          id: n.id,
          type: 'jobNode',
          position: { x, y },
          data: {
            ...n,
            type: n.type,
          },
        });
      });
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
            Theo dõi trạng thái, chuỗi phụ thuộc (depends_on), lý do chờ (wait_reason) và lý do chặn điều phối.
          </p>
        </div>

        <div className="filter-group">
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

      {error && <ErrorDisplay error={error} onRetry={loadData} />}

      {loading ? (
        <div className="state-box">
          <div className="state-title">Đang nạp danh sách job...</div>
        </div>
      ) : viewMode === 'flow' ? (
        <div className="flow-container" style={{ height: 620 }} aria-label="Luồng phụ thuộc React Flow">
          <ReactFlow
            nodes={flowNodes}
            edges={flowEdges}
            nodeTypes={nodeTypes}
            fitView
            fitViewOptions={{ padding: 0.2 }}
            onNodeClick={(_event, node) => {
              const matchedJob = jobs.find((j) => j.job_id === node.id);
              if (matchedJob) setSelectedJob(matchedJob);
            }}
          >
            <Background color="var(--line)" gap={16} />
            <Controls />
            <MiniMap style={{ background: 'var(--surface)', border: '1px solid var(--line)' }} />
          </ReactFlow>
        </div>
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
              {jobs.map((job) => (
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
                    <StatusChip status={job.status} waitReason={job.wait_reason} kind="job" />
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
                    {/* Wait Reason rendering */}
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

                    {/* Dispatch Block Reasons rendering */}
                    {job.dispatch_block_reasons?.length ? (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 4, marginTop: job.wait_reason ? 4 : 0 }}>
                        {job.dispatch_block_reasons.map((reason, idx) => (
                          <div
                            key={idx}
                            style={{
                              padding: '4px 6px',
                              backgroundColor: 'var(--danger-bg)',
                              border: '1px solid var(--danger)',
                              borderRadius: 'var(--radius-sm)',
                              fontSize: '11px',
                              color: 'var(--danger)',
                              display: 'flex',
                              alignItems: 'center',
                              gap: 4,
                            }}
                          >
                            <ShieldAlert size={12} />
                            <strong>{reason}</strong>
                          </div>
                        ))}
                      </div>
                    ) : null}

                    {!job.wait_reason && !job.dispatch_block_reasons?.length && (
                      <span style={{ color: 'var(--muted)', fontSize: 'var(--text-xs)' }}>Sẵn sàng / Đang tiến hành</span>
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
              ))}
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
              {selectedJob.wait_reason && (
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
