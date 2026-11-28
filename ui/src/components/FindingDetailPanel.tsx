import React, { useEffect, useMemo, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  AlertTriangle,
  CheckCircle2,
  Clock,
  Download,
  ExternalLink,
  EyeOff,
  FileText,
  GitCommit,
  KeyRound,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  X,
} from 'lucide-react';
import { ApiError, apiClient, generateIdempotencyKey, toUiError } from '../api/client';
import type {
  AppError,
  Finding,
  FindingHistoryResponse,
  FindingStatus,
  ProvenanceDetail,
  SeverityAssessment,
  UiError,
} from '../api/types';
import {
  FINDING_STATUS_META,
  formatAssessmentTrigger,
  formatTransitionCause,
  getAllowedOperatorTransitions,
  getLatestTransitionSeq,
  isSafeHttpUrl,
  resolveSourceRefLink,
} from '../utils/findings';
import { CopyableId } from './CopyableId';
import { ErrorDisplay, InlineFieldError } from './ErrorDisplay';
import { SeverityChip, StatusChip } from './StatusChip';

interface FindingDetailPanelProps {
  finding: Finding | null;
  history: FindingHistoryResponse | null;
  historyLoading: boolean;
  historyError: UiError | null;
  provenance: ProvenanceDetail | null;
  provenanceLoading: boolean;
  provenanceError: UiError | null;
  campaignId?: string;
  onRetryHistory: () => void;
  onRefreshFinding: () => void;
  onTransitionSuccess: (updated: Finding) => void;
  onClose: () => void;
}

function renderAssessmentActor(assessment: SeverityAssessment): string {
  const { assessed_by: by } = assessment;
  if (by.kind === 'agent') {
    const model = by.model ? `model ${by.model}` : 'agent';
    const prompt = by.prompt_version ? ` (${by.prompt_version})` : '';
    return `Agent · ${model}${prompt}`;
  }
  if (by.kind === 'operator') {
    return `Operator · ${by.actor?.id || 'operator'}`;
  }
  return 'Quy tắc hệ thống (rule / fallback)';
}

function formatLocationValue(val: unknown): string {
  if (val === null || val === undefined) return '—';
  if (typeof val === 'string' || typeof val === 'number' || typeof val === 'boolean') {
    return String(val);
  }
  return JSON.stringify(val);
}

export const FindingDetailPanel: React.FC<FindingDetailPanelProps> = ({
  finding,
  history,
  historyLoading,
  historyError,
  provenance,
  provenanceLoading,
  provenanceError,
  campaignId,
  onRetryHistory,
  onRefreshFinding,
  onTransitionSuccess,
  onClose,
}) => {
  const allowedTargets = useMemo(
    () => (finding ? getAllowedOperatorTransitions(finding.status) : []),
    [finding]
  );

  const [targetStatus, setTargetStatus] = useState<FindingStatus | ''>('');
  const [reason, setReason] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [clientReasonError, setClientReasonError] = useState<string | undefined>(undefined);
  const [serverFieldError, setServerFieldError] = useState<AppError | null>(null);
  const [submitError, setSubmitError] = useState<UiError | null>(null);
  const [conflictStaleSeq, setConflictStaleSeq] = useState(false);
  const [submitSuccess, setSubmitSuccess] = useState<string | null>(null);

  const currentSeq = useMemo(() => getLatestTransitionSeq(history), [history]);
  const idempotencyKeyRef = useRef<{ signature: string; key: string } | null>(null);

  // Sync default target status when selected finding or its status changes
  const findingId = finding?.finding_id || '';
  const findingStatus = finding?.status || '';
  useEffect(() => {
    if (!finding) {
      setTargetStatus('');
      return;
    }
    const targets = getAllowedOperatorTransitions(finding.status);
    setTargetStatus((prev) => (prev && targets.includes(prev) ? prev : targets[0] || ''));
    setClientReasonError(undefined);
    setServerFieldError(null);
    setSubmitError(null);
    setConflictStaleSeq(false);
  }, [finding, findingId, findingStatus]);

  useEffect(() => {
    setSubmitSuccess(null);
    setReason('');
    idempotencyKeyRef.current = null;
  }, [findingId]);

  if (!finding) return null;

  const sortedAssessments = history?.assessments
    ? [...history.assessments].sort((a, b) => b.input_revision - a.input_revision)
    : [];
  const assessment = finding.severity_assessment ?? sortedAssessments[0];
  const locationEntries = finding.location ? Object.entries(finding.location) : [];
  const sortedRuns = history
    ? [...history.runs].sort((a, b) => Date.parse(b.observed_at) - Date.parse(a.observed_at))
    : [];
  const sortedTransitions = history
    ? [...history.transitions].sort((a, b) => a.seq - b.seq)
    : [];

  const handleTransitionSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetStatus || historyLoading || historyError) return;

    const trimmedReason = reason.trim();
    if (trimmedReason.length < 3) {
      setClientReasonError('Lý do chuyển trạng thái là bắt buộc (tối thiểu 3 ký tự).');
      return;
    }

    setClientReasonError(undefined);
    setServerFieldError(null);
    setSubmitError(null);
    setConflictStaleSeq(false);
    setSubmitSuccess(null);

    const signature = `${finding.finding_id}|${targetStatus}|${trimmedReason}|${currentSeq}`;
    if (!idempotencyKeyRef.current || idempotencyKeyRef.current.signature !== signature) {
      idempotencyKeyRef.current = {
        signature,
        key: generateIdempotencyKey(),
      };
    }

    try {
      setSubmitting(true);
      const updated = await apiClient.transitionFinding(
        finding.finding_id,
        {
          to: targetStatus,
          reason: trimmedReason,
          expected_seq: currentSeq,
        },
        { idempotencyKey: idempotencyKeyRef.current.key }
      );
      idempotencyKeyRef.current = null;
      setReason('');
      setSubmitSuccess(
        `Đã chuyển trạng thái sang ${FINDING_STATUS_META[updated.status]?.label || updated.status}.`
      );
      onTransitionSuccess(updated);
    } catch (err: unknown) {
      const uiErr = toUiError(err, `/findings/${finding.finding_id}/transitions`);
      setSubmitError(uiErr);
      if (err instanceof ApiError) {
        const isStaleOrStateConflict =
          err.status === 409 &&
          (err.code !== 'IDEMPOTENCY_CONFLICT' ||
            /expected_seq|transition_seq|stale|changed while|transitions\.v2\.yaml/i.test(
              err.message
            ));
        if (isStaleOrStateConflict) {
          setConflictStaleSeq(true);
        }
        if (err.appError?.field === '/reason') {
          setServerFieldError(err.appError);
        }
      }
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <aside className="finding-detail-panel" aria-label="Bảng chi tiết Finding">
      {/* Header */}
      <div className="provenance-header">
        <div className="provenance-title" style={{ minWidth: 0 }}>
          <ShieldAlert size={18} style={{ color: 'var(--accent)', flexShrink: 0 }} />
          <span>Chi tiết Finding</span>
        </div>
        <button
          type="button"
          onClick={onClose}
          className="btn btn-sm"
          style={{ padding: '2px 6px', border: 'none', background: 'transparent' }}
          aria-label="Đóng chi tiết finding"
        >
          <X size={16} />
        </button>
      </div>

      <div>
        <h2
          style={{
            fontSize: 'var(--text-base)',
            fontWeight: 700,
            color: 'var(--ink)',
            lineHeight: 1.35,
            wordBreak: 'break-word',
          }}
        >
          {finding.title}
        </h2>
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginTop: 8 }}>
          <SeverityChip severity={finding.severity} />
          <StatusChip status={finding.status} kind="finding" />
          {finding.category && <span className="brand-badge">{finding.category}</span>}
        </div>
        <div style={{ marginTop: 8 }}>
          <CopyableId value={finding.finding_id} prefix="Finding ID" truncate={false} />
        </div>
      </div>

      {/* CVE IDs */}
      <section className="detail-section" aria-label="Mã CVE liên quan">
        <span className="provenance-label">Mã CVE / Lỗ hổng (vulnerability_ids)</span>
        {finding.vulnerability_ids && finding.vulnerability_ids.length > 0 ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {finding.vulnerability_ids.map((vulnId) => {
              const isCve = /^CVE-\d{4}-\d+$/i.test(vulnId);
              return (
                <div
                  key={vulnId}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    gap: 8,
                    flexWrap: 'wrap',
                    padding: '6px 8px',
                    borderRadius: 'var(--radius-sm)',
                    backgroundColor: 'var(--subtle)',
                    border: '1px solid var(--line)',
                  }}
                >
                  {isCve ? (
                    <a
                      href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(vulnId)}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="mono"
                      style={{
                        fontSize: 'var(--text-sm)',
                        fontWeight: 700,
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: 4,
                      }}
                    >
                      <span>{vulnId}</span>
                      <ExternalLink size={12} />
                    </a>
                  ) : (
                    <span className="mono" style={{ fontSize: 'var(--text-sm)', fontWeight: 700 }}>
                      {vulnId}
                    </span>
                  )}
                  <CopyableId value={vulnId} truncate={false} />
                </div>
              );
            })}
          </div>
        ) : (
          <span style={{ fontSize: 'var(--text-xs)', color: 'var(--muted)' }}>
            Không gắn mã CVE (phát hiện từ cấu hình / bề mặt).
          </span>
        )}
      </section>

      {/* Severity & Assessment (or UNRATED fallback) */}
      <section className="detail-section" aria-label="Đánh giá mức nghiêm trọng">
        <span className="provenance-label">Mức nghiêm trọng &amp; Đánh giá (C07)</span>

        {assessment ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
              <SeverityChip severity={assessment.severity} />
              <span className="brand-badge">{formatAssessmentTrigger(assessment.trigger)}</span>
              <span className="brand-badge">rev #{assessment.input_revision}</span>
            </div>

            <div style={{ fontSize: 'var(--text-xs)', color: 'var(--muted)' }}>
              <strong>Nguồn đánh giá:</strong> {renderAssessmentActor(assessment)}
            </div>

            {assessment.failure ? (
              <div
                role="status"
                style={{
                  padding: '8px 10px',
                  borderRadius: 'var(--radius-md)',
                  backgroundColor: 'var(--warning-bg)',
                  border: '1px solid var(--warning)',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 6,
                  fontSize: 'var(--text-xs)',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: 'var(--warning)', fontWeight: 700 }}>
                  <AlertTriangle size={14} />
                  <span>UNRATED — Fallback do đánh giá tự động thất bại</span>
                </div>
                <div style={{ color: 'var(--ink)' }}>
                  <strong>Mã lỗi:</strong> <span className="mono">{assessment.failure.code}</span> ·{' '}
                  <strong>Lần thử:</strong> {assessment.failure.attempt}
                  {assessment.failure.finish_reason ? ` · ${assessment.failure.finish_reason}` : ''}
                </div>
                <div style={{ color: 'var(--ink)', wordBreak: 'break-word' }}>
                  {assessment.failure.message}
                </div>
                {(assessment.failure.provider || assessment.failure.model) && (
                  <div className="mono" style={{ color: 'var(--muted)' }}>
                    {[assessment.failure.provider, assessment.failure.model].filter(Boolean).join(' / ')}
                  </div>
                )}

                {assessment.raw_signals && assessment.raw_signals.length > 0 && (
                  <div>
                    <div style={{ fontWeight: 600, color: 'var(--ink)', marginBottom: 4 }}>
                      Tín hiệu thô đối chiếu (raw_signals):
                    </div>
                    <ul style={{ paddingLeft: 16, display: 'flex', flexDirection: 'column', gap: 3 }}>
                      {assessment.raw_signals.map((sig, idx) => (
                        <li key={`${sig.kind}-${sig.ref}-${idx}`} style={{ wordBreak: 'break-word' }}>
                          <span className="brand-badge">{sig.kind}</span>{' '}
                          <span className="mono">{sig.ref}</span>
                          {sig.value ? ` — ${sig.value}` : ''}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            ) : null}

            {assessment.reasons.length > 0 && (
              <div>
                <div style={{ fontSize: 'var(--text-xs)', fontWeight: 600, color: 'var(--ink)', marginBottom: 3 }}>
                  Lý do đánh giá:
                </div>
                <ul style={{ paddingLeft: 16, fontSize: 'var(--text-xs)', color: 'var(--ink)', display: 'flex', flexDirection: 'column', gap: 3 }}>
                  {assessment.reasons.map((r, idx) => (
                    <li key={idx} style={{ wordBreak: 'break-word' }}>
                      {r}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {!assessment.failure && assessment.source_refs && assessment.source_refs.length > 0 && (
              <div>
                <div style={{ fontSize: 'var(--text-xs)', fontWeight: 600, color: 'var(--ink)', marginBottom: 3 }}>
                  Nguồn trích dẫn (source_refs):
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  {assessment.source_refs.map((ref, idx) => {
                    const resolved = resolveSourceRefLink(ref, finding);
                    return (
                      <div
                        key={`${ref.kind}-${ref.ref}-${idx}`}
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          gap: 6,
                          flexWrap: 'wrap',
                          fontSize: 'var(--text-xs)',
                        }}
                      >
                        <span className="brand-badge">{ref.kind}</span>
                        {resolved ? (
                          resolved.type === 'external' ? (
                            <a
                              href={resolved.href}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="mono"
                              style={{
                                wordBreak: 'break-all',
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: 4,
                              }}
                            >
                              <span>{ref.ref}</span>
                              <ExternalLink size={11} />
                            </a>
                          ) : (
                            <a
                              href={resolved.href}
                              className="mono"
                              style={{ wordBreak: 'break-all' }}
                              onClick={(e) => {
                                const target = document.getElementById(resolved.href.slice(1));
                                if (target) {
                                  e.preventDefault();
                                  target.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
                                }
                              }}
                            >
                              {ref.ref}
                            </a>
                          )
                        ) : (
                          <span className="mono" style={{ wordBreak: 'break-all', color: 'var(--ink)' }}>
                            {ref.ref}
                          </span>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {/* Signals snapshot (CVSS / KEV / EPSS / Exposure) */}
            {(assessment.inputs.cvss ||
              assessment.inputs.kev ||
              assessment.inputs.epss ||
              assessment.inputs.exposure ||
              assessment.inputs.scanner_severity) && (
              <div
                style={{
                  padding: '8px 10px',
                  borderRadius: 'var(--radius-sm)',
                  backgroundColor: 'var(--subtle)',
                  border: '1px solid var(--line)',
                  display: 'flex',
                  flexWrap: 'wrap',
                  gap: 8,
                  fontSize: 'var(--text-xs)',
                }}
              >
                {assessment.inputs.cvss?.base_score !== undefined && (
                  <span className="mono">
                    <strong>CVSS:</strong> {assessment.inputs.cvss.base_score.toFixed(1)}
                  </span>
                )}
                {assessment.inputs.epss?.score !== undefined && (
                  <span className="mono">
                    <strong>EPSS:</strong> {(assessment.inputs.epss.score * 100).toFixed(2)}%
                  </span>
                )}
                {assessment.inputs.kev && (
                  <span className={assessment.inputs.kev.listed ? 'status-chip danger' : 'status-chip neutral'}>
                    {assessment.inputs.kev.listed ? 'Trong CISA KEV' : 'Không trong KEV'}
                  </span>
                )}
                {assessment.inputs.exposure && (
                  <span className="brand-badge">Phơi nhiễm: {assessment.inputs.exposure}</span>
                )}
                {assessment.inputs.scanner_severity && (
                  <span className="brand-badge">Scanner: {assessment.inputs.scanner_severity}</span>
                )}
              </div>
            )}

            {assessment.uncertainty.length > 0 && (
              <div>
                <div style={{ fontSize: 'var(--text-xs)', fontWeight: 600, color: 'var(--muted)', marginBottom: 3 }}>
                  Điểm chưa chắc chắn:
                </div>
                <ul style={{ paddingLeft: 16, fontSize: 'var(--text-xs)', color: 'var(--muted)', display: 'flex', flexDirection: 'column', gap: 2 }}>
                  {assessment.uncertainty.map((u, idx) => (
                    <li key={idx}>{u}</li>
                  ))}
                </ul>
              </div>
            )}

            {assessment.recommended_actions.length > 0 && (
              <div>
                <div style={{ fontSize: 'var(--text-xs)', fontWeight: 600, color: 'var(--ink)', marginBottom: 3 }}>
                  Khuyến nghị xử lý:
                </div>
                <ul style={{ paddingLeft: 16, fontSize: 'var(--text-xs)', color: 'var(--ink)', display: 'flex', flexDirection: 'column', gap: 2 }}>
                  {assessment.recommended_actions.map((a, idx) => (
                    <li key={idx}>{a}</li>
                  ))}
                </ul>
              </div>
            )}

            <div className="mono" style={{ fontSize: '11px', color: 'var(--muted)', wordBreak: 'break-all' }}>
              dedup_key: {assessment.dedup_key}
            </div>
          </div>
        ) : (
          <div
            style={{
              padding: '8px 10px',
              borderRadius: 'var(--radius-sm)',
              backgroundColor: 'var(--subtle)',
              border: '1px dashed var(--line)',
              fontSize: 'var(--text-xs)',
              color: 'var(--muted)',
            }}
          >
            {finding.severity === 'UNRATED'
              ? 'UNRATED — Chưa có bản đánh giá mức nghiêm trọng.'
              : `Mức nghiêm trọng ${finding.severity} (chưa kèm chi tiết assessment từ API).`}
          </div>
        )}
      </section>

      {/* Provider sources & Classification */}
      <section className="detail-section" aria-label="Nguồn cung cấp và phân loại">
        <span className="provenance-label">Nguồn phát hiện (Providers) &amp; So khớp</span>

        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
          {finding.providers && finding.providers.length > 0 ? (
            finding.providers.map((provider) => (
              <span key={provider} className="brand-badge">
                {provider}
              </span>
            ))
          ) : (
            <span style={{ fontSize: 'var(--text-xs)', color: 'var(--muted)' }}>
              Không có thông tin provider
            </span>
          )}
          {finding.match_method && (
            <span className="status-chip accent">{finding.match_method}</span>
          )}
        </div>

        {typeof finding.confidence === 'number' && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ fontSize: 'var(--text-xs)', color: 'var(--muted)' }}>Độ tin cậy:</span>
            <div
              style={{
                flex: 1,
                height: 7,
                backgroundColor: 'var(--subtle)',
                borderRadius: 'var(--radius-sm)',
                overflow: 'hidden',
                border: '1px solid var(--line)',
              }}
            >
              <div
                style={{
                  width: `${Math.round(finding.confidence * 100)}%`,
                  height: '100%',
                  backgroundColor: finding.confidence >= 0.8 ? 'var(--success)' : 'var(--warning)',
                }}
              />
            </div>
            <span className="mono" style={{ fontSize: 'var(--text-xs)', fontWeight: 600 }}>
              {(finding.confidence * 100).toFixed(0)}%
            </span>
          </div>
        )}

        <div style={{ fontSize: 'var(--text-xs)', color: 'var(--muted)' }}>
          <strong>Rule ID:</strong> <span className="mono">{finding.rule_id}</span>
        </div>

        {locationEntries.length > 0 && (
          <div
            style={{
              padding: '6px 8px',
              borderRadius: 'var(--radius-sm)',
              backgroundColor: 'var(--subtle)',
              border: '1px solid var(--line)',
              fontSize: 'var(--text-xs)',
              display: 'flex',
              flexDirection: 'column',
              gap: 3,
            }}
          >
            {locationEntries.map(([k, v]) => (
              <div key={k} style={{ wordBreak: 'break-word' }}>
                <span style={{ color: 'var(--muted)' }}>{k}:</span>{' '}
                <span className="mono" style={{ color: 'var(--ink)' }}>
                  {formatLocationValue(v)}
                </span>
              </div>
            ))}
          </div>
        )}

        <div>
          <span className="provenance-label" style={{ display: 'block', marginBottom: 4 }}>
            Fingerprint (SHA-256)
          </span>
          <CopyableId value={finding.fingerprint} truncate={false} />
        </div>

        {finding.secret && (
          <div
            style={{
              padding: '8px 10px',
              borderRadius: 'var(--radius-md)',
              backgroundColor: 'var(--danger-bg)',
              border: '1px solid var(--danger)',
              display: 'flex',
              flexDirection: 'column',
              gap: 6,
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 'var(--text-xs)', fontWeight: 700, color: 'var(--danger)' }}>
              <KeyRound size={14} />
              <span>Bằng chứng Secret (hiển thị đầy đủ theo chính sách)</span>
            </div>
            {finding.secret.detector && (
              <div style={{ fontSize: 'var(--text-xs)' }}>
                <strong>Detector:</strong> <span className="mono">{finding.secret.detector}</span>
              </div>
            )}
            {finding.secret.value !== undefined && (
              <div>
                <div style={{ fontSize: '11px', color: 'var(--muted)', marginBottom: 2 }}>Giá trị:</div>
                <CopyableId value={finding.secret.value} truncate={false} />
              </div>
            )}
            {finding.secret.fingerprint && (
              <div>
                <div style={{ fontSize: '11px', color: 'var(--muted)', marginBottom: 2 }}>Secret Fingerprint:</div>
                <CopyableId value={finding.secret.fingerprint} truncate={false} />
              </div>
            )}
          </div>
        )}
      </section>

      {/* Evidence (SHA-256 + Download) */}
      <section className="detail-section" aria-label="Bằng chứng và SHA-256">
        <span className="provenance-label">Bằng chứng (Evidence · {finding.evidence.length})</span>
        {finding.evidence.length === 0 ? (
          <span style={{ fontSize: 'var(--text-xs)', color: 'var(--muted)' }}>
            Chưa có bằng chứng đính kèm.
          </span>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {finding.evidence.map((ev) => (
              <div
                key={ev.evidence_id}
                id={`finding-evidence-${ev.evidence_id}`}
                style={{
                  padding: '8px 10px',
                  borderRadius: 'var(--radius-md)',
                  border: '1px solid var(--line)',
                  backgroundColor: 'var(--subtle)',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 6,
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 6, flexWrap: 'wrap' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
                    <FileText size={13} style={{ color: 'var(--muted)' }} />
                    {ev.source_tool && <span className="brand-badge">{ev.source_tool}</span>}
                    {ev.media_type && <span className="brand-badge">{ev.media_type}</span>}
                  </div>
                  {isSafeHttpUrl(ev.download_url) ? (
                    <a
                      href={ev.download_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      download
                      className="btn btn-sm btn-primary"
                      style={{ textDecoration: 'none' }}
                    >
                      <Download size={12} /> Tải bằng chứng
                    </a>
                  ) : (
                    <span style={{ fontSize: '11px', color: 'var(--muted)' }}>
                      Chưa có signed download URL
                    </span>
                  )}
                </div>

                <div>
                  <div style={{ fontSize: '11px', color: 'var(--muted)', marginBottom: 2 }}>Evidence ID:</div>
                  <CopyableId value={ev.evidence_id} truncate={false} />
                </div>

                <div>
                  <div style={{ fontSize: '11px', color: 'var(--muted)', marginBottom: 2 }}>SHA-256:</div>
                  <CopyableId value={ev.sha256} truncate={false} />
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      {/* Provenance */}
      <section id="finding-provenance" className="detail-section" aria-label="Nguồn gốc tài sản">
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
          <span className="provenance-label" style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}>
            <ShieldCheck size={13} style={{ color: 'var(--accent)' }} />
            Nguồn gốc (Provenance)
          </span>
          <Link
            to={campaignId ? `/assets?campaign_id=${encodeURIComponent(campaignId)}` : '/assets'}
            style={{ fontSize: 'var(--text-xs)' }}
          >
            Xem trên đồ thị
          </Link>
        </div>

        <CopyableId value={finding.asset_key} prefix="Asset Key" truncate={false} />
        <CopyableId value={finding.asset_id} prefix="Asset ID" truncate={false} />

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, fontSize: 'var(--text-xs)' }}>
          <div>
            <span style={{ color: 'var(--muted)', display: 'block' }}>Phát hiện đầu:</span>
            <span className="mono">{new Date(finding.first_seen).toLocaleString('vi-VN')}</span>
          </div>
          <div>
            <span style={{ color: 'var(--muted)', display: 'block' }}>Quan sát cuối:</span>
            <span className="mono">{new Date(finding.last_seen).toLocaleString('vi-VN')}</span>
          </div>
        </div>

        {provenanceLoading ? (
          <div style={{ fontSize: 'var(--text-xs)', color: 'var(--muted)' }}>
            Đang nạp chi tiết nguồn gốc tài sản...
          </div>
        ) : provenanceError ? (
          <div style={{ fontSize: 'var(--text-xs)', color: 'var(--muted)' }}>
            Không tải được lịch sử tài sản bổ sung ({provenanceError.code}).
          </div>
        ) : provenance ? (
          <div
            style={{
              padding: '8px 10px',
              borderRadius: 'var(--radius-sm)',
              border: '1px solid var(--line)',
              backgroundColor: 'var(--subtle)',
              display: 'flex',
              flexDirection: 'column',
              gap: 5,
              fontSize: 'var(--text-xs)',
            }}
          >
            {(provenance.tool || provenance.provider) && (
              <div>
                <strong>Công cụ quan sát:</strong>{' '}
                <span>{provenance.tool || provenance.provider}</span>
                {provenance.version ? <span className="brand-badge" style={{ marginLeft: 6 }}>{provenance.version}</span> : null}
              </div>
            )}
            {provenance.jobId && (
              <div>
                <strong>Job / Scan:</strong> <span className="mono">{provenance.jobId}</span>
              </div>
            )}
            {provenance.sourceAsset && (
              <div>
                <strong>Tài sản nguồn:</strong> <span className="mono" style={{ wordBreak: 'break-all' }}>{provenance.sourceAsset}</span>
              </div>
            )}
            {provenance.observedAt && (
              <div>
                <strong>Thời điểm quan sát:</strong>{' '}
                <span className="mono">{new Date(provenance.observedAt).toLocaleString('vi-VN')}</span>
              </div>
            )}
          </div>
        ) : (
          <div style={{ fontSize: 'var(--text-xs)', color: 'var(--muted)' }}>
            Chưa có bản ghi quan sát tài sản bổ sung.
          </div>
        )}
      </section>

      {/* Status Timeline (incl. "no longer seen") */}
      <section className="detail-section" aria-label="Dòng thời gian trạng thái và các lần quét">
        <span className="provenance-label">Dòng thời gian trạng thái &amp; Lịch sử quét</span>

        {historyLoading ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            <div className="skeleton-line" style={{ width: '80%' }} />
            <div className="skeleton-line" style={{ width: '65%' }} />
          </div>
        ) : historyError ? (
          <ErrorDisplay error={historyError} onRetry={onRetryHistory} />
        ) : !history ? (
          <span style={{ fontSize: 'var(--text-xs)', color: 'var(--muted)' }}>
            Chưa có dữ liệu lịch sử.
          </span>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {/* Finding Runs */}
            <div>
              <div style={{ fontSize: 'var(--text-xs)', fontWeight: 600, color: 'var(--ink)', marginBottom: 6 }}>
                Các lần quét kiểm tra ({sortedRuns.length})
              </div>
              {sortedRuns.length === 0 ? (
                <div style={{ fontSize: 'var(--text-xs)', color: 'var(--muted)' }}>
                  Chưa ghi nhận lần chạy kiểm tra nào.
                </div>
              ) : (
                <div className="timeline-list">
                  {sortedRuns.map((run, idx) => (
                    <div
                      key={`${run.scan_id}-${run.observed_at}-${idx}`}
                      id={`finding-run-${run.scan_id}`}
                      className={`timeline-item ${run.seen ? '' : 'timeline-item-unseen'}`}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 6, flexWrap: 'wrap' }}>
                        {run.seen ? (
                          <span className="status-chip success">
                            <CheckCircle2 size={12} /> Phát hiện (seen)
                          </span>
                        ) : (
                          <span className="status-chip warning">
                            <EyeOff size={12} /> Không còn thấy (no longer seen)
                          </span>
                        )}
                        <span className="mono" style={{ fontSize: '11px', color: 'var(--muted)' }}>
                          {new Date(run.observed_at).toLocaleString('vi-VN')}
                        </span>
                      </div>

                      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginTop: 4 }}>
                        <StatusChip status={run.status} kind="finding" />
                        <SeverityChip severity={run.severity} />
                      </div>

                      {run.severity_reason && (
                        <div style={{ fontSize: 'var(--text-xs)', color: 'var(--ink)', marginTop: 4, wordBreak: 'break-word' }}>
                          {run.severity_reason}
                        </div>
                      )}

                      <div className="mono" style={{ fontSize: '11px', color: 'var(--muted)', marginTop: 4, wordBreak: 'break-all' }}>
                        scan_id: {run.scan_id}
                        {run.evidence_id ? ` · evidence: ${run.evidence_id}` : ''}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Status Transitions */}
            <div>
              <div style={{ fontSize: 'var(--text-xs)', fontWeight: 600, color: 'var(--ink)', marginBottom: 6 }}>
                Lịch sử chuyển trạng thái ({sortedTransitions.length})
              </div>
              {sortedTransitions.length === 0 ? (
                <div style={{ fontSize: 'var(--text-xs)', color: 'var(--muted)' }}>
                  Chưa có lần chuyển trạng thái nào.
                </div>
              ) : (
                <div className="timeline-list">
                  {sortedTransitions.map((tr) => (
                    <div key={tr.seq} className="timeline-item">
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 6, flexWrap: 'wrap' }}>
                        <span className="mono" style={{ fontSize: '11px', fontWeight: 700, color: 'var(--accent)', display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                          <GitCommit size={12} /> seq #{tr.seq}
                        </span>
                        <span className="mono" style={{ fontSize: '11px', color: 'var(--muted)' }}>
                          {new Date(tr.created_at).toLocaleString('vi-VN')}
                        </span>
                      </div>

                      <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap', marginTop: 4 }}>
                        <span className="brand-badge">{tr.from_status || 'Khởi tạo (null)'}</span>
                        <span style={{ color: 'var(--muted)', fontSize: 'var(--text-xs)' }}>→</span>
                        <StatusChip status={tr.to_status} kind="finding" />
                      </div>

                      <div style={{ fontSize: 'var(--text-xs)', color: 'var(--ink)', marginTop: 4, wordBreak: 'break-word' }}>
                        {tr.reason}
                      </div>

                      <div style={{ fontSize: '11px', color: 'var(--muted)', marginTop: 4, display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                        <span>
                          <strong>Tác nhân:</strong> <span className="mono">{tr.actor.kind}:{tr.actor.id}</span>
                        </span>
                        <span>
                          <strong>Nguyên nhân:</strong> {formatTransitionCause(tr.cause)}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
            {/* Assessment History (newest first) */}
            <div>
              <div style={{ fontSize: 'var(--text-xs)', fontWeight: 600, color: 'var(--ink)', marginBottom: 6 }}>
                Lịch sử đánh giá mức nghiêm trọng ({sortedAssessments.length})
              </div>
              {sortedAssessments.length === 0 ? (
                <div style={{ fontSize: 'var(--text-xs)', color: 'var(--muted)' }}>
                  Chưa có bản ghi lịch sử đánh giá.
                </div>
              ) : (
                <div className="timeline-list">
                  {sortedAssessments.map((item) => (
                    <div key={item.dedup_key} className="timeline-item">
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
                        <SeverityChip severity={item.severity} />
                        <span className="brand-badge">{formatAssessmentTrigger(item.trigger)}</span>
                        <span className="brand-badge">rev #{item.input_revision}</span>
                      </div>

                      <div style={{ fontSize: 'var(--text-xs)', color: 'var(--muted)', marginTop: 4 }}>
                        {renderAssessmentActor(item)}
                      </div>

                      {item.failure && (
                        <div style={{ fontSize: 'var(--text-xs)', color: 'var(--warning)', marginTop: 4, wordBreak: 'break-word' }}>
                          Fallback {item.failure.code}: {item.failure.message}
                        </div>
                      )}

                      {item.reasons.length > 0 && (
                        <div style={{ fontSize: 'var(--text-xs)', color: 'var(--ink)', marginTop: 4, wordBreak: 'break-word' }}>
                          {item.reasons[0]}
                        </div>
                      )}

                      {(item.inputs.cvss?.base_score !== undefined ||
                        item.inputs.epss?.score !== undefined ||
                        item.inputs.kev) && (
                        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', fontSize: '11px', color: 'var(--muted)', marginTop: 4 }}>
                          {item.inputs.cvss?.base_score !== undefined && (
                            <span className="mono">CVSS {item.inputs.cvss.base_score.toFixed(1)}</span>
                          )}
                          {item.inputs.epss?.score !== undefined && (
                            <span className="mono">EPSS {(item.inputs.epss.score * 100).toFixed(2)}%</span>
                          )}
                          {item.inputs.kev && (
                            <span>{item.inputs.kev.listed ? 'KEV: Có' : 'KEV: Không'}</span>
                          )}
                        </div>
                      )}

                      <div className="mono" style={{ fontSize: '11px', color: 'var(--muted)', marginTop: 4, wordBreak: 'break-all' }}>
                        {item.dedup_key}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}
      </section>

      {/* Operator Transition Action */}
      <section className="detail-section" aria-label="Thao tác chuyển trạng thái Finding">
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 6, flexWrap: 'wrap' }}>
          <span className="provenance-label">Chuyển trạng thái (Operator)</span>
          {historyLoading ? (
            <span className="brand-badge" aria-live="polite">
              <Clock size={11} style={{ marginRight: 3 }} /> Đang nạp seq...
            </span>
          ) : historyError && !history ? (
            <span className="brand-badge">Chưa rõ seq</span>
          ) : (
            <span className="brand-badge">
              <Clock size={11} style={{ marginRight: 3 }} /> seq hiện tại: #{currentSeq}
            </span>
          )}
        </div>

        {submitSuccess && (
          <div
            role="status"
            style={{
              padding: '8px 10px',
              borderRadius: 'var(--radius-sm)',
              backgroundColor: 'var(--success-bg)',
              border: '1px solid var(--success)',
              color: 'var(--success)',
              fontSize: 'var(--text-xs)',
              fontWeight: 600,
            }}
          >
            {submitSuccess}
          </div>
        )}

        {conflictStaleSeq && (
          <div
            role="alert"
            style={{
              padding: '10px',
              borderRadius: 'var(--radius-md)',
              backgroundColor: 'var(--warning-bg)',
              border: '1px solid var(--warning)',
              display: 'flex',
              flexDirection: 'column',
              gap: 8,
              fontSize: 'var(--text-xs)',
            }}
          >
            <div style={{ fontWeight: 700, color: 'var(--warning)' }}>
              Xung đột phiên bản trạng thái (HTTP 409 — expected_seq đã cũ)
            </div>
            <div style={{ color: 'var(--ink)' }}>
              Finding đã có cập nhật mới trên máy chủ khiến số thứ tự hiện tại khác với <span className="mono">seq #{currentSeq}</span>. Lý do bạn đã nhập vẫn được giữ lại; hãy tải lại trạng thái mới nhất trước khi gửi lại.
            </div>
            <div>
              <button
                type="button"
                className="btn btn-sm btn-primary"
                onClick={() => {
                  setConflictStaleSeq(false);
                  setSubmitError(null);
                  onRefreshFinding();
                }}
              >
                <RefreshCw size={12} /> Tải lại trạng thái &amp; seq mới nhất
              </button>
            </div>
          </div>
        )}

        {submitError && <ErrorDisplay error={submitError} />}

        {allowedTargets.length === 0 ? (
          <div style={{ fontSize: 'var(--text-xs)', color: 'var(--muted)' }}>
            Trạng thái <span className="mono">{finding.status}</span> không có chuyển trạng thái hợp lệ cho operator theo bảng chuyển đổi (chỉ M20 chuyển sang <span className="mono">REGRESSED</span> nếu tái phát).
          </div>
        ) : (
          <form onSubmit={handleTransitionSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            <div className="form-field" style={{ marginBottom: 0 }}>
              <label htmlFor="finding-transition-to" className="form-label">
                Trạng thái đích (to)
              </label>
              <select
                id="finding-transition-to"
                className="form-input"
                value={targetStatus}
                onChange={(e) => setTargetStatus(e.target.value as FindingStatus)}
                disabled={submitting || historyLoading}
              >
                {allowedTargets.map((status) => (
                  <option key={status} value={status}>
                    {FINDING_STATUS_META[status].label}
                  </option>
                ))}
              </select>
            </div>

            <div className="form-field" style={{ marginBottom: 0 }}>
              <label htmlFor="finding-transition-reason" className="form-label">
                Lý do chuyển trạng thái (tối thiểu 3 ký tự)
              </label>
              <textarea
                id="finding-transition-reason"
                className="form-textarea"
                rows={3}
                value={reason}
                onChange={(e) => {
                  setReason(e.target.value);
                  if (clientReasonError && e.target.value.trim().length >= 3) {
                    setClientReasonError(undefined);
                  }
                }}
                placeholder="Nhập lý do xác minh / loại trừ (bắt buộc để ghi nhận kiểm toán)..."
                aria-invalid={Boolean(clientReasonError || serverFieldError)}
                disabled={submitting}
              />
              <InlineFieldError clientError={clientReasonError} serverError={serverFieldError} />
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
              <button
                type="submit"
                className="btn btn-primary"
                disabled={submitting || historyLoading || Boolean(historyError) || !targetStatus}
              >
                {submitting ? 'Đang cập nhật...' : 'Xác nhận chuyển trạng thái'}
              </button>
            </div>
          </form>
        )}
      </section>
    </aside>
  );
};
