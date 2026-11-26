import React from 'react';
import { AlertTriangle, Shield } from 'lucide-react';
import type { AppError, CapabilityItem } from '../api/types';
import { InlineFieldError } from './ErrorDisplay';
import { parseLines, type PolicyFormValues } from '../utils/campaignValidation';

interface RoEPolicyFieldsProps {
  idPrefix: string;
  values: PolicyFormValues;
  onChange: (patch: Partial<PolicyFormValues>) => void;
  clientErrors: Record<string, string>;
  serverErrors: Record<string, AppError | undefined>;
  capabilities?: CapabilityItem[];
  disabled?: boolean;
}

export const RoEPolicyFields: React.FC<RoEPolicyFieldsProps> = ({
  idPrefix,
  values,
  onChange,
  clientErrors,
  serverErrors,
  capabilities = [],
  disabled = false,
}) => {
  const isInternet = values.networkProfile === 'internet';
  const selectedDeniedCaps = new Set(parseLines(values.capabilityDenylistText));

  const toggleCapabilityDeny = (capId: string) => {
    const current = parseLines(values.capabilityDenylistText);
    const next = current.includes(capId)
      ? current.filter((item) => item !== capId)
      : [...current, capId];
    onChange({ capabilityDenylistText: next.join('\n') });
  };

  return (
    <div>
      {/* Network Profile */}
      <div className="form-field">
        <span className="form-label">Profile mạng thực thi (network_profile) *</span>
        <div className="profile-choice-grid" role="radiogroup" aria-label="Profile mạng thực thi">
          <label
            className={`profile-choice-card ${!isInternet ? 'selected' : ''}`}
            htmlFor={`${idPrefix}-profile-lab`}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <input
                id={`${idPrefix}-profile-lab`}
                type="radio"
                name={`${idPrefix}-network-profile`}
                value="lab"
                checked={!isInternet}
                disabled={disabled}
                onChange={() => onChange({ networkProfile: 'lab' })}
              />
              <strong style={{ fontSize: 'var(--text-sm)', color: 'var(--ink)' }}>lab (Mặc định an toàn)</strong>
            </div>
            <span className="form-help">
              Mạng lab nội bộ của deployment. Không có đường ra internet.
            </span>
          </label>

          <label
            className={`profile-choice-card ${isInternet ? 'selected-internet' : ''}`}
            htmlFor={`${idPrefix}-profile-internet`}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <input
                id={`${idPrefix}-profile-internet`}
                type="radio"
                name={`${idPrefix}-network-profile`}
                value="internet"
                checked={isInternet}
                disabled={disabled}
                onChange={() => onChange({ networkProfile: 'internet' })}
              />
              <strong style={{ fontSize: 'var(--text-sm)', color: 'var(--ink)' }}>internet (Ra ngoài qua Broker)</strong>
            </div>
            <span className="form-help">
              Chạy qua L7 egress broker. Bắt buộc trần tốc độ/kết nối và xác nhận ủy quyền.
            </span>
          </label>
        </div>
        <InlineFieldError clientError={clientErrors.networkProfile} serverError={serverErrors.networkProfile} />
      </div>

      {isInternet && (
        <div
          style={{
            padding: 12,
            backgroundColor: 'var(--warning-bg)',
            border: '1px solid var(--warning)',
            borderRadius: 'var(--radius-md)',
            marginBottom: 12,
          }}
        >
          <div
            role="note"
            style={{
              color: 'var(--warning)',
              fontSize: 'var(--text-xs)',
              display: 'flex',
              alignItems: 'flex-start',
              gap: 8,
              marginBottom: 10,
            }}
          >
            <AlertTriangle size={16} style={{ flexShrink: 0, marginTop: 1 }} />
            <div>
              <strong>Chế độ Internet được chọn:</strong> Hợp đồng <code className="mono">roe-policy.v2</code> bắt buộc{' '}
              <code className="mono">requests_per_second_per_host</code>,{' '}
              <code className="mono">max_concurrent_connections_per_host</code> và khối ủy quyền{' '}
              <code className="mono">authorization</code> (owner, reference, date, authorized_suffixes).
            </div>
          </div>

          <div className="form-grid-2">
            <div className="form-field" style={{ marginBottom: 8 }}>
              <label className="form-label" htmlFor={`${idPrefix}-auth-owner`}>
                Chủ sở hữu hợp pháp (authorization.owner) *
              </label>
              <input
                id={`${idPrefix}-auth-owner`}
                type="text"
                className="form-input"
                maxLength={200}
                placeholder="Ví dụ: owner / Công ty ABC"
                value={values.authOwner}
                disabled={disabled}
                aria-invalid={Boolean(clientErrors.authOwner || serverErrors.authOwner)}
                onChange={(e) => onChange({ authOwner: e.target.value })}
              />
              <InlineFieldError clientError={clientErrors.authOwner} serverError={serverErrors.authOwner} />
            </div>

            <div className="form-field" style={{ marginBottom: 8 }}>
              <label className="form-label" htmlFor={`${idPrefix}-auth-date`}>
                Ngày ủy quyền (authorization.date, YYYY-MM-DD) *
              </label>
              <input
                id={`${idPrefix}-auth-date`}
                type="date"
                className="form-input tabular"
                value={values.authDate}
                disabled={disabled}
                aria-invalid={Boolean(clientErrors.authDate || serverErrors.authDate)}
                onChange={(e) => onChange({ authDate: e.target.value })}
              />
              <InlineFieldError clientError={clientErrors.authDate} serverError={serverErrors.authDate} />
            </div>
          </div>

          <div className="form-field" style={{ marginBottom: 8 }}>
            <label className="form-label" htmlFor={`${idPrefix}-auth-reference`}>
              Tham chiếu bằng chứng ủy quyền (authorization.reference, ≥ 3 ký tự) *
            </label>
            <input
              id={`${idPrefix}-auth-reference`}
              type="text"
              className="form-input"
              maxLength={300}
              placeholder="Ví dụ: Quyết định / Ticket #61 (2026-11-25)"
              value={values.authReference}
              disabled={disabled}
              aria-invalid={Boolean(clientErrors.authReference || serverErrors.authReference)}
              onChange={(e) => onChange({ authReference: e.target.value })}
            />
            <InlineFieldError clientError={clientErrors.authReference} serverError={serverErrors.authReference} />
          </div>

          <div className="form-field" style={{ marginBottom: 0 }}>
            <label className="form-label" htmlFor={`${idPrefix}-auth-suffixes`}>
              Hậu tố tên miền được phép (authorization.authorized_suffixes — mỗi dòng một hậu tố) *
            </label>
            <textarea
              id={`${idPrefix}-auth-suffixes`}
              className="form-textarea"
              style={{ minHeight: 54 }}
              placeholder="Ví dụ:&#10;example.com&#10;sub.example.vn"
              value={values.authSuffixesText}
              disabled={disabled}
              aria-invalid={Boolean(clientErrors.authSuffixesText || serverErrors.authSuffixesText)}
              onChange={(e) => onChange({ authSuffixesText: e.target.value })}
            />
            <InlineFieldError
              clientError={clientErrors.authSuffixesText}
              serverError={serverErrors.authSuffixesText}
            />
          </div>
        </div>
      )}

      {/* Parallel jobs & duration */}
      <div className="form-grid-2">
        <div className="form-field">
          <label className="form-label" htmlFor={`${idPrefix}-max-parallel`}>
            Số job đồng thời tối đa (1–50) *
          </label>
          <input
            id={`${idPrefix}-max-parallel`}
            type="number"
            min={1}
            max={50}
            step={1}
            className="form-input tabular"
            value={values.maxParallelJobs}
            disabled={disabled}
            aria-invalid={Boolean(clientErrors.maxParallelJobs || serverErrors.maxParallelJobs)}
            onChange={(e) => onChange({ maxParallelJobs: e.target.value })}
          />
          <InlineFieldError clientError={clientErrors.maxParallelJobs} serverError={serverErrors.maxParallelJobs} />
        </div>

        <div className="form-field">
          <label className="form-label" htmlFor={`${idPrefix}-max-duration`}>
            Thời lượng tối đa — giờ (1–168) *
          </label>
          <input
            id={`${idPrefix}-max-duration`}
            type="number"
            min={1}
            max={168}
            step={1}
            className="form-input tabular"
            value={values.maxDurationHours}
            disabled={disabled}
            aria-invalid={Boolean(clientErrors.maxDurationHours || serverErrors.maxDurationHours)}
            onChange={(e) => onChange({ maxDurationHours: e.target.value })}
          />
          <InlineFieldError clientError={clientErrors.maxDurationHours} serverError={serverErrors.maxDurationHours} />
        </div>
      </div>

      {/* Rate limits */}
      <div
        style={{
          padding: 12,
          backgroundColor: 'var(--subtle)',
          border: '1px solid var(--line)',
          borderRadius: 'var(--radius-md)',
          marginBottom: 12,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 'var(--text-xs)', fontWeight: 600, color: 'var(--ink)', marginBottom: 8 }}>
          <Shield size={14} style={{ color: 'var(--accent)' }} />
          <span>Giới hạn tốc độ (rate_limits)</span>
        </div>

        <div className="form-grid-2">
          <div className="form-field" style={{ marginBottom: 8 }}>
            <label className="form-label" htmlFor={`${idPrefix}-rps`}>
              Tốc độ / host (req/s) {isInternet ? '*' : '(tùy chọn)'}
            </label>
            <input
              id={`${idPrefix}-rps`}
              type="number"
              min={0.1}
              max={1000}
              step="any"
              className="form-input tabular"
              value={values.requestsPerSecondPerHost}
              disabled={disabled}
              aria-invalid={Boolean(
                clientErrors.requestsPerSecondPerHost || serverErrors.requestsPerSecondPerHost
              )}
              onChange={(e) => onChange({ requestsPerSecondPerHost: e.target.value })}
            />
            <InlineFieldError
              clientError={clientErrors.requestsPerSecondPerHost}
              serverError={serverErrors.requestsPerSecondPerHost}
            />
          </div>

          <div className="form-field" style={{ marginBottom: 8 }}>
            <label className="form-label" htmlFor={`${idPrefix}-max-conn`}>
              Kết nối đồng thời / host (1–100) {isInternet ? '*' : '(tùy chọn)'}
            </label>
            <input
              id={`${idPrefix}-max-conn`}
              type="number"
              min={1}
              max={100}
              step={1}
              className="form-input tabular"
              value={values.maxConcurrentConnectionsPerHost}
              disabled={disabled}
              aria-invalid={Boolean(
                clientErrors.maxConcurrentConnectionsPerHost ||
                  serverErrors.maxConcurrentConnectionsPerHost
              )}
              onChange={(e) => onChange({ maxConcurrentConnectionsPerHost: e.target.value })}
            />
            <InlineFieldError
              clientError={clientErrors.maxConcurrentConnectionsPerHost}
              serverError={serverErrors.maxConcurrentConnectionsPerHost}
            />
          </div>

          <div className="form-field" style={{ marginBottom: 0 }}>
            <label className="form-label" htmlFor={`${idPrefix}-pps`}>
              Gói tin / giây quét cổng (1–100000)
            </label>
            <input
              id={`${idPrefix}-pps`}
              type="number"
              min={1}
              max={100000}
              step={1}
              className="form-input tabular"
              value={values.packetsPerSecond}
              disabled={disabled}
              aria-invalid={Boolean(clientErrors.packetsPerSecond || serverErrors.packetsPerSecond)}
              onChange={(e) => onChange({ packetsPerSecond: e.target.value })}
            />
            <InlineFieldError clientError={clientErrors.packetsPerSecond} serverError={serverErrors.packetsPerSecond} />
          </div>

          <div className="form-field" style={{ marginBottom: 0 }}>
            <label className="form-label" htmlFor={`${idPrefix}-jpm`}>
              Số job / phút (1–600)
            </label>
            <input
              id={`${idPrefix}-jpm`}
              type="number"
              min={1}
              max={600}
              step={1}
              className="form-input tabular"
              value={values.jobsPerMinute}
              disabled={disabled}
              aria-invalid={Boolean(clientErrors.jobsPerMinute || serverErrors.jobsPerMinute)}
              onChange={(e) => onChange({ jobsPerMinute: e.target.value })}
            />
            <InlineFieldError clientError={clientErrors.jobsPerMinute} serverError={serverErrors.jobsPerMinute} />
          </div>
        </div>
      </div>

      {/* Budget & Idle Cycles */}
      <div
        style={{
          padding: 12,
          backgroundColor: 'var(--subtle)',
          border: '1px solid var(--line)',
          borderRadius: 'var(--radius-md)',
          marginBottom: 12,
        }}
      >
        <div style={{ fontSize: 'var(--text-xs)', fontWeight: 600, color: 'var(--ink)', marginBottom: 8 }}>
          Ngân sách & Chu kỳ rỗi (budget)
        </div>

        <div className="form-grid-2">
          <div className="form-field" style={{ marginBottom: 8 }}>
            <label className="form-label" htmlFor={`${idPrefix}-llm-cost`}>
              Chi phí LLM tối đa (USD)
            </label>
            <input
              id={`${idPrefix}-llm-cost`}
              type="number"
              min={0}
              step="any"
              className="form-input tabular"
              value={values.maxLlmCostUsd}
              disabled={disabled}
              aria-invalid={Boolean(clientErrors.maxLlmCostUsd || serverErrors.maxLlmCostUsd)}
              onChange={(e) => onChange({ maxLlmCostUsd: e.target.value })}
            />
            <InlineFieldError clientError={clientErrors.maxLlmCostUsd} serverError={serverErrors.maxLlmCostUsd} />
          </div>

          <div className="form-field" style={{ marginBottom: 8 }}>
            <label className="form-label" htmlFor={`${idPrefix}-llm-tokens`}>
              Token LLM tối đa
            </label>
            <input
              id={`${idPrefix}-llm-tokens`}
              type="number"
              min={0}
              step={1}
              className="form-input tabular"
              value={values.maxLlmTokens}
              disabled={disabled}
              aria-invalid={Boolean(clientErrors.maxLlmTokens || serverErrors.maxLlmTokens)}
              onChange={(e) => onChange({ maxLlmTokens: e.target.value })}
            />
            <InlineFieldError clientError={clientErrors.maxLlmTokens} serverError={serverErrors.maxLlmTokens} />
          </div>

          <div className="form-field" style={{ marginBottom: 8 }}>
            <label className="form-label" htmlFor={`${idPrefix}-max-jobs`}>
              Tổng số job tối đa
            </label>
            <input
              id={`${idPrefix}-max-jobs`}
              type="number"
              min={1}
              step={1}
              className="form-input tabular"
              value={values.maxJobs}
              disabled={disabled}
              aria-invalid={Boolean(clientErrors.maxJobs || serverErrors.maxJobs)}
              onChange={(e) => onChange({ maxJobs: e.target.value })}
            />
            <InlineFieldError clientError={clientErrors.maxJobs} serverError={serverErrors.maxJobs} />
          </div>

          <div className="form-field" style={{ marginBottom: 8 }}>
            <label className="form-label" htmlFor={`${idPrefix}-max-sessions`}>
              Số phiên agent tối đa
            </label>
            <input
              id={`${idPrefix}-max-sessions`}
              type="number"
              min={1}
              step={1}
              className="form-input tabular"
              value={values.maxAgentSessions}
              disabled={disabled}
              aria-invalid={Boolean(clientErrors.maxAgentSessions || serverErrors.maxAgentSessions)}
              onChange={(e) => onChange({ maxAgentSessions: e.target.value })}
            />
            <InlineFieldError
              clientError={clientErrors.maxAgentSessions}
              serverError={serverErrors.maxAgentSessions}
            />
          </div>
        </div>

        <div className="form-field" style={{ marginBottom: 0 }}>
          <label className="form-label" htmlFor={`${idPrefix}-idle-cycles`}>
            Chu kỳ rỗi trước khi tạm dừng (idle_cycles_before_pause, 3–5)
          </label>
          <input
            id={`${idPrefix}-idle-cycles`}
            type="number"
            min={3}
            max={5}
            step={1}
            className="form-input tabular"
            style={{ maxWidth: 180 }}
            value={values.idleCyclesBeforePause}
            disabled={disabled}
            aria-invalid={Boolean(
              clientErrors.idleCyclesBeforePause || serverErrors.idleCyclesBeforePause
            )}
            onChange={(e) => onChange({ idleCyclesBeforePause: e.target.value })}
          />
          <InlineFieldError
            clientError={clientErrors.idleCyclesBeforePause}
            serverError={serverErrors.idleCyclesBeforePause}
          />
        </div>
      </div>

      {/* Capability denylist & Target denylist */}
      <div className="form-field">
        <label className="form-label" htmlFor={`${idPrefix}-cap-denylist`}>
          Loại trừ Capability (capability_denylist — mỗi dòng một mã)
        </label>
        {capabilities.length > 0 && (
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 6 }}>
            {capabilities.map((cap) => {
              const denied = selectedDeniedCaps.has(cap.capability);
              return (
                <button
                  key={cap.capability}
                  type="button"
                  disabled={disabled}
                  onClick={() => toggleCapabilityDeny(cap.capability)}
                  className={`btn btn-sm ${denied ? 'btn-danger' : ''}`}
                  style={{ fontFamily: 'var(--font-mono)', fontSize: '11px' }}
                  aria-pressed={denied}
                >
                  {denied ? '✕ ' : '+ '}
                  {cap.capability}
                </button>
              );
            })}
          </div>
        )}
        <textarea
          id={`${idPrefix}-cap-denylist`}
          className="form-textarea"
          style={{ minHeight: 58 }}
          placeholder="Ví dụ: network.discover_services"
          value={values.capabilityDenylistText}
          disabled={disabled}
          aria-invalid={Boolean(clientErrors.capabilityDenylistText || serverErrors.capabilityDenylistText)}
          onChange={(e) => onChange({ capabilityDenylistText: e.target.value })}
        />
        <InlineFieldError
          clientError={clientErrors.capabilityDenylistText}
          serverError={serverErrors.capabilityDenylistText}
        />
      </div>

      <div className="form-field" style={{ marginBottom: 0 }}>
        <label className="form-label" htmlFor={`${idPrefix}-target-denylist`}>
          Loại trừ Mục tiêu (target_denylist — mỗi dòng một mục tiêu)
        </label>
        <textarea
          id={`${idPrefix}-target-denylist`}
          className="form-textarea"
          style={{ minHeight: 58 }}
          placeholder="Ví dụ: vault.internal.example"
          value={values.targetDenylistText}
          disabled={disabled}
          aria-invalid={Boolean(clientErrors.targetDenylistText || serverErrors.targetDenylistText)}
          onChange={(e) => onChange({ targetDenylistText: e.target.value })}
        />
        <InlineFieldError
          clientError={clientErrors.targetDenylistText}
          serverError={serverErrors.targetDenylistText}
        />
      </div>
    </div>
  );
};
