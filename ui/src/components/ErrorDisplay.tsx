import React from 'react';
import { AlertCircle, HelpCircle, ArrowRight } from 'lucide-react';
import type { AppError, UiError } from '../api/types';
import { toUiError } from '../api/client';

interface ErrorDisplayProps {
  error: UiError | AppError | Error | string;
  onRetry?: () => void;
}

export const ErrorDisplay: React.FC<ErrorDisplayProps> = ({ error, onRetry }) => {
  const uiError = toUiError(error);

  return (
    <div
      style={{
        padding: 14,
        backgroundColor: 'var(--danger-bg)',
        border: '1px solid var(--danger)',
        borderRadius: 'var(--radius-md)',
        color: 'var(--ink)',
        fontSize: 'var(--text-sm)',
        display: 'flex',
        flexDirection: 'column',
        gap: 8,
      }}
      role="alert"
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: 'var(--danger)', fontWeight: 600, flexWrap: 'wrap' }}>
        <AlertCircle size={18} />
        <span>Mã lỗi: {uiError.code}</span>
        {uiError.status !== undefined && (
          <span
            className="brand-badge"
            style={{ color: 'var(--danger)', borderColor: 'var(--danger)', backgroundColor: 'var(--surface)' }}
          >
            HTTP {uiError.status}
          </span>
        )}
      </div>

      <div style={{ color: 'var(--ink)' }}>{uiError.message}</div>

      {uiError.path && (
        <div style={{ fontSize: 'var(--text-xs)', fontFamily: 'var(--font-mono)', color: 'var(--muted)', wordBreak: 'break-all' }}>
          Đường dẫn (path): {uiError.path}
        </div>
      )}

      {uiError.field && (
        <div style={{ fontSize: 'var(--text-xs)', fontFamily: 'var(--font-mono)', color: 'var(--danger)' }}>
          Trường lỗi (field): {uiError.field}
        </div>
      )}

      {uiError.technical_cause && (
        <div style={{ fontSize: 'var(--text-xs)', fontFamily: 'var(--font-mono)', color: 'var(--muted)', wordBreak: 'break-word' }}>
          Nguyên nhân kỹ thuật: {uiError.technical_cause}
        </div>
      )}

      {uiError.trace_id && (
        <div style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--muted)' }}>
          Trace ID: {uiError.trace_id}
        </div>
      )}

      {(uiError.next_action || onRetry) && (
        <div
          style={{
            marginTop: 4,
            padding: '6px 10px',
            backgroundColor: 'var(--surface)',
            borderRadius: 'var(--radius-sm)',
            border: '1px solid var(--line)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: 8,
            flexWrap: 'wrap',
          }}
        >
          {uiError.next_action ? (
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 'var(--text-xs)' }}>
              <HelpCircle size={14} style={{ color: 'var(--accent)', flexShrink: 0 }} />
              <span>
                <strong>Bước tiếp theo (next_action):</strong> {uiError.next_action}
                {uiError.next_action_detail && ` - ${uiError.next_action_detail}`}
              </span>
            </div>
          ) : (
            <span />
          )}
          {onRetry && (
            <button type="button" onClick={onRetry} className="btn btn-sm btn-primary">
              Thực hiện lại <ArrowRight size={12} />
            </button>
          )}
        </div>
      )}
    </div>
  );
};

interface InlineFieldErrorProps {
  clientError?: string;
  serverError?: AppError | null;
}

export const InlineFieldError: React.FC<InlineFieldErrorProps> = ({ clientError, serverError }) => {
  if (!clientError && !serverError) return null;

  return (
    <div
      role="alert"
      style={{
        marginTop: 4,
        padding: '6px 8px',
        backgroundColor: 'var(--danger-bg)',
        border: '1px solid var(--danger)',
        borderRadius: 'var(--radius-sm)',
        color: 'var(--danger)',
        fontSize: 'var(--text-xs)',
        lineHeight: 1.4,
      }}
    >
      {clientError && <div>{clientError}</div>}
      {serverError && (
        <div>
          <span className="mono" style={{ fontWeight: 600 }}>
            [{serverError.code}]
          </span>{' '}
          {serverError.field && (
            <span className="mono" style={{ fontWeight: 600 }}>
              ({serverError.field})
            </span>
          )}{' '}
          <span>{serverError.message}</span>
          <div style={{ color: 'var(--ink)', marginTop: 2 }}>
            <strong>Bước tiếp theo:</strong> {serverError.next_action}
            {serverError.next_action_detail ? ` — ${serverError.next_action_detail}` : ''}
          </div>
        </div>
      )}
    </div>
  );
};
