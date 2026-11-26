import React from 'react';
import { AlertCircle, HelpCircle, ArrowRight } from 'lucide-react';
import type { AppError } from '../api/types';

interface ErrorDisplayProps {
  error: AppError | Error | string;
  onRetry?: () => void;
}

export const ErrorDisplay: React.FC<ErrorDisplayProps> = ({ error, onRetry }) => {
  const isAppError = typeof error === 'object' && error !== null && 'code' in error;
  const appError = isAppError ? (error as AppError) : null;
  const message = typeof error === 'string' ? error : error.message;

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
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: 'var(--danger)', fontWeight: 600 }}>
        <AlertCircle size={18} />
        <span>Mã lỗi: {appError ? appError.code : 'ERROR'}</span>
      </div>

      <div style={{ color: 'var(--ink)' }}>{message}</div>

      {appError?.field && (
        <div style={{ fontSize: 'var(--text-xs)', fontFamily: 'var(--font-mono)', color: 'var(--danger)' }}>
          Trường lỗi (field): {appError.field}
        </div>
      )}

      {appError?.technical_cause && (
        <div style={{ fontSize: 'var(--text-xs)', fontFamily: 'var(--font-mono)', color: 'var(--muted)' }}>
          Nguyên nhân kỹ thuật: {appError.technical_cause}
        </div>
      )}

      {appError?.trace_id && (
        <div style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--muted)' }}>
          Trace ID: {appError.trace_id}
        </div>
      )}

      {appError?.next_action && (
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
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 'var(--text-xs)' }}>
            <HelpCircle size={14} style={{ color: 'var(--accent)' }} />
            <span>
              <strong>Bước tiếp theo (next_action):</strong> {appError.next_action}
              {appError.next_action_detail && ` - ${appError.next_action_detail}`}
            </span>
          </div>
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
