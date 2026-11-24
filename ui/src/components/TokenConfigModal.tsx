import React, { useState } from 'react';
import { Key, Eye, EyeOff, ShieldCheck, Trash2 } from 'lucide-react';
import { getOperatorToken, setOperatorToken } from '../api/client';

interface TokenConfigModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const TokenConfigModal: React.FC<TokenConfigModalProps> = ({ isOpen, onClose }) => {
  const [tokenInput, setTokenInput] = useState(() => getOperatorToken());
  const [showToken, setShowToken] = useState(false);
  const [savedSuccess, setSavedSuccess] = useState(false);

  if (!isOpen) return null;

  const handleSave = () => {
    setOperatorToken(tokenInput);
    setSavedSuccess(true);
    setTimeout(() => {
      setSavedSuccess(false);
      onClose();
    }, 400);
  };

  const handleClear = () => {
    setOperatorToken('');
    setTokenInput('');
    setSavedSuccess(true);
    setTimeout(() => {
      setSavedSuccess(false);
      onClose();
    }, 400);
  };

  return (
    <div className="modal-overlay" role="dialog" aria-modal="true" onClick={onClose}>
      <div
        className="modal-content"
        onClick={(e) => e.stopPropagation()}
        style={{ maxWidth: 480 }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
          <div
            style={{
              width: 36,
              height: 36,
              borderRadius: 'var(--radius-md)',
              backgroundColor: 'var(--accent-bg)',
              color: 'var(--accent)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <Key size={18} />
          </div>
          <div>
            <h3 style={{ fontSize: 'var(--text-lg)', fontWeight: 600, color: 'var(--ink)' }}>
              Cấu hình Operator Bearer Token
            </h3>
            <p style={{ fontSize: 'var(--text-xs)', color: 'var(--muted)' }}>
              Xác thực API backend thật (Authorization: Bearer &lt;token&gt;)
            </p>
          </div>
        </div>

        <div
          style={{
            padding: '10px 12px',
            backgroundColor: 'var(--subtle)',
            borderRadius: 'var(--radius-md)',
            border: '1px solid var(--line)',
            fontSize: 'var(--text-xs)',
            color: 'var(--muted)',
            marginBottom: 16,
            lineHeight: 1.5,
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontWeight: 600, color: 'var(--ink)', marginBottom: 4 }}>
            <ShieldCheck size={14} style={{ color: 'var(--success)' }} />
            <span>Bảo mật & Lưu trữ cục bộ:</span>
          </div>
          Token chỉ được lưu trong <code>localStorage</code> của trình duyệt người dùng và không bao giờ được ghi hay commit vào repository.
        </div>

        <div style={{ marginBottom: 16 }}>
          <label
            htmlFor="operator-token-input"
            style={{ display: 'block', fontSize: 'var(--text-xs)', fontWeight: 600, color: 'var(--ink)', marginBottom: 6 }}
          >
            Operator Token:
          </label>
          <div style={{ position: 'relative' }}>
            <input
              id="operator-token-input"
              type={showToken ? 'text' : 'password'}
              className="input-search"
              style={{ width: '100%', paddingRight: 40, fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)' }}
              placeholder="Nhập Bearer Token (ví dụ: token-of-soc-1-0123456789)..."
              value={tokenInput}
              onChange={(e) => setTokenInput(e.target.value)}
              aria-label="Nhập Operator Token"
            />
            <button
              type="button"
              onClick={() => setShowToken(!showToken)}
              style={{
                position: 'absolute',
                right: 8,
                top: '50%',
                transform: 'translateY(-50%)',
                background: 'none',
                border: 'none',
                cursor: 'pointer',
                color: 'var(--muted)',
                padding: 4,
                display: 'flex',
                alignItems: 'center',
              }}
              title={showToken ? 'Ẩn token' : 'Hiện token'}
              aria-label={showToken ? 'Ẩn token' : 'Hiện token'}
            >
              {showToken ? <EyeOff size={15} /> : <Eye size={15} />}
            </button>
          </div>
          <div style={{ fontSize: '11px', color: 'var(--muted)', marginTop: 4 }}>
            Mặc định môi trường dev: <code>token-of-soc-1-0123456789</code>
          </div>
        </div>

        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <button
            type="button"
            className="btn btn-sm"
            style={{ color: 'var(--danger)', borderColor: 'var(--line)' }}
            onClick={handleClear}
            title="Xóa token khỏi bộ nhớ trình duyệt"
          >
            <Trash2 size={13} /> Xóa token
          </button>

          <div style={{ display: 'flex', gap: 8 }}>
            <button type="button" className="btn btn-sm" onClick={onClose}>
              Đóng
            </button>
            <button
              type="button"
              className="btn btn-sm btn-primary"
              onClick={handleSave}
            >
              {savedSuccess ? 'Đã lưu!' : 'Lưu Token'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
