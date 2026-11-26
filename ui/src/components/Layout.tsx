import React, { useEffect, useState } from 'react';
import { NavLink, Outlet } from 'react-router-dom';
import {
  Shield,
  Layers,
  GitBranch,
  Network,
  Wrench,
  Sun,
  Moon,
  Radio,
  Key,
} from 'lucide-react';
import { apiClient, getOperatorToken } from '../api/client';
import { TokenConfigModal } from './TokenConfigModal';

export const Layout: React.FC = () => {
  const [theme, setTheme] = useState<'light' | 'dark'>(() => {
    return (localStorage.getItem('ultron-theme') as 'light' | 'dark') || 'light';
  });
  const [token, setToken] = useState<string>(() => getOperatorToken());
  const [isTokenModalOpen, setIsTokenModalOpen] = useState(false);

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('ultron-theme', theme);
  }, [theme]);

  useEffect(() => {
    const handleTokenChange = () => {
      setToken(getOperatorToken());
    };
    const handleOpenTokenModal = () => {
      setIsTokenModalOpen(true);
    };
    window.addEventListener('ultron-token-changed', handleTokenChange);
    window.addEventListener('ultron-open-token-modal', handleOpenTokenModal);
    return () => {
      window.removeEventListener('ultron-token-changed', handleTokenChange);
      window.removeEventListener('ultron-open-token-modal', handleOpenTokenModal);
    };
  }, []);

  const toggleTheme = () => {
    setTheme((prev) => (prev === 'light' ? 'dark' : 'light'));
  };

  return (
    <div className="app-container">
      <header className="app-header">
        <div className="brand-section">
          <div className="brand-logo">
            <Shield size={22} style={{ color: 'var(--accent)' }} />
            <span>ULTRON</span>
          </div>
          <span className="brand-badge">Bảng điều khiển tác chiến</span>
          {apiClient.isMock ? (
            <span
              className="status-chip warning"
              style={{ fontSize: '11px', padding: '1px 6px' }}
              title="Dữ liệu mock từ hợp đồng OpenAPI v2. Đặt VITE_USE_MOCK=false để nối backend thật"
            >
              MOCK MODE
            </span>
          ) : (
            <span
              className="status-chip success"
              style={{ fontSize: '11px', padding: '1px 6px' }}
              title="Đang kết nối backend API thật"
            >
              REAL API
            </span>
          )}
        </div>

        <nav className="nav-links" aria-label="Điều hướng chính">
          <NavLink
            to="/campaigns"
            className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
          >
            <Layers size={16} />
            <span>Chiến dịch</span>
          </NavLink>
          <NavLink
            to="/jobs"
            className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
          >
            <GitBranch size={16} />
            <span>Kế hoạch & Luồng Job</span>
          </NavLink>
          <NavLink
            to="/assets"
            className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
          >
            <Network size={16} />
            <span>Đồ thị Tài sản</span>
          </NavLink>
          <NavLink
            to="/tools"
            className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
          >
            <Wrench size={16} />
            <span>Danh mục Công cụ</span>
          </NavLink>
        </nav>

        <div className="header-actions">
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              fontSize: 'var(--text-xs)',
              color: 'var(--success)',
            }}
          >
            <Radio size={14} className="pulse-icon" />
            <span style={{ fontWeight: 600 }}>SSE Live</span>
          </div>

          <button
            type="button"
            onClick={() => setIsTokenModalOpen(true)}
            className="theme-toggle-btn"
            style={{
              color: token ? 'var(--ink)' : 'var(--warning)',
              borderColor: token ? 'var(--line)' : 'var(--warning)',
            }}
            title="Cấu hình Operator Bearer Token"
            aria-label="Cấu hình Operator Bearer Token"
          >
            <Key size={14} />
            <span>{token ? 'Token: Đã cấu hình' : 'Token: Chưa cấu hình'}</span>
          </button>

          <button
            type="button"
            onClick={toggleTheme}
            className="theme-toggle-btn"
            aria-label="Chuyển chế độ sáng tối"
          >
            {theme === 'light' ? (
              <>
                <Moon size={14} /> <span>Giao diện tối</span>
              </>
            ) : (
              <>
                <Sun size={14} /> <span>Giao diện sáng</span>
              </>
            )}
          </button>
        </div>
      </header>

      {!token && (
        <div className="first-run-banner" role="region" aria-label="Hướng dẫn cấu hình Operator Token lần đầu">
          <div>
            <strong>Hướng dẫn chạy lần đầu (Operator Token):</strong>{' '}
            {apiClient.isMock ? 'Đang ở chế độ MOCK MODE — khi chuyển sang API thật, cần ' : 'API thật yêu cầu Bearer token — '}
            mở nút <code className="mono">Token: Chưa cấu hình</code> để nhập token lấy từ{' '}
            <code className="mono">.local/operator-token</code> (do <code className="mono">make run-local</code> tạo; server chỉ lưu SHA-256 tại{' '}
            <code className="mono">.local/operators.json</code>). Token được lưu trong trình duyệt tại{' '}
            <code className="mono">localStorage[&apos;ultron-operator-token&apos;]</code>.
          </div>
          <button
            type="button"
            className="btn btn-sm btn-primary"
            onClick={() => setIsTokenModalOpen(true)}
          >
            <Key size={13} /> Cấu hình Operator Token
          </button>
        </div>
      )}

      <main className="page-content">
        <Outlet />
      </main>

      <TokenConfigModal
        isOpen={isTokenModalOpen}
        onClose={() => setIsTokenModalOpen(false)}
      />
    </div>
  );
};
