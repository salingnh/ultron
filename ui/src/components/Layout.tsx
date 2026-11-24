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
} from 'lucide-react';
import { apiClient } from '../api/client';

export const Layout: React.FC = () => {
  const [theme, setTheme] = useState<'light' | 'dark'>(() => {
    return (localStorage.getItem('ultron-theme') as 'light' | 'dark') || 'light';
  });

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('ultron-theme', theme);
  }, [theme]);

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
          {apiClient.isMock && (
            <span
              className="status-chip warning"
              style={{ fontSize: '11px', padding: '1px 6px' }}
              title="Dữ liệu mock từ hợp đồng OpenAPI v2. Có thể đổi qua backend thật bằng VITE_API_BASE"
            >
              MOCK MODE
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

      <main className="page-content">
        <Outlet />
      </main>
    </div>
  );
};
