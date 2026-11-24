import { describe, it, expect } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { StatusChip } from '../components/StatusChip';
import { CopyableId } from '../components/CopyableId';
import { TruncatedBanner } from '../components/TruncatedBanner';
import { ProvenancePanel } from '../components/ProvenancePanel';
import { ErrorDisplay } from '../components/ErrorDisplay';
import { TokenConfigModal } from '../components/TokenConfigModal';
import { getOperatorToken } from '../api/client';

describe('Ultron UI Reusable Components', () => {
  it('renders StatusChip with Vietnamese text and correct styling', () => {
    render(<StatusChip status="SUCCEEDED" />);
    expect(screen.getByText('Thành công (Succeeded)')).toBeInTheDocument();

    render(<StatusChip status="approved" />);
    expect(screen.getByText('Đã duyệt (Approved)')).toBeInTheDocument();

    render(<StatusChip status="rejected" />);
    expect(screen.getByText('Từ chối (Rejected)')).toBeInTheDocument();

    render(<StatusChip status="QUEUED" />);
    expect(screen.getByText('Đang chờ (Queued)')).toBeInTheDocument();

    render(<StatusChip status="RUNNING" />);
    expect(screen.getByText('Đang chạy (Running)')).toBeInTheDocument();

    render(<StatusChip status="FAILED" />);
    expect(screen.getByText('Thất bại (Failed)')).toBeInTheDocument();

    render(<StatusChip status="healthy" kind="health" />);
    const healthChip = screen.getByText('Khớp Manifest (Healthy)');
    expect(healthChip).toBeInTheDocument();
    expect(healthChip.closest('.status-chip')).toHaveAttribute(
      'title',
      'healthy = manifest re-admittable + pin match (not a runtime probe)'
    );
  });

  it('renders CopyableId with monospace font and copy button', () => {
    render(<CopyableId value="01934f6a-0000-7000-8000-000000000001" prefix="ID" />);
    expect(screen.getByText('ID:')).toBeInTheDocument();
    expect(screen.getByLabelText('Sao chép')).toBeInTheDocument();
  });

  it('renders TruncatedBanner with contract limit explanations', () => {
    render(
      <TruncatedBanner
        truncated={true}
        limitsApplied={{ max_hops: 1, limit: 50, timeout_ms: 2000 }}
      />
    );
    expect(screen.getByRole('alert')).toBeInTheDocument();
    expect(screen.getByText(/Dữ liệu đồ thị bị giới hạn/)).toBeInTheDocument();
    expect(screen.getByText(/Giới hạn 50 node/)).toBeInTheDocument();
  });

  it('renders ProvenancePanel with tool, version, job, observed_at, confidence, and full unmasked SHA-256', () => {
    const mockProvenance = {
      tool: 'subfinder',
      version: 'v2.17.0',
      adapterVersion: '1.0.0',
      jobId: '01934f6a-0000-7000-8000-00000000d001',
      observedAt: '2026-11-20T08:12:30Z',
      confidence: 0.9,
      sha256: '1e1c8bcdd33168e15528d61a006bf5e5e5a31e5b8e4d4d4f1f10ad0876240a9f',
      sourceAsset: 'dns:internal.example',
      targetAsset: 'dns:vpn.internal.example',
      evidenceUri: 's3://evidence/sample.json',
    };

    render(<ProvenancePanel data={mockProvenance} onClose={() => {}} />);
    expect(screen.getByText('Nguồn gốc & Bằng chứng')).toBeInTheDocument();
    expect(screen.getByText('subfinder')).toBeInTheDocument();
    expect(screen.getByText('v2.17.0')).toBeInTheDocument();
    expect(screen.getByText('1e1c8bcdd33168e15528d61a006bf5e5e5a31e5b8e4d4d4f1f10ad0876240a9f')).toBeInTheDocument();
    expect(screen.getByText('90%')).toBeInTheDocument();
  });

  it('renders ErrorDisplay with standard error code, description, and next_action', () => {
    const mockError = {
      code: 'NETWORK_TIMEOUT' as const,
      message: 'Hết thời gian kết nối (30s) khi truy vấn máy chủ DNS',
      technical_cause: 'exit code 124',
      next_action: 'RETRY_LATER' as const,
      next_action_detail: 'Thử lại sau 60s',
    };

    render(<ErrorDisplay error={mockError} />);
    expect(screen.getByRole('alert')).toBeInTheDocument();
    expect(screen.getByText('Mã lỗi: NETWORK_TIMEOUT')).toBeInTheDocument();
    expect(screen.getByText('Hết thời gian kết nối (30s) khi truy vấn máy chủ DNS')).toBeInTheDocument();
    expect(screen.getByText(/RETRY_LATER/)).toBeInTheDocument();
  });

  it('renders TokenConfigModal and saves token to localStorage', () => {
    let isClosed = false;
    render(<TokenConfigModal isOpen={true} onClose={() => { isClosed = true; }} />);

    expect(screen.getByText('Cấu hình Operator Bearer Token')).toBeInTheDocument();
    const input = screen.getByLabelText('Nhập Operator Token');
    expect(input).toBeInTheDocument();

    fireEvent.change(input, { target: { value: 'my-secret-operator-token' } });
    fireEvent.click(screen.getByRole('button', { name: 'Lưu Token' }));

    expect(getOperatorToken()).toBe('my-secret-operator-token');
    expect(isClosed).toBe(false); // Closes after animation delay
  });
});
