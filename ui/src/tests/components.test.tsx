import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import { StatusChip } from '../components/StatusChip';
import { CopyableId } from '../components/CopyableId';
import { TruncatedBanner } from '../components/TruncatedBanner';
import { ProvenancePanel } from '../components/ProvenancePanel';
import { VulnerabilityPanel } from '../components/VulnerabilityPanel';
import { ServiceTable } from '../components/ServiceTable';
import { AssetGraphScreen } from '../screens/AssetGraphScreen';
import { ErrorDisplay } from '../components/ErrorDisplay';
import { TokenConfigModal } from '../components/TokenConfigModal';
import { CampaignDetailScreen } from '../screens/CampaignDetailScreen';
import { apiClient, getOperatorToken } from '../api/client';

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
    expect(screen.getByText('Bằng chứng SHA-256 (Evidence SHA-256)')).toBeInTheDocument();
    expect(screen.getByText('90%')).toBeInTheDocument();
  });

  it('renders ProvenancePanel with Evidence ID when returned without SHA-256', () => {
    const mockProvenance = {
      tool: 'subfinder',
      version: 'v2.6.8',
      jobId: '01a20cfb-fa5e-7002-b2ff-03d86947d84b',
      observedAt: '2026-11-24T16:56:11Z',
      evidenceIds: ['01a20cfc-0041-75b1-b041-ccf5c4fba5a8'],
      sourceAsset: 'dns:www.lab.aegis.test',
      targetAsset: 'dns:lab.aegis.test',
    };

    render(<ProvenancePanel data={mockProvenance} onClose={() => {}} />);
    expect(screen.getByText('Mã bằng chứng (Evidence ID)')).toBeInTheDocument();
    expect(screen.getByText('01a20cfc-0041-75b1-b041-ccf5c4fba5a8')).toBeInTheDocument();
    expect(screen.queryByText('Bằng chứng SHA-256 (Evidence SHA-256)')).not.toBeInTheDocument();
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

  it('renders "Chưa có dữ liệu ngân sách" when campaign has no budget data', async () => {
    vi.spyOn(apiClient, 'getCampaign').mockResolvedValueOnce({
      campaign_id: 'campaign-no-budget',
      name: 'Chiến dịch không có ngân sách',
      status: 'RUNNING',
      policy_version: 'roe-1',
      created_at: '2026-11-20T08:00:00Z',
    } as unknown as import('../api/types').Campaign);

    render(
      <MemoryRouter initialEntries={['/campaigns/campaign-no-budget']}>
        <Routes>
          <Route path="/campaigns/:id" element={<CampaignDetailScreen />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByText('Chưa có dữ liệu ngân sách')).toBeInTheDocument();
  });

  it('renders VulnerabilityPanel with NVD link, candidate-only Vietnamese label, and all fields', () => {
    render(
      <VulnerabilityPanel
        data={{
          assetId: '01934f6a-0000-7000-8000-0000000000f6',
          assetKey: 'service:203.0.113.10:80/tcp',
          candidate: {
            vulnerability_id: 'CVE-2021-41773',
            cvss_base: 9.8,
            cvss_severity: 'CRITICAL',
            kev: true,
            kev_due_date: '2021-11-17',
            epss: 0.97431,
            match_method: 'cpe_range',
            affected_range: '>= 2.4.49, <= 2.4.50',
            confidence: 0.7,
            snapshot_id: '01934f6a-0000-7000-8000-00000000c001',
            candidate_since: '2026-11-20T08:25:00Z',
          },
        }}
        onClose={() => {}}
      />
    );

    expect(screen.getByText('Ứng viên (chưa xác minh)')).toBeInTheDocument();
    const nvdLink = screen.getByRole('link', { name: /CVE-2021-41773/ });
    expect(nvdLink).toHaveAttribute('href', 'https://nvd.nist.gov/vuln/detail/CVE-2021-41773');
    expect(screen.getByText('9.8')).toBeInTheDocument();
    expect(screen.getByText('CRITICAL')).toBeInTheDocument();
    expect(screen.getByText('Có trong CISA KEV')).toBeInTheDocument();
    expect(screen.getByText('97.43%')).toBeInTheDocument();
    expect(screen.getByText('>= 2.4.49, <= 2.4.50')).toBeInTheDocument();
    expect(screen.getByText('cpe_range')).toBeInTheDocument();
    expect(screen.getByText('70% (0.70)')).toBeInTheDocument();
    expect(screen.getByText('01934f6a-0000-7000-8000-00000000c001')).toBeInTheDocument();
    expect(document.body.textContent?.toLowerCase()).not.toContain('confirmed');
    expect(document.body.textContent?.toLowerCase()).not.toContain('vulnerable');
  });

  it('renders ServiceTable with host, port, protocol, product, version, CPE, and CVE/KEV counts', () => {
    const onSelect = vi.fn();
    render(
      <ServiceTable
        rows={[
          {
            asset: {
              asset_id: '01934f6a-0000-7000-8000-0000000000f6',
              canonical_key: 'service:10.114.53.215:80/tcp',
              kind: 'service',
              first_seen: '2026-11-25T08:00:00Z',
              last_seen: '2026-11-25T08:05:00Z',
            },
            host: '10.114.53.215',
            port: '80',
            transport: 'tcp',
            protocol: 'http (tcp)',
            product: 'http_server',
            version: '2.4.49',
            cpe: 'cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*',
            candidates: [
              {
                vulnerability_id: 'CVE-2021-41773',
                cvss_base: 9.8,
                kev: true,
                epss: 0.97431,
                match_method: 'cpe_range',
                confidence: 0.7,
                candidate_since: '2026-11-25T08:06:00Z',
              },
            ],
            candidateCount: 1,
            kevCount: 1,
            truncatedCandidates: false,
          },
        ]}
        onSelectVulnerability={onSelect}
        onFocusInGraph={() => {}}
      />
    );

    expect(screen.getByText('10.114.53.215')).toBeInTheDocument();
    expect(screen.getByText('80')).toBeInTheDocument();
    expect(screen.getByText('http (tcp)')).toBeInTheDocument();
    expect(screen.getByText('http_server')).toBeInTheDocument();
    expect(screen.getByText('2.4.49')).toBeInTheDocument();
    expect(screen.getByText('cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*')).toBeInTheDocument();
    expect(screen.getByText('1 ứng viên')).toBeInTheDocument();
    expect(screen.getByText('1 KEV')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /CVE-2021-41773/ }));
    expect(onSelect).toHaveBeenCalledTimes(1);
  });

  it('renders AssetGraphScreen with IP -> Service -> Application -> Vulnerability chain and opens VulnerabilityPanel on click', async () => {
    render(
      <MemoryRouter initialEntries={['/assets?campaign_id=01934f6a-0000-7000-8000-000000000001']}>
        <Routes>
          <Route path="/assets" element={<AssetGraphScreen />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByText('CVE-2021-41773')).toBeInTheDocument();
    expect(screen.getAllByText('EXPOSES').length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText('SERVES').length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText('AFFECTED_BY').length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText(/http_server 2\.4\.49/).length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText(/Apache HTTP Server:2\.4\.49/).length).toBeGreaterThanOrEqual(1);
    expect(screen.getByRole('alert')).toBeInTheDocument(); // TruncatedBanner

    // Click vulnerability node to open VulnerabilityPanel
    fireEvent.click(screen.getByRole('button', { name: 'Ứng viên CVE CVE-2021-41773' }));
    expect(await screen.findByLabelText('Bảng chi tiết ứng viên CVE')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /CVE-2021-41773/ })).toHaveAttribute(
      'href',
      'https://nvd.nist.gov/vuln/detail/CVE-2021-41773'
    );

    // Filter by kind = service
    fireEvent.change(screen.getByLabelText('Lọc loại tài sản'), { target: { value: 'service' } });
    expect(screen.queryByRole('button', { name: 'Ứng viên CVE CVE-2021-41773' })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Dịch vụ service:203.0.113.10:80/tcp' })).toBeInTheDocument();

    // Switch to Service Table
    fireEvent.click(screen.getByRole('button', { name: /Bảng Dịch vụ/ }));
    expect(await screen.findByRole('table', { name: 'Bảng dịch vụ theo chiến dịch' })).toBeInTheDocument();
  });
});
