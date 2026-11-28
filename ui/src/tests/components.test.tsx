import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent, within } from '@testing-library/react';
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
import { Layout } from '../components/Layout';
import { CampaignListScreen } from '../screens/CampaignListScreen';
import { CampaignCreateScreen } from '../screens/CampaignCreateScreen';
import { CampaignDetailScreen } from '../screens/CampaignDetailScreen';
import { ActivityScreen } from '../screens/ActivityScreen';
import { JobTableFlowScreen } from '../screens/JobTableFlowScreen';
import { FindingsScreen } from '../screens/FindingsScreen';
import { FindingDetailPanel } from '../components/FindingDetailPanel';
import { ApiError, apiClient, getOperatorToken, setOperatorToken } from '../api/client';
import type { SSEOptions } from '../api/sse';
import type { Campaign } from '../api/types';
import { resetMockData } from '../mock/handlers';

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

  it('shows first-run token help banner when operator token is not set', () => {
    setOperatorToken('');
    render(
      <MemoryRouter initialEntries={['/campaigns']}>
        <Routes>
          <Route path="/" element={<Layout />}>
            <Route path="campaigns" element={<CampaignListScreen />} />
          </Route>
        </Routes>
      </MemoryRouter>
    );

    expect(screen.getByRole('region', { name: 'Hướng dẫn cấu hình Operator Token lần đầu' })).toBeInTheDocument();
    expect(screen.getByText(/\.local\/operator-token/)).toBeInTheDocument();
    expect(screen.getByText(/ultron-operator-token/)).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /Cấu hình Operator Token/ }));
    expect(screen.getByText('Cấu hình Operator Bearer Token')).toBeInTheDocument();
  });

  it('navigates from CampaignListScreen Create button without alert()', async () => {
    resetMockData();
    const alertSpy = vi.spyOn(window, 'alert').mockImplementation(() => {});
    render(
      <MemoryRouter initialEntries={['/campaigns']}>
        <Routes>
          <Route path="/campaigns" element={<CampaignListScreen />} />
          <Route path="/campaigns/new" element={<div>Create Page Marker</div>} />
        </Routes>
      </MemoryRouter>
    );

    const createLink = await screen.findByRole('link', { name: /Tạo chiến dịch/ });
    expect(createLink).toHaveAttribute('href', '/campaigns/new');
    fireEvent.click(createLink);
    expect(await screen.findByText('Create Page Marker')).toBeInTheDocument();
    expect(alertSpy).not.toHaveBeenCalled();
    alertSpy.mockRestore();
  });

  it('validates CampaignCreateScreen inputs, requires internet confirmation, and maps server error.v2 inline', async () => {
    resetMockData();
    render(
      <MemoryRouter initialEntries={['/campaigns/new']}>
        <Routes>
          <Route path="/campaigns/new" element={<CampaignCreateScreen />} />
          <Route path="/campaigns/:id" element={<div>Created Detail Screen</div>} />
        </Routes>
      </MemoryRouter>
    );

    // Safe defaults: lab selected
    const labRadio = screen.getByLabelText(/lab \(Mặc định an toàn\)/) as HTMLInputElement;
    expect(labRadio.checked).toBe(true);

    // Submit empty -> client-side inline errors
    fireEvent.click(screen.getByRole('button', { name: /Tạo chiến dịch/ }));
    expect(await screen.findByText('Tên chiến dịch là bắt buộc.')).toBeInTheDocument();
    expect(screen.getByText('Mục tiêu chiến dịch là bắt buộc.')).toBeInTheDocument();
    expect(
      screen.getByText('Cần ít nhất một mục tiêu hợp lệ (domain, IP/CIDR hoặc từ khóa).')
    ).toBeInTheDocument();

    // Fill valid fields, switch to internet -> confirmation modal required
    fireEvent.change(screen.getByLabelText(/Tên chiến dịch/), { target: { value: 'UI Test Scan' } });
    fireEvent.change(screen.getByLabelText(/Mục tiêu tác chiến/), {
      target: { value: 'Verify form flow' },
    });
    fireEvent.change(screen.getByLabelText(/Tên miền \(targets\.domains/), {
      target: { value: 'lab.aegis.test' },
    });
    fireEvent.click(screen.getByLabelText(/internet \(Ra ngoài qua Broker\)/));
    fireEvent.change(screen.getByLabelText(/Chủ sở hữu hợp pháp \(authorization\.owner\)/), {
      target: { value: 'owner' },
    });
    fireEvent.change(screen.getByLabelText(/Ngày ủy quyền \(authorization\.date/), {
      target: { value: '2026-11-25' },
    });
    fireEvent.change(screen.getByLabelText(/Tham chiếu bằng chứng ủy quyền \(authorization\.reference/), {
      target: { value: 'owner, item 61, 2026-11-25' },
    });
    fireEvent.change(screen.getByLabelText(/Hậu tố tên miền được phép \(authorization\.authorized_suffixes/), {
      target: { value: 'lab.aegis.test' },
    });

    fireEvent.click(screen.getByRole('button', { name: /Kiểm tra & Xác nhận Internet/ }));
    expect(
      await screen.findByText('Quét chủ động ra internet — chỉ trên tài sản bạn sở hữu/được ủy quyền')
    ).toBeInTheDocument();
    const confirmBtn = screen.getByRole('button', { name: /Xác nhận & Thực thi/ });
    expect(confirmBtn).toBeDisabled();

    // Cancel confirmation, switch to lab, simulate server error.v2 inline on /targets/domains/0
    fireEvent.click(screen.getByRole('button', { name: /Quay lại chỉnh sửa/ }));
    fireEvent.click(labRadio);

    vi.spyOn(apiClient, 'createCampaign').mockRejectedValueOnce(
      new ApiError(400, {
        code: 'INPUT_INVALID',
        message: 'request body does not satisfy campaign-create: bad domain seed',
        next_action: 'FIX_INPUT',
        field: '/targets/domains/0',
      })
    );
    fireEvent.click(screen.getByRole('button', { name: /Tạo chiến dịch/ }));
    expect(await screen.findAllByText(/\/targets\/domains\/0/)).not.toHaveLength(0);
    expect(screen.getAllByText(/INPUT_INVALID/).length).toBeGreaterThanOrEqual(1);

    // Retry succeeds and navigates
    fireEvent.click(screen.getByRole('button', { name: /Tạo chiến dịch/ }));
    expect(await screen.findByText('Created Detail Screen')).toBeInTheDocument();
  });

  it('allows adopting a new RoE policy snapshot on active campaign in CampaignDetailScreen', async () => {
    resetMockData();
    render(
      <MemoryRouter initialEntries={['/campaigns/01934f6a-0000-7000-8000-000000000001']}>
        <Routes>
          <Route path="/campaigns/:id" element={<CampaignDetailScreen />} />
        </Routes>
      </MemoryRouter>
    );

    const editBtn = await screen.findByRole('button', { name: /Tạo bản chụp RoE mới/ });
    fireEvent.click(editBtn);

    fireEvent.change(screen.getByLabelText(/Lý do cập nhật RoE/), {
      target: { value: 'Cap nhat gioi han dong thoi len 3' },
    });
    fireEvent.change(screen.getByLabelText(/Số job đồng thời tối đa/), {
      target: { value: '3' },
    });
    fireEvent.click(screen.getByRole('button', { name: /Lưu & Kích hoạt RoE mới/ }));

    expect(await screen.findByText(/Đã tạo và kích hoạt bản chụp RoE mới: roe-/)).toBeInTheDocument();
  });

  it('disables policy adoption on terminal COMPLETED campaign in CampaignDetailScreen', async () => {
    resetMockData();
    render(
      <MemoryRouter initialEntries={['/campaigns/01934f6a-0000-7000-8000-000000000003']}>
        <Routes>
          <Route path="/campaigns/:id" element={<CampaignDetailScreen />} />
        </Routes>
      </MemoryRouter>
    );

    expect(
      await screen.findByText(/Chiến dịch đã kết thúc \(COMPLETED\) — API chỉ cho phép tạo bản chụp RoE mới/)
    ).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Tạo bản chụp RoE mới/ })).not.toBeInTheDocument();
  });

  it('scopes AssetGraphScreen graph error to Graph view only and renders HTTP status + path (F1)', async () => {
    resetMockData();
    const graphSpy = vi.spyOn(apiClient, 'getAssetGraph').mockRejectedValueOnce(
      new ApiError(
        500,
        {
          code: 'INTERNAL_ERROR',
          message: 'the app has no graph driver',
          next_action: 'CHECK_PROVIDER',
        },
        'the app has no graph driver',
        '/assets/01934f6a-0000-7000-8000-0000000000f3/graph?campaign_id=01934f6a-0000-7000-8000-000000000001'
      )
    );

    try {
      render(
        <MemoryRouter initialEntries={['/assets?campaign_id=01934f6a-0000-7000-8000-000000000001']}>
          <Routes>
            <Route path="/assets" element={<AssetGraphScreen />} />
          </Routes>
        </MemoryRouter>
      );

      expect(await screen.findByText('HTTP 500')).toBeInTheDocument();
      expect(screen.getByText(/Mã lỗi: INTERNAL_ERROR/)).toBeInTheDocument();
      expect(
        screen.getByText(/Đường dẫn \(path\): \/assets\/01934f6a-0000-7000-8000-0000000000f3\/graph/)
      ).toBeInTheDocument();

      // Switch to Bảng Dịch vụ -> graph error banner must NOT appear above service table
      fireEvent.click(screen.getByRole('button', { name: /Bảng Dịch vụ/ }));
      expect(await screen.findByRole('table', { name: 'Bảng dịch vụ theo chiến dịch' })).toBeInTheDocument();
      expect(screen.queryByText(/Mã lỗi: INTERNAL_ERROR/)).not.toBeInTheDocument();

      // Switch to Bảng Tài sản -> graph error banner must NOT appear above asset table
      fireEvent.click(screen.getByRole('button', { name: 'Bảng Tài sản' }));
      expect(await screen.findByRole('table', { name: 'Bảng tài sản số' })).toBeInTheDocument();
      expect(screen.queryByText(/Mã lỗi: INTERNAL_ERROR/)).not.toBeInTheDocument();
    } finally {
      graphSpy.mockRestore();
    }
  });

  it('opens CVE panel when clicking ServiceTable row or candidate/KEV badges (F5)', () => {
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

    fireEvent.click(screen.getByRole('button', { name: '1 ứng viên' }));
    expect(onSelect).toHaveBeenCalledTimes(1);

    fireEvent.click(screen.getByRole('button', { name: '1 KEV' }));
    expect(onSelect).toHaveBeenCalledTimes(2);

    fireEvent.click(screen.getByText('http_server'));
    expect(onSelect).toHaveBeenCalledTimes(3);
  });

  it('closes TokenConfigModal on Escape and focuses first input with focus trap (F6)', async () => {
    const onClose = vi.fn();
    render(<TokenConfigModal isOpen={true} onClose={onClose} />);

    const input = screen.getByLabelText('Nhập Operator Token');
    await vi.waitFor(() => {
      expect(document.activeElement).toBe(input);
    });

    // Tab backwards from first focusable element wraps to last button (Lưu Token)
    fireEvent.keyDown(document, { key: 'Tab', shiftKey: true });
    expect(document.activeElement).toBe(screen.getByRole('button', { name: 'Lưu Token' }));

    // Tab forward from last wraps back to first input
    fireEvent.keyDown(document, { key: 'Tab' });
    expect(document.activeElement).toBe(input);

    // Escape closes modal
    fireEvent.keyDown(document, { key: 'Escape' });
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('renders ActivityScreen with decisions, reasons, linked jobs, sessions, budget, and filters', async () => {
    resetMockData();
    render(
      <MemoryRouter initialEntries={['/activity?campaign_id=01934f6a-0000-7000-8000-000000000001']}>
        <Routes>
          <Route path="/activity" element={<ActivityScreen />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByText('Nhật ký Hoạt động Agent (Activity)')).toBeInTheDocument();
    expect(await screen.findByText('network.discover_services')).toBeInTheDocument();
    expect(screen.getByText(/Lý do từ chối: OUT_OF_SCOPE/)).toBeInTheDocument();
    expect(screen.getByText(/Luật: target_denied/)).toBeInTheDocument();
    expect(screen.getByText('dns.resolve')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /Xem Job/ })).toHaveAttribute(
      'href',
      '/jobs?campaign_id=01934f6a-0000-7000-8000-000000000001&job_id=01934f6a-0000-7000-8000-00000000d002'
    );
    expect(screen.getByText(/Bị chặn \(Blocker\): DEPENDENCY_MISSING/)).toBeInTheDocument();
    expect(screen.getByText(/4,250 tokens/)).toBeInTheDocument();

    // Filter to denied only
    fireEvent.change(screen.getByLabelText('Lọc trạng thái quyết định'), {
      target: { value: 'denied' },
    });
    expect(screen.getByText('network.discover_services')).toBeInTheDocument();
    expect(screen.queryByText('dns.resolve')).not.toBeInTheDocument();
  });

  it('renders contract budget {limits,used,remaining} and counters {jobs_by_status,assets_by_kind} on list and detail (F2)', async () => {
    resetMockData();
    const { unmount } = render(
      <MemoryRouter initialEntries={['/campaigns']}>
        <Routes>
          <Route path="/campaigns" element={<CampaignListScreen />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByText('Chiến dịch Recon Hạ tầng Vận hành Q4')).toBeInTheDocument();
    expect(screen.getByText(/Còn 36\.5h \/ 48h/)).toBeInTheDocument();
    expect(screen.getByText(/\$7\.50 \/ \$150\.00/)).toBeInTheDocument();
    expect(screen.getByText(/12\/50 jobs · 3\/20 phiên/)).toBeInTheDocument();
    expect(screen.getAllByTitle('Tổng số job')[0]).toHaveTextContent(/12\s+jobs/);
    expect(screen.getByText(/28\s+tài sản/)).toBeInTheDocument();
    expect(screen.getByText(/domain: 12 · IP: 8 · service: 6 · app: 2/)).toBeInTheDocument();
    unmount();

    // Detail screen with partial/uncapped budget (01934f6a-...-0002 only caps max_duration_hours)
    render(
      <MemoryRouter initialEntries={['/campaigns/01934f6a-0000-7000-8000-000000000002']}>
        <Routes>
          <Route path="/campaigns/:id" element={<CampaignDetailScreen />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByText('Ngân sách & Bộ đếm Tác chiến')).toBeInTheDocument();
    expect(screen.getByText('Ngân sách thực thi (Đã dùng / Giới hạn & Còn lại)')).toBeInTheDocument();
    expect(screen.getByText('6.00h')).toBeInTheDocument();
    expect(screen.getByText('Còn lại: 18.00h')).toBeInTheDocument();
    expect(screen.getAllByText('Không giới hạn trần RoE').length).toBeGreaterThanOrEqual(4);
    expect(screen.getByText('Bộ đếm Job & Tài sản')).toBeInTheDocument();
    expect(screen.getByText('SUCCEEDED: 5')).toBeInTheDocument();
    expect(screen.getByText('WAITING: 1')).toBeInTheDocument();
    expect(screen.getByText('domain: 8')).toBeInTheDocument();
    expect(screen.getByText('IP: 4')).toBeInTheDocument();
    expect(screen.getByText('service: 2')).toBeInTheDocument();
  });

  it('never fabricates numbers when budget or counters fields are absent (F2)', async () => {
    const partialCampaign: Campaign = {
      campaign_id: '01934f6a-0000-7000-8000-000000000099',
      name: 'Chiến dịch thiếu trường ngân sách',
      status: 'CREATED',
      policy_version: 'roe-1',
      scope_id: '01934f6a-0000-7000-8000-0000000000a9',
      created_at: '2026-11-26T00:00:00Z',
      budget: {
        limits: {
          max_duration_hours: 12,
          max_llm_cost_usd: 50,
        },
        used: {
          hours: 1,
          llm_cost_usd: 0.5,
          llm_tokens: 1000,
          jobs: 2,
          agent_sessions: 1,
        },
        remaining: {
          hours: 11,
        },
      },
    };
    const listSpy = vi.spyOn(apiClient, 'listCampaigns').mockResolvedValueOnce({
      items: [partialCampaign],
      next_cursor: undefined,
    });
    const detailSpy = vi.spyOn(apiClient, 'getCampaign').mockResolvedValueOnce(partialCampaign);

    const { unmount } = render(
      <MemoryRouter initialEntries={['/campaigns']}>
        <Routes>
          <Route path="/campaigns" element={<CampaignListScreen />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByText('Chiến dịch thiếu trường ngân sách')).toBeInTheDocument();
    expect(screen.getByText('Chưa có bộ đếm')).toBeInTheDocument();
    unmount();

    render(
      <MemoryRouter initialEntries={['/campaigns/01934f6a-0000-7000-8000-000000000099']}>
        <Routes>
          <Route path="/campaigns/:id" element={<CampaignDetailScreen />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByText('Chiến dịch thiếu trường ngân sách')).toBeInTheDocument();
    expect(screen.getByText('Chưa có dữ liệu bộ đếm')).toBeInTheDocument();
    expect(screen.getByText('Còn lại: —')).toBeInTheDocument();
    expect(screen.queryByText('$0.00')).not.toBeInTheDocument();

    listSpy.mockRestore();
    detailSpy.mockRestore();
  });

  it('collapses schema dump behind technical details toggle while keeping short operator summary (D3)', () => {
    const schemaDumpError = new ApiError(
      500,
      {
        code: 'INTERNAL_ERROR',
        message:
          "graph read model violates mcp/graph-queries.v2.schema.json#/$defs/get_asset_neighbors/properties/output: /edges/6/to: None is not valid under each of {'title': 'ip', 'pattern': '^ip:(?:[0-9]{1,3})'}",
        next_action: 'ESCALATE',
        trace_id: 'trace-abc-123',
      },
      undefined,
      '/assets/01934f6a-0000-7000-8000-0000000000f3/graph?campaign_id=01934f6a-0000-7000-8000-000000000001'
    );

    render(<ErrorDisplay error={schemaDumpError} onRetry={() => {}} />);

    expect(screen.getByText('Mã lỗi: INTERNAL_ERROR')).toBeInTheDocument();
    expect(screen.getByText('HTTP 500')).toBeInTheDocument();
    expect(
      screen.getByText(/Không thể dựng đồ thị tài sản vì dữ liệu trả về từ máy chủ không khớp hợp đồng/)
    ).toBeInTheDocument();
    expect(screen.getByText(/Đường dẫn \(path\): \/assets\//)).toBeInTheDocument();
    expect(screen.getByText(/ESCALATE/)).toBeInTheDocument();

    // Schema regex dump must NOT be visible by default
    expect(screen.queryByText(/None is not valid under each of/)).not.toBeInTheDocument();

    const toggle = screen.getByRole('button', { name: /Xem chi tiết kỹ thuật/ });
    expect(toggle).toHaveAttribute('aria-expanded', 'false');
    fireEvent.click(toggle);

    expect(toggle).toHaveAttribute('aria-expanded', 'true');
    expect(screen.getByText(/None is not valid under each of/)).toBeInTheDocument();
    expect(screen.getByText(/trace-abc-123/)).toBeInTheDocument();
  });

  it('omits max_agent_sessions by default and shows capability-derived minimum hint (D4)', async () => {
    resetMockData();
    const createSpy = vi.spyOn(apiClient, 'createCampaign');

    try {
      render(
        <MemoryRouter initialEntries={['/campaigns/new']}>
          <Routes>
            <Route path="/campaigns/new" element={<CampaignCreateScreen />} />
            <Route path="/campaigns/:id" element={<div>Created Detail Screen</div>} />
          </Routes>
        </MemoryRouter>
      );

      const sessionsInput = screen.getByLabelText(/Số phiên agent tối đa/) as HTMLInputElement;
      expect(sessionsInput.value).toBe('');

      // Wait for capabilities (4 capabilities in mock) to render the derived minimum hint (4 + 1 = 5)
      expect(await screen.findByText(/Chuỗi 4 capability đang bật cần tối thiểu/)).toBeInTheDocument();

      // Entering < 5 shows non-blocking warning hint
      fireEvent.change(sessionsInput, { target: { value: '4' } });
      expect(screen.getByText(/Cảnh báo: 4 phiên thấp hơn tối thiểu 5 phiên/)).toBeInTheDocument();

      // Clear back to blank -> payload omits max_agent_sessions so API default applies
      fireEvent.change(sessionsInput, { target: { value: '' } });
      fireEvent.change(screen.getByLabelText(/Tên chiến dịch/), { target: { value: 'Default Session Cap' } });
      fireEvent.change(screen.getByLabelText(/Mục tiêu tác chiến/), { target: { value: 'Run full chain' } });
      fireEvent.change(screen.getByLabelText(/Tên miền \(targets\.domains/), {
        target: { value: 'lab.aegis.test' },
      });

      fireEvent.click(screen.getByRole('button', { name: /Tạo chiến dịch/ }));
      expect(await screen.findByText('Created Detail Screen')).toBeInTheDocument();

      expect(createSpy).toHaveBeenCalledTimes(1);
      const sentPayload = createSpy.mock.calls[0][0];
      expect(sentPayload.policy.budget?.max_agent_sessions).toBeUndefined();
    } finally {
      createSpy.mockRestore();
    }
  });

  it('makes O(1) GETs on open when SSE replays 355 historical events across campaign screens (D1)', async () => {
    resetMockData();
    vi.useFakeTimers();

    const campaignId = '01934f6a-0000-7000-8000-000000000003';
    const getCampaignSpy = vi.spyOn(apiClient, 'getCampaign');
    const getActivitySpy = vi.spyOn(apiClient, 'getCampaignActivity');
    const listJobsSpy = vi.spyOn(apiClient, 'listJobs');
    const getFlowSpy = vi.spyOn(apiClient, 'getCampaignFlow');

    const capturedSubs: SSEOptions[] = [];
    const subSpy = vi.spyOn(apiClient, 'subscribeCampaignEvents').mockImplementation((opts) => {
      capturedSubs.push(opts);
      opts.onStatusChange?.('connected');
      return { close: vi.fn(), getLastEventId: () => '355' };
    });

    const emitBurst = (count: number) => {
      const active = capturedSubs[capturedSubs.length - 1];
      for (let i = 1; i <= count; i++) {
        const type = i % 5 === 0 ? 'job.completed.v2' : 'observation.changed.v2';
        active?.onEvent({
          id: String(i),
          type,
          data: { event_id: `ev-${i}`, type, payload: {} },
          raw: '{}',
          timestamp: Date.now(),
        });
      }
    };

    try {
      // 1. CampaignDetailScreen
      const detailView = render(
        <MemoryRouter initialEntries={[`/campaigns/${campaignId}`]}>
          <Routes>
            <Route path="/campaigns/:id" element={<CampaignDetailScreen />} />
          </Routes>
        </MemoryRouter>
      );
      await vi.advanceTimersByTimeAsync(50);
      expect(getCampaignSpy).toHaveBeenCalledTimes(1);
      emitBurst(355);
      await vi.advanceTimersByTimeAsync(350);
      expect(getCampaignSpy).toHaveBeenCalledTimes(2);
      detailView.unmount();

      // 2. ActivityScreen
      const activityView = render(
        <MemoryRouter initialEntries={[`/activity?campaign_id=${campaignId}`]}>
          <Routes>
            <Route path="/activity" element={<ActivityScreen />} />
          </Routes>
        </MemoryRouter>
      );
      await vi.advanceTimersByTimeAsync(50);
      expect(getActivitySpy).toHaveBeenCalledTimes(1);
      emitBurst(355);
      await vi.advanceTimersByTimeAsync(350);
      expect(getActivitySpy).toHaveBeenCalledTimes(2);
      activityView.unmount();

      // 3. JobTableFlowScreen (also verify irrelevant observation events trigger 0 extra GETs and filter change does not reopen SSE)
      const jobsView = render(
        <MemoryRouter initialEntries={[`/jobs?campaign_id=${campaignId}`]}>
          <Routes>
            <Route path="/jobs" element={<JobTableFlowScreen />} />
          </Routes>
        </MemoryRouter>
      );
      await vi.advanceTimersByTimeAsync(50);
      const subCallsBeforeFilter = subSpy.mock.calls.length;
      expect(listJobsSpy).toHaveBeenCalledTimes(1);
      expect(getFlowSpy).toHaveBeenCalledTimes(1);

      // Irrelevant events only -> 0 extra GETs
      const activeJobSub = capturedSubs[capturedSubs.length - 1];
      for (let i = 1; i <= 100; i++) {
        activeJobSub?.onEvent({
          id: String(400 + i),
          type: 'vulnerability.matched.v2',
          data: { event_id: `v-${i}`, type: 'vulnerability.matched.v2', payload: {} },
          raw: '{}',
          timestamp: Date.now(),
        });
      }
      await vi.advanceTimersByTimeAsync(350);
      expect(listJobsSpy).toHaveBeenCalledTimes(1);
      expect(getFlowSpy).toHaveBeenCalledTimes(1);

      // Relevant burst of 355 events -> O(1) coalesced refetch
      emitBurst(355);
      await vi.advanceTimersByTimeAsync(350);
      expect(listJobsSpy).toHaveBeenCalledTimes(2);
      expect(getFlowSpy).toHaveBeenCalledTimes(2);

      // Changing status filter must not reopen SSE subscription
      fireEvent.change(screen.getByLabelText('Lọc trạng thái job'), { target: { value: 'RUNNING' } });
      await vi.advanceTimersByTimeAsync(50);
      expect(subSpy.mock.calls.length).toBe(subCallsBeforeFilter);
      jobsView.unmount();
    } finally {
      vi.useRealTimers();
      subSpy.mockRestore();
      getCampaignSpy.mockRestore();
      getActivitySpy.mockRestore();
      listJobsSpy.mockRestore();
      getFlowSpy.mockRestore();
    }
  });

  it('renders non-empty React Flow MiniMap nodes in JobTableFlowScreen flow view (D7)', async () => {
    resetMockData();
    const origResizeObserver = globalThis.ResizeObserver;
    if (typeof globalThis.ResizeObserver === 'undefined') {
      globalThis.ResizeObserver = class ResizeObserver {
        observe() {}
        unobserve() {}
        disconnect() {}
      };
    }

    try {
      render(
        <MemoryRouter initialEntries={['/jobs?campaign_id=01934f6a-0000-7000-8000-000000000001']}>
          <Routes>
            <Route path="/jobs" element={<JobTableFlowScreen />} />
          </Routes>
        </MemoryRouter>
      );

      const flowBtn = await screen.findByRole('button', { name: /Đồ thị Luồng \(React Flow\)/ });
      fireEvent.click(flowBtn);

      const minimap = await screen.findByTestId('rf__minimap');
      expect(minimap).toBeInTheDocument();
      const minimapNodes = minimap.querySelectorAll('.react-flow__minimap-node');
      expect(minimapNodes.length).toBeGreaterThan(0);
    } finally {
      globalThis.ResizeObserver = origResizeObserver;
    }
  });

  it('ranks ServiceTable CVEs (KEV -> EPSS -> CVSS), collapses after top 5 with +N expander, and shows KEV/Critical/High counts', () => {
    const onSelect = vi.fn();
    const candidates: import('../api/types').VulnerabilityCandidate[] = [
      // Unsorted input order intentionally: low/alphabetical first, KEV buried in middle
      {
        vulnerability_id: 'CVE-1999-0001',
        cvss_base: 5.0,
        cvss_severity: 'MEDIUM',
        kev: false,
        epss: 0.01,
        match_method: 'cpe_range',
        confidence: 0.6,
        candidate_since: '2026-11-25T08:06:00Z',
      },
      {
        vulnerability_id: 'CVE-2020-0002',
        cvss_base: 7.5,
        cvss_severity: 'HIGH',
        kev: false,
        epss: 0.45,
        match_method: 'cpe_range',
        confidence: 0.7,
        candidate_since: '2026-11-25T08:06:00Z',
      },
      {
        vulnerability_id: 'CVE-2021-41773',
        cvss_base: 7.5,
        cvss_severity: 'HIGH',
        kev: true,
        epss: 0.05,
        match_method: 'cpe_range',
        confidence: 0.8,
        candidate_since: '2026-11-25T08:06:00Z',
      },
      {
        vulnerability_id: 'CVE-2022-0003',
        cvss_base: 9.8,
        cvss_severity: 'CRITICAL',
        kev: false,
        epss: 0.1,
        match_method: 'cpe_range',
        confidence: 0.7,
        candidate_since: '2026-11-25T08:06:00Z',
      },
      {
        vulnerability_id: 'CVE-2023-0004',
        cvss_base: 9.1,
        cvss_severity: 'CRITICAL',
        kev: false,
        epss: 0.8,
        match_method: 'cpe_range',
        confidence: 0.7,
        candidate_since: '2026-11-25T08:06:00Z',
      },
      {
        vulnerability_id: 'CVE-2024-0005',
        cvss_base: 8.2,
        cvss_severity: 'HIGH',
        kev: false,
        epss: 0.3,
        match_method: 'cpe_range',
        confidence: 0.7,
        candidate_since: '2026-11-25T08:06:00Z',
      },
      {
        vulnerability_id: 'CVE-2025-0006',
        cvss_base: 9.9,
        cvss_severity: 'CRITICAL',
        kev: false,
        epss: 0.3,
        match_method: 'cpe_range',
        confidence: 0.7,
        candidate_since: '2026-11-25T08:06:00Z',
      },
      {
        vulnerability_id: 'CVE-2026-0007',
        cvss_base: 4.3,
        cvss_severity: 'MEDIUM',
        kev: false,
        epss: null,
        match_method: 'cpe_range',
        confidence: 0.5,
        candidate_since: '2026-11-25T08:06:00Z',
      },
    ];

    render(
      <ServiceTable
        rows={[
          {
            asset: {
              asset_id: '01934f6a-0000-7000-8000-0000000000f8',
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
            candidates,
            candidateCount: candidates.length,
            kevCount: 1,
            truncatedCandidates: false,
          },
        ]}
        onSelectVulnerability={onSelect}
        onFocusInGraph={() => {}}
      />
    );

    // Count summary badges: total, KEV, Critical, High
    expect(screen.getByText('8 ứng viên')).toBeInTheDocument();
    expect(screen.getByText('1 KEV')).toBeInTheDocument();
    expect(screen.getByText('3 Critical')).toBeInTheDocument();
    expect(screen.getByText('3 High')).toBeInTheDocument();

    // Expected top 5 ranking:
    // 1. CVE-2021-41773 (KEV=true)
    // 2. CVE-2023-0004 (EPSS 0.80)
    // 3. CVE-2020-0002 (EPSS 0.45)
    // 4. CVE-2025-0006 (EPSS 0.30, CVSS 9.9)
    // 5. CVE-2024-0005 (EPSS 0.30, CVSS 8.2)
    // Collapsed: CVE-2022-0003 (EPSS 0.10), CVE-1999-0001 (EPSS 0.01), CVE-2026-0007 (EPSS null)
    const chipButtons = screen.getAllByRole('button', { name: /CVE-/ });
    expect(chipButtons.map((b) => b.textContent)).toEqual([
      'CVE-2021-41773KEV',
      'CVE-2023-0004',
      'CVE-2020-0002',
      'CVE-2025-0006',
      'CVE-2024-0005',
    ]);
    expect(screen.queryByText('CVE-1999-0001')).not.toBeInTheDocument();
    expect(screen.queryByText('CVE-2022-0003')).not.toBeInTheDocument();

    // Expander '+3' expands all 8, and 'Thu gọn' collapses back to top 5
    const expandBtn = screen.getByRole('button', { name: /Hiện thêm 3 ứng viên CVE/ });
    expect(expandBtn).toHaveTextContent('+3');
    expect(expandBtn).toHaveAttribute('aria-expanded', 'false');
    fireEvent.click(expandBtn);

    expect(screen.getByText('CVE-1999-0001')).toBeInTheDocument();
    expect(screen.getByText('CVE-2022-0003')).toBeInTheDocument();
    expect(screen.getByText('CVE-2026-0007')).toBeInTheDocument();

    const collapseBtn = screen.getByRole('button', { name: /Thu gọn danh sách ứng viên CVE/ });
    expect(collapseBtn).toHaveAttribute('aria-expanded', 'true');
    fireEvent.click(collapseBtn);
    expect(screen.queryByText('CVE-1999-0001')).not.toBeInTheDocument();

    // Clicking Critical badge opens highest-ranked CRITICAL candidate (CVE-2023-0004)
    fireEvent.click(screen.getByRole('button', { name: '3 Critical' }));
    expect(onSelect).toHaveBeenLastCalledWith(
      expect.objectContaining({ host: '10.114.53.215' }),
      expect.objectContaining({ vulnerability_id: 'CVE-2023-0004' })
    );
  });

  it('keeps the full sortable candidate list in VulnerabilityPanel', () => {
    const siblings: import('../api/types').VulnerabilityCandidate[] = Array.from(
      { length: 8 },
      (_, idx) => ({
        vulnerability_id: `CVE-202${idx}-100${idx}`,
        cvss_base: idx === 2 ? 9.8 : 5.0 + idx * 0.4,
        cvss_severity: idx === 2 ? 'CRITICAL' : 'MEDIUM',
        kev: idx === 5,
        epss: idx === 1 ? 0.92 : idx * 0.05,
        match_method: 'cpe_range' as const,
        confidence: 0.7,
        candidate_since: '2026-11-25T08:06:00Z',
      })
    );
    const onSelectCandidate = vi.fn();

    render(
      <VulnerabilityPanel
        data={{
          assetId: '01934f6a-0000-7000-8000-0000000000f8',
          assetKey: 'service:10.114.53.215:80/tcp',
          candidate: siblings[5],
          siblings,
        }}
        onSelectCandidate={onSelectCandidate}
        onClose={() => {}}
      />
    );

    const listItems = screen.getAllByRole('listitem');
    expect(listItems).toHaveLength(8);
    // Default rank: KEV first (CVE-2025-1005), then highest EPSS (CVE-2021-1001)
    expect(listItems[0]).toHaveTextContent('CVE-2025-1005');
    expect(listItems[1]).toHaveTextContent('CVE-2021-1001');

    // Switch sort to CVSS desc -> CVE-2022-1002 (9.8) first
    const sortSelect = screen.getByLabelText('Sắp xếp ứng viên CVE');
    fireEvent.change(sortSelect, { target: { value: 'cvss' } });
    expect(screen.getAllByRole('listitem')[0]).toHaveTextContent('CVE-2022-1002');

    // Switch sort to EPSS desc -> CVE-2021-1001 (0.92) first
    fireEvent.change(sortSelect, { target: { value: 'epss' } });
    expect(screen.getAllByRole('listitem')[0]).toHaveTextContent('CVE-2021-1001');

    // Switch sort to CVE ID Z->A -> CVE-2027-1007 first
    fireEvent.change(sortSelect, { target: { value: 'cve_desc' } });
    expect(screen.getAllByRole('listitem')[0]).toHaveTextContent('CVE-2027-1007');

    // Clicking an item calls onSelectCandidate
    fireEvent.click(screen.getAllByRole('listitem')[0]);
    expect(onSelectCandidate).toHaveBeenCalledWith(
      expect.objectContaining({ vulnerability_id: 'CVE-2027-1007' })
    );
  });

  it('collapses 99 CVE candidates to top 5 + +94 expander and keeps all 99 in VulnerabilityPanel', () => {
    const many: import('../api/types').VulnerabilityCandidate[] = Array.from(
      { length: 99 },
      (_, idx) => ({
        vulnerability_id: `CVE-2025-${String(1000 + idx).padStart(4, '0')}`,
        cvss_base: idx === 50 ? 9.5 : 5.0,
        cvss_severity: null,
        kev: idx === 77,
        epss: idx === 77 ? 0.2 : idx === 10 ? 0 : idx === 11 ? null : (idx % 10) * 0.05,
        match_method: 'cpe_range' as const,
        confidence: 0.7,
        candidate_since: '2026-11-25T08:06:00Z',
      })
    );
    const onSelect = vi.fn();

    render(
      <ServiceTable
        rows={[
          {
            asset: {
              asset_id: '01934f6a-0000-7000-8000-0000000000f9',
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
            candidates: many,
            candidateCount: 99,
            kevCount: 1,
            truncatedCandidates: false,
          },
        ]}
        onSelectVulnerability={onSelect}
        onFocusInGraph={() => {}}
      />
    );

    expect(screen.getByText('99 ứng viên')).toBeInTheDocument();
    expect(screen.getByText('1 KEV')).toBeInTheDocument();
    expect(screen.getByText('1 Critical')).toBeInTheDocument();
    expect(screen.getAllByRole('button', { name: /CVE-/ })).toHaveLength(5);
    expect(screen.getByRole('button', { name: /Hiện thêm 94 ứng viên CVE/ })).toHaveTextContent('+94');

    const { unmount } = render(
      <VulnerabilityPanel
        data={{
          assetId: '01934f6a-0000-7000-8000-0000000000f9',
          assetKey: 'service:10.114.53.215:80/tcp',
          candidate: many[77],
          siblings: many,
        }}
        onSelectCandidate={() => {}}
        onClose={() => {}}
      />
    );
    const allItems = screen.getAllByRole('listitem');
    expect(allItems).toHaveLength(99);
    // KEV first, and epss=0 (CVE-2025-1010) ranks ahead of epss=null (CVE-2025-1011)
    expect(allItems[0]).toHaveTextContent('CVE-2025-1077');
    const idxZero = allItems.findIndex((el) => el.textContent?.includes('CVE-2025-1010'));
    const idxNull = allItems.findIndex((el) => el.textContent?.includes('CVE-2025-1011'));
    expect(idxZero).toBeGreaterThan(-1);
    expect(idxNull).toBeGreaterThan(idxZero);
    unmount();
  });

  it('renders FindingsScreen with filters, finding detail, UNRATED fallback, SHA-256 download, and no-longer-seen timeline', async () => {
    resetMockData();
    render(
      <MemoryRouter initialEntries={['/findings']}>
        <Routes>
          <Route path="/findings" element={<FindingsScreen />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByText('Apache HTTP Server 2.4.49 Path Traversal (CVE-2021-41773)')).toBeInTheDocument();

    // Open detail of first finding (CRITICAL + CVE-2021-41773 + seen=false run)
    const detailButtons = screen.getAllByRole('button', { name: /Chi tiết/ });
    fireEvent.click(detailButtons[0]);

    const detailPanel = await screen.findByLabelText('Bảng chi tiết Finding');
    expect(detailPanel).toBeInTheDocument();
    expect(await screen.findByText('Không còn thấy (no longer seen)')).toBeInTheDocument();
    expect(detailPanel).toHaveTextContent('e00400000000000000000000000000000000000000000000000000000000e004');
    expect(screen.getByRole('link', { name: /Tải bằng chứng/ })).toHaveAttribute('href', expect.stringContaining('https://s3.lab.local/'));
    expect(detailPanel).toHaveTextContent('seq hiện tại: #1');

    // Filter by severity=UNRATED and inspect UNRATED fallback finding
    const severitySelect = screen.getByLabelText('Lọc theo mức nghiêm trọng');
    fireEvent.change(severitySelect, { target: { value: 'UNRATED' } });
    const findingsTable = await screen.findByRole('table', { name: 'Bảng danh sách findings' });
    expect(await within(findingsTable).findByText(/Nginx 1\.18\.0/)).toBeInTheDocument();
    expect(within(findingsTable).queryByText(/Apache HTTP Server 2\.4\.49/)).not.toBeInTheDocument();

    const unratedDetailBtn = within(findingsTable).getAllByRole('button', { name: /Chi tiết/ })[0];
    fireEvent.click(unratedDetailBtn);
    expect(await screen.findByText(/UNRATED — Fallback do đánh giá tự động thất bại/)).toBeInTheDocument();
    expect(screen.getByText('RATE_LIMITED')).toBeInTheDocument();
    expect(screen.getByText(/Tín hiệu thô đối chiếu/)).toBeInTheDocument();
  });

  it('submits operator transition with reason and handles 409 stale expected_seq cleanly', async () => {
    resetMockData();
    const finding = await apiClient.getFinding('01934f6a-0000-7000-8000-00000000f101');
    const history = await apiClient.getFindingHistory('01934f6a-0000-7000-8000-00000000f101');
    const onRefreshFinding = vi.fn();
    const onTransitionSuccess = vi.fn();

    // Simulate concurrent transition on backend while UI still holds seq=1
    await apiClient.transitionFinding(
      finding.finding_id,
      { to: 'ACCEPTED_RISK', reason: 'Concurrent update', expected_seq: 1 },
      { idempotencyKey: 'concurrent-key-1' }
    );

    render(
      <MemoryRouter>
        <FindingDetailPanel
          finding={finding}
          history={history}
          historyLoading={false}
          historyError={null}
          provenance={null}
          provenanceLoading={false}
          provenanceError={null}
          onRetryHistory={() => {}}
          onRefreshFinding={onRefreshFinding}
          onTransitionSuccess={onTransitionSuccess}
          onClose={() => {}}
        />
      </MemoryRouter>
    );

    // Validation error on short reason
    const reasonInput = screen.getByLabelText(/Lý do chuyển trạng thái/);
    fireEvent.change(reasonInput, { target: { value: 'ab' } });
    fireEvent.click(screen.getByRole('button', { name: 'Xác nhận chuyển trạng thái' }));
    expect(
      await screen.findByText('Lý do chuyển trạng thái là bắt buộc (tối thiểu 3 ký tự).')
    ).toBeInTheDocument();

    // Valid reason triggers 409 conflict because UI still has stale expected_seq=1
    fireEvent.change(reasonInput, { target: { value: 'Da kiem tra va xac nhan bao nham' } });
    fireEvent.click(screen.getByRole('button', { name: 'Xác nhận chuyển trạng thái' }));
    expect(
      await screen.findByText(/Xung đột phiên bản trạng thái \(HTTP 409 — expected_seq đã cũ\)/)
    ).toBeInTheDocument();
    // Preserves operator's typed reason and offers reload button
    expect((reasonInput as HTMLTextAreaElement).value).toBe('Da kiem tra va xac nhan bao nham');
    fireEvent.click(screen.getByRole('button', { name: /Tải lại trạng thái & seq mới nhất/ }));
    expect(onRefreshFinding).toHaveBeenCalledTimes(1);
  });

  it('shows stale-seq recovery banner when real backend returns 409 IDEMPOTENCY_CONFLICT with expected_seq message', async () => {
    resetMockData();
    const finding = await apiClient.getFinding('01934f6a-0000-7000-8000-00000000f101');
    const history = await apiClient.getFindingHistory('01934f6a-0000-7000-8000-00000000f101');
    const spy = vi.spyOn(apiClient, 'transitionFinding').mockRejectedValueOnce(
      new ApiError(
        409,
        {
          code: 'IDEMPOTENCY_CONFLICT',
          message: 'expected_seq 1 does not match the current transition_seq 2',
          next_action: 'RETRY',
        },
        'expected_seq 1 does not match the current transition_seq 2'
      )
    );

    try {
      render(
        <MemoryRouter>
          <FindingDetailPanel
            finding={finding}
            history={history}
            historyLoading={false}
            historyError={null}
            provenance={null}
            provenanceLoading={false}
            provenanceError={null}
            onRetryHistory={() => {}}
            onRefreshFinding={() => {}}
            onTransitionSuccess={() => {}}
            onClose={() => {}}
          />
        </MemoryRouter>
      );

      fireEvent.change(screen.getByLabelText(/Lý do chuyển trạng thái/), {
        target: { value: 'Kiem tra xung dot seq tu backend that' },
      });
      fireEvent.click(screen.getByRole('button', { name: 'Xác nhận chuyển trạng thái' }));
      expect(
        await screen.findByText(/Xung đột phiên bản trạng thái \(HTTP 409 — expected_seq đã cũ\)/)
      ).toBeInTheDocument();
    } finally {
      spy.mockRestore();
    }
  });
});
