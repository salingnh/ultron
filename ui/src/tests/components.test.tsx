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
import { Layout } from '../components/Layout';
import { CampaignListScreen } from '../screens/CampaignListScreen';
import { CampaignCreateScreen } from '../screens/CampaignCreateScreen';
import { CampaignDetailScreen } from '../screens/CampaignDetailScreen';
import { ActivityScreen } from '../screens/ActivityScreen';
import { ApiError, apiClient, getOperatorToken, setOperatorToken } from '../api/client';
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
});
