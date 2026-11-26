import { test, expect, Page } from '@playwright/test';
import { execFileSync } from 'child_process';
import fs from 'fs';
import path from 'path';

const SCREENSHOT_DIR = path.resolve(process.cwd(), 'screenshots');
const LEADER_DIR =
  process.env.AEGIS_LEADER_SHOTS_DIR || '/orca/bots/ultron-lead/memory/reports/screenshots/ui-ops';

function resolveTestToken(): string {
  if (process.env.AEGIS_TEST_OPERATOR_TOKEN) return process.env.AEGIS_TEST_OPERATOR_TOKEN;
  if (process.env.VITE_BEARER_TOKEN) return process.env.VITE_BEARER_TOKEN;
  const localTokenPath = path.resolve(process.cwd(), '../.local/operator-token');
  if (process.env.VITE_USE_MOCK === 'false' && fs.existsSync(localTokenPath)) {
    return fs.readFileSync(localTokenPath, 'utf8').trim();
  }
  return 'token-of-soc-1-0123456789';
}

test.beforeAll(() => {
  fs.mkdirSync(SCREENSHOT_DIR, { recursive: true });
  fs.mkdirSync(LEADER_DIR, { recursive: true });
});

async function captureScreen(page: Page, filename: string) {
  // Wait for loading indicators and web fonts to settle deterministically
  await expect(page.locator('.state-title', { hasText: /^Đang nạp/ })).toBeHidden();
  await page.evaluate(() => document.fonts.ready);
  const localPath = path.join(SCREENSHOT_DIR, filename);
  const isRealMode = process.env.VITE_USE_MOCK === 'false';

  // Only overwrite screenshots in ui/screenshots/ when in real mode or if they don't exist yet
  if (isRealMode || !fs.existsSync(localPath)) {
    await page.screenshot({ path: localPath, fullPage: true });
  } else {
    const tempDir = path.resolve(process.cwd(), 'test-results/screenshots');
    fs.mkdirSync(tempDir, { recursive: true });
    await page.screenshot({ path: path.join(tempDir, filename), fullPage: true });
  }

  // Copy to reports directory for review artifacts only when running real verification
  // or when explicitly enabled, so CI mock tests never overwrite leader review artifacts.
  if (isRealMode || process.env.COPY_LEADER_SHOTS === 'true') {
    try {
      fs.copyFileSync(localPath, path.join(LEADER_DIR, filename));
    } catch {
      // ignore if directory permission restricts in some sandboxes
    }
  }
}

async function assertNoHorizontalOverflow(page: Page) {
  const metrics = await page.evaluate(() => {
    const header = document.querySelector('.app-header');
    const lastAction = document.querySelector('.app-header .header-actions')?.lastElementChild;
    return {
      scrollWidth: document.documentElement.scrollWidth,
      innerWidth: window.innerWidth,
      headerScrollWidth: header ? header.scrollWidth : 0,
      headerClientWidth: header ? header.clientWidth : window.innerWidth,
      lastActionRight: lastAction ? lastAction.getBoundingClientRect().right : 0,
    };
  });
  expect(metrics.scrollWidth).toBeLessThanOrEqual(metrics.innerWidth);
  expect(metrics.headerScrollWidth).toBeLessThanOrEqual(metrics.headerClientWidth + 1);
  expect(metrics.lastActionRight).toBeLessThanOrEqual(metrics.innerWidth + 1);
}

for (const theme of ['light', 'dark'] as const) {
  test.describe(`Ultron Operations UI - 1440px (${theme})`, () => {
    test.use({ viewport: { width: 1440, height: 900 } });

    test(`Capture all screens and verify FE defects (${theme})`, async ({ page }) => {
      const isRealMode = process.env.VITE_USE_MOCK === 'false';
      const token = resolveTestToken();

      // Set theme and token in localStorage before navigating
      await page.addInitScript(({ t, tok }) => {
        window.localStorage.setItem('ultron-theme', t);
        if (tok) {
          window.localStorage.setItem('ultron-operator-token', tok);
        }
        document.documentElement?.setAttribute('data-theme', t);
      }, { t: theme, tok: token });

      // 1. Campaign List Screen + F3 single-line "Chi tiết" + F6 Token modal Escape & focus
      await page.goto('/campaigns');
      if (token) {
        await page.evaluate((tok) => {
          window.localStorage.setItem('ultron-operator-token', tok);
          window.dispatchEvent(new CustomEvent('ultron-token-changed', { detail: { token: tok } }));
        }, token);
      }
      await expect(page.getByText('Quản lý Chiến dịch (Campaigns)')).toBeVisible();
      await expect(
        page.getByRole('table', { name: 'Bảng danh sách chiến dịch' }).or(page.getByText('Chưa có chiến dịch nào'))
      ).toBeVisible();
      if (isRealMode) {
        await expect(page.getByText('REAL API')).toBeVisible();
        await expect(page.getByText('Token: Đã cấu hình')).toBeVisible();
      }
      await assertNoHorizontalOverflow(page);

      // F3: verify "Chi tiết" button does not wrap onto 2 lines
      const firstDetailBtn = page.locator('table a[href^="/campaigns/"]').first();
      if ((await firstDetailBtn.count()) > 0) {
        const box = await firstDetailBtn.boundingBox();
        expect(box?.height ?? 0).toBeLessThan(36);
      }

      // F2: verify contract budget & counters render on list
      if ((await firstDetailBtn.count()) > 0) {
        await expect(page.locator('table[aria-label="Bảng danh sách chiến dịch"]')).toContainText('tài sản');
        await expect(page.getByText('Chưa có dữ liệu ngân sách')).toBeHidden();
        await expect(page.getByText('Chưa có bộ đếm')).toBeHidden();
      }

      // F6: verify TokenConfigModal focuses input and closes on Escape
      await page.getByRole('button', { name: 'Cấu hình Operator Bearer Token' }).click();
      const tokenInput = page.getByLabel('Nhập Operator Token');
      await expect(tokenInput).toBeVisible();
      await expect(tokenInput).toBeFocused();
      await page.keyboard.press('Escape');
      await expect(tokenInput).toBeHidden();

      await captureScreen(page, `01-campaign-list-${theme}.png`);

      // Resolve campaign ID: prefer explicit env var or G1.6c/vulnlab campaign in real mode
      let campaignId = process.env.AEGIS_SCREENSHOT_CAMPAIGN_ID || '01934f6a-0000-7000-8000-000000000001';
      if (!process.env.AEGIS_SCREENSHOT_CAMPAIGN_ID) {
        const preferredLink = page
          .locator('table tr', { hasText: /G1\.6c|vulnlab-lab-httpd/ })
          .locator('a[href^="/campaigns/"]')
          .first();
        const detailLink = page.locator('table a[href^="/campaigns/"]').first();
        try {
          await detailLink.waitFor({ state: 'visible', timeout: 6000 });
          const targetLink = (await preferredLink.count()) > 0 ? preferredLink : detailLink;
          const href = await targetLink.getAttribute('href');
          if (href) {
            campaignId = href.replace('/campaigns/', '');
          }
        } catch {
          // fallback to default id if not rendered in time
        }
      }

      // 2. Campaign Detail Screen
      await page.goto(`/campaigns/${campaignId}`);
      await expect(page.getByText('Mục tiêu đầu vào (Target Seeds)')).toBeVisible();
      await expect(page.getByText('Chính sách Thực thi RoE (Policy)')).toBeVisible();
      await expect(page.getByText('Ngân sách thực thi (Đã dùng / Giới hạn & Còn lại)')).toBeVisible();
      await expect(page.getByText('Bộ đếm Job & Tài sản')).toBeVisible();
      await assertNoHorizontalOverflow(page);
      await captureScreen(page, `02-campaign-detail-${theme}.png`);

      // 3. Job Table View Screen (showing status, priority, and wait/block reasons)
      await page.goto(`/jobs?campaign_id=${campaignId}`);
      await expect(page.getByText('Kế hoạch & Luồng thực thi Job')).toBeVisible();
      await expect(page.getByRole('table', { name: 'Bảng chi tiết Job' })).toBeVisible();
      await assertNoHorizontalOverflow(page);
      await captureScreen(page, `03-job-table-${theme}.png`);

      // 4. Job React Flow View Screen + F7 fitView no horizontal overflow
      await page.getByRole('button', { name: 'Đồ thị Luồng (React Flow)' }).click();
      await expect(page.locator('.react-flow__renderer')).toBeVisible();
      await expect(page.locator('.react-flow__node').first()).toBeVisible();
      const rfOverflow = await page.locator('.react-flow').evaluate((el) => ({
        scrollWidth: el.scrollWidth,
        clientWidth: el.clientWidth,
      }));
      expect(rfOverflow.scrollWidth).toBeLessThanOrEqual(rfOverflow.clientWidth + 2);
      await assertNoHorizontalOverflow(page);
      await captureScreen(page, `04-job-flow-reactflow-${theme}.png`);

      // 4b. Agent Activity Screen
      await page.goto(`/activity?campaign_id=${campaignId}`);
      await expect(page.getByText('Nhật ký Hoạt động Agent (Activity)')).toBeVisible();
      await assertNoHorizontalOverflow(page);
      await captureScreen(page, `04b-activity-${theme}.png`);

      // 5. Asset Graph View Screen (IP -> Service -> Application -> Vulnerability)
      await page.goto(`/assets?campaign_id=${campaignId}`);
      await expect(page.getByText('Đồ thị Tri thức & Dịch vụ Tài sản')).toBeVisible();
      const graphNode = page.locator('.graph-container svg g[role="button"]').first();
      const emptyGraph = page.getByText('Chưa có dữ liệu đồ thị tài sản cho chiến dịch này');
      const graphError = page.getByText('Không thể tải đồ thị tài sản cho chiến dịch này');
      await expect(graphNode.or(emptyGraph).or(graphError)).toBeVisible({ timeout: 15000 });
      if (await graphError.isVisible()) {
        await expect(page.getByRole('alert')).toContainText('Đường dẫn (path):');
        await expect(page.getByRole('alert')).toContainText('Mã lỗi:');
      }
      await assertNoHorizontalOverflow(page);
      await captureScreen(page, `05-asset-graph-provenance-${theme}.png`);

      // 5b. Vulnerability Panel on click (from graph CVE node if present)
      const vulnNode = page.locator('.graph-container svg g[aria-label^="Ứng viên CVE "]').first();
      if ((await vulnNode.count()) > 0) {
        await vulnNode.click();
        const vulnPanel = page.getByLabel('Bảng chi tiết ứng viên CVE');
        await expect(vulnPanel).toBeVisible();
        await expect(vulnPanel.getByText('Ứng viên (chưa xác minh)')).toBeVisible();
        await captureScreen(page, `05c-vulnerability-panel-${theme}.png`);
      }

      // 5c. Service Table per campaign + F5 badge click opens CVE panel + F1 graphError isolated from table views
      await page.getByRole('button', { name: /Bảng Dịch vụ/ }).click();
      await expect(graphError).toBeHidden();
      await expect(
        page.getByRole('table', { name: 'Bảng dịch vụ theo chiến dịch' }).or(
          page.getByText('Chưa phát hiện dịch vụ nào khớp bộ lọc trong chiến dịch')
        )
      ).toBeVisible();
      const candidateBadge = page
        .locator('table[aria-label="Bảng dịch vụ theo chiến dịch"] button', { hasText: /ứng viên/ })
        .first();
      if ((await candidateBadge.count()) > 0) {
        await candidateBadge.click();
        await expect(page.getByLabel('Bảng chi tiết ứng viên CVE')).toBeVisible();
      }
      await assertNoHorizontalOverflow(page);
      await captureScreen(page, `05b-service-table-${theme}.png`);

      // 5d. Asset Table View Screen + F1 graphError stays hidden above AssetTable
      await page.getByRole('button', { name: 'Bảng Tài sản' }).click();
      await expect(graphError).toBeHidden();
      await expect(
        page.getByRole('table', { name: 'Bảng tài sản số' }).or(page.getByText('Không tìm thấy tài sản nào phù hợp'))
      ).toBeVisible();
      await assertNoHorizontalOverflow(page);
      await captureScreen(page, `05d-asset-table-${theme}.png`);

      // 6. Tool Catalogue Screen (Wired to real GET /capabilities)
      await page.goto('/tools');
      await expect(page.getByText('Danh mục Công cụ & Bộ điều hợp (Tool Catalogue)')).toBeVisible();
      await expect(page.getByText('dns.enumerate_subdomains')).toBeVisible();
      await expect(page.getByText('subfinder', { exact: true })).toBeVisible();
      if (isRealMode) {
        await expect(page.getByText('Khớp Manifest (Healthy)').first()).toBeVisible();
      }
      await assertNoHorizontalOverflow(page);
      await captureScreen(page, `06-tool-catalogue-${theme}.png`);
    });
  });
}

test.describe('Ultron Operations UI - 390px Responsive Verification', () => {
  test.use({ viewport: { width: 390, height: 844 } });

  for (const theme of ['light', 'dark'] as const) {
    test(`Renders all main routes without horizontal overflow at 390px (${theme})`, async ({ page }) => {
      const token = resolveTestToken();
      await page.addInitScript(({ t, tok }) => {
        window.localStorage.setItem('ultron-theme', t);
        if (tok) {
          window.localStorage.setItem('ultron-operator-token', tok);
        }
        document.documentElement?.setAttribute('data-theme', t);
      }, { t: theme, tok: token });

      await page.goto('/campaigns');
      await expect(page.getByText('Quản lý Chiến dịch (Campaigns)')).toBeVisible();
      await assertNoHorizontalOverflow(page);
      await captureScreen(page, `09-mobile-390-campaigns-${theme}.png`);

      const firstLink = page.locator('table a[href^="/campaigns/"]').first();
      let campaignId = process.env.AEGIS_SCREENSHOT_CAMPAIGN_ID || '01934f6a-0000-7000-8000-000000000001';
      if ((await firstLink.count()) > 0) {
        const href = await firstLink.getAttribute('href');
        if (href) campaignId = href.replace('/campaigns/', '');
      }

      await page.goto(`/campaigns/${campaignId}`);
      await expect(page.getByText('Chính sách Thực thi RoE (Policy)')).toBeVisible();
      await expect(page.getByText('Ngân sách & Bộ đếm Tác chiến')).toBeVisible();
      await assertNoHorizontalOverflow(page);
      await captureScreen(page, `09e-mobile-390-campaign-detail-${theme}.png`);

      await page.goto(`/jobs?campaign_id=${campaignId}`);
      await expect(page.getByText('Kế hoạch & Luồng thực thi Job')).toBeVisible();
      await assertNoHorizontalOverflow(page);
      await page.getByRole('button', { name: 'Đồ thị Luồng (React Flow)' }).click();
      await expect(page.locator('.react-flow__renderer')).toBeVisible();
      await assertNoHorizontalOverflow(page);
      await captureScreen(page, `09b-mobile-390-jobs-flow-${theme}.png`);

      await page.goto(`/activity?campaign_id=${campaignId}`);
      await expect(page.getByText('Nhật ký Hoạt động Agent (Activity)')).toBeVisible();
      await assertNoHorizontalOverflow(page);
      await captureScreen(page, `09c-mobile-390-activity-${theme}.png`);

      await page.goto(`/assets?campaign_id=${campaignId}`);
      await expect(page.getByText('Đồ thị Tri thức & Dịch vụ Tài sản')).toBeVisible();
      await expect(
        page
          .locator('.graph-container svg g[role="button"]')
          .first()
          .or(page.getByText('Chưa có dữ liệu đồ thị tài sản cho chiến dịch này'))
          .or(page.getByText('Không thể tải đồ thị tài sản cho chiến dịch này'))
      ).toBeVisible({ timeout: 15000 });
      await assertNoHorizontalOverflow(page);
      await captureScreen(page, `09d-mobile-390-assets-${theme}.png`);

      await page.goto('/tools');
      await expect(page.getByText('Danh mục Công cụ & Bộ điều hợp (Tool Catalogue)')).toBeVisible();
      await assertNoHorizontalOverflow(page);
    });
  }
});

test.describe('Ultron Operations UI - Create & Live Flows', () => {
  test.use({ viewport: { width: 1440, height: 900 } });

  test('Campaign create form, internet confirmation, validation error, policy adopt, and first-run token help', async ({
    page,
  }) => {
    if (process.env.AEGIS_WATCH_CAMPAIGN_COMPLETE === 'true') {
      test.setTimeout(300000);
    }
    const theme = 'light';
    const isRealMode = process.env.VITE_USE_MOCK === 'false';
    const token = resolveTestToken();

    // First-run help check without token
    await page.addInitScript(({ t }) => {
      window.localStorage.setItem('ultron-theme', t);
      window.localStorage.removeItem('ultron-operator-token');
      document.documentElement?.setAttribute('data-theme', t);
    }, { t: theme });

    await page.goto('/campaigns');
    await expect(
      page.getByRole('region', { name: 'Hướng dẫn cấu hình Operator Token lần đầu' })
    ).toBeVisible();
    await captureScreen(page, `00-first-run-token-help-${theme}.png`);

    // Set operator token via the modal (or direct storage for subsequent flows)
    if (token) {
      await page.getByRole('button', { name: /Cấu hình Operator Token/ }).click();
      await expect(page.getByText('Cấu hình Operator Bearer Token')).toBeVisible();
      await page.getByLabel('Nhập Operator Token').fill(token);
      await page.getByRole('button', { name: 'Lưu Token' }).click();
      await expect(page.getByText('Cấu hình Operator Bearer Token')).toBeHidden();
      await expect(page.getByText('Token: Đã cấu hình')).toBeVisible();
    }

    await expect(
      page
        .getByRole('table', { name: 'Bảng danh sách chiến dịch' })
        .or(page.getByText('Chưa có chiến dịch nào'))
    ).toBeVisible();
    if (isRealMode) {
      await expect(page.getByText('REAL API')).toBeVisible();
      await captureScreen(page, `01-campaign-list-real-${theme}.png`);
    }

    // Navigate to Campaign Create via button (no alert)
    await page.getByRole('link', { name: /Tạo chiến dịch/ }).click();
    await expect(page.getByText('Tạo chiến dịch mới (Create Campaign)')).toBeVisible();
    await expect(page.getByLabel(/lab \(Mặc định an toàn\)/)).toBeChecked();
    if (isRealMode) {
      await expect(page.getByText('REAL API')).toBeVisible();
    }
    await captureScreen(page, `01b-campaign-create-form-${theme}.png`);

    // Validation error inline check
    await page.getByLabel(/Tên miền \(targets\.domains/).fill('https://invalid domain!');
    await page.getByRole('button', { name: /Tạo chiến dịch/ }).click();
    await expect(page.getByText('Tên chiến dịch là bắt buộc.')).toBeVisible();
    await expect(page.getByText(/không hợp lệ/)).toBeVisible();
    await captureScreen(page, `01c-campaign-create-validation-error-${theme}.png`);

    // Fill valid fields and trigger internet confirmation step
    const uniqueSuffix = Date.now().toString(36);
    await page.getByLabel(/Tên chiến dịch/).fill(`UI Ops Lab Scan ${uniqueSuffix}`);
    await page.getByLabel(/Mục tiêu tác chiến/).fill('Khảo sát vùng lab nội bộ từ UI');
    await page.getByLabel(/Tham chiếu ủy quyền/).fill('owner, item 63, 2026-11-25');
    await page.getByLabel(/Tên miền \(targets\.domains/).fill('lab.aegis.test');
    await page.getByLabel(/internet \(Ra ngoài qua Broker\)/).click();
    await page.getByLabel(/Chủ sở hữu hợp pháp \(authorization\.owner\)/).fill('owner');
    await page.getByLabel(/Ngày ủy quyền \(authorization\.date/).fill('2026-11-25');
    await page.getByLabel(/Tham chiếu bằng chứng ủy quyền \(authorization\.reference/).fill('owner, item 63, 2026-11-25');
    await page.getByLabel(/Hậu tố tên miền được phép \(authorization\.authorized_suffixes/).fill('lab.aegis.test');
    await page.getByRole('button', { name: /Kiểm tra & Xác nhận Internet/ }).click();

    await expect(
      page.getByText('Quét chủ động ra internet — chỉ trên tài sản bạn sở hữu/được ủy quyền')
    ).toBeVisible();
    await expect(page.getByText('Tóm tắt giới hạn an toàn (Caps & RoE)')).toBeVisible();
    await captureScreen(page, `01d-campaign-create-internet-confirm-${theme}.png`);

    // Cancel internet confirmation, switch back to safe lab profile and submit
    await page.getByRole('button', { name: /Quay lại chỉnh sửa/ }).click();
    await page.getByLabel(/lab \(Mặc định an toàn\)/).click();
    await page.getByRole('button', { name: /Tạo chiến dịch/ }).click();

    await page.waitForURL(/\/campaigns\/[0-9a-f-]+$/);
    await expect(page.getByText(`UI Ops Lab Scan ${uniqueSuffix}`)).toBeVisible();
    await expect(page.getByText('Chính sách Thực thi RoE (Policy)')).toBeVisible();

    // Adopt a new RoE snapshot while campaign is active (CREATED/RUNNING/WAITING)
    const adoptBtn = page.getByRole('button', { name: /Tạo bản chụp RoE mới/ });
    if (await adoptBtn.isVisible()) {
      await adoptBtn.click();
      await page.getByLabel(/Lý do cập nhật RoE/).fill('Tang song song len 3 tu UI');
      await page.getByLabel(/Số job đồng thời tối đa/).fill('3');
      await page.getByRole('button', { name: /Lưu & Kích hoạt RoE mới/ }).click();
      await expect(page.getByText(/Đã tạo và kích hoạt bản chụp RoE mới: roe-/)).toBeVisible();
    }

    // In real mode with workers running, watch the created lab campaign reach COMPLETED
    if (isRealMode && process.env.AEGIS_WATCH_CAMPAIGN_COMPLETE === 'true') {
      await expect(page.locator('.status-chip', { hasText: 'Hoàn thành (Completed)' })).toBeVisible({
        timeout: 240000,
      });
    }

    await captureScreen(page, `02b-campaign-created-detail-${theme}.png`);
  });

  test('Live update: a status change made via API appears in the UI within 2 s without reload', async ({ page }) => {
    const throwawayDsn = process.env.AEGIS_E2E_THROWAWAY_DSN;
    const isRealMode = process.env.VITE_USE_MOCK === 'false' && Boolean(throwawayDsn);
    const token = process.env.VITE_BEARER_TOKEN || 'token-of-soc-1-0123456789';

    if (!isRealMode || !throwawayDsn) {
      console.log('AEGIS_E2E_THROWAWAY_DSN not configured; skipping live mutation test to protect soak/production DB.');
      test.skip();
      return;
    }

    await page.addInitScript((tok) => {
      window.localStorage.setItem('ultron-theme', 'light');
      window.localStorage.setItem('ultron-operator-token', tok);
      document.documentElement?.setAttribute('data-theme', 'light');
    }, token);

    // Navigate to campaigns and get the active campaign
    await page.goto('/campaigns');
    if (token) {
      await page.evaluate((tok) => {
        window.localStorage.setItem('ultron-operator-token', tok);
        window.dispatchEvent(new CustomEvent('ultron-token-changed', { detail: { token: tok } }));
      }, token);
    }
    const detailLink = page.locator('table a[href^="/campaigns/"]').first();
    await detailLink.waitFor({ state: 'visible', timeout: 6000 });
    const href = await detailLink.getAttribute('href');
    const campaignId = href ? href.replace('/campaigns/', '') : '';
    expect(campaignId).toBeTruthy();

    // Prepare a fresh RUNNING job in this campaign via real M05 submission & runner dispatch
    let targetJobId = '';
    try {
      const out = execFileSync('../.venv/bin/python', ['e2e/terminalise.py', throwawayDsn, 'prepare', campaignId], {
        stdio: 'pipe',
      }).toString();
      const match = out.match(/PREPARED_JOB_ID\s+([^\s]+)/);
      if (match) targetJobId = match[1];
    } catch (e) {
      console.warn('Failed to prepare fresh job via terminalise.py:', e);
    }
    if (!targetJobId) {
      console.log('No active RUNNING campaign available to submit new job; skipping live mutation test.');
      test.skip();
      return;
    }
    expect(targetJobId).toBeTruthy();

    // Navigate to jobs table
    await page.goto(`/jobs?campaign_id=${campaignId}`);
    await expect(page.getByText('Kế hoạch & Luồng thực thi Job')).toBeVisible();
    await expect(page.getByText('SSE Live')).toBeVisible();

    // Target job row must initially show RUNNING status
    const targetJobRow = page.locator('tr').filter({ hasText: targetJobId.slice(-8) });
    await expect(targetJobRow.locator('.status-chip').filter({ hasText: 'Đang chạy (Running)' })).toBeVisible({ timeout: 5000 });

    // Capture before screenshot (showing RUNNING)
    await captureScreen(page, '07-live-status-before.png');

    // Trigger terminalise of target job via real M06 backend callback and outbox event
    execFileSync('../.venv/bin/python', ['e2e/terminalise.py', throwawayDsn, 'terminalise', targetJobId], { stdio: 'pipe' });
    const startTime = Date.now();

    // Wait for the UI to reflect the status change without page reload (< 2s)
    await expect(targetJobRow.locator('.status-chip').filter({ hasText: 'Thành công (Succeeded)' })).toBeVisible({
      timeout: 2000,
    });
    const latencyMs = Date.now() - startTime;
    console.log(`SSE Live status change appeared in UI in ${latencyMs}ms (under 2000ms threshold)`);
    expect(latencyMs).toBeLessThanOrEqual(2000);

    // Capture after screenshot showing updated state without reload
    await captureScreen(page, '08-live-status-after.png');
  });
});
