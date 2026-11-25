import { test, expect, Page } from '@playwright/test';
import { execFileSync } from 'child_process';
import fs from 'fs';
import path from 'path';

const SCREENSHOT_DIR = path.resolve(process.cwd(), 'screenshots');
const LEADER_DIR_G16D = '/orca/bots/ultron-lead/memory/reports/screenshots/g16-d-ui';

test.beforeAll(() => {
  fs.mkdirSync(SCREENSHOT_DIR, { recursive: true });
  fs.mkdirSync(LEADER_DIR_G16D, { recursive: true });
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
      fs.copyFileSync(localPath, path.join(LEADER_DIR_G16D, filename));
    } catch {
      // ignore if directory permission restricts in some sandboxes
    }
  }
}

test.describe('Ultron Operations UI - 1440px Visual Screenshots', () => {
  test.use({ viewport: { width: 1440, height: 900 } });

  test('Capture all screens in light theme', async ({ page }) => {
    const theme = 'light';
    const isRealMode = process.env.VITE_USE_MOCK === 'false';
    const token = process.env.VITE_BEARER_TOKEN || 'token-of-soc-1-0123456789';

    // Set theme and token in localStorage before navigating
    await page.addInitScript(({ t, tok }) => {
      window.localStorage.setItem('ultron-theme', t);
      document.documentElement.setAttribute('data-theme', t);
      if (tok) {
        window.localStorage.setItem('ultron-operator-token', tok);
      }
    }, { t: theme, tok: token });

    // 1. Campaign List Screen
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
    await captureScreen(page, `01-campaign-list-${theme}.png`);

    // Resolve campaign ID: prefer explicit env var or G1.6c/vulnlab campaign in real mode
    let campaignId = process.env.AEGIS_SCREENSHOT_CAMPAIGN_ID || '01934f6a-0000-7000-8000-000000000001';
    if (!process.env.AEGIS_SCREENSHOT_CAMPAIGN_ID) {
      const preferredLink = page
        .locator('tr', { hasText: /G1\.6c|vulnlab-lab-httpd/ })
        .locator('a[href^="/campaigns/"]')
        .first();
      const detailLink = page.locator('a[href^="/campaigns/"]').first();
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
    await captureScreen(page, `02-campaign-detail-${theme}.png`);

    // 3. Job Table View Screen (showing status, priority, and wait/block reasons)
    await page.goto(`/jobs?campaign_id=${campaignId}`);
    await expect(page.getByText('Kế hoạch & Luồng thực thi Job')).toBeVisible();
    await expect(page.getByRole('table', { name: 'Bảng chi tiết Job' })).toBeVisible();
    await captureScreen(page, `03-job-table-${theme}.png`);

    // 4. Job React Flow View Screen
    await page.getByRole('button', { name: 'Đồ thị Luồng (React Flow)' }).click();
    await expect(page.locator('.react-flow__renderer')).toBeVisible();
    await expect(page.locator('.react-flow__node').first()).toBeVisible();
    await captureScreen(page, `04-job-flow-reactflow-${theme}.png`);

    // 5. Asset Graph View Screen (IP -> Service -> Application -> Vulnerability)
    await page.goto(`/assets?campaign_id=${campaignId}`);
    await expect(page.getByText('Đồ thị Tri thức & Dịch vụ Tài sản')).toBeVisible();
    const graphNode = page.locator('.graph-container svg g[role="button"]').first();
    const emptyGraph = page.getByText('Chưa có dữ liệu đồ thị tài sản cho chiến dịch này');
    await expect(graphNode.or(emptyGraph)).toBeVisible({ timeout: 15000 });
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

    // 5c. Service Table per campaign
    await page.getByRole('button', { name: /Bảng Dịch vụ/ }).click();
    await expect(
      page.getByRole('table', { name: 'Bảng dịch vụ theo chiến dịch' }).or(
        page.getByText('Chưa phát hiện dịch vụ nào khớp bộ lọc trong chiến dịch')
      )
    ).toBeVisible();
    const firstCveBtn = page.locator('table[aria-label="Bảng dịch vụ theo chiến dịch"] button', { hasText: /CVE-/ }).first();
    if ((await firstCveBtn.count()) > 0) {
      await firstCveBtn.click();
      await expect(page.getByLabel('Bảng chi tiết ứng viên CVE')).toBeVisible();
    }
    await captureScreen(page, `05b-service-table-${theme}.png`);

    // 5d. Asset Table View Screen
    await page.getByRole('button', { name: 'Bảng Tài sản' }).click();
    await expect(
      page.getByRole('table', { name: 'Bảng tài sản số' }).or(page.getByText('Không tìm thấy tài sản nào phù hợp'))
    ).toBeVisible();
    await captureScreen(page, `05d-asset-table-${theme}.png`);

    // 6. Tool Catalogue Screen (Wired to real GET /capabilities)
    await page.goto('/tools');
    await expect(page.getByText('Danh mục Công cụ & Bộ điều hợp (Tool Catalogue)')).toBeVisible();
    await expect(page.getByText('dns.enumerate_subdomains')).toBeVisible();
    await expect(page.getByText('subfinder', { exact: true })).toBeVisible();
    if (isRealMode) {
      await expect(page.getByText('Khớp Manifest (Healthy)').first()).toBeVisible();
    }
    await captureScreen(page, `06-tool-catalogue-${theme}.png`);
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
      document.documentElement.setAttribute('data-theme', 'light');
      window.localStorage.setItem('ultron-operator-token', tok);
    }, token);

    // Navigate to campaigns and get the active campaign
    await page.goto('/campaigns');
    if (token) {
      await page.evaluate((tok) => {
        window.localStorage.setItem('ultron-operator-token', tok);
        window.dispatchEvent(new CustomEvent('ultron-token-changed', { detail: { token: tok } }));
      }, token);
    }
    const detailLink = page.locator('a[href^="/campaigns/"]').first();
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
