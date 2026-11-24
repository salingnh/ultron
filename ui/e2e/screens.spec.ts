import { test, expect, Page } from '@playwright/test';
import { execFileSync } from 'child_process';
import fs from 'fs';
import path from 'path';

const SCREENSHOT_DIR = path.resolve(process.cwd(), 'screenshots');
const LEADER_DIR_WIRE = '/orca/bots/ultron-lead/memory/reports/screenshots/g1.5b-wire';
const LEADER_DIR_LEGACY = '/orca/bots/ultron-lead/memory/reports/screenshots/g1.5b';

test.beforeAll(() => {
  fs.mkdirSync(SCREENSHOT_DIR, { recursive: true });
  fs.mkdirSync(LEADER_DIR_WIRE, { recursive: true });
  fs.mkdirSync(LEADER_DIR_LEGACY, { recursive: true });
});

async function captureScreen(page: Page, filename: string, isRealMode: boolean) {
  // Wait for loading states and animations to settle
  await page.waitForTimeout(700);
  const localPath = path.join(SCREENSHOT_DIR, filename);

  // If in mock mode (e.g. CI runner), do NOT overwrite committed real screenshots
  if (!isRealMode && fs.existsSync(localPath)) {
    return;
  }

  await page.screenshot({ path: localPath, fullPage: true });

  // Copy to reports directory for review artifacts
  try {
    fs.copyFileSync(localPath, path.join(LEADER_DIR_WIRE, filename));
    fs.copyFileSync(localPath, path.join(LEADER_DIR_LEGACY, filename));
  } catch {
    // ignore if directory permission restricts in some sandboxes
  }
}

test.describe('Ultron Operations UI - 1440px Visual Screenshots', () => {
  test.use({ viewport: { width: 1440, height: 900 } });

  for (const theme of ['light', 'dark'] as const) {
    test(`Capture all screens in ${theme} theme`, async ({ page }) => {
      const isRealMode = process.env.VITE_USE_MOCK === 'false' || (!process.env.CI && process.env.VITE_USE_MOCK !== 'true');
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
      if (isRealMode) {
        await expect(page.getByText('REAL API')).toBeVisible();
        await expect(page.getByText('Token: Đã cấu hình')).toBeVisible();
      }
      await captureScreen(page, `01-campaign-list-${theme}.png`, isRealMode);

      // Resolve campaign ID dynamically from UI or fallback to mock ID
      let campaignId = '01934f6a-0000-7000-8000-000000000001';
      const detailLink = page.locator('a[href^="/campaigns/"]').first();
      try {
        await detailLink.waitFor({ state: 'visible', timeout: 6000 });
        const href = await detailLink.getAttribute('href');
        if (href) {
          campaignId = href.replace('/campaigns/', '');
        }
      } catch {
        // fallback to default id if not rendered in time
      }

      // 2. Campaign Detail Screen
      await page.goto(`/campaigns/${campaignId}`);
      await expect(page.getByText('Mục tiêu đầu vào (Target Seeds)')).toBeVisible();
      await expect(page.getByText('Chính sách Thực thi RoE (Policy)')).toBeVisible();
      await captureScreen(page, `02-campaign-detail-${theme}.png`, isRealMode);

      // 3. Job Table View Screen (showing status, priority, and wait/block reasons)
      await page.goto(`/jobs?campaign_id=${campaignId}`);
      await expect(page.getByText('Kế hoạch & Luồng thực thi Job')).toBeVisible();
      await captureScreen(page, `03-job-table-${theme}.png`, isRealMode);

      // 4. Job React Flow View Screen
      await page.getByRole('button', { name: 'Đồ thị Luồng (React Flow)' }).click();
      await page.waitForTimeout(600);
      await captureScreen(page, `04-job-flow-reactflow-${theme}.png`, isRealMode);

      // 5. Asset Graph View Screen
      await page.goto('/assets');
      await expect(page.getByText('Đồ thị Tri thức & Nguồn gốc Tài sản')).toBeVisible();
      if (isRealMode) {
        await expect(page.getByText('Chưa có API backend cho Đồ thị Tài sản')).toBeVisible();
      } else {
        await expect(page.getByText('Nguồn gốc & Bằng chứng', { exact: true })).toBeVisible();
        await expect(page.getByText('Bằng chứng SHA-256 (Evidence SHA-256)')).toBeVisible();
      }
      await captureScreen(page, `05-asset-graph-provenance-${theme}.png`, isRealMode);

      // 6. Tool Catalogue Screen (Wired to real GET /capabilities)
      await page.goto('/tools');
      await expect(page.getByText('Danh mục Công cụ & Bộ điều hợp (Tool Catalogue)')).toBeVisible();
      await expect(page.getByText('dns.enumerate_subdomains')).toBeVisible();
      await expect(page.getByText('subfinder', { exact: true })).toBeVisible();
      if (isRealMode) {
        await expect(page.getByText('Khớp Manifest (Healthy)').first()).toBeVisible();
      }
      await captureScreen(page, `06-tool-catalogue-${theme}.png`, isRealMode);
    });
  }

  test('Live update: a status change made via API appears in the UI within 2 s without reload', async ({ page }) => {
    const isRealMode = process.env.VITE_USE_MOCK === 'false' || (!process.env.CI && process.env.VITE_USE_MOCK !== 'true');
    const token = process.env.VITE_BEARER_TOKEN || 'token-of-soc-1-0123456789';
    const pgDsn = process.env.AEGIS_PG_DSN || 'postgresql://aegis:aegis@127.0.0.1:42443/aegis';

    if (!isRealMode) {
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
      const out = execFileSync('../.venv/bin/python', ['e2e/terminalise.py', pgDsn, 'prepare', campaignId], {
        stdio: 'pipe',
      }).toString();
      const match = out.match(/PREPARED_JOB_ID\s+([^\s]+)/);
      if (match) targetJobId = match[1];
    } catch (e) {
      console.warn('Failed to prepare fresh job via terminalise.py:', e);
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
    await captureScreen(page, '07-live-status-before.png', isRealMode);

    // Trigger terminalise of target job via real M06 backend callback and outbox event
    execFileSync('../.venv/bin/python', ['e2e/terminalise.py', pgDsn, 'terminalise', targetJobId], { stdio: 'pipe' });
    const startTime = Date.now();

    // Wait for the UI to reflect the status change without page reload (< 2s)
    await expect(targetJobRow.locator('.status-chip').filter({ hasText: 'Thành công (Succeeded)' })).toBeVisible({
      timeout: 2000,
    });
    const latencyMs = Date.now() - startTime;
    console.log(`SSE Live status change appeared in UI in ${latencyMs}ms (under 2000ms threshold)`);
    expect(latencyMs).toBeLessThanOrEqual(2000);

    // Capture after screenshot showing updated state without reload
    await captureScreen(page, '08-live-status-after.png', isRealMode);
  });
});
