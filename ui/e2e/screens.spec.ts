import { test, expect, Page } from '@playwright/test';
import fs from 'fs';
import path from 'path';

const SCREENSHOT_DIR = path.resolve(process.cwd(), 'screenshots');
const LEADER_SCREENSHOT_DIR = '/orca/bots/ultron-lead/memory/reports/screenshots/g1.5b';

test.beforeAll(() => {
  fs.mkdirSync(SCREENSHOT_DIR, { recursive: true });
  fs.mkdirSync(LEADER_SCREENSHOT_DIR, { recursive: true });
});

async function captureScreen(page: Page, filename: string) {
  // Wait for loading states to settle
  await page.waitForTimeout(600);
  const localPath = path.join(SCREENSHOT_DIR, filename);
  const leaderPath = path.join(LEADER_SCREENSHOT_DIR, filename);
  await page.screenshot({ path: localPath, fullPage: true });
  fs.copyFileSync(localPath, leaderPath);
}

test.describe('Ultron Operations UI - 1440px Visual Screenshots', () => {
  test.use({ viewport: { width: 1440, height: 900 } });

  for (const theme of ['light', 'dark'] as const) {
    test(`Capture all screens in ${theme} theme`, async ({ page }) => {
      // Set theme in localStorage before navigating
      await page.addInitScript((t) => {
        window.localStorage.setItem('ultron-theme', t);
        document.documentElement.setAttribute('data-theme', t);
      }, theme);

      // 1. Campaign List Screen
      await page.goto('/campaigns');
      await expect(page.getByText('Quản lý Chiến dịch (Campaigns)')).toBeVisible();
      await captureScreen(page, `01-campaign-list-${theme}.png`);

      // 2. Campaign Detail Screen
      await page.goto('/campaigns/01934f6a-0000-7000-8000-000000000001');
      await expect(page.getByText('Mục tiêu đầu vào (Target Seeds)')).toBeVisible();
      await expect(page.getByText('Chính sách Thực thi RoE (Policy)')).toBeVisible();
      await captureScreen(page, `02-campaign-detail-${theme}.png`);

      // 3. Job Table View Screen (showing wait reasons & dispatch block reasons)
      await page.goto('/jobs?campaign_id=01934f6a-0000-7000-8000-000000000001');
      await expect(page.getByText('Kế hoạch & Luồng thực thi Job')).toBeVisible();
      await expect(page.getByText('Chờ job tiền nhiệm (Pending)')).toBeVisible();
      await expect(page.getByText('LEGACY_POLICY_V1')).toBeVisible();
      await captureScreen(page, `03-job-table-${theme}.png`);

      // 4. Job React Flow View Screen
      await page.getByRole('button', { name: 'Đồ thị Luồng (React Flow)' }).click();
      await page.waitForTimeout(600);
      await captureScreen(page, `04-job-flow-reactflow-${theme}.png`);

      // 5. Asset Graph View Screen with Provenance Panel open
      await page.goto('/assets');
      await expect(page.getByText('Đồ thị Tri thức & Nguồn gốc Tài sản')).toBeVisible();
      // Ensure provenance panel is visible with exact text match
      await expect(page.getByText('Nguồn gốc & Bằng chứng', { exact: true })).toBeVisible();
      await expect(page.getByText('Bằng chứng SHA-256 (Evidence SHA-256)')).toBeVisible();
      await captureScreen(page, `05-asset-graph-provenance-${theme}.png`);

      // 6. Tool Catalogue Screen
      await page.goto('/tools');
      await expect(page.getByText('Danh mục Công cụ & Bộ điều hợp (Tool Catalogue)')).toBeVisible();
      await expect(page.getByText('dns.enumerate_subdomains')).toBeVisible();
      await captureScreen(page, `06-tool-catalogue-${theme}.png`);
    });
  }
});
