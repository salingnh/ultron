import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  ApiError,
  apiClient,
  getOperatorToken,
  setOperatorToken,
  STORAGE_KEY_TOKEN,
} from '../api/client';
import { resetMockData } from '../mock/handlers';
import {
  clearAllCampaignEventIds,
  createCoalescedRefresh,
  getLatestCampaignEventId,
  parseSSEBlock,
  subscribeToCampaignEvents,
} from '../api/sse';

describe('ApiClient (Mock & Contract Operations)', () => {
  beforeEach(() => {
    resetMockData();
    localStorage.removeItem(STORAGE_KEY_TOKEN);
  });

  it('manages operator token in localStorage without committing to repo', () => {
    expect(getOperatorToken()).toBe('');

    setOperatorToken('test-token-operator-123');
    expect(getOperatorToken()).toBe('test-token-operator-123');
    expect(localStorage.getItem(STORAGE_KEY_TOKEN)).toBe('test-token-operator-123');

    setOperatorToken('');
    expect(getOperatorToken()).toBe('');
    expect(localStorage.getItem(STORAGE_KEY_TOKEN)).toBeNull();
  });

  it('parses SSE frames correctly including comments, event types and IDs', () => {
    // 1. Comments only (ready message or heartbeat comments)
    const commentBlock = ': m26-sse#g1 ready\n';
    expect(parseSSEBlock(commentBlock)).toBeNull();

    // 2. Standard job event frame
    const frame = 'id: 42\nevent: job.completed.v2\ndata: {"job_id":"01934f6a","status":"SUCCEEDED"}\n';
    const parsed = parseSSEBlock(frame);
    expect(parsed).not.toBeNull();
    expect(parsed?.id).toBe('42');
    expect(parsed?.type).toBe('job.completed.v2');
    expect((parsed?.data as Record<string, unknown>).job_id).toBe('01934f6a');
    expect((parsed?.data as Record<string, unknown>).status).toBe('SUCCEEDED');

    // 3. Multiline data
    const multilineFrame = 'id: 43\nevent: custom.event\ndata: line 1\ndata: line 2\n';
    const parsedMulti = parseSSEBlock(multilineFrame);
    expect(parsedMulti?.id).toBe('43');
    expect(parsedMulti?.type).toBe('custom.event');
    expect(parsedMulti?.raw).toBe('line 1\nline 2');
  });

  it('lists campaigns with status filtering', async () => {
    const res = await apiClient.listCampaigns();
    expect(res.items.length).toBeGreaterThanOrEqual(3);

    const running = await apiClient.listCampaigns({ status: 'RUNNING' });
    expect(running.items.every((c) => c.status === 'RUNNING')).toBe(true);
  });

  it('retrieves single campaign by ID', async () => {
    const campaign = await apiClient.getCampaign('01934f6a-0000-7000-8000-000000000001');
    expect(campaign.campaign_id).toBe('01934f6a-0000-7000-8000-000000000001');
    expect(campaign.name).toContain('Chiến dịch Recon');
    expect(campaign.policy?.max_parallel_jobs).toBe(5);
  });

  it('pauses, resumes, and cancels a campaign', async () => {
    const campaignId = '01934f6a-0000-7000-8000-000000000001';

    // Pause
    const paused = await apiClient.pauseCampaign(campaignId, 'Tạm dừng điều độ');
    expect(paused.status).toBe('PAUSED');
    expect(paused.status_reason).toBe('Tạm dừng điều độ');

    // Resume
    const resumed = await apiClient.resumeCampaign(campaignId, 'Tiếp tục rà quét');
    expect(resumed.status).toBe('RUNNING');
    expect(resumed.status_reason).toBe('Tiếp tục rà quét');

    // Cancel
    const cancelled = await apiClient.cancelCampaign(campaignId, 'Hủy toàn bộ');
    expect(cancelled.status).toBe('CANCELLED');
    expect(cancelled.status_reason).toBe('Hủy toàn bộ');
  });

  it('lists jobs for a campaign with the reason a queued job is waiting', async () => {
    const res = await apiClient.listJobs({ campaign_id: '01934f6a-0000-7000-8000-000000000001' });
    expect(res.items.length).toBeGreaterThanOrEqual(6);

    const queuedWithWait = res.items.filter((j) => j.wait_reason !== undefined);
    expect(queuedWithWait.length).toBeGreaterThan(0);
    const dependencyWaits = queuedWithWait.filter((j) => j.wait_reason?.code === 'DEPENDENCY_PENDING');
    expect(dependencyWaits.length).toBeGreaterThan(0);
    for (const job of dependencyWaits) {
      expect(job.wait_reason?.blocking_job_ids?.length).toBeGreaterThan(0);
    }
  });

  it('cancels a job with cancel intent', async () => {
    const cancelledJob = await apiClient.cancelJob('01934f6a-0000-7000-8000-00000000d001', 'Hủy do phát hiện bất thường');
    expect(cancelledJob.status).toBe('CANCELLED');
    expect(cancelledJob.cancel?.reason).toBe('Hủy do phát hiện bất thường');
    expect(cancelledJob.cancel?.requested_by.kind).toBe('operator');
  });

  it('retrieves flow nodes and edges for campaign', async () => {
    const flow = await apiClient.getCampaignFlow('01934f6a-0000-7000-8000-000000000001');
    expect(flow.revision).toBe(14);
    expect(flow.nodes.length).toBeGreaterThan(0);
    expect(flow.edges.length).toBeGreaterThan(0);
  });

  it('retrieves asset graph with truncation and provenance details', async () => {
    const graph = await apiClient.getAssetGraph('01934f6a-0000-7000-8000-0000000000f1', {
      campaign_id: '01934f6a-0000-7000-8000-000000000001',
      max_hops: 1,
      limit: 50,
    });
    expect(graph.truncated).toBe(true);
    expect(graph.nodes.length).toBeGreaterThan(0);
    expect(graph.edges.length).toBeGreaterThan(0);

    const prov = await apiClient.getProvenance('01934f6a-0000-7000-8000-0000000000f2');
    expect(prov).toBeDefined();
    expect(prov?.tool).toBe('subfinder');
    expect(prov?.version).toBe('v2.17.0');
    expect(prov?.sha256).toBe('1e1c8bcdd33168e15528d61a006bf5e5e5a31e5b8e4d4d4f1f10ad0876240a9f');
  });

  it('retrieves asset history with observations and evidence ids', async () => {
    const history = await apiClient.getAssetHistory('01934f6a-0000-7000-8000-0000000000f1');
    expect(history.asset).toBeDefined();
    expect(history.asset.canonical_key).toBe('dns:internal.example');
    expect(history.items.length).toBeGreaterThan(0);
    expect(history.items[0].scan_id).toBeDefined();
    expect(history.items[0].observed_at).toBeDefined();
  });

  it('handles edge provenance derivation', async () => {
    const edge = {
      type: 'SUBDOMAIN_OF',
      from: 'dns:vpn.internal.example',
      to: 'dns:internal.example',
      valid_from: '2026-11-20T08:12:30Z',
      valid_to: null,
      source_job_id: '01934f6a-0000-7000-8000-00000000d001',
      confidence: 1.0,
    };
    // Test provenance fallback for edge
    apiClient.setMock(false);
    const edgeProv = await apiClient.getProvenance('edge-dns:vpn.internal.example-dns:internal.example', { edge });
    expect(edgeProv).toBeDefined();
    expect(edgeProv?.jobId).toBe(edge.source_job_id);
    expect(edgeProv?.sourceAsset).toBe(edge.from);
    expect(edgeProv?.targetAsset).toBe(edge.to);
    apiClient.setMock(null);
  });

  it('lists capabilities in registry catalogue', async () => {
    const res = await apiClient.listCapabilities();
    expect(res.items.some((c) => c.capability === 'dns.enumerate_subdomains')).toBe(true);
    expect(res.items.some((c) => c.capability === 'dns.resolve')).toBe(true);
  });

  it('lists candidate vulnerabilities for a service asset and supports kev_only filter', async () => {
    const all = await apiClient.listAssetVulnerabilities('01934f6a-0000-7000-8000-0000000000f6');
    expect(all.asset.canonical_key).toBe('service:203.0.113.10:80/tcp');
    expect(all.items).toHaveLength(1);
    expect(all.items[0].vulnerability_id).toBe('CVE-2021-41773');
    expect(all.items[0].kev).toBe(true);

    const nonKevFiltered = await apiClient.listAssetVulnerabilities(
      '01934f6a-0000-7000-8000-0000000000f7',
      { kev_only: true }
    );
    expect(nonKevFiltered.items).toHaveLength(0);
  });

  it('lists campaign asset.discovered.v2 events', async () => {
    const res = await apiClient.listCampaignEvents('01934f6a-0000-7000-8000-000000000001', {
      types: ['asset.discovered.v2'],
      limit: 200,
    });
    expect(res.items.length).toBeGreaterThanOrEqual(9);
    expect(res.items.every((ev) => ev.type === 'asset.discovered.v2')).toBe(true);
  });

  it('creates a campaign with Idempotency-Key replay and 409 conflict handling in mock mode', async () => {
    const payload = {
      name: 'Lab verification campaign',
      objective: 'Test lab campaign creation',
      targets: { domains: ['lab.aegis.test'] },
      policy: {
        network_profile: 'lab' as const,
        max_parallel_jobs: 2,
        max_duration_hours: 2,
      },
    };
    const key = 'test-create-idemp-key-0001';
    const created = await apiClient.createCampaign(payload, { idempotencyKey: key });
    expect(created.status).toBe('CREATED');
    expect(created.policy_version).toMatch(/^roe-\d+$/);

    const replayed = await apiClient.createCampaign(payload, { idempotencyKey: key });
    expect(replayed.campaign_id).toBe(created.campaign_id);

    await expect(
      apiClient.createCampaign({ ...payload, name: 'Different body' }, { idempotencyKey: key })
    ).rejects.toMatchObject({
      status: 409,
      code: 'IDEMPOTENCY_CONFLICT',
    });

    const fetched = await apiClient.getCampaign(created.campaign_id);
    expect(fetched.name).toBe('Lab verification campaign');
    expect(fetched.policy?.network_profile).toBe('lab');
  });

  it('adopts a new policy snapshot on active campaign and rejects terminal campaign', async () => {
    const activeId = '01934f6a-0000-7000-8000-000000000001';
    const res = await apiClient.updateCampaignPolicy(
      activeId,
      {
        policy: {
          network_profile: 'lab',
          max_parallel_jobs: 4,
          max_duration_hours: 12,
        },
        reason: 'Tang gioi han song song len 4',
      },
      { idempotencyKey: 'test-policy-key-0001' }
    );
    expect(res.policy_version).toMatch(/^roe-\d+$/);
    const updated = await apiClient.getCampaign(activeId);
    expect(updated.policy_version).toBe(res.policy_version);
    expect(updated.policy?.max_parallel_jobs).toBe(4);

    // Campaign 0003 is COMPLETED -> 409 conflict
    await expect(
      apiClient.updateCampaignPolicy(
        '01934f6a-0000-7000-8000-000000000003',
        {
          policy: { max_parallel_jobs: 2, max_duration_hours: 4 },
          reason: 'Khong duoc phep tren terminal',
        },
        { idempotencyKey: 'test-policy-key-0002' }
      )
    ).rejects.toBeInstanceOf(ApiError);
  });

  it('sends Idempotency-Key and Bearer token headers on POST /campaigns in real mode', async () => {
    setOperatorToken('op-real-token-xyz');
    apiClient.setMock(false);
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          campaign_id: '01934f6a-0000-7000-8000-000000000099',
          status: 'CREATED',
          policy_version: 'roe-1',
          scope_id: '01934f6a-0000-7000-8000-0000000000aa',
        }),
        { status: 202, headers: { 'Content-Type': 'application/json' } }
      )
    );

    try {
      await apiClient.createCampaign(
        {
          name: 'Header check',
          objective: 'Verify headers',
          targets: { domains: ['lab.aegis.test'] },
          policy: { network_profile: 'lab', max_parallel_jobs: 1, max_duration_hours: 1 },
        },
        { idempotencyKey: 'fixed-idemp-key-9999' }
      );
      expect(fetchSpy).toHaveBeenCalledTimes(1);
      const [, init] = fetchSpy.mock.calls[0];
      const headers = init?.headers as Headers;
      expect(headers.get('Idempotency-Key')).toBe('fixed-idemp-key-9999');
      expect(headers.get('Authorization')).toBe('Bearer op-real-token-xyz');
    } finally {
      fetchSpy.mockRestore();
      apiClient.setMock(null);
    }
  });

  it('captures HTTP status, API error code, and request path on ApiError/UiError, and translates network failure to Vietnamese', async () => {
    apiClient.setMock(false);
    const fetchSpy = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            code: 'INTERNAL_ERROR',
            message: 'the app has no graph driver',
            next_action: 'CHECK_PROVIDER',
          }),
          { status: 500, headers: { 'Content-Type': 'application/json' } }
        )
      )
      .mockRejectedValueOnce(new TypeError('Failed to fetch'));

    try {
      let caughtHttp: unknown;
      try {
        await apiClient.getAssetGraph('01934f6a-0000-7000-8000-0000000000f1', {
          campaign_id: '01934f6a-0000-7000-8000-000000000001',
          max_hops: 2,
        });
      } catch (e) {
        caughtHttp = e;
      }
      expect(caughtHttp).toBeInstanceOf(ApiError);
      const httpUiErr = (caughtHttp as ApiError).toUiError();
      expect(httpUiErr.status).toBe(500);
      expect(httpUiErr.code).toBe('INTERNAL_ERROR');
      expect(httpUiErr.path).toContain('/assets/01934f6a-0000-7000-8000-0000000000f1/graph');

      let caughtNet: unknown;
      try {
        await apiClient.listCampaigns();
      } catch (e) {
        caughtNet = e;
      }
      expect(caughtNet).toBeInstanceOf(ApiError);
      const netUiErr = (caughtNet as ApiError).toUiError();
      expect(netUiErr.status).toBeUndefined();
      expect(netUiErr.code).toBe('NETWORK_ERROR');
      expect(netUiErr.path).toBe('/campaigns');
      expect(netUiErr.message).toContain('Không thể kết nối tới máy chủ API');
    } finally {
      fetchSpy.mockRestore();
      apiClient.setMock(null);
    }
  });

  it('retrieves campaign activity timeline with cursor pagination', async () => {
    const page1 = await apiClient.getCampaignActivity('01934f6a-0000-7000-8000-000000000001', {
      limit: 3,
    });
    expect(page1.items).toHaveLength(3);
    expect(page1.truncated).toBe(true);
    expect(page1.next_cursor).toBeTruthy();

    const page2 = await apiClient.getCampaignActivity('01934f6a-0000-7000-8000-000000000001', {
      cursor: page1.next_cursor,
      limit: 10,
    });
    expect(page2.items.length).toBeGreaterThan(0);
    expect(page2.truncated).toBe(false);
  });

  it('tracks Last-Event-ID per campaign, sends types filter, and resets stale checkpoint on 400 (D1)', async () => {
    clearAllCampaignEventIds();
    const campaignId = '01934f6a-0000-7000-8000-0000000000aa';

    const encoder = new TextEncoder();
    const sseBody = new ReadableStream({
      start(controller) {
        controller.enqueue(
          encoder.encode(
            'id: 355\nevent: job.completed.v2\ndata: {"event_id":"e1","type":"job.completed.v2","payload":{}}\n\n'
          )
        );
        controller.close();
      },
    });

    const fetchSpy = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(
        new Response(sseBody, {
          status: 200,
          headers: { 'Content-Type': 'text/event-stream' },
        })
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ code: 'INPUT_INVALID', message: 'resume point beyond head' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' },
        })
      );

    try {
      const sub1 = subscribeToCampaignEvents({
        campaignId,
        types: ['job.started.v2', 'job.completed.v2'],
        onEvent: () => {},
        reconnectDelayMs: 5000,
      });

      await vi.waitFor(() => {
        expect(getLatestCampaignEventId(campaignId)).toBe('355');
      });
      expect(String(fetchSpy.mock.calls[0][0])).toContain(
        'types=job.started.v2%2Cjob.completed.v2'
      );
      const firstHeaders = fetchSpy.mock.calls[0][1]?.headers as Record<string, string>;
      expect(firstHeaders['Last-Event-ID']).toBeUndefined();
      sub1.close();

      // Second subscription starts from cached Last-Event-ID=355; 400 clears stale checkpoint
      const sub2 = subscribeToCampaignEvents({
        campaignId,
        onEvent: () => {},
        reconnectDelayMs: 5000,
      });

      await vi.waitFor(() => {
        expect(fetchSpy).toHaveBeenCalledTimes(2);
      });
      const secondHeaders = fetchSpy.mock.calls[1][1]?.headers as Record<string, string>;
      expect(secondHeaders['Last-Event-ID']).toBe('355');
      await vi.waitFor(() => {
        expect(getLatestCampaignEventId(campaignId)).toBeNull();
      });
      sub2.close();
    } finally {
      fetchSpy.mockRestore();
      clearAllCampaignEventIds();
    }
  });

  it('coalesces burst triggers and overlapping in-flight refreshes into O(1) calls (D1)', async () => {
    vi.useFakeTimers();
    try {
      const fn = vi.fn().mockResolvedValue(undefined);
      const refresher = createCoalescedRefresh(fn, 200);

      for (let i = 0; i < 355; i++) {
        refresher.trigger();
      }
      expect(fn).not.toHaveBeenCalled();

      await vi.advanceTimersByTimeAsync(200);
      expect(fn).toHaveBeenCalledTimes(1);
      refresher.cancel();
    } finally {
      vi.useRealTimers();
    }
  });

  it('lists findings with status/severity/campaign/kev filters and cursor pagination', async () => {
    const page1 = await apiClient.listFindings({ limit: 2 });
    expect(page1.items).toHaveLength(2);
    expect(page1.next_cursor).toBeTruthy();

    const page2 = await apiClient.listFindings({ cursor: page1.next_cursor, limit: 10 });
    expect(page2.items.length).toBeGreaterThanOrEqual(4);
    expect(page2.items.some((f) => f.finding_id === page1.items[0].finding_id)).toBe(false);

    const byStatus = await apiClient.listFindings({ status: ['CANDIDATE'], severity: ['UNRATED'] });
    expect(byStatus.items.length).toBeGreaterThan(0);
    expect(byStatus.items.every((f) => f.status === 'CANDIDATE' && f.severity === 'UNRATED')).toBe(true);

    const byCampaignKev = await apiClient.listFindings({
      campaign_id: '01934f6a-0000-7000-8000-000000000001',
      kev: true,
    });
    expect(byCampaignKev.items).toHaveLength(1);
    expect(byCampaignKev.items[0].vulnerability_ids).toContain('CVE-2021-41773');
  });

  it('serializes OpenAPI form explode=false array params and sends Idempotency-Key on transitionFinding in real mode', async () => {
    setOperatorToken('op-real-token-findings');
    apiClient.setMock(false);
    const fetchSpy = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ items: [] }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        })
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            finding_id: '01934f6a-0000-7000-8000-00000000f101',
            fingerprint: 'a'.repeat(64),
            asset_id: '01934f6a-0000-7000-8000-0000000000f6',
            asset_key: 'service:203.0.113.10:80/tcp',
            rule_id: 'r1',
            title: 'Test finding',
            status: 'FALSE_POSITIVE',
            severity: 'CRITICAL',
            first_seen: '2026-11-20T08:00:00Z',
            last_seen: '2026-11-20T09:00:00Z',
            evidence: [],
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        )
      );

    try {
      await apiClient.listFindings({
        campaign_id: '01934f6a-0000-7000-8000-000000000001',
        status: ['CANDIDATE', 'CORROBORATED'],
        severity: ['CRITICAL', 'HIGH'],
      });
      const [listUrl] = fetchSpy.mock.calls[0];
      expect(String(listUrl)).toContain('status=CANDIDATE%2CCORROBORATED');
      expect(String(listUrl)).toContain('severity=CRITICAL%2CHIGH');

      await apiClient.transitionFinding(
        '01934f6a-0000-7000-8000-00000000f101',
        { to: 'FALSE_POSITIVE', reason: 'Verified safe', expected_seq: 1 },
        { idempotencyKey: 'finding-trans-key-1' }
      );
      const [postUrl, init] = fetchSpy.mock.calls[1];
      expect(String(postUrl)).toContain('/findings/01934f6a-0000-7000-8000-00000000f101/transitions');
      const headers = init?.headers as Headers;
      expect(headers.get('Idempotency-Key')).toBe('finding-trans-key-1');
      expect(headers.get('Authorization')).toBe('Bearer op-real-token-findings');
    } finally {
      fetchSpy.mockRestore();
      apiClient.setMock(null);
    }
  });

  it('retrieves finding history with no-longer-seen run and enforces expected_seq on transitionFinding', async () => {
    const findingId = '01934f6a-0000-7000-8000-00000000f101';
    const history = await apiClient.getFindingHistory(findingId);
    expect(history.runs.some((r) => r.seen === false)).toBe(true);
    expect(history.transitions[0].seq).toBe(1);

    const updated = await apiClient.transitionFinding(
      findingId,
      { to: 'ACCEPTED_RISK', reason: 'Lab isolation accepted', expected_seq: 1 },
      { idempotencyKey: 'finding-idemp-seq-1' }
    );
    expect(updated.status).toBe('ACCEPTED_RISK');

    // Stale expected_seq=1 after transition incremented seq to 2 -> 409
    await expect(
      apiClient.transitionFinding(
        findingId,
        { to: 'CANDIDATE', reason: 'Reopen with stale seq', expected_seq: 1 },
        { idempotencyKey: 'finding-idemp-seq-2' }
      )
    ).rejects.toMatchObject({ status: 409 });
  });
});
