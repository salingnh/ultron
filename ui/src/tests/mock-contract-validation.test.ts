import { describe, it, expect, beforeAll } from 'vitest';
import fs from 'fs';
import path from 'path';
import * as yaml from 'js-yaml';
import Ajv2020 from 'ajv/dist/2020';
import addFormats from 'ajv-formats';
import {
  mockCampaigns,
  mockJobs,
  mockCampaignFlow,
  mockAssets,
  mockAssetGraph,
  mockCapabilities,
} from '../mock/fixtures';
import { mockHandlers, resetMockData } from '../mock/handlers';
import {
  SAFE_LAB_POLICY_DEFAULTS,
  validateCampaignForm,
} from '../utils/campaignValidation';

describe('Mock Fixtures Contract Validation against OpenAPI v2 Schema', () => {
  let ajv: Ajv2020;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let openApiDoc: any;

  beforeAll(() => {
    ajv = new Ajv2020({
      allErrors: true,
      strict: false,
      validateFormats: true,
    });
    addFormats(ajv);

    // Register custom Aegis formats as valid string formats
    const customFormats = [
      'aegis-canonical-key',
      'aegis-iana-timezone',
      'aegis-cron-5',
      'aegis-sha256-hex',
      'aegis-c14n-canonical-json',
      'aegis-signature-ed25519',
      'aegis-public-key-ed25519',
      'aegis-key-id',
      'aegis-semver',
      'aegis-domain-seed',
      'aegis-ip-or-cidr',
    ];
    for (const fmt of customFormats) {
      ajv.addFormat(fmt, { validate: () => true });
    }

    const contractsRoot = path.resolve(__dirname, '../../../contracts');

    // Recursively find and register all *.schema.json files
    function findSchemaFiles(dir: string): string[] {
      let results: string[] = [];
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          results = results.concat(findSchemaFiles(full));
        } else if (entry.name.endsWith('.schema.json')) {
          results.push(full);
        }
      }
      return results;
    }

    const allSchemaPaths = findSchemaFiles(contractsRoot);

    for (const fullPath of allSchemaPaths) {
      const relPath = path.relative(contractsRoot, fullPath);
      const schema = JSON.parse(fs.readFileSync(fullPath, 'utf8'));

      // Register by $id
      if (schema.$id) {
        try {
          ajv.addSchema(schema, schema.$id);
        } catch {
          // ignore
        }
      }
      // Register by relative paths
      try {
        ajv.addSchema(schema, `../${relPath}`);
      } catch {
        // ignore
      }
      try {
        ajv.addSchema(schema, relPath);
      } catch {
        // ignore
      }
      // Register by filename for sibling references (e.g. campaign-create.v2.schema.json)
      const baseName = path.basename(fullPath);
      try {
        ajv.addSchema(schema, baseName);
      } catch {
        // ignore
      }
    }

    // Load openapi.v2.yaml
    const openApiPath = path.join(contractsRoot, 'api/openapi.v2.yaml');
    openApiDoc = yaml.load(fs.readFileSync(openApiPath, 'utf8'));

    // Register components.schemas
    if (openApiDoc.components?.schemas) {
      for (const [name, schema] of Object.entries(openApiDoc.components.schemas)) {
        try {
          ajv.addSchema(schema as object, `#/components/schemas/${name}`);
        } catch {
          // ignore
        }
      }
    }
  });

  it('validates mockHandlers.listCampaigns() matches /campaigns 200 schema', async () => {
    const schema = openApiDoc.paths['/campaigns']?.get?.responses['200']?.content['application/json']?.schema;
    expect(schema).toBeDefined();

    const validate = ajv.compile(schema);
    const res = await mockHandlers.listCampaigns();
    const valid = validate(res);
    expect(validate.errors).toBeNull();
    expect(valid).toBe(true);
  });

  it('validates each mock campaign matches campaign.v2.schema.json', () => {
    const campaignSchema = ajv.getSchema('https://aegis.io/contracts/campaign/campaign.v2.schema.json');
    expect(campaignSchema).toBeDefined();

    for (const campaign of mockCampaigns) {
      const valid = campaignSchema!(campaign);
      expect(campaignSchema!.errors, `Campaign ${campaign.campaign_id} validation failed`).toBeNull();
      expect(valid).toBe(true);
      expect(campaign.budget?.limits.max_duration_hours).toBeGreaterThanOrEqual(1);
      expect(campaign.budget?.used).toBeDefined();
      expect(campaign.budget?.remaining.hours).toBeGreaterThanOrEqual(0);
      expect(campaign.counters?.jobs_by_status).toBeDefined();
      expect(campaign.counters?.assets_by_kind).toBeDefined();
    }
  });

  it('validates pause, resume, cancel responses match campaign.v2.schema.json', async () => {
    resetMockData();
    const campaignSchema = ajv.getSchema('https://aegis.io/contracts/campaign/campaign.v2.schema.json')!;
    const id = mockCampaigns[0].campaign_id;

    const paused = await mockHandlers.pauseCampaign(id, 'Pause for maintenance');
    expect(campaignSchema(paused)).toBe(true);
    expect(campaignSchema.errors).toBeNull();

    const resumed = await mockHandlers.resumeCampaign(id, 'Resume operation');
    expect(campaignSchema(resumed)).toBe(true);
    expect(campaignSchema.errors).toBeNull();

    const cancelled = await mockHandlers.cancelCampaign(id, 'Cancel operation');
    expect(campaignSchema(cancelled)).toBe(true);
    expect(campaignSchema.errors).toBeNull();
  });

  it('validates mockHandlers.listJobs() matches /jobs 200 schema and items match job.v2.schema.json', async () => {
    const schema = openApiDoc.paths['/jobs']?.get?.responses['200']?.content['application/json']?.schema;
    expect(schema).toBeDefined();

    const validate = ajv.compile(schema);
    const res = await mockHandlers.listJobs({ campaign_id: mockCampaigns[0].campaign_id });
    const valid = validate(res);
    expect(validate.errors).toBeNull();
    expect(valid).toBe(true);

    const jobSchema = ajv.getSchema('https://aegis.io/contracts/capability/job.v2.schema.json')!;
    for (const job of mockJobs) {
      const jobValid = jobSchema(job);
      expect(jobSchema.errors, `Validation failed for job ${job.job_id}`).toBeNull();
      expect(jobValid).toBe(true);
    }
  });

  it('validates cancelJob response matches job.v2.schema.json', async () => {
    resetMockData();
    const jobSchema = ajv.getSchema('https://aegis.io/contracts/capability/job.v2.schema.json')!;
    const cancelledJob = await mockHandlers.cancelJob(mockJobs[0].job_id, 'Hủy kiểm thử');
    expect(jobSchema(cancelledJob)).toBe(true);
    expect(jobSchema.errors).toBeNull();
  });

  it('validates mockCampaignFlow matches /campaigns/{campaign_id}/flow 200 schema', () => {
    const schema = openApiDoc.paths['/campaigns/{campaign_id}/flow']?.get?.responses['200']?.content['application/json']?.schema;
    expect(schema).toBeDefined();

    const validate = ajv.compile(schema);
    const valid = validate(mockCampaignFlow);
    expect(validate.errors).toBeNull();
    expect(valid).toBe(true);
  });

  it('validates mockHandlers.listAssets() matches /assets 200 schema', async () => {
    const schema = openApiDoc.paths['/assets']?.get?.responses['200']?.content['application/json']?.schema;
    expect(schema).toBeDefined();

    const validate = ajv.compile(schema);
    const res = await mockHandlers.listAssets();
    const valid = validate(res);
    expect(validate.errors).toBeNull();
    expect(valid).toBe(true);

    // Validate individual assets against Asset schema
    const assetSchema = ajv.getSchema('#/components/schemas/Asset')!;
    for (const asset of mockAssets) {
      expect(assetSchema(asset)).toBe(true);
      expect(assetSchema.errors).toBeNull();
    }
  });

  it('validates mockAssetGraph matches /assets/{asset_id}/graph 200 schema', () => {
    const schema = openApiDoc.paths['/assets/{asset_id}/graph']?.get?.responses['200']?.content['application/json']?.schema;
    expect(schema).toBeDefined();

    const validate = ajv.compile(schema);
    const valid = validate(mockAssetGraph);
    expect(validate.errors).toBeNull();
    expect(valid).toBe(true);
  });

  it('validates mockHandlers.getAssetHistory matches /assets/{asset_id}/history 200 schema', async () => {
    const schema = openApiDoc.paths['/assets/{asset_id}/history']?.get?.responses['200']?.content['application/json']?.schema;
    expect(schema).toBeDefined();

    const validate = ajv.compile(schema);
    for (const assetId of [
      '01934f6a-0000-7000-8000-0000000000f1',
      '01934f6a-0000-7000-8000-0000000000f6',
      '01934f6a-0000-7000-8000-0000000000f7',
      '01934f6a-0000-7000-8000-0000000000f8',
      '01934f6a-0000-7000-8000-0000000000f9',
    ]) {
      const res = await mockHandlers.getAssetHistory(assetId);
      const valid = validate(res);
      expect(validate.errors, `History validation failed for ${assetId}`).toBeNull();
      expect(valid).toBe(true);
    }
  });

  it('validates mockHandlers.listAssetVulnerabilities matches /assets/{asset_id}/vulnerabilities 200 schema', async () => {
    const schema =
      openApiDoc.paths['/assets/{asset_id}/vulnerabilities']?.get?.responses['200']?.content[
        'application/json'
      ]?.schema;
    expect(schema).toBeDefined();

    const validate = ajv.compile(schema);
    for (const assetId of [
      '01934f6a-0000-7000-8000-0000000000f6',
      '01934f6a-0000-7000-8000-0000000000f7',
    ]) {
      const res = await mockHandlers.listAssetVulnerabilities(assetId);
      const valid = validate(res);
      expect(validate.errors, `Vulnerabilities validation failed for ${assetId}`).toBeNull();
      expect(valid).toBe(true);
    }
  });

  it('validates mockHandlers.listCampaignEvents matches /campaigns/{campaign_id}/events 200 JSON schema', async () => {
    const schema =
      openApiDoc.paths['/campaigns/{campaign_id}/events']?.get?.responses['200']?.content[
        'application/json'
      ]?.schema;
    expect(schema).toBeDefined();

    const validate = ajv.compile(schema);
    const res = await mockHandlers.listCampaignEvents('01934f6a-0000-7000-8000-000000000001', {
      types: ['asset.discovered.v2'],
    });
    const valid = validate(res);
    expect(validate.errors).toBeNull();
    expect(valid).toBe(true);
  });

  it('validates mockCapabilities matches /capabilities 200 schema', () => {
    const schema = openApiDoc.paths['/capabilities']?.get?.responses['200']?.content['application/json']?.schema;
    expect(schema).toBeDefined();

    const validate = ajv.compile(schema);
    const valid = validate(mockCapabilities);
    expect(validate.errors).toBeNull();
    expect(valid).toBe(true);
  });

  it('validates CampaignCreateScreen safe-default payload and mockHandlers.createCampaign()', async () => {
    resetMockData();
    const { errors, payload } = validateCampaignForm({
      ...SAFE_LAB_POLICY_DEFAULTS,
      name: 'Contract check lab campaign',
      objective: 'Verify campaign-create.v2 contract conformance from UI defaults',
      authorizationLabel: 'owner, item 63, 2026-11-25',
      domainsText: 'lab.aegis.test',
      ipsText: '10.20.0.0/24',
      keywordsText: 'aegis lab',
    });
    expect(errors).toEqual({});
    expect(payload).toBeDefined();

    const createReqSchema = ajv.getSchema(
      'https://aegis.io/contracts/campaign/campaign-create.v2.schema.json'
    )!;
    expect(createReqSchema(payload)).toBe(true);
    expect(createReqSchema.errors).toBeNull();

    const createResSchema = ajv.compile(
      openApiDoc.paths['/campaigns']?.post?.responses['202']?.content['application/json']?.schema
    );
    const created = await mockHandlers.createCampaign(payload!, 'contract-test-key-1234');
    expect(createResSchema(created)).toBe(true);
    expect(createResSchema.errors).toBeNull();

    const campaignSchema = ajv.getSchema(
      'https://aegis.io/contracts/campaign/campaign.v2.schema.json'
    )!;
    const fetched = await mockHandlers.getCampaign(created.campaign_id);
    expect(campaignSchema(fetched)).toBe(true);
    expect(campaignSchema.errors).toBeNull();
  });

  it('validates mockHandlers.updateCampaignPolicy() matches /campaigns/{id}/policy POST schema', async () => {
    resetMockData();
    const policyReqSchema = ajv.compile(
      openApiDoc.paths['/campaigns/{campaign_id}/policy']?.post?.requestBody?.content[
        'application/json'
      ]?.schema
    );
    const policyResSchema = ajv.compile(
      openApiDoc.paths['/campaigns/{campaign_id}/policy']?.post?.responses['200']?.content[
        'application/json'
      ]?.schema
    );

    const body = {
      policy: {
        network_profile: 'internet' as const,
        max_parallel_jobs: 2,
        max_duration_hours: 4,
        rate_limits: {
          requests_per_second_per_host: 1,
          max_concurrent_connections_per_host: 2,
        },
        budget: {
          max_jobs: 10,
          idle_cycles_before_pause: 3,
        },
        authorization: {
          owner: 'owner',
          reference: 'owner, item 61, 2026-11-25',
          date: '2026-11-25',
          authorized_suffixes: ['example.com'],
        },
      },
      reason: 'Thu hep gioi han toc do theo RoE moi',
    };
    expect(policyReqSchema(body)).toBe(true);
    expect(policyReqSchema.errors).toBeNull();

    const res = await mockHandlers.updateCampaignPolicy(
      mockCampaigns[0].campaign_id,
      body,
      'policy-contract-key-1234'
    );
    expect(policyResSchema(res)).toBe(true);
    expect(policyResSchema.errors).toBeNull();
  });

  it('validates mockHandlers.getCampaignActivity() matches /campaigns/{id}/activity 200 schema', async () => {
    const activitySchema = ajv.compile(
      openApiDoc.paths['/campaigns/{campaign_id}/activity']?.get?.responses['200']?.content[
        'application/json'
      ]?.schema
    );

    const res = await mockHandlers.getCampaignActivity(mockCampaigns[0].campaign_id, { limit: 50 });
    expect(activitySchema(res)).toBe(true);
    expect(activitySchema.errors).toBeNull();

    const page1 = await mockHandlers.getCampaignActivity(mockCampaigns[0].campaign_id, { limit: 3 });
    expect(activitySchema(page1)).toBe(true);
    expect(page1.truncated).toBe(true);
    expect(page1.next_cursor).toBeTruthy();
  });
});
