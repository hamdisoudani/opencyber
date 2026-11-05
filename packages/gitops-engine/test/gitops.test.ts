import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import {
  type AuditTombstone,
  buildEndpointKey,
  type FindingReport,
  type RouteObservationBatch,
  type ScopeConfig,
  sha256Hex,
  type TrafficLedgerEntry,
} from '@opencyber/shared';
import { simpleGit } from 'simple-git';
import { afterEach, describe, expect, it } from 'vitest';
import { stringify as stringifyYaml } from 'yaml';
import {
  BlobVault,
  LockManager,
  reduceObservationsToSurface,
  runDeterministicCiGate,
  StateDb,
  WorktreeManager,
} from '../src/index.js';

function createSampleScope(engagementId: string = 'eng-acme-2026'): ScopeConfig {
  return {
    engagementId,
    programName: 'Acme Corp Bug Bounty Posture Review',
    authorizedDomains: ['api.acme.test', '*.acme.test'],
    excludedPaths: ['/admin/destructive/**'],
    maxRpsPerHost: 10,
    complianceHeaders: {
      'X-Aegis-Engagement': engagementId,
    },
    authProfiles: {
      readonly_viewer: {
        description: 'Read-only tenant viewer session',
        allowedMethods: ['GET', 'HEAD', 'OPTIONS'],
        headerNames: ['Authorization'],
      },
    },
    strictReadOnly: true,
  };
}

function createSampleFinding(
  overrides: Partial<FindingReport> = {},
): FindingReport {
  return {
    findingId: 'AUD-001-cors-exposure',
    title: 'Permissive CORS with Credential Reflection on User Roles Endpoint',
    category: 'PERMISSIVE_CORS',
    severity: 'HIGH',
    host: 'api.acme.test',
    endpointId: 'api.acme.test:GET:/v1/users/{param}/roles',
    summary:
      'GET /v1/users/{param}/roles reflects arbitrary Origin headers alongside Access-Control-Allow-Credentials: true.',
    architecturalAnalysis:
      'Edge gateway mirrors request Origin dynamically without validating against an explicit allowlist of trusted origins.',
    remediation:
      'Configure an explicit origin allowlist at the API gateway and omit Access-Control-Allow-Credentials for untrusted origins.',
    reproducibleCheckFile: 'reports/AUD-001-cors-exposure/verify_posture.py',
    evidencePointers: [
      {
        sha256: '0123456789abcdef0123456789abcdef',
        blobPath: 'objects/01/0123456789abcdef0123456789abcdef.blob',
        requestUrl: 'https://api.acme.test/v1/users/42/roles',
        method: 'OPTIONS',
        statusCode: 204,
        capturedAt: '2026-11-05T00:10:00.000Z',
      },
    ],
    status: 'PENDING_HUMAN_REVIEW',
    createdAt: '2026-11-05T00:15:00.000Z',
    ...overrides,
  };
}

describe('@opencyber/gitops-engine', () => {
  const tempRoots: string[] = [];

  async function makeTempRoot(prefix: string): Promise<string> {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), `aegis-${prefix}-`));
    tempRoots.push(dir);
    return dir;
  }

  afterEach(async () => {
    while (tempRoots.length > 0) {
      const dir = tempRoots.pop();
      if (dir) {
        await fs.rm(dir, { recursive: true, force: true });
      }
    }
  });

  describe('1. LockManager & Fencing Token Split-Brain Defense', () => {
    it('prevents concurrent acquisition, supports heartbeats, and rejects superseded zombie subagents at Stage 3 CI Gate', async () => {
      const root = await makeTempRoot('fencing');
      const repoDir = path.join(root, 'engagement-repo');
      const worktreeManager = new WorktreeManager({ repoDir });
      const scope = createSampleScope();
      await worktreeManager.initEngagementRepo(scope);

      const lockManager = new LockManager();
      const resourceKey = 'endpoint:api.acme.test:GET:/v1/users/{param}/roles';

      // Subagent A acquires lock with short 20ms TTL
      const acqA = lockManager.acquire(resourceKey, 'task-subagent-a', 20);
      expect(acqA.acquired).toBe(true);
      if (!acqA.acquired) {
        throw new Error('Expected Subagent A to acquire lock');
      }
      expect(acqA.lock.fencingToken).toBe(1);

      // Subagent B attempts acquisition before TTL expiry -> blocked
      const blockedB = lockManager.acquire(
        resourceKey,
        'task-subagent-b',
        300_000,
        acqA.lock.acquiredAtMs + 5,
      );
      expect(blockedB.acquired).toBe(false);
      if (!blockedB.acquired) {
        expect(blockedB.holderTaskId).toBe('task-subagent-a');
      }

      // Both subagents prepare isolated worktrees while A stalls past TTL
      const wtA = await worktreeManager.createTaskWorktree(
        'task-subagent-a',
        'aud-001-zombie-a',
      );
      await fs.mkdir(path.join(wtA.worktreePath, 'reports', 'AUD-001-cors-exposure'), {
        recursive: true,
      });
      await fs.writeFile(
        path.join(wtA.worktreePath, 'reports', 'AUD-001-cors-exposure', 'finding.yaml'),
        stringifyYaml(createSampleFinding()),
        'utf8',
      );
      await worktreeManager.commitWorktreeChanges(
        wtA.worktreePath,
        'feat(audit): subagent A finding submission',
      );

      // Wait for Subagent A's short TTL to expire
      await delay(35);

      // Before B acquires, expired token fails with LOCK_EXPIRED_OR_MISSING
      const expiredCheck = lockManager.validateFencingToken(resourceKey, 1);
      expect(expiredCheck).toEqual({
        valid: false,
        reason: 'LOCK_EXPIRED_OR_MISSING',
      });

      // Subagent B acquires lock -> monotonic fencingToken = 2
      const acqB = lockManager.acquire(resourceKey, 'task-subagent-b', 300_000);
      expect(acqB.acquired).toBe(true);
      if (!acqB.acquired) {
        throw new Error('Expected Subagent B to acquire expired lock');
      }
      expect(acqB.lock.fencingToken).toBe(2);

      // Subagent A (zombie) cannot heartbeat or release B's lock
      expect(
        lockManager.heartbeat(resourceKey, 'task-subagent-a', 1, 300_000),
      ).toBe(false);
      expect(lockManager.release(resourceKey, 'task-subagent-a', 1)).toBe(
        false,
      );

      // Subagent A attempts Stage 3 CI Gate with stale fencingToken=1 -> REJECTED!
      const gateResultA = await runDeterministicCiGate({
        worktreeManager,
        branchName: wtA.branchName,
        lockManager,
        lockResourceKey: resourceKey,
        fencingToken: acqA.lock.fencingToken,
      });
      expect(gateResultA.passed).toBe(false);
      expect(gateResultA.violations).toContain(
        'FENCING_TOKEN_INVALID: SUPERSEDED_FENCING_TOKEN',
      );

      // Subagent B commits valid finding and passes Stage 3 CI Gate with fencingToken=2
      const wtB = await worktreeManager.createTaskWorktree(
        'task-subagent-b',
        'aud-001-valid-b',
      );
      await fs.mkdir(path.join(wtB.worktreePath, 'reports', 'AUD-001-cors-exposure'), {
        recursive: true,
      });
      await fs.writeFile(
        path.join(wtB.worktreePath, 'reports', 'AUD-001-cors-exposure', 'finding.yaml'),
        stringifyYaml(createSampleFinding()),
        'utf8',
      );
      await worktreeManager.commitWorktreeChanges(
        wtB.worktreePath,
        'feat(audit): subagent B finding submission',
      );

      expect(
        lockManager.heartbeat(resourceKey, 'task-subagent-b', 2, 600_000),
      ).toBe(true);
      expect(lockManager.listActiveLocks()).toHaveLength(1);

      const gateResultB = await runDeterministicCiGate({
        worktreeManager,
        branchName: wtB.branchName,
        lockManager,
        lockResourceKey: resourceKey,
        fencingToken: acqB.lock.fencingToken,
      });
      expect(gateResultB.passed).toBe(true);
      expect(gateResultB.violations).toEqual([]);

      expect(lockManager.release(resourceKey, 'task-subagent-b', 2)).toBe(true);
      expect(lockManager.listActiveLocks()).toHaveLength(0);
    });
  });

  describe('2. Real git worktree + Stage 3 Deterministic CI Gate', () => {
    it('rejects scope.yaml tampering, unauthorized paths, and >50KB blobs, and merges valid finding branches cleanly', async () => {
      const root = await makeTempRoot('ci-gate');
      const repoDir = path.join(root, 'engagement-repo');
      const worktreeManager = new WorktreeManager({ repoDir });
      const scope = createSampleScope();
      await worktreeManager.initEngagementRepo(scope);

      // Sibling worktree directory must sit outside repoDir
      expect(worktreeManager.worktreesDir).toBe(`${repoDir}-worktrees`);

      // Case A: Reject branch modifying immutable scope.yaml
      const wtImmutable = await worktreeManager.createTaskWorktree(
        'task-immutable',
        'tamper-scope',
      );
      await fs.appendFile(
        path.join(wtImmutable.worktreePath, 'scope.yaml'),
        '\n# unauthorized tamper\n',
        'utf8',
      );
      await worktreeManager.commitWorktreeChanges(
        wtImmutable.worktreePath,
        'chore: tamper scope',
      );

      // Verify main working tree remains completely clean while worktrees exist
      const mainStatus = await simpleGit(repoDir).status();
      expect(mainStatus.isClean()).toBe(true);

      const immutableGate = await runDeterministicCiGate({
        worktreeManager,
        branchName: wtImmutable.branchName,
      });
      expect(immutableGate.passed).toBe(false);
      expect(
        immutableGate.violations.some((v) =>
          v.includes('IMMUTABLE_FILE_MODIFIED'),
        ),
      ).toBe(true);

      // Case B: Reject branch committing >50KB file
      const wtLarge = await worktreeManager.createTaskWorktree(
        'task-large-blob',
        'oversized-bundle',
      );
      const largePayload = 'x'.repeat(55 * 1024);
      await fs.writeFile(
        path.join(wtLarge.worktreePath, 'observations', 'huge-bundle.json'),
        largePayload,
        'utf8',
      );
      await worktreeManager.commitWorktreeChanges(
        wtLarge.worktreePath,
        'feat: commit oversized raw bundle',
      );

      const largeGate = await runDeterministicCiGate({
        worktreeManager,
        branchName: wtLarge.branchName,
      });
      expect(largeGate.passed).toBe(false);
      expect(
        largeGate.violations.some((v) => v.includes('MAX_BLOB_SIZE_EXCEEDED')),
      ).toBe(true);

      // Case C: Reject branch modifying unauthorized path (surface/ directly)
      const wtUnauth = await worktreeManager.createTaskWorktree(
        'task-unauth-path',
        'direct-surface-write',
      );
      await fs.mkdir(
        path.join(wtUnauth.worktreePath, 'surface', 'hosts', 'api.acme.test'),
        { recursive: true },
      );
      await fs.writeFile(
        path.join(
          wtUnauth.worktreePath,
          'surface',
          'hosts',
          'api.acme.test',
          'host.yaml',
        ),
        'hostname: api.acme.test\n',
        'utf8',
      );
      await worktreeManager.commitWorktreeChanges(
        wtUnauth.worktreePath,
        'feat: direct surface write',
      );

      const unauthGate = await runDeterministicCiGate({
        worktreeManager,
        branchName: wtUnauth.branchName,
      });
      expect(unauthGate.passed).toBe(false);
      expect(
        unauthGate.violations.some((v) => v.includes('UNAUTHORIZED_PATH')),
      ).toBe(true);

      // Case D: Valid branch with finding.yaml + verify_posture.py passes, merges --no-ff, and cleans up
      const wtValid = await worktreeManager.createTaskWorktree(
        'task-valid-finding',
        'AUD-001 cors exposure',
      );
      expect(wtValid.branchName).toBe('task/AUD-001-cors-exposure');

      const reportDir = path.join(
        wtValid.worktreePath,
        'reports',
        'AUD-001-cors-exposure',
      );
      await fs.mkdir(reportDir, { recursive: true });

      const finding = createSampleFinding();
      const verifyScript = [
        '#!/usr/bin/env python3',
        '"""Read-only OPTIONS/GET CORS posture check."""',
        'import urllib.request',
        'req = urllib.request.Request("https://api.acme.test/v1/users/42/roles", method="OPTIONS")',
      ].join('\n');

      await fs.writeFile(
        path.join(reportDir, 'finding.yaml'),
        stringifyYaml(finding),
        'utf8',
      );
      await fs.writeFile(
        path.join(reportDir, 'verify_posture.py'),
        verifyScript,
        'utf8',
      );

      const commitRes = await worktreeManager.commitWorktreeChanges(
        wtValid.worktreePath,
        'feat(audit): add AUD-001 CORS posture finding and read-only check',
      );
      expect(commitRes.committed).toBe(true);
      expect(commitRes.commitSha).toMatch(/^[a-f0-9]{40}$/);
      expect(commitRes.changedFiles.sort()).toEqual([
        'reports/AUD-001-cors-exposure/finding.yaml',
        'reports/AUD-001-cors-exposure/verify_posture.py',
      ]);

      const validGate = await runDeterministicCiGate({
        worktreeManager,
        branchName: wtValid.branchName,
      });
      expect(validGate.passed).toBe(true);
      expect(validGate.violations).toEqual([]);
      expect(validGate.validatedFindings).toHaveLength(1);
      expect(validGate.validatedFindings[0]?.findingId).toBe(
        'AUD-001-cors-exposure',
      );
      expect(validGate.verificationScripts).toHaveLength(1);
      expect(validGate.verificationScripts[0]?.relativePath).toBe(
        'reports/AUD-001-cors-exposure/verify_posture.py',
      );

      const { mergeCommitSha } = await worktreeManager.mergeBranchToMain(
        wtValid.branchName,
        'Merge task/AUD-001-cors-exposure after CI & orchestrator review',
      );
      expect(mergeCommitSha).toMatch(/^[a-f0-9]{40}$/);

      // Clean up worktree and delete merged branch
      await worktreeManager.cleanupWorktree(
        'task-valid-finding',
        wtValid.branchName,
        true,
      );

      await expect(fs.access(wtValid.worktreePath)).rejects.toThrow();

      // Merged file is present on main and history reflects the --no-ff merge commit
      const mergedFindingPath = path.join(
        repoDir,
        'reports',
        'AUD-001-cors-exposure',
        'finding.yaml',
      );
      const mergedContent = await fs.readFile(mergedFindingPath, 'utf8');
      expect(mergedContent).toContain('AUD-001-cors-exposure');

      const history = await worktreeManager.getHistory(10);
      expect(history.branches).toContain('main');
      expect(history.branches).not.toContain(wtValid.branchName);
      expect(
        history.commits.some((c) =>
          c.message.includes('Merge task/AUD-001-cors-exposure'),
        ),
      ).toBe(true);
    });

    it('rejects empty diffs and malformed observation/finding schemas', async () => {
      const root = await makeTempRoot('ci-schemas');
      const repoDir = path.join(root, 'engagement-repo');
      const worktreeManager = new WorktreeManager({ repoDir });
      await worktreeManager.initEngagementRepo(createSampleScope());

      // Empty diff branch
      const wtEmpty = await worktreeManager.createTaskWorktree(
        'task-empty',
        'noop-branch',
      );
      const noChanges = await worktreeManager.commitWorktreeChanges(
        wtEmpty.worktreePath,
        'should not commit',
      );
      expect(noChanges.committed).toBe(false);

      const emptyGate = await runDeterministicCiGate({
        worktreeManager,
        branchName: wtEmpty.branchName,
      });
      expect(emptyGate.passed).toBe(false);
      expect(emptyGate.violations).toContain('EMPTY_DIFF');

      // Malformed observation JSON
      const wtBadObs = await worktreeManager.createTaskWorktree(
        'task-bad-obs',
        'bad-observation',
      );
      await fs.writeFile(
        path.join(wtBadObs.worktreePath, 'observations', 'invalid.json'),
        JSON.stringify({ runId: '', agentRole: 'UNKNOWN_ROLE' }),
        'utf8',
      );
      await worktreeManager.commitWorktreeChanges(
        wtBadObs.worktreePath,
        'feat: invalid observation',
      );

      const badObsGate = await runDeterministicCiGate({
        worktreeManager,
        branchName: wtBadObs.branchName,
      });
      expect(badObsGate.passed).toBe(false);
      expect(
        badObsGate.violations.some((v) =>
          v.includes('OBSERVATION_SCHEMA_INVALID'),
        ),
      ).toBe(true);
    });
  });

  describe('3. Parallel Discovery Reducer + PGlite Attack Surface Graph Store', () => {
    it('merges parallel Recon and Static JS AST batches without Git conflicts into canonical surface and builds PGlite graph', async () => {
      const root = await makeTempRoot('reducer-graph');
      const repoDir = path.join(root, 'engagement-repo');
      const engagementId = 'eng-acme-2026';
      const scope = createSampleScope(engagementId);

      const worktreeManager = new WorktreeManager({ repoDir });
      await worktreeManager.initEngagementRepo(scope);

      const stateDb = new StateDb();
      await stateDb.init();
      await stateDb.upsertEngagement(scope);

      // Parallel Subagent 1 (RECON) & Subagent 2 (STATIC_JS_AST) write separate observation batches concurrently
      const [wtRecon, wtAst] = await Promise.all([
        worktreeManager.createTaskWorktree('task-recon-1', 'recon-batch-1'),
        worktreeManager.createTaskWorktree('task-ast-1', 'ast-batch-1'),
      ]);

      const reconBatch: RouteObservationBatch = {
        runId: 'run-recon-001',
        agentRole: 'RECON',
        createdAt: '2026-11-05T00:01:00.000Z',
        hosts: [
          {
            hostname: 'api.acme.test',
            discoveredAt: '2026-11-05T00:01:00.000Z',
            sources: ['httpx-passive'],
            statusCode: 200,
            serverHeader: 'envoy',
            securityHeaders: {
              'strict-transport-security': 'max-age=63072000; includeSubDomains',
            },
            fingerprints: ['envoy', 'nodejs'],
          },
        ],
        endpoints: [
          {
            host: 'api.acme.test',
            method: 'GET',
            rawPath: '/v1/users/42/roles',
            source: 'recon-har',
            parameters: ['includeInherited'],
            authRequired: true,
            responseContentType: 'application/json',
          },
          {
            host: 'api.acme.test',
            method: 'GET',
            rawPath: '/v1/health',
            source: 'recon-probe',
            parameters: [],
            authRequired: false,
            responseContentType: 'application/json',
          },
        ],
      };

      const astBatch: RouteObservationBatch = {
        runId: 'run-ast-002',
        agentRole: 'STATIC_JS_AST',
        createdAt: '2026-11-05T00:02:00.000Z',
        bundleSha256: sha256Hex('/* app.bundle.js */'),
        hosts: [
          {
            hostname: 'API.ACME.TEST',
            discoveredAt: '2026-11-05T00:02:00.000Z',
            sources: ['js-ast-extractor'],
            securityHeaders: {
              'x-content-type-options': 'nosniff',
            },
            fingerprints: ['react-router', 'nodejs'],
          },
        ],
        endpoints: [
          {
            host: 'API.ACME.TEST',
            method: 'GET',
            rawPath: '/v1/users/:userId/roles',
            source: 'bundle-ast',
            parameters: ['orgId'],
            authRequired: undefined,
          },
        ],
      };

      await Promise.all([
        fs.writeFile(
          path.join(wtRecon.worktreePath, 'observations', 'run-recon-001.json'),
          JSON.stringify(reconBatch, null, 2),
          'utf8',
        ),
        fs.writeFile(
          path.join(wtAst.worktreePath, 'observations', 'run-ast-002.json'),
          JSON.stringify(astBatch, null, 2),
          'utf8',
        ),
      ]);

      await Promise.all([
        worktreeManager.commitWorktreeChanges(
          wtRecon.worktreePath,
          'feat(recon): add run-recon-001 observations',
        ),
        worktreeManager.commitWorktreeChanges(
          wtAst.worktreePath,
          'feat(ast): add run-ast-002 observations',
        ),
      ]);

      const [gateRecon, gateAst] = await Promise.all([
        runDeterministicCiGate({
          worktreeManager,
          branchName: wtRecon.branchName,
        }),
        runDeterministicCiGate({
          worktreeManager,
          branchName: wtAst.branchName,
        }),
      ]);

      expect(gateRecon.passed).toBe(true);
      expect(gateAst.passed).toBe(true);

      // Both branches merge cleanly to main with zero Git conflicts
      await worktreeManager.mergeBranchToMain(
        wtRecon.branchName,
        'Merge recon observations',
      );
      await worktreeManager.mergeBranchToMain(
        wtAst.branchName,
        'Merge AST observations',
      );

      // Run deterministic surface reducer across both batches
      const reduced = await reduceObservationsToSurface({
        repoDir,
        worktreeManager,
        batches: [
          ...gateRecon.validatedObservations,
          ...gateAst.validatedObservations,
        ],
        stateDb,
        engagementId,
      });

      expect(reduced.commitSha).toMatch(/^[a-f0-9]{40}$/);
      expect(reduced.hosts).toHaveLength(1);
      expect(reduced.hosts[0]).toMatchObject({
        hostname: 'api.acme.test',
        discoveredAt: '2026-11-05T00:01:00.000Z',
        fingerprints: ['envoy', 'nodejs', 'react-router'],
        securityHeaders: {
          'strict-transport-security': 'max-age=63072000; includeSubDomains',
          'x-content-type-options': 'nosniff',
        },
      });

      // '/v1/users/42/roles' and '/v1/users/:userId/roles' collapse into 1 canonical endpoint (+ '/v1/health' = 2 total)
      expect(reduced.endpoints).toHaveLength(2);
      const rolesEndpointKey = buildEndpointKey(
        'api.acme.test',
        'GET',
        '/v1/users/42/roles',
      );
      const rolesEndpoint = reduced.endpoints.find(
        (ep) => ep.endpointId === rolesEndpointKey.endpointId,
      );
      expect(rolesEndpoint).toBeDefined();
      expect(rolesEndpoint).toMatchObject({
        endpointId: 'api.acme.test:GET:/v1/users/{param}/roles',
        host: 'api.acme.test',
        method: 'GET',
        canonicalPath: '/v1/users/{param}/roles',
        observedRawPaths: ['/v1/users/42/roles', '/v1/users/:userId/roles'],
        sources: ['bundle-ast', 'recon-har'],
        parameters: ['includeInherited', 'orgId'],
        authRequired: true,
        responseContentTypes: ['application/json'],
        firstSeenAt: '2026-11-05T00:01:00.000Z',
        lastUpdatedAt: '2026-11-05T00:02:00.000Z',
      });

      // Canonical YAML files exist on main
      await expect(
        fs.access(path.join(repoDir, 'surface/hosts/api.acme.test/host.yaml')),
      ).resolves.toBeUndefined();
      await expect(
        fs.access(path.join(repoDir, rolesEndpointKey.repoRelativePath)),
      ).resolves.toBeUndefined();

      // Re-running reducer with identical inputs is idempotent (no new commit)
      const secondReduced = await reduceObservationsToSurface({
        repoDir,
        worktreeManager,
        batches: [reconBatch, astBatch],
        stateDb,
        engagementId,
      });
      expect(secondReduced.commitSha).toBeUndefined();

      // Verify StateDb surface sync, findings, tombstones, traffic, reviews, and graph
      const dbHosts = await stateDb.listHosts(engagementId);
      const dbEndpoints = await stateDb.listEndpoints(engagementId);
      expect(dbHosts).toHaveLength(1);
      expect(dbEndpoints).toHaveLength(2);

      const healthEndpointId = 'api.acme.test:GET:/v1/health';
      expect(
        await stateDb.isEndpointEvaluated(
          engagementId,
          rolesEndpointKey.endpointId,
        ),
      ).toBe(false);
      expect(
        await stateDb.isEndpointEvaluated(engagementId, healthEndpointId),
      ).toBe(false);

      // Record finding on roles endpoint + compliant tombstone on health endpoint
      const finding = createSampleFinding({
        endpointId: rolesEndpointKey.endpointId,
      });
      await stateDb.upsertFinding(engagementId, finding);

      const tombstone: AuditTombstone = {
        endpointId: healthEndpointId,
        host: 'api.acme.test',
        method: 'GET',
        canonicalPath: '/v1/health',
        evaluatedAt: '2026-11-05T00:20:00.000Z',
        evaluatedByTask: 'task-audit-health',
        status: 'COMPLIANT',
        notes: 'Strict security headers and cache-control verified.',
      };
      await stateDb.recordTombstone(engagementId, tombstone);

      expect(
        await stateDb.isEndpointEvaluated(
          engagementId,
          rolesEndpointKey.endpointId,
        ),
      ).toBe(true);
      expect(
        await stateDb.isEndpointEvaluated(engagementId, healthEndpointId),
      ).toBe(true);
      expect(await stateDb.listTombstones(engagementId)).toHaveLength(1);

      // Update finding status during HITL review
      const updatedFinding = await stateDb.updateFindingStatus(
        finding.findingId,
        'APPROVED',
        'Verified reproducible via passive OPTIONS check.',
      );
      expect(updatedFinding?.status).toBe('APPROVED');
      const approvedFindings = await stateDb.listFindings(
        engagementId,
        'APPROVED',
      );
      expect(approvedFindings).toHaveLength(1);
      expect(approvedFindings[0]?.reviewerNote).toBe(
        'Verified reproducible via passive OPTIONS check.',
      );

      // Record traffic ledger entry and GitOps review audit record
      const trafficEntry: TrafficLedgerEntry = {
        id: 'req-001',
        timestamp: '2026-11-05T00:10:00.000Z',
        engagementId,
        taskId: 'task-audit-1',
        fencingToken: 2,
        method: 'OPTIONS',
        url: 'https://api.acme.test/v1/users/42/roles',
        host: 'api.acme.test',
        pathname: '/v1/users/42/roles',
        authProfile: 'readonly_viewer',
        decision: 'ALLOWED',
        upstreamStatus: 204,
        durationMs: 18,
      };
      await stateDb.recordTraffic(trafficEntry);
      expect(await stateDb.listTraffic(engagementId, 10)).toHaveLength(1);

      await stateDb.recordReview({
        id: 'rev-001',
        engagementId,
        branchName: 'task/AUD-001-cors-exposure',
        taskId: 'task-audit-1',
        ciPassed: true,
        decision: 'APPROVE_MERGE',
        rationale: 'Clean passive CORS check with cryptographic HAR evidence.',
        commitSha: reduced.commitSha,
        createdAt: '2026-11-05T00:16:00.000Z',
      });
      expect(await stateDb.listReviews(engagementId)).toHaveLength(1);

      // Verify full Attack Surface Graph nodes & edges
      const graph = await stateDb.getAttackSurfaceGraph(engagementId);
      expect(graph.engagementId).toBe(engagementId);

      const nodeIds = graph.nodes.map((n) => n.id);
      expect(nodeIds).toContain(engagementId); // PROGRAM
      expect(nodeIds).toContain('host:api.acme.test'); // HOST
      expect(nodeIds).toContain(rolesEndpointKey.endpointId); // ENDPOINT 1
      expect(nodeIds).toContain(healthEndpointId); // ENDPOINT 2
      expect(nodeIds).toContain(finding.findingId); // FINDING
      expect(nodeIds).toContain(`tombstone:${healthEndpointId}`); // TOMBSTONE

      expect(graph.edges).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            source: engagementId,
            target: 'host:api.acme.test',
            type: 'IN_SCOPE',
          }),
          expect.objectContaining({
            source: 'host:api.acme.test',
            target: rolesEndpointKey.endpointId,
            type: 'EXPOSES',
          }),
          expect.objectContaining({
            source: 'host:api.acme.test',
            target: healthEndpointId,
            type: 'EXPOSES',
          }),
          expect.objectContaining({
            source: rolesEndpointKey.endpointId,
            target: finding.findingId,
            type: 'HAS_FINDING',
          }),
          expect.objectContaining({
            source: healthEndpointId,
            target: `tombstone:${healthEndpointId}`,
            type: 'VERIFIED_COMPLIANT',
          }),
        ]),
      );

      await stateDb.close();
    });
  });

  describe('4. BlobVault Content-Addressed Storage', () => {
    it('stores, deduplicates, checks, and retrieves large artifacts by SHA-256 outside Git', async () => {
      const root = await makeTempRoot('vault');
      const vault = new BlobVault(path.join(root, 'artifact-vault'));

      const bundleSource =
        'export async function fetchRoles(id) { return fetch(`/v1/users/${id}/roles`); }\n'.repeat(
          1024,
        );
      const expectedSha = sha256Hex(bundleSource);

      expect(await vault.has(expectedSha)).toBe(false);
      expect(await vault.get(expectedSha)).toBeNull();

      const stored = await vault.put(bundleSource, 'application/javascript', {
        originUrl: 'https://api.acme.test/assets/app.js',
        capturedBy: 'task-recon-1',
      });

      expect(stored.sha256).toBe(expectedSha);
      expect(stored.sizeBytes).toBe(Buffer.byteLength(bundleSource, 'utf8'));
      expect(stored.blobPath).toContain(
        path.join('objects', expectedSha.slice(0, 2), `${expectedSha}.blob`),
      );

      expect(await vault.has(expectedSha)).toBe(true);

      const retrieved = await vault.get(expectedSha);
      expect(retrieved).not.toBeNull();
      expect(retrieved?.content.toString('utf8')).toBe(bundleSource);
      expect(retrieved?.mediaType).toBe('application/javascript');
      expect(retrieved?.sizeBytes).toBe(stored.sizeBytes);
      expect(retrieved?.metadata).toEqual({
        originUrl: 'https://api.acme.test/assets/app.js',
        capturedBy: 'task-recon-1',
      });

      // Binary Uint8Array round-trip & path traversal rejection
      const binaryBytes = new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0x00, 0xff]);
      const binRes = await vault.put(binaryBytes, 'application/octet-stream');
      const binLoaded = await vault.get(binRes.sha256);
      expect(Buffer.compare(binLoaded!.content, Buffer.from(binaryBytes))).toBe(
        0,
      );

      expect(await vault.has('../../etc/passwd')).toBe(false);
      expect(await vault.get('../../etc/passwd')).toBeNull();
    });
  });
});
