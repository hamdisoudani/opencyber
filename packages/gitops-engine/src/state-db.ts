import { PGlite } from '@electric-sql/pglite';
import {
  type AuditTombstone,
  AuditTombstoneSchema,
  type CanonicalEndpoint,
  CanonicalEndpointSchema,
  type FindingReport,
  FindingReportSchema,
  type FindingStatus,
  FindingStatusSchema,
  type HostEntity,
  HostEntitySchema,
  type ScopeConfig,
  ScopeConfigSchema,
  type TrafficLedgerEntry,
  TrafficLedgerEntrySchema,
} from '@opencyber/shared';

export type SurfaceGraphNodeType =
  | 'PROGRAM'
  | 'HOST'
  | 'ENDPOINT'
  | 'FINDING'
  | 'TOMBSTONE';

export type SurfaceGraphEdgeType =
  | 'IN_SCOPE'
  | 'EXPOSES'
  | 'HAS_FINDING'
  | 'VERIFIED_COMPLIANT';

export interface SurfaceGraphNode {
  id: string;
  type: SurfaceGraphNodeType;
  label: string;
  metadata: Record<string, unknown>;
}

export interface SurfaceGraphEdge {
  id: string;
  source: string;
  target: string;
  type: SurfaceGraphEdgeType;
}

export interface SurfaceGraphSnapshot {
  engagementId: string;
  nodes: SurfaceGraphNode[];
  edges: SurfaceGraphEdge[];
}

export interface GitOpsReviewRecord {
  id: string;
  engagementId: string;
  branchName: string;
  taskId: string;
  ciPassed: boolean;
  decision: string;
  rationale: string;
  commitSha?: string;
  createdAt: string;
}

function parseJsonColumn(raw: unknown): unknown {
  if (typeof raw === 'string') {
    return JSON.parse(raw);
  }
  return raw;
}

export class StateDb {
  private readonly db: PGlite;
  private initialized = false;

  constructor(dataDir?: string) {
    this.db = dataDir ? new PGlite(dataDir) : new PGlite();
  }

  async init(): Promise<void> {
    if (this.initialized) {
      return;
    }

    await this.db.exec(`
      CREATE TABLE IF NOT EXISTS engagements (
        engagement_id TEXT PRIMARY KEY,
        program_name TEXT NOT NULL,
        scope_json JSONB NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS hosts (
        engagement_id TEXT NOT NULL,
        hostname TEXT NOT NULL,
        discovered_at TEXT NOT NULL,
        data_json JSONB NOT NULL,
        PRIMARY KEY (engagement_id, hostname)
      );

      CREATE TABLE IF NOT EXISTS endpoints (
        engagement_id TEXT NOT NULL,
        endpoint_id TEXT NOT NULL,
        host TEXT NOT NULL,
        method TEXT NOT NULL,
        canonical_path TEXT NOT NULL,
        data_json JSONB NOT NULL,
        PRIMARY KEY (engagement_id, endpoint_id)
      );

      CREATE TABLE IF NOT EXISTS tombstones (
        engagement_id TEXT NOT NULL,
        endpoint_id TEXT NOT NULL,
        host TEXT NOT NULL,
        status TEXT NOT NULL,
        evaluated_at TEXT NOT NULL,
        data_json JSONB NOT NULL,
        PRIMARY KEY (engagement_id, endpoint_id)
      );

      CREATE TABLE IF NOT EXISTS findings (
        finding_id TEXT PRIMARY KEY,
        engagement_id TEXT NOT NULL,
        host TEXT NOT NULL,
        endpoint_id TEXT NOT NULL,
        severity TEXT NOT NULL,
        category TEXT NOT NULL,
        status TEXT NOT NULL,
        reviewer_note TEXT,
        created_at TEXT NOT NULL,
        data_json JSONB NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_findings_engagement
        ON findings (engagement_id);

      CREATE TABLE IF NOT EXISTS traffic_ledger (
        id TEXT PRIMARY KEY,
        engagement_id TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        task_id TEXT NOT NULL,
        fencing_token INTEGER NOT NULL,
        decision TEXT NOT NULL,
        data_json JSONB NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_traffic_engagement_ts
        ON traffic_ledger (engagement_id, timestamp DESC);

      CREATE TABLE IF NOT EXISTS gitops_reviews (
        id TEXT PRIMARY KEY,
        engagement_id TEXT NOT NULL,
        branch_name TEXT NOT NULL,
        task_id TEXT NOT NULL,
        ci_passed BOOLEAN NOT NULL,
        decision TEXT NOT NULL,
        rationale TEXT NOT NULL,
        commit_sha TEXT,
        created_at TEXT NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_reviews_engagement
        ON gitops_reviews (engagement_id, created_at DESC);
    `);

    this.initialized = true;
  }

  private async ensureInitialized(): Promise<void> {
    if (!this.initialized) {
      await this.init();
    }
  }

  async upsertEngagement(scope: ScopeConfig): Promise<void> {
    await this.ensureInitialized();
    const validated = ScopeConfigSchema.parse(scope);
    await this.db.query(
      `
      INSERT INTO engagements (engagement_id, program_name, scope_json, updated_at)
      VALUES ($1, $2, $3::jsonb, NOW())
      ON CONFLICT (engagement_id) DO UPDATE SET
        program_name = EXCLUDED.program_name,
        scope_json = EXCLUDED.scope_json,
        updated_at = NOW()
      `,
      [validated.engagementId, validated.programName, JSON.stringify(validated)],
    );
  }

  async syncSurface(
    engagementId: string,
    hosts: HostEntity[],
    endpoints: CanonicalEndpoint[],
  ): Promise<void> {
    await this.ensureInitialized();
    await this.db.transaction(async (tx) => {
      for (const rawHost of hosts) {
        const host = HostEntitySchema.parse(rawHost);
        await tx.query(
          `
          INSERT INTO hosts (engagement_id, hostname, discovered_at, data_json)
          VALUES ($1, $2, $3, $4::jsonb)
          ON CONFLICT (engagement_id, hostname) DO UPDATE SET
            discovered_at = EXCLUDED.discovered_at,
            data_json = EXCLUDED.data_json
          `,
          [
            engagementId,
            host.hostname,
            host.discoveredAt,
            JSON.stringify(host),
          ],
        );
      }

      for (const rawEndpoint of endpoints) {
        const ep = CanonicalEndpointSchema.parse(rawEndpoint);
        await tx.query(
          `
          INSERT INTO endpoints (engagement_id, endpoint_id, host, method, canonical_path, data_json)
          VALUES ($1, $2, $3, $4, $5, $6::jsonb)
          ON CONFLICT (engagement_id, endpoint_id) DO UPDATE SET
            host = EXCLUDED.host,
            method = EXCLUDED.method,
            canonical_path = EXCLUDED.canonical_path,
            data_json = EXCLUDED.data_json
          `,
          [
            engagementId,
            ep.endpointId,
            ep.host,
            ep.method,
            ep.canonicalPath,
            JSON.stringify(ep),
          ],
        );
      }
    });
  }

  async listHosts(engagementId: string): Promise<HostEntity[]> {
    await this.ensureInitialized();
    const res = await this.db.query<{ data_json: unknown }>(
      `
      SELECT data_json
      FROM hosts
      WHERE engagement_id = $1
      ORDER BY hostname ASC
      `,
      [engagementId],
    );
    return res.rows.map((row) =>
      HostEntitySchema.parse(parseJsonColumn(row.data_json)),
    );
  }

  async listEndpoints(engagementId: string): Promise<CanonicalEndpoint[]> {
    await this.ensureInitialized();
    const res = await this.db.query<{ data_json: unknown }>(
      `
      SELECT data_json
      FROM endpoints
      WHERE engagement_id = $1
      ORDER BY endpoint_id ASC
      `,
      [engagementId],
    );
    return res.rows.map((row) =>
      CanonicalEndpointSchema.parse(parseJsonColumn(row.data_json)),
    );
  }

  async recordTombstone(
    engagementId: string,
    tombstone: AuditTombstone,
  ): Promise<void> {
    await this.ensureInitialized();
    const validated = AuditTombstoneSchema.parse(tombstone);
    await this.db.query(
      `
      INSERT INTO tombstones (engagement_id, endpoint_id, host, status, evaluated_at, data_json)
      VALUES ($1, $2, $3, $4, $5, $6::jsonb)
      ON CONFLICT (engagement_id, endpoint_id) DO UPDATE SET
        host = EXCLUDED.host,
        status = EXCLUDED.status,
        evaluated_at = EXCLUDED.evaluated_at,
        data_json = EXCLUDED.data_json
      `,
      [
        engagementId,
        validated.endpointId,
        validated.host,
        validated.status,
        validated.evaluatedAt,
        JSON.stringify(validated),
      ],
    );
  }

  async listTombstones(engagementId: string): Promise<AuditTombstone[]> {
    await this.ensureInitialized();
    const res = await this.db.query<{ data_json: unknown }>(
      `
      SELECT data_json
      FROM tombstones
      WHERE engagement_id = $1
      ORDER BY endpoint_id ASC
      `,
      [engagementId],
    );
    return res.rows.map((row) =>
      AuditTombstoneSchema.parse(parseJsonColumn(row.data_json)),
    );
  }

  async isEndpointEvaluated(
    engagementId: string,
    endpointId: string,
  ): Promise<boolean> {
    await this.ensureInitialized();
    const res = await this.db.query<{ evaluated: boolean }>(
      `
      SELECT (
        EXISTS (
          SELECT 1 FROM tombstones
          WHERE engagement_id = $1 AND endpoint_id = $2
        )
        OR EXISTS (
          SELECT 1 FROM findings
          WHERE engagement_id = $1 AND endpoint_id = $2
        )
      ) AS evaluated
      `,
      [engagementId, endpointId],
    );
    return Boolean(res.rows[0]?.evaluated);
  }

  async upsertFinding(
    engagementId: string,
    finding: FindingReport,
  ): Promise<void> {
    await this.ensureInitialized();
    const validated = FindingReportSchema.parse(finding);
    await this.db.query(
      `
      INSERT INTO findings (
        finding_id,
        engagement_id,
        host,
        endpoint_id,
        severity,
        category,
        status,
        created_at,
        data_json
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb)
      ON CONFLICT (finding_id) DO UPDATE SET
        engagement_id = EXCLUDED.engagement_id,
        host = EXCLUDED.host,
        endpoint_id = EXCLUDED.endpoint_id,
        severity = EXCLUDED.severity,
        category = EXCLUDED.category,
        status = EXCLUDED.status,
        created_at = EXCLUDED.created_at,
        data_json = EXCLUDED.data_json
      `,
      [
        validated.findingId,
        engagementId,
        validated.host,
        validated.endpointId,
        validated.severity,
        validated.category,
        validated.status,
        validated.createdAt,
        JSON.stringify(validated),
      ],
    );
  }

  async updateFindingStatus(
    findingId: string,
    status: FindingStatus,
    reviewerNote?: string,
  ): Promise<FindingReport | null> {
    await this.ensureInitialized();
    const validatedStatus = FindingStatusSchema.parse(status);

    const existingRes = await this.db.query<{
      data_json: unknown;
      reviewer_note: string | null;
    }>(
      `SELECT data_json, reviewer_note FROM findings WHERE finding_id = $1`,
      [findingId],
    );

    const existingRow = existingRes.rows[0];
    if (!existingRow) {
      return null;
    }

    const existingFinding = FindingReportSchema.parse(
      parseJsonColumn(existingRow.data_json),
    );
    const updatedFinding: FindingReport = {
      ...existingFinding,
      status: validatedStatus,
    };

    const nextNote =
      reviewerNote !== undefined ? reviewerNote : existingRow.reviewer_note;

    await this.db.query(
      `
      UPDATE findings
      SET status = $2,
          reviewer_note = $3,
          data_json = $4::jsonb
      WHERE finding_id = $1
      `,
      [
        findingId,
        validatedStatus,
        nextNote,
        JSON.stringify(updatedFinding),
      ],
    );

    return updatedFinding;
  }

  async listFindings(
    engagementId: string,
    status?: FindingStatus,
  ): Promise<Array<FindingReport & { reviewerNote?: string }>> {
    await this.ensureInitialized();

    const rowsRes = status
      ? await this.db.query<{
          data_json: unknown;
          status: string;
          reviewer_note: string | null;
        }>(
          `
          SELECT data_json, status, reviewer_note
          FROM findings
          WHERE engagement_id = $1 AND status = $2
          ORDER BY created_at DESC, finding_id ASC
          `,
          [engagementId, status],
        )
      : await this.db.query<{
          data_json: unknown;
          status: string;
          reviewer_note: string | null;
        }>(
          `
          SELECT data_json, status, reviewer_note
          FROM findings
          WHERE engagement_id = $1
          ORDER BY created_at DESC, finding_id ASC
          `,
          [engagementId],
        );

    return rowsRes.rows.map((row) => {
      const parsed = FindingReportSchema.parse(parseJsonColumn(row.data_json));
      const report: FindingReport & { reviewerNote?: string } = {
        ...parsed,
        status: FindingStatusSchema.parse(row.status),
      };
      if (row.reviewer_note !== null && row.reviewer_note !== undefined) {
        report.reviewerNote = row.reviewer_note;
      }
      return report;
    });
  }

  async recordTraffic(entry: TrafficLedgerEntry): Promise<void> {
    await this.ensureInitialized();
    const validated = TrafficLedgerEntrySchema.parse(entry);
    await this.db.query(
      `
      INSERT INTO traffic_ledger (
        id,
        engagement_id,
        timestamp,
        task_id,
        fencing_token,
        decision,
        data_json
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)
      ON CONFLICT (id) DO UPDATE SET
        timestamp = EXCLUDED.timestamp,
        decision = EXCLUDED.decision,
        data_json = EXCLUDED.data_json
      `,
      [
        validated.id,
        validated.engagementId,
        validated.timestamp,
        validated.taskId,
        validated.fencingToken,
        validated.decision,
        JSON.stringify(validated),
      ],
    );
  }

  async listTraffic(
    engagementId: string,
    limit: number = 100,
  ): Promise<TrafficLedgerEntry[]> {
    await this.ensureInitialized();
    const res = await this.db.query<{ data_json: unknown }>(
      `
      SELECT data_json
      FROM traffic_ledger
      WHERE engagement_id = $1
      ORDER BY timestamp DESC, id DESC
      LIMIT $2
      `,
      [engagementId, limit],
    );
    return res.rows.map((row) =>
      TrafficLedgerEntrySchema.parse(parseJsonColumn(row.data_json)),
    );
  }

  async recordReview(review: GitOpsReviewRecord): Promise<void> {
    await this.ensureInitialized();
    await this.db.query(
      `
      INSERT INTO gitops_reviews (
        id,
        engagement_id,
        branch_name,
        task_id,
        ci_passed,
        decision,
        rationale,
        commit_sha,
        created_at
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      ON CONFLICT (id) DO UPDATE SET
        ci_passed = EXCLUDED.ci_passed,
        decision = EXCLUDED.decision,
        rationale = EXCLUDED.rationale,
        commit_sha = EXCLUDED.commit_sha,
        created_at = EXCLUDED.created_at
      `,
      [
        review.id,
        review.engagementId,
        review.branchName,
        review.taskId,
        review.ciPassed,
        review.decision,
        review.rationale,
        review.commitSha ?? null,
        review.createdAt,
      ],
    );
  }

  async listReviews(engagementId: string): Promise<GitOpsReviewRecord[]> {
    await this.ensureInitialized();
    const res = await this.db.query<{
      id: string;
      engagement_id: string;
      branch_name: string;
      task_id: string;
      ci_passed: boolean;
      decision: string;
      rationale: string;
      commit_sha: string | null;
      created_at: string;
    }>(
      `
      SELECT
        id,
        engagement_id,
        branch_name,
        task_id,
        ci_passed,
        decision,
        rationale,
        commit_sha,
        created_at
      FROM gitops_reviews
      WHERE engagement_id = $1
      ORDER BY created_at DESC, id ASC
      `,
      [engagementId],
    );

    return res.rows.map((row) => {
      const record: GitOpsReviewRecord = {
        id: row.id,
        engagementId: row.engagement_id,
        branchName: row.branch_name,
        taskId: row.task_id,
        ciPassed: Boolean(row.ci_passed),
        decision: row.decision,
        rationale: row.rationale,
        createdAt: row.created_at,
      };
      if (row.commit_sha !== null && row.commit_sha !== undefined) {
        record.commitSha = row.commit_sha;
      }
      return record;
    });
  }

  async getAttackSurfaceGraph(
    engagementId: string,
  ): Promise<SurfaceGraphSnapshot> {
    await this.ensureInitialized();

    const [engagementRes, hosts, endpoints, findings, tombstones] =
      await Promise.all([
        this.db.query<{ program_name: string; scope_json: unknown }>(
          `SELECT program_name, scope_json FROM engagements WHERE engagement_id = $1`,
          [engagementId],
        ),
        this.listHosts(engagementId),
        this.listEndpoints(engagementId),
        this.listFindings(engagementId),
        this.listTombstones(engagementId),
      ]);

    const nodes = new Map<string, SurfaceGraphNode>();
    const edges = new Map<string, SurfaceGraphEdge>();

    const engagementRow = engagementRes.rows[0];
    const scopeMeta = engagementRow
      ? (parseJsonColumn(engagementRow.scope_json) as Record<string, unknown>)
      : { engagementId };

    nodes.set(engagementId, {
      id: engagementId,
      type: 'PROGRAM',
      label: engagementRow?.program_name ?? engagementId,
      metadata: scopeMeta,
    });

    const ensureHostNode = (hostname: string, hostEntity?: HostEntity): string => {
      const hostNodeId = `host:${hostname}`;
      if (!nodes.has(hostNodeId)) {
        nodes.set(hostNodeId, {
          id: hostNodeId,
          type: 'HOST',
          label: hostname,
          metadata: hostEntity ? { ...hostEntity } : { hostname },
        });
      }
      const inScopeEdgeId = `IN_SCOPE:${engagementId}->${hostNodeId}`;
      if (!edges.has(inScopeEdgeId)) {
        edges.set(inScopeEdgeId, {
          id: inScopeEdgeId,
          source: engagementId,
          target: hostNodeId,
          type: 'IN_SCOPE',
        });
      }
      return hostNodeId;
    };

    for (const host of hosts) {
      ensureHostNode(host.hostname, host);
    }

    for (const endpoint of endpoints) {
      const hostNodeId = ensureHostNode(endpoint.host);
      nodes.set(endpoint.endpointId, {
        id: endpoint.endpointId,
        type: 'ENDPOINT',
        label: `${endpoint.method} ${endpoint.canonicalPath}`,
        metadata: { ...endpoint },
      });

      const exposesEdgeId = `EXPOSES:${hostNodeId}->${endpoint.endpointId}`;
      edges.set(exposesEdgeId, {
        id: exposesEdgeId,
        source: hostNodeId,
        target: endpoint.endpointId,
        type: 'EXPOSES',
      });
    }

    for (const finding of findings) {
      nodes.set(finding.findingId, {
        id: finding.findingId,
        type: 'FINDING',
        label: finding.title,
        metadata: { ...finding },
      });

      const hasFindingEdgeId = `HAS_FINDING:${finding.endpointId}->${finding.findingId}`;
      edges.set(hasFindingEdgeId, {
        id: hasFindingEdgeId,
        source: finding.endpointId,
        target: finding.findingId,
        type: 'HAS_FINDING',
      });
    }

    for (const tombstone of tombstones) {
      const tombstoneNodeId = `tombstone:${tombstone.endpointId}`;
      nodes.set(tombstoneNodeId, {
        id: tombstoneNodeId,
        type: 'TOMBSTONE',
        label: `${tombstone.status}: ${tombstone.method} ${tombstone.canonicalPath}`,
        metadata: { ...tombstone },
      });

      const verifiedEdgeId = `VERIFIED_COMPLIANT:${tombstone.endpointId}->${tombstoneNodeId}`;
      edges.set(verifiedEdgeId, {
        id: verifiedEdgeId,
        source: tombstone.endpointId,
        target: tombstoneNodeId,
        type: 'VERIFIED_COMPLIANT',
      });
    }

    return {
      engagementId,
      nodes: Array.from(nodes.values()),
      edges: Array.from(edges.values()),
    };
  }

  async close(): Promise<void> {
    await this.db.close();
  }
}
