import {
  type FindingReport,
  FindingReportSchema,
  type RouteObservationBatch,
  RouteObservationBatchSchema,
} from '@opencyber/shared';
import { parse as parseYaml } from 'yaml';
import type { LockManager } from './lock-manager.js';
import type { WorktreeManager } from './worktree-manager.js';

export interface CiGateInput {
  worktreeManager: WorktreeManager;
  branchName: string;
  lockManager?: LockManager;
  lockResourceKey?: string;
  fencingToken?: number;
  maxFileBytes?: number;
  allowedPrefixes?: string[];
}

export interface CiGateResult {
  passed: boolean;
  violations: string[];
  changedFiles: string[];
  diffText: string;
  validatedObservations: RouteObservationBatch[];
  validatedFindings: FindingReport[];
  verificationScripts: Array<{ relativePath: string; content: string }>;
}

const DEFAULT_MAX_FILE_BYTES = 50 * 1024;
const DEFAULT_ALLOWED_PREFIXES = ['observations/', 'schemas/', 'reports/'];
const IMMUTABLE_FILES = new Set(['scope.yaml', 'POLICY.md']);

const OBSERVATION_OR_SCHEMA_FILE_RE =
  /^(?:observations|schemas)\/.+\.(?:json|yaml|yml)$/i;
const FINDING_FILE_RE = /^reports\/[^/]+\/finding\.(?:yaml|yml|json)$/i;
const VERIFICATION_SCRIPT_RE = /^reports\/[^/]+\/verify_[^/]*\.py$/;

function parseStructuredContent(relativePath: string, content: string): unknown {
  if (relativePath.toLowerCase().endsWith('.json')) {
    return JSON.parse(content);
  }
  return parseYaml(content);
}

export async function runDeterministicCiGate(
  input: CiGateInput,
): Promise<CiGateResult> {
  const maxFileBytes = input.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES;
  const allowedPrefixes = input.allowedPrefixes ?? DEFAULT_ALLOWED_PREFIXES;

  const violations: string[] = [];
  const validatedObservations: RouteObservationBatch[] = [];
  const validatedFindings: FindingReport[] = [];
  const verificationScripts: Array<{ relativePath: string; content: string }> =
    [];

  if (
    input.lockManager &&
    input.lockResourceKey &&
    input.fencingToken !== undefined
  ) {
    const tokenValidation = input.lockManager.validateFencingToken(
      input.lockResourceKey,
      input.fencingToken,
    );
    if (!tokenValidation.valid) {
      violations.push(
        `FENCING_TOKEN_INVALID: ${tokenValidation.reason ?? 'INVALID_TOKEN'}`,
      );
    }
  }

  const { changedFiles, diffText, filesWithContent } =
    await input.worktreeManager.inspectBranchDiff(input.branchName);

  if (changedFiles.length === 0) {
    violations.push('EMPTY_DIFF');
  }

  const rejectedPaths = new Set<string>();

  for (const rawPath of changedFiles) {
    const normalizedPath = rawPath.replace(/\\/g, '/');
    const segments = normalizedPath.split('/');

    if (IMMUTABLE_FILES.has(normalizedPath)) {
      violations.push(`IMMUTABLE_FILE_MODIFIED: ${normalizedPath}`);
      rejectedPaths.add(rawPath);
      continue;
    }

    if (
      normalizedPath.startsWith('/') ||
      segments.includes('..') ||
      !allowedPrefixes.some((prefix) => normalizedPath.startsWith(prefix))
    ) {
      violations.push(`UNAUTHORIZED_PATH: ${normalizedPath}`);
      rejectedPaths.add(rawPath);
    }
  }

  for (const file of filesWithContent) {
    if (file.sizeBytes > maxFileBytes) {
      violations.push(
        `MAX_BLOB_SIZE_EXCEEDED: ${file.relativePath} (${file.sizeBytes} bytes > ${maxFileBytes} bytes)`,
      );
      rejectedPaths.add(file.relativePath);
    }
  }

  for (const file of filesWithContent) {
    if (rejectedPaths.has(file.relativePath)) {
      continue;
    }

    const normalizedPath = file.relativePath.replace(/\\/g, '/');

    if (OBSERVATION_OR_SCHEMA_FILE_RE.test(normalizedPath)) {
      let rawParsed: unknown;
      try {
        rawParsed = parseStructuredContent(normalizedPath, file.content);
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        violations.push(`SCHEMA_PARSE_ERROR: ${normalizedPath}: ${message}`);
        continue;
      }

      const validation = RouteObservationBatchSchema.safeParse(rawParsed);
      if (!validation.success) {
        violations.push(
          `OBSERVATION_SCHEMA_INVALID: ${normalizedPath}: ${validation.error.message}`,
        );
      } else {
        validatedObservations.push(validation.data);
      }
      continue;
    }

    if (FINDING_FILE_RE.test(normalizedPath)) {
      let rawParsed: unknown;
      try {
        rawParsed = parseStructuredContent(normalizedPath, file.content);
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        violations.push(`FINDING_PARSE_ERROR: ${normalizedPath}: ${message}`);
        continue;
      }

      const validation = FindingReportSchema.safeParse(rawParsed);
      if (!validation.success) {
        violations.push(
          `FINDING_SCHEMA_INVALID: ${normalizedPath}: ${validation.error.message}`,
        );
      } else {
        validatedFindings.push(validation.data);
      }
      continue;
    }

    if (VERIFICATION_SCRIPT_RE.test(normalizedPath)) {
      verificationScripts.push({
        relativePath: normalizedPath,
        content: file.content,
      });
    }
  }

  return {
    passed: violations.length === 0,
    violations,
    changedFiles,
    diffText,
    validatedObservations,
    validatedFindings,
    verificationScripts,
  };
}
