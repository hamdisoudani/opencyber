import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import { beforeAll, describe, expect, it, vi } from 'vitest';
import {
  createDefaultSandboxProvider,
  E2BSandboxProvider,
  LocalSandboxProvider,
  SandboxBudgetExceededError,
  type SandboxRevokeReason,
  SandboxRevokedError,
} from '../src/index.js';

function loadWorkspaceDotEnvIfNeeded(): void {
  if (process.env.E2B_API_KEY) {
    return;
  }

  const envPath = '/home/antigravity/hamdisoudani/opencyber/.env';
  if (!fs.existsSync(envPath)) {
    return;
  }

  const raw = fs.readFileSync(envPath, 'utf8');
  for (const rawLine of raw.split(/\r?\n/)) {
    const trimmed = rawLine.trim();
    if (!trimmed || trimmed.startsWith('#')) {
      continue;
    }

    const normalized = trimmed.startsWith('export ') ? trimmed.slice(7).trim() : trimmed;
    const eqIdx = normalized.indexOf('=');
    if (eqIdx <= 0) {
      continue;
    }

    const key = normalized.slice(0, eqIdx).trim();
    let value = normalized.slice(eqIdx + 1).trim();

    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }

    if (key && process.env[key] === undefined) {
      process.env[key] = value;
    }
  }
}

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

beforeAll(() => {
  loadWorkspaceDotEnvIfNeeded();
});

describe('LocalSandboxProvider & ManagedSandboxSession Governance', () => {
  it('executes bash commands, captures exit codes, and runs Python verification scripts', async () => {
    const provider = new LocalSandboxProvider();
    expect(provider.providerType).toBe('local');

    const session = await provider.createSession({ maxCommands: 10 });
    const workspaceDir = session.workspaceDir;

    try {
      const echoRes = await session.executeCommand('echo "aegis-ready:$TEST_FLAG"', {
        env: { TEST_FLAG: 'strict-defensive' },
      });
      expect(echoRes.exitCode).toBe(0);
      expect(echoRes.stdout.trim()).toBe('aegis-ready:strict-defensive');
      expect(echoRes.durationMs).toBeGreaterThanOrEqual(0);

      const nonZeroRes = await session.executeCommand('echo "check failed" >&2; exit 4');
      expect(nonZeroRes.exitCode).toBe(4);
      expect(nonZeroRes.stderr.trim()).toBe('check failed');

      const pyPass = await session.runPythonVerification(
        [
          'import os, sys',
          'print("VERIFY_OK:" + os.environ.get("CHECK_MODE", "none"))',
          'sys.exit(0)',
        ].join('\n'),
        { CHECK_MODE: 'passive' },
      );
      expect(pyPass.passed).toBe(true);
      expect(pyPass.exitCode).toBe(0);
      expect(pyPass.stdout.trim()).toBe('VERIFY_OK:passive');

      const pyFail = await session.runPythonVerification(
        ['import sys', 'sys.stderr.write("POSTURE_DRIFT\\n")', 'sys.exit(1)'].join('\n'),
      );
      expect(pyFail.passed).toBe(false);
      expect(pyFail.exitCode).toBe(1);
      expect(pyFail.stderr.trim()).toBe('POSTURE_DRIFT');

      expect(session.getTelemetry().commandsUsed).toBe(4);
    } finally {
      await session.close();
    }

    // Verify isolated temp workspace directory was removed on close
    await expect(fsp.access(workspaceDir)).rejects.toThrow();
  });

  it('writes and reads workspace files while blocking path traversal escapes', async () => {
    const provider = new LocalSandboxProvider();
    const session = await provider.createSession();

    try {
      await session.writeFile('nested/posture.json', '{"tls":true}');
      const content = await session.readFile('nested/posture.json');
      expect(content).toBe('{"tls":true}');

      await expect(session.writeFile('../escape.txt', 'forbidden')).rejects.toThrow(/escapes/i);
      await expect(session.readFile('../../etc/passwd')).rejects.toThrow(/escapes/i);
      await expect(session.readFile('/etc/hosts')).rejects.toThrow(/escapes/i);
    } finally {
      await session.close();
    }
  });

  it('terminates timed-out local commands cleanly without hanging', async () => {
    const provider = new LocalSandboxProvider();
    const session = await provider.createSession();

    try {
      const start = Date.now();
      const res = await session.executeCommand('echo "starting"; sleep 10', { timeoutMs: 120 });
      const elapsed = Date.now() - start;

      expect(res.exitCode).toBe(124);
      expect(res.stdout).toContain('starting');
      expect(elapsed).toBeLessThan(2_000);
    } finally {
      await session.close();
    }
  });

  it('enforces maxCommands budget, revokes session, and fires onRevoked("BUDGET_EXCEEDED")', async () => {
    const provider = new LocalSandboxProvider();
    const onRevoked = vi.fn<(reason: SandboxRevokeReason, sessionId: string) => void>();

    const session = await provider.createSession({
      maxCommands: 3,
      onRevoked,
    });

    try {
      await session.executeCommand('echo 1');
      await session.executeCommand('echo 2');
      await session.executeCommand('echo 3');

      expect(session.getTelemetry().commandsUsed).toBe(3);
      expect(session.getTelemetry().revoked).toBe(false);

      await expect(session.executeCommand('echo 4')).rejects.toBeInstanceOf(
        SandboxBudgetExceededError,
      );

      const telemetry = session.getTelemetry();
      expect(telemetry.revoked).toBe(true);
      expect(telemetry.revokeReason).toBe('BUDGET_EXCEEDED');
      expect(telemetry.commandsUsed).toBe(3);

      expect(onRevoked).toHaveBeenCalledTimes(1);
      expect(onRevoked).toHaveBeenCalledWith('BUDGET_EXCEEDED', session.sessionId);

      // Subsequent calls throw SandboxRevokedError
      await expect(session.executeCommand('echo 5')).rejects.toBeInstanceOf(SandboxRevokedError);
    } finally {
      await session.close();
    }

    // Idempotent close must not invoke onRevoked a second time
    expect(onRevoked).toHaveBeenCalledTimes(1);
  });

  it('enforces Dead-Man\'s Switch when heartbeat is missed', async () => {
    const provider = new LocalSandboxProvider();
    const onRevoked = vi.fn<(reason: SandboxRevokeReason, sessionId: string) => void>();

    const session = await provider.createSession({
      heartbeatTimeoutMs: 120,
      ttlMs: 10_000,
      onRevoked,
    });

    try {
      await sleep(220);

      const telemetry = session.getTelemetry();
      expect(telemetry.revoked).toBe(true);
      expect(telemetry.revokeReason).toBe('HEARTBEAT_MISSED');
      expect(onRevoked).toHaveBeenCalledTimes(1);
      expect(onRevoked).toHaveBeenCalledWith('HEARTBEAT_MISSED', session.sessionId);

      await expect(session.executeCommand('echo late')).rejects.toBeInstanceOf(SandboxRevokedError);
    } finally {
      await session.close();
    }
  });

  it('keeps session alive when worker sends periodic heartbeats and enforces hard TTL', async () => {
    const provider = new LocalSandboxProvider();
    const onRevoked = vi.fn<(reason: SandboxRevokeReason, sessionId: string) => void>();

    const session = await provider.createSession({
      heartbeatTimeoutMs: 140,
      ttlMs: 360,
      onRevoked,
    });

    try {
      for (let i = 0; i < 3; i += 1) {
        await sleep(70);
        session.heartbeat();
      }

      // 210ms > 140ms heartbeatTimeoutMs, yet session is still active because of heartbeats
      expect(session.getTelemetry().revoked).toBe(false);

      // Wait past hard ttlMs (360ms) while continuing to heartbeat
      for (let i = 0; i < 4; i += 1) {
        await sleep(60);
        session.heartbeat();
      }

      expect(session.getTelemetry().revoked).toBe(true);
      expect(session.getTelemetry().revokeReason).toBe('TTL_EXPIRED');
      expect(onRevoked).toHaveBeenCalledWith('TTL_EXPIRED', session.sessionId);
    } finally {
      await session.close();
    }
  });

  it('selects appropriate provider via createDefaultSandboxProvider', async () => {
    const localForced = createDefaultSandboxProvider({ preferE2B: false });
    expect(localForced.providerType).toBe('local');

    const e2bSelected = createDefaultSandboxProvider({
      preferE2B: true,
      e2bApiKey: 'synthetic-non-secret-token',
    });
    expect(e2bSelected.providerType).toBe('e2b');

    const savedKey = process.env.E2B_API_KEY;
    try {
      delete process.env.E2B_API_KEY;
      const fallbackLocal = createDefaultSandboxProvider();
      expect(fallbackLocal.providerType).toBe('local');

      const missingKeyProvider = new E2BSandboxProvider();
      await expect(missingKeyProvider.createSession()).rejects.toThrow(/Missing E2B API key/i);
    } finally {
      if (savedKey !== undefined) {
        process.env.E2B_API_KEY = savedKey;
      }
    }
  });
});

describe('E2BSandboxProvider Live Cloud Integration', () => {
  it(
    'provisions a real E2B cloud sandbox, verifies Linux posture via Python, handles files & non-zero exits, and closes cleanly',
    async () => {
      expect(Boolean(process.env.E2B_API_KEY?.trim())).toBe(true);

      const provider = new E2BSandboxProvider();
      expect(provider.providerType).toBe('e2b');

      const session = await provider.createSession({
        maxCommands: 10,
        ttlMs: 120_000,
        heartbeatTimeoutMs: 60_000,
      });

      try {
        expect(session.providerType).toBe('e2b');
        expect(session.getTelemetry().providerType).toBe('e2b');
        expect(session.sessionId.length).toBeGreaterThan(0);

        // 1. Verify Linux kernel inside real E2B cloud microVM
        const unameRes = await session.executeCommand('uname -s');
        expect(unameRes.exitCode).toBe(0);
        expect(unameRes.stdout.trim()).toBe('Linux');

        // 2. Verify non-zero exit code returns CommandResult cleanly instead of throwing CommandExitError
        const nonZeroRes = await session.executeCommand('sh -c "echo e2b-stderr >&2; exit 2"');
        expect(nonZeroRes.exitCode).toBe(2);
        expect(nonZeroRes.stderr.trim()).toBe('e2b-stderr');

        // 3. Write and read workspace security posture fixture
        const postureFixture = {
          service: 'aegis-gateway',
          tls: { minVersion: '1.3', enforceHttps: true },
          auth: { allowAnonymous: false, mfaRequired: true },
          cors: { allowOrigins: ['https://console.opencyber.internal'] },
        };
        const serializedFixture = JSON.stringify(postureFixture, null, 2);
        await session.writeFile('posture_target.json', serializedFixture);

        const readBack = await session.readFile('posture_target.json');
        expect(JSON.parse(readBack)).toEqual(postureFixture);

        // 4. Run passive Python JSON posture verification inside E2B sandbox
        const postureVerifyScript = [
          'import json, pathlib, sys',
          `cfg_path = pathlib.Path(${JSON.stringify(path.posix.join(session.workspaceDir, 'posture_target.json'))})`,
          'data = json.loads(cfg_path.read_text(encoding="utf-8"))',
          'checks = {',
          '    "tls_1_3": data.get("tls", {}).get("minVersion") == "1.3" and data.get("tls", {}).get("enforceHttps") is True,',
          '    "no_anon": data.get("auth", {}).get("allowAnonymous") is False,',
          '    "no_wildcard_cors": "*" not in data.get("cors", {}).get("allowOrigins", []),',
          '}',
          'passed = all(checks.values())',
          'print(json.dumps({"passed": passed, "checks": checks}))',
          'sys.exit(0 if passed else 1)',
        ].join('\n');

        const verifyRes = await session.runPythonVerification(postureVerifyScript);
        expect(verifyRes.passed).toBe(true);
        expect(verifyRes.exitCode).toBe(0);

        const parsedReport = JSON.parse(verifyRes.stdout.trim()) as {
          passed: boolean;
          checks: Record<string, boolean>;
        };
        expect(parsedReport.passed).toBe(true);
        expect(parsedReport.checks).toEqual({
          tls_1_3: true,
          no_anon: true,
          no_wildcard_cors: true,
        });
      } finally {
        await session.close();
      }

      const finalTelemetry = session.getTelemetry();
      expect(finalTelemetry.revoked).toBe(true);
      expect(finalTelemetry.revokeReason).toBe('MANUAL_CLOSE');
    },
    90_000,
  );
});
