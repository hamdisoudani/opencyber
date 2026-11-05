import path from 'node:path';
import {
  type CommandExecOptions,
  type CommandResult,
  type PythonVerificationResult,
  type RawSandboxHandle,
  type SandboxBudgetConfig,
  SandboxBudgetExceededError,
  type SandboxRevokeReason,
  SandboxRevokedError,
  type SandboxTelemetry,
} from './types.js';

const DEFAULT_MAX_COMMANDS = 15;
const DEFAULT_TTL_MS = 300_000;
const DEFAULT_HEARTBEAT_TIMEOUT_MS = 60_000;

export class ManagedSandboxSession {
  private readonly handle: RawSandboxHandle;
  private readonly maxCommands: number;
  private readonly ttlMs: number;
  private readonly heartbeatTimeoutMs: number;
  private readonly onRevoked?: SandboxBudgetConfig['onRevoked'];
  private readonly startedAtMs: number;

  private lastHeartbeatMs: number;
  private commandsUsed = 0;
  private revoked = false;
  private revokeReason?: SandboxRevokeReason;
  private ttlTimer?: ReturnType<typeof setTimeout>;
  private heartbeatTimer?: ReturnType<typeof setTimeout>;
  private revokePromise: Promise<void> | null = null;

  constructor(handle: RawSandboxHandle, budget?: SandboxBudgetConfig) {
    this.handle = handle;
    this.maxCommands = budget?.maxCommands ?? DEFAULT_MAX_COMMANDS;
    this.ttlMs = budget?.ttlMs ?? DEFAULT_TTL_MS;
    this.heartbeatTimeoutMs = budget?.heartbeatTimeoutMs ?? DEFAULT_HEARTBEAT_TIMEOUT_MS;
    this.onRevoked = budget?.onRevoked;

    const now = Date.now();
    this.startedAtMs = now;
    this.lastHeartbeatMs = now;

    this.startTtlTimer();
    this.resetHeartbeatTimer();
  }

  public get sessionId(): string {
    return this.handle.sessionId;
  }

  public get providerType(): 'e2b' | 'local' {
    return this.handle.providerType;
  }

  public get workspaceDir(): string {
    return this.handle.workspaceDir;
  }

  public get isRevoked(): boolean {
    return this.revoked;
  }

  public heartbeat(): void {
    if (this.revoked) {
      return;
    }
    this.lastHeartbeatMs = Date.now();
    this.resetHeartbeatTimer();
  }

  public async executeCommand(cmd: string, opts?: CommandExecOptions): Promise<CommandResult> {
    this.assertNotRevoked();

    if (this.commandsUsed >= this.maxCommands) {
      await this.revoke('BUDGET_EXCEEDED');
      throw new SandboxBudgetExceededError(this.sessionId, this.maxCommands, this.commandsUsed);
    }

    this.commandsUsed += 1;
    this.heartbeat();

    const effectiveOpts: CommandExecOptions = {
      cwd: opts?.cwd ?? this.handle.workspaceDir,
      ...(opts?.env ? { env: opts.env } : {}),
      ...(opts?.timeoutMs !== undefined ? { timeoutMs: opts.timeoutMs } : {}),
    };

    const result = await this.handle.exec(cmd, effectiveOpts);
    if (!this.revoked) {
      this.heartbeat();
    }
    return result;
  }

  public async writeFile(relativeOrAbsPath: string, content: string): Promise<void> {
    this.assertNotRevoked();
    const targetPath = this.resolveWorkspacePath(relativeOrAbsPath);
    this.heartbeat();
    await this.handle.writeFile(targetPath, content);
  }

  public async readFile(relativeOrAbsPath: string): Promise<string> {
    this.assertNotRevoked();
    const targetPath = this.resolveWorkspacePath(relativeOrAbsPath);
    this.heartbeat();
    return await this.handle.readFile(targetPath);
  }

  public async runPythonVerification(
    scriptContent: string,
    env?: Record<string, string>,
    timeoutMs: number = 15_000,
  ): Promise<PythonVerificationResult> {
    this.assertNotRevoked();

    if (this.commandsUsed >= this.maxCommands) {
      await this.revoke('BUDGET_EXCEEDED');
      throw new SandboxBudgetExceededError(this.sessionId, this.maxCommands, this.commandsUsed);
    }

    const normalizedWorkspace = this.handle.workspaceDir.replace(/\/+$/, '');
    const scriptPath = `${normalizedWorkspace}/verify_check.py`;
    await this.writeFile(scriptPath, scriptContent);

    const res = await this.executeCommand(`python3 ${scriptPath}`, {
      cwd: this.handle.workspaceDir,
      ...(env ? { env } : {}),
      timeoutMs,
    });

    return {
      passed: res.exitCode === 0,
      exitCode: res.exitCode,
      stdout: res.stdout,
      stderr: res.stderr,
    };
  }

  public getTelemetry(): SandboxTelemetry {
    return {
      sessionId: this.handle.sessionId,
      providerType: this.handle.providerType,
      commandsUsed: this.commandsUsed,
      maxCommands: this.maxCommands,
      startedAtMs: this.startedAtMs,
      lastHeartbeatMs: this.lastHeartbeatMs,
      revoked: this.revoked,
      ...(this.revokeReason !== undefined ? { revokeReason: this.revokeReason } : {}),
    };
  }

  public async revoke(reason: SandboxRevokeReason): Promise<void> {
    if (this.revokePromise) {
      return this.revokePromise;
    }

    this.revoked = true;
    this.revokeReason = reason;
    this.clearTimers();

    this.revokePromise = (async () => {
      try {
        await this.handle.destroy();
      } catch {
        // Ignore teardown errors on already-terminated sandboxes so revocation remains idempotent.
      } finally {
        if (this.onRevoked) {
          await this.onRevoked(reason, this.handle.sessionId);
        }
      }
    })();

    return this.revokePromise;
  }

  public async close(): Promise<void> {
    return this.revoke('MANUAL_CLOSE');
  }

  private assertNotRevoked(): void {
    if (this.revoked) {
      throw new SandboxRevokedError(this.sessionId, this.revokeReason ?? 'MANUAL_CLOSE');
    }
  }

  private resolveWorkspacePath(relativeOrAbsPath: string): string {
    const pathMod = this.handle.providerType === 'e2b' ? path.posix : path;
    const root = pathMod.resolve(this.handle.workspaceDir);
    const resolved = pathMod.isAbsolute(relativeOrAbsPath)
      ? pathMod.resolve(relativeOrAbsPath)
      : pathMod.resolve(root, relativeOrAbsPath);

    if (resolved !== root && !resolved.startsWith(root + pathMod.sep)) {
      throw new Error(
        `Path "${relativeOrAbsPath}" escapes sandbox workspace "${this.handle.workspaceDir}".`,
      );
    }

    return resolved;
  }

  private startTtlTimer(): void {
    if (this.ttlMs > 0 && Number.isFinite(this.ttlMs)) {
      this.ttlTimer = setTimeout(() => {
        void this.revoke('TTL_EXPIRED');
      }, this.ttlMs);
      this.ttlTimer.unref();
    }
  }

  private resetHeartbeatTimer(): void {
    if (this.heartbeatTimer) {
      clearTimeout(this.heartbeatTimer);
      this.heartbeatTimer = undefined;
    }
    if (!this.revoked && this.heartbeatTimeoutMs > 0 && Number.isFinite(this.heartbeatTimeoutMs)) {
      this.heartbeatTimer = setTimeout(() => {
        void this.revoke('HEARTBEAT_MISSED');
      }, this.heartbeatTimeoutMs);
      this.heartbeatTimer.unref();
    }
  }

  private clearTimers(): void {
    if (this.ttlTimer) {
      clearTimeout(this.ttlTimer);
      this.ttlTimer = undefined;
    }
    if (this.heartbeatTimer) {
      clearTimeout(this.heartbeatTimer);
      this.heartbeatTimer = undefined;
    }
  }
}
