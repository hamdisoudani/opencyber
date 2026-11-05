import type { ManagedSandboxSession } from './managed-session.js';

export type SandboxProviderType = 'e2b' | 'local';

export type SandboxRevokeReason =
  | 'BUDGET_EXCEEDED'
  | 'TTL_EXPIRED'
  | 'HEARTBEAT_MISSED'
  | 'MANUAL_CLOSE';

export interface CommandResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  durationMs: number;
}

export interface CommandExecOptions {
  cwd?: string;
  env?: Record<string, string>;
  timeoutMs?: number;
}

export interface SandboxBudgetConfig {
  maxCommands?: number;       // default 15
  ttlMs?: number;             // default 300_000 (5 min)
  heartbeatTimeoutMs?: number;// default 60_000
  onRevoked?: (
    reason: 'BUDGET_EXCEEDED' | 'TTL_EXPIRED' | 'HEARTBEAT_MISSED' | 'MANUAL_CLOSE',
    sessionId: string,
  ) => void | Promise<void>;
}

export interface SandboxTelemetry {
  sessionId: string;
  providerType: 'e2b' | 'local';
  commandsUsed: number;
  maxCommands: number;
  startedAtMs: number;
  lastHeartbeatMs: number;
  revoked: boolean;
  revokeReason?: string;
}

export interface RawSandboxHandle {
  readonly sessionId: string;
  readonly providerType: 'e2b' | 'local';
  readonly workspaceDir: string;
  exec(cmd: string, opts?: CommandExecOptions): Promise<CommandResult>;
  writeFile(filePath: string, content: string): Promise<void>;
  readFile(filePath: string): Promise<string>;
  destroy(): Promise<void>;
}

export interface SandboxProvider {
  readonly providerType: 'e2b' | 'local';
  createSession(budget?: SandboxBudgetConfig): Promise<ManagedSandboxSession>;
}

export interface PythonVerificationResult {
  passed: boolean;
  exitCode: number;
  stdout: string;
  stderr: string;
}

export class SandboxBudgetExceededError extends Error {
  public readonly sessionId: string;
  public readonly maxCommands: number;
  public readonly commandsUsed: number;

  constructor(sessionId: string, maxCommands: number, commandsUsed: number) {
    super(
      `Sandbox session "${sessionId}" exceeded command budget (${commandsUsed}/${maxCommands} commands used).`,
    );
    this.name = 'SandboxBudgetExceededError';
    this.sessionId = sessionId;
    this.maxCommands = maxCommands;
    this.commandsUsed = commandsUsed;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class SandboxRevokedError extends Error {
  public readonly sessionId: string;
  public readonly reason: string;

  constructor(sessionId: string, reason: string) {
    super(`Sandbox session "${sessionId}" has been revoked (reason: ${reason}).`);
    this.name = 'SandboxRevokedError';
    this.sessionId = sessionId;
    this.reason = reason;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}
