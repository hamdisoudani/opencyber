import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { CommandExitError, Sandbox } from 'e2b';
import { ManagedSandboxSession } from './managed-session.js';
import type {
  CommandExecOptions,
  CommandResult,
  RawSandboxHandle,
  SandboxBudgetConfig,
  SandboxProvider,
} from './types.js';

export interface E2BSandboxProviderOptions {
  apiKey?: string;
  defaultWorkspaceDir?: string;
}

function resolveSafePosixPath(workspaceDir: string, targetPath: string): string {
  const root = path.posix.resolve(workspaceDir);
  const resolved = path.posix.isAbsolute(targetPath)
    ? path.posix.resolve(targetPath)
    : path.posix.resolve(root, targetPath);

  if (resolved !== root && !resolved.startsWith(`${root}/`)) {
    throw new Error(`Path "${targetPath}" escapes E2B workspace "${workspaceDir}".`);
  }

  return resolved;
}

export class E2BSandboxProvider implements SandboxProvider {
  public readonly providerType = 'e2b' as const;

  private readonly configuredApiKey?: string;
  private readonly defaultWorkspaceDir: string;

  constructor(opts?: E2BSandboxProviderOptions) {
    this.configuredApiKey = opts?.apiKey;
    this.defaultWorkspaceDir = opts?.defaultWorkspaceDir ?? '/tmp/aegis-work';
  }

  public async createSession(budget?: SandboxBudgetConfig): Promise<ManagedSandboxSession> {
    const apiKey = (this.configuredApiKey ?? process.env.E2B_API_KEY)?.trim();
    if (!apiKey) {
      throw new Error(
        'Missing E2B API key: provide `apiKey` to E2BSandboxProvider or set `process.env.E2B_API_KEY`.',
      );
    }

    const proxy =
      process.env.HTTPS_PROXY ||
      process.env.HTTP_PROXY ||
      process.env.https_proxy ||
      process.env.http_proxy ||
      undefined;

    const timeoutMs = Math.max(budget?.ttlMs ?? 120_000, 30_000);
    const workspaceDir = path.posix.resolve(this.defaultWorkspaceDir);

    const sbx = await Sandbox.create({
      apiKey,
      timeoutMs,
      ...(proxy ? { proxy } : {}),
    });

    try {
      await sbx.commands.run(`mkdir -p ${JSON.stringify(workspaceDir)}`);
    } catch (err) {
      await sbx.kill().catch(() => undefined);
      throw err;
    }

    let destroyed = false;

    const handle: RawSandboxHandle = {
      sessionId: sbx.sandboxId,
      providerType: 'e2b',
      workspaceDir,

      exec: async (cmd: string, opts?: CommandExecOptions): Promise<CommandResult> => {
        const startMs = performance.now();
        const cwd = opts?.cwd ? resolveSafePosixPath(workspaceDir, opts.cwd) : workspaceDir;

        try {
          const res = await sbx.commands.run(cmd, {
            cwd,
            ...(opts?.env ? { envs: opts.env } : {}),
            ...(opts?.timeoutMs !== undefined ? { timeoutMs: opts.timeoutMs } : {}),
          });

          return {
            exitCode: res.exitCode,
            stdout: res.stdout ?? '',
            stderr: res.stderr ?? '',
            durationMs: Math.max(0, Math.round(performance.now() - startMs)),
          };
        } catch (err: unknown) {
          const durationMs = Math.max(0, Math.round(performance.now() - startMs));

          if (err instanceof CommandExitError) {
            return {
              exitCode: err.exitCode,
              stdout: err.stdout ?? '',
              stderr: err.stderr ?? '',
              durationMs,
            };
          }

          const candidate = err as {
            exitCode?: unknown;
            stdout?: unknown;
            stderr?: unknown;
            result?: {
              exitCode?: unknown;
              stdout?: unknown;
              stderr?: unknown;
            };
          };

          if (candidate?.result && typeof candidate.result.exitCode === 'number') {
            return {
              exitCode: candidate.result.exitCode,
              stdout: typeof candidate.result.stdout === 'string' ? candidate.result.stdout : '',
              stderr: typeof candidate.result.stderr === 'string' ? candidate.result.stderr : '',
              durationMs,
            };
          }

          if (typeof candidate?.exitCode === 'number') {
            return {
              exitCode: candidate.exitCode,
              stdout: typeof candidate.stdout === 'string' ? candidate.stdout : '',
              stderr: typeof candidate.stderr === 'string' ? candidate.stderr : '',
              durationMs,
            };
          }

          throw err;
        }
      },

      writeFile: async (filePath: string, content: string): Promise<void> => {
        const resolved = resolveSafePosixPath(workspaceDir, filePath);
        await sbx.files.write(resolved, content);
      },

      readFile: async (filePath: string): Promise<string> => {
        const resolved = resolveSafePosixPath(workspaceDir, filePath);
        return await sbx.files.read(resolved);
      },

      destroy: async (): Promise<void> => {
        if (destroyed) {
          return;
        }
        destroyed = true;
        await sbx.kill();
      },
    };

    return new ManagedSandboxSession(handle, budget);
  }
}
