import { execFile } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { ManagedSandboxSession } from './managed-session.js';
import type {
  CommandExecOptions,
  CommandResult,
  RawSandboxHandle,
  SandboxBudgetConfig,
  SandboxProvider,
} from './types.js';

async function resolveSafeLocalPath(workspaceDir: string, targetPath: string): Promise<string> {
  const root = path.resolve(workspaceDir);
  const resolved = path.isAbsolute(targetPath)
    ? path.resolve(targetPath)
    : path.resolve(root, targetPath);

  if (resolved !== root && !resolved.startsWith(`${root}${path.sep}`)) {
    throw new Error(`Path "${targetPath}" escapes local sandbox workspace "${workspaceDir}".`);
  }

  // Also verify nearest existing ancestor via realpath to block symlink escapes.
  let probe = resolved;
  while (true) {
    try {
      const realProbe = await fs.realpath(probe);
      if (realProbe !== root && !realProbe.startsWith(`${root}${path.sep}`)) {
        throw new Error(
          `Symlink path "${targetPath}" escapes local sandbox workspace "${workspaceDir}".`,
        );
      }
      break;
    } catch (err: unknown) {
      const code = (err as NodeJS.ErrnoException)?.code;
      if (code === 'ENOENT') {
        const parent = path.dirname(probe);
        if (parent === probe) {
          break;
        }
        probe = parent;
        continue;
      }
      throw err;
    }
  }

  return resolved;
}

export class LocalSandboxProvider implements SandboxProvider {
  public readonly providerType = 'local' as const;

  public async createSession(budget?: SandboxBudgetConfig): Promise<ManagedSandboxSession> {
    const rawTmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'aegis-sbx-'));
    const workspaceDir = await fs.realpath(rawTmpDir);
    const sessionId = `local-${crypto.randomUUID()}`;
    let destroyed = false;

    const handle: RawSandboxHandle = {
      sessionId,
      providerType: 'local',
      workspaceDir,

      exec: async (cmd: string, opts?: CommandExecOptions): Promise<CommandResult> => {
        const cwd = opts?.cwd ? await resolveSafeLocalPath(workspaceDir, opts.cwd) : workspaceDir;
        const env: NodeJS.ProcessEnv = opts?.env ? { ...process.env, ...opts.env } : process.env;
        const timeout = opts?.timeoutMs ?? 60_000;
        const startMs = performance.now();

        return await new Promise<CommandResult>((resolve, reject) => {
          let settled = false;
          let forceDrainTimer: ReturnType<typeof setTimeout> | undefined;

          const child = execFile(
            'bash',
            ['-lc', cmd],
            {
              cwd,
              env,
              timeout,
              killSignal: 'SIGKILL',
              maxBuffer: 10 * 1024 * 1024,
            },
            (error, stdout, stderr) => {
              if (settled) {
                return;
              }
              settled = true;
              if (forceDrainTimer) {
                clearTimeout(forceDrainTimer);
              }

              const durationMs = Math.max(0, Math.round(performance.now() - startMs));
              const outStr = typeof stdout === 'string' ? stdout : String(stdout ?? '');
              const errStr = typeof stderr === 'string' ? stderr : String(stderr ?? '');

              if (!error) {
                resolve({
                  exitCode: 0,
                  stdout: outStr,
                  stderr: errStr,
                  durationMs,
                });
                return;
              }

              const execErr = error as NodeJS.ErrnoException & {
                killed?: boolean;
                signal?: NodeJS.Signals | null;
              };

              if (typeof execErr.code === 'number') {
                resolve({
                  exitCode: execErr.code,
                  stdout: outStr,
                  stderr: errStr,
                  durationMs,
                });
                return;
              }

              if (execErr.killed || execErr.signal) {
                const suffix = `Command terminated due to timeout or signal (${execErr.signal ?? 'SIGKILL'}).`;
                resolve({
                  exitCode: 124,
                  stdout: outStr,
                  stderr: errStr ? `${errStr}\n${suffix}` : suffix,
                  durationMs,
                });
                return;
              }

              reject(error);
            },
          );

          if (timeout > 0 && Number.isFinite(timeout)) {
            forceDrainTimer = setTimeout(() => {
              if (!settled) {
                child.kill('SIGKILL');
                child.stdout?.destroy();
                child.stderr?.destroy();
              }
            }, timeout + 50);
            forceDrainTimer.unref();
          }
        });
      },

      writeFile: async (filePath: string, content: string): Promise<void> => {
        const resolved = await resolveSafeLocalPath(workspaceDir, filePath);
        await fs.mkdir(path.dirname(resolved), { recursive: true });
        await fs.writeFile(resolved, content, 'utf8');
      },

      readFile: async (filePath: string): Promise<string> => {
        const resolved = await resolveSafeLocalPath(workspaceDir, filePath);
        return await fs.readFile(resolved, 'utf8');
      },

      destroy: async (): Promise<void> => {
        if (destroyed) {
          return;
        }
        destroyed = true;
        await fs.rm(workspaceDir, { recursive: true, force: true });
      },
    };

    return new ManagedSandboxSession(handle, budget);
  }
}
