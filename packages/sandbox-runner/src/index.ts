import { E2BSandboxProvider } from './e2b-provider.js';
import { LocalSandboxProvider } from './local-provider.js';
import type { SandboxProvider } from './types.js';

export {
  type CommandExecOptions,
  type CommandResult,
  type PythonVerificationResult,
  type RawSandboxHandle,
  type SandboxBudgetConfig,
  SandboxBudgetExceededError,
  type SandboxProvider,
  type SandboxProviderType,
  type SandboxRevokeReason,
  SandboxRevokedError,
  type SandboxTelemetry,
} from './types.js';

export { ManagedSandboxSession } from './managed-session.js';
export { E2BSandboxProvider, type E2BSandboxProviderOptions } from './e2b-provider.js';
export { LocalSandboxProvider } from './local-provider.js';

export interface CreateDefaultSandboxProviderOptions {
  preferE2B?: boolean;
  e2bApiKey?: string;
}

export function createDefaultSandboxProvider(
  opts?: CreateDefaultSandboxProviderOptions,
): SandboxProvider {
  const apiKey = (opts?.e2bApiKey ?? process.env.E2B_API_KEY)?.trim();
  if (opts?.preferE2B !== false && apiKey) {
    return new E2BSandboxProvider({ apiKey });
  }
  return new LocalSandboxProvider();
}
