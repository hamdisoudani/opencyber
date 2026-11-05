import { z } from 'zod';
import {
  AegisGroqClient,
  type CompleteJsonOptions,
  type LlmProviderName,
  type StreamTextOptions,
  type StructuredLlmClient,
} from './groq-client.js';
import { AegisOpenRouterClient } from './openrouter-client.js';

export interface AegisModelRouterOptions {
  openRouterApiKey?: string;
  openRouterBaseUrl?: string;
  groqApiKey?: string;
  orchestratorProvider?: LlmProviderName;
  subagentProvider?: LlmProviderName;
  orchestratorModel?: string;
  openRouterOrchestratorModel?: string;
  groqOrchestratorModel?: string;
  subagentModel?: string;
  promptGuardModel?: string;
  enableFallback?: boolean;
  openRouterClient?: StructuredLlmClient;
  groqClient?: StructuredLlmClient;
}

function resolveOrchestratorProvider(
  opts: AegisModelRouterOptions | undefined,
  hasOpenRouter: boolean,
  hasGroq: boolean,
): LlmProviderName {
  if (opts?.orchestratorProvider === 'openrouter' || opts?.orchestratorProvider === 'groq') {
    return opts.orchestratorProvider;
  }

  const envPref = process.env.AEGIS_ORCHESTRATOR_PROVIDER?.trim().toLowerCase();
  if (envPref === 'openrouter' && (hasOpenRouter || !hasGroq)) {
    return 'openrouter';
  }
  if (envPref === 'groq' && (hasGroq || !hasOpenRouter)) {
    return 'groq';
  }

  if (hasOpenRouter) {
    return 'openrouter';
  }
  return 'groq';
}

function resolveSubagentProvider(
  opts: AegisModelRouterOptions | undefined,
  hasOpenRouter: boolean,
  hasGroq: boolean,
): LlmProviderName {
  if (opts?.subagentProvider === 'openrouter' || opts?.subagentProvider === 'groq') {
    return opts.subagentProvider;
  }

  if (hasGroq) {
    return 'groq';
  }
  if (hasOpenRouter) {
    return 'openrouter';
  }
  return 'groq';
}

export class AegisModelRouter implements StructuredLlmClient {
  public readonly orchestratorProvider: LlmProviderName;
  public readonly subagentProvider: LlmProviderName;
  public readonly orchestratorModel: string;
  public readonly subagentModel: string;
  public readonly promptGuardModel: string;
  public readonly isConfigured: boolean;
  public readonly enableFallback: boolean;

  private readonly configuredOpenRouterApiKey?: string;
  private readonly configuredGroqApiKey?: string;
  private readonly customOpenRouterClientProvided: boolean;
  private readonly customGroqClientProvided: boolean;
  private readonly openRouterClient: StructuredLlmClient;
  private readonly groqClient: StructuredLlmClient;

  constructor(opts?: AegisModelRouterOptions) {
    this.configuredOpenRouterApiKey = opts?.openRouterApiKey;
    this.configuredGroqApiKey = opts?.groqApiKey;
    this.customOpenRouterClientProvided = Boolean(opts?.openRouterClient);
    this.customGroqClientProvided = Boolean(opts?.groqClient);
    this.enableFallback = opts?.enableFallback ?? true;

    const hasOpenRouter = this.hasProviderAvailable('openrouter');
    const hasGroq = this.hasProviderAvailable('groq');
    this.isConfigured = hasOpenRouter || hasGroq;

    this.orchestratorProvider = resolveOrchestratorProvider(opts, hasOpenRouter, hasGroq);
    this.subagentProvider = resolveSubagentProvider(opts, hasOpenRouter, hasGroq);

    const openRouterOrchModel =
      opts?.openRouterOrchestratorModel ??
      (this.orchestratorProvider === 'openrouter' ? opts?.orchestratorModel : undefined);
    const openRouterSubModel =
      this.subagentProvider === 'openrouter' ? opts?.subagentModel : undefined;

    this.openRouterClient =
      opts?.openRouterClient ??
      new AegisOpenRouterClient({
        ...(opts?.openRouterApiKey !== undefined ? { apiKey: opts.openRouterApiKey } : {}),
        ...(opts?.openRouterBaseUrl !== undefined ? { baseUrl: opts.openRouterBaseUrl } : {}),
        ...(openRouterOrchModel !== undefined ? { orchestratorModel: openRouterOrchModel } : {}),
        ...(openRouterSubModel !== undefined ? { subagentModel: openRouterSubModel } : {}),
      });

    const groqOrchModel =
      opts?.groqOrchestratorModel ??
      (this.orchestratorProvider === 'groq' ? opts?.orchestratorModel : undefined);
    const groqSubModel =
      this.subagentProvider === 'groq' ? opts?.subagentModel : undefined;

    this.groqClient =
      opts?.groqClient ??
      new AegisGroqClient({
        ...(opts?.groqApiKey !== undefined ? { apiKey: opts.groqApiKey } : {}),
        ...(groqOrchModel !== undefined ? { orchestratorModel: groqOrchModel } : {}),
        ...(groqSubModel !== undefined ? { subagentModel: groqSubModel } : {}),
        ...(opts?.promptGuardModel !== undefined
          ? { promptGuardModel: opts.promptGuardModel }
          : {}),
      });

    this.orchestratorModel =
      this.orchestratorProvider === 'openrouter'
        ? this.openRouterClient.orchestratorModel
        : this.groqClient.orchestratorModel;

    this.subagentModel =
      this.subagentProvider === 'openrouter'
        ? this.openRouterClient.subagentModel
        : this.groqClient.subagentModel;

    this.promptGuardModel =
      this.groqClient.promptGuardModel ?? 'meta-llama/llama-prompt-guard-2-86m';
  }

  private hasProviderAvailable(provider: LlmProviderName): boolean {
    if (provider === 'openrouter') {
      if (this.customOpenRouterClientProvided && this.configuredOpenRouterApiKey !== '') {
        return true;
      }
      return Boolean(
        (this.configuredOpenRouterApiKey ?? process.env.OPENROUTER_API_KEY)?.trim(),
      );
    }

    if (this.customGroqClientProvided && this.configuredGroqApiKey !== '') {
      return true;
    }
    return Boolean((this.configuredGroqApiKey ?? process.env.GROQ_API_KEY)?.trim());
  }

  public async completeJson<T>(opts: CompleteJsonOptions<T>): Promise<T> {
    const primaryProvider: LlmProviderName =
      opts.tier === 'ORCHESTRATOR' ? this.orchestratorProvider : this.subagentProvider;
    const secondaryProvider: LlmProviderName =
      primaryProvider === 'openrouter' ? 'groq' : 'openrouter';

    const primaryClient =
      primaryProvider === 'openrouter' ? this.openRouterClient : this.groqClient;
    const secondaryClient =
      secondaryProvider === 'openrouter' ? this.openRouterClient : this.groqClient;

    try {
      return await primaryClient.completeJson(opts);
    } catch (primaryError) {
      if (this.enableFallback && this.hasProviderAvailable(secondaryProvider)) {
        return await secondaryClient.completeJson(opts);
      }
      throw primaryError;
    }
  }

  public async streamText(opts: StreamTextOptions): Promise<string> {
    const primaryProvider: LlmProviderName =
      opts.tier === 'ORCHESTRATOR' ? this.orchestratorProvider : this.subagentProvider;
    const secondaryProvider: LlmProviderName =
      primaryProvider === 'openrouter' ? 'groq' : 'openrouter';

    const primaryClient =
      primaryProvider === 'openrouter' ? this.openRouterClient : this.groqClient;
    const secondaryClient =
      secondaryProvider === 'openrouter' ? this.openRouterClient : this.groqClient;

    let emittedAnyDelta = false;
    const wrappedOnDelta = async (delta: string): Promise<void> => {
      if (delta.length > 0) {
        emittedAnyDelta = true;
      }
      if (opts.onDelta) {
        await opts.onDelta(delta);
      }
    };

    const executeClientStream = async (
      client: StructuredLlmClient,
      onDeltaCb: ((delta: string) => void | Promise<void>) | undefined,
    ): Promise<string> => {
      if (client.streamText) {
        return client.streamText({
          ...opts,
          ...(onDeltaCb !== undefined ? { onDelta: onDeltaCb } : {}),
        });
      }

      const ReplyFallbackSchema = z.object({ reply: z.string() });
      const transcript = opts.messages
        .map((m) => `${m.role.toUpperCase()}: ${m.content}`)
        .join('\n\n');
      const fallbackRes = await client.completeJson({
        tier: opts.tier,
        systemPrompt: `${opts.systemPrompt}\nRespond with a JSON object {"reply": "<markdown response>"}.`,
        userPrompt: transcript || 'Respond to the user.',
        schema: ReplyFallbackSchema,
        ...(opts.temperature !== undefined ? { temperature: opts.temperature } : {}),
      });
      if (fallbackRes.reply.length > 0 && onDeltaCb) {
        await onDeltaCb(fallbackRes.reply);
      }
      return fallbackRes.reply;
    };

    try {
      return await executeClientStream(primaryClient, wrappedOnDelta);
    } catch (primaryError) {
      if (
        !emittedAnyDelta &&
        this.enableFallback &&
        this.hasProviderAvailable(secondaryProvider) &&
        secondaryClient.streamText
      ) {
        return await secondaryClient.streamText(opts);
      }
      throw primaryError;
    }
  }

  public async scorePromptInjection(chunk: string): Promise<number> {
    if (this.hasProviderAvailable('groq') && this.groqClient.scorePromptInjection) {
      return this.groqClient.scorePromptInjection(chunk);
    }
    return 0;
  }
}
