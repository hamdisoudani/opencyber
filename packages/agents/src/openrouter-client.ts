import {
  type CompleteJsonOptions,
  createThinkTagStreamFilter,
  type LlmProviderName,
  type StreamTextOptions,
  stripFencesAndReasoning,
  type StructuredLlmClient,
} from './groq-client.js';

export interface AegisOpenRouterClientOptions {
  apiKey?: string;
  baseUrl?: string;
  orchestratorModel?: string;
  subagentModel?: string;
  appReferer?: string;
  appTitle?: string;
}

interface OpenRouterErrorPayload {
  message?: string;
  code?: number | string;
  metadata?: Record<string, unknown>;
}

interface OpenRouterContentPart {
  type?: string;
  text?: string;
}

interface OpenRouterChatCompletionEnvelope {
  id?: string;
  error?: OpenRouterErrorPayload | string;
  choices?: Array<{
    message?: {
      role?: string;
      content?: string | OpenRouterContentPart[] | null;
      reasoning?: string | null;
    };
    error?: OpenRouterErrorPayload | string;
  }>;
}

interface OpenRouterStreamChunkEnvelope {
  id?: string;
  error?: OpenRouterErrorPayload | string;
  choices?: Array<{
    delta?: {
      role?: string;
      content?: string | OpenRouterContentPart[] | null;
      reasoning?: string | null;
    };
    error?: OpenRouterErrorPayload | string;
    finish_reason?: string | null;
  }>;
}

export class OpenRouterApiError extends Error {
  public readonly statusCode: number;
  public readonly providerCode?: number | string;

  constructor(message: string, statusCode: number, providerCode?: number | string) {
    super(message);
    this.name = 'OpenRouterApiError';
    this.statusCode = statusCode;
    this.providerCode = providerCode;
  }
}

function extractOpenRouterErrorInfo(
  errPayload: OpenRouterErrorPayload | string | undefined,
  fallbackText: string,
): { message: string; code?: number | string } {
  if (typeof errPayload === 'string' && errPayload.trim().length > 0) {
    return { message: errPayload.trim() };
  }
  if (typeof errPayload === 'object' && errPayload !== null) {
    const msg =
      typeof errPayload.message === 'string' && errPayload.message.trim().length > 0
        ? errPayload.message.trim()
        : fallbackText;
    return {
      message: msg,
      ...(errPayload.code !== undefined ? { code: errPayload.code } : {}),
    };
  }
  return { message: fallbackText };
}

export class AegisOpenRouterClient implements StructuredLlmClient {
  public readonly orchestratorProvider: LlmProviderName = 'openrouter';
  public readonly subagentProvider: LlmProviderName = 'openrouter';
  public readonly baseUrl: string;
  public readonly orchestratorModel: string;
  public readonly subagentModel: string;

  private readonly configuredApiKey?: string;
  private readonly appReferer: string;
  private readonly appTitle: string;

  constructor(opts?: AegisOpenRouterClientOptions) {
    this.configuredApiKey = opts?.apiKey;
    this.baseUrl = (
      opts?.baseUrl ??
      process.env.OPENROUTER_BASE_URL ??
      'https://openrouter.ai/api/v1'
    ).replace(/\/+$/, '');
    this.orchestratorModel =
      opts?.orchestratorModel ||
      process.env.OPENROUTER_ORCHESTRATOR_MODEL ||
      'stealth/crouton-alpha';
    this.subagentModel =
      opts?.subagentModel ||
      process.env.OPENROUTER_SUBAGENT_MODEL ||
      'stealth/crouton-alpha';
    this.appReferer = opts?.appReferer || 'https://github.com/hamdisoudani/opencyber';
    this.appTitle = opts?.appTitle || 'OpenCyber Aegis-GitOps';
  }

  private resolveApiKey(): string {
    const apiKey = (this.configuredApiKey ?? process.env.OPENROUTER_API_KEY)?.trim();
    if (!apiKey) {
      throw new Error(
        'Missing OpenRouter API key: provide `apiKey` to AegisOpenRouterClient or set `process.env.OPENROUTER_API_KEY`.',
      );
    }
    return apiKey;
  }

  public async completeJson<T>(opts: CompleteJsonOptions<T>): Promise<T> {
    const apiKey = this.resolveApiKey();
    const model =
      opts.tier === 'ORCHESTRATOR' ? this.orchestratorModel : this.subagentModel;
    const temperature = opts.temperature ?? 0.1;

    const systemPrompt =
      /json/i.test(opts.systemPrompt) || /json/i.test(opts.userPrompt)
        ? opts.systemPrompt
        : `${opts.systemPrompt}\nRespond strictly with a valid JSON object.`;

    let currentUserPrompt = opts.userPrompt;
    let lastFailureMessage = 'Unknown validation error';
    const endpointUrl = `${this.baseUrl}/chat/completions`;

    for (let attempt = 0; attempt < 2; attempt += 1) {
      const res = await fetch(endpointUrl, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${apiKey}`,
          'Content-Type': 'application/json',
          'HTTP-Referer': this.appReferer,
          'X-Title': this.appTitle,
        },
        body: JSON.stringify({
          model,
          temperature,
          response_format: { type: 'json_object' },
          messages: [
            { role: 'system', content: systemPrompt },
            { role: 'user', content: currentUserPrompt },
          ],
        }),
      });

      const rawBody = await res.text();
      const trimmedBody = rawBody.trim();

      let envelope: OpenRouterChatCompletionEnvelope | undefined;
      try {
        envelope = trimmedBody
          ? (JSON.parse(trimmedBody) as OpenRouterChatCompletionEnvelope)
          : undefined;
      } catch (envelopeErr) {
        if (!res.ok) {
          throw new OpenRouterApiError(
            `OpenRouter HTTP ${res.status}: ${trimmedBody.slice(0, 300) || res.statusText || 'Request failed'}`,
            res.status,
          );
        }
        throw new OpenRouterApiError(
          `OpenRouter returned malformed JSON envelope (HTTP ${res.status}): ${(envelopeErr as Error).message}`,
          res.status,
        );
      }

      const choiceError = envelope?.choices?.[0]?.error;
      if (!res.ok || envelope?.error || choiceError) {
        const fallbackMsg =
          trimmedBody.slice(0, 300) || res.statusText || 'Unknown OpenRouter API error';
        const info = extractOpenRouterErrorInfo(envelope?.error ?? choiceError, fallbackMsg);
        const effectiveStatus = !res.ok
          ? res.status
          : typeof info.code === 'number'
            ? info.code
            : 502;
        throw new OpenRouterApiError(
          `OpenRouter API error (${effectiveStatus}): ${info.message}`,
          effectiveStatus,
          info.code,
        );
      }

      const messageContent = envelope?.choices?.[0]?.message?.content;
      const rawContent =
        typeof messageContent === 'string'
          ? messageContent
          : Array.isArray(messageContent)
            ? messageContent
                .map((part) => (typeof part?.text === 'string' ? part.text : ''))
                .join('')
            : '';

      const cleanedJson = stripFencesAndReasoning(rawContent);

      let parsedObj: unknown;
      try {
        parsedObj = JSON.parse(cleanedJson);
      } catch (parseErr) {
        lastFailureMessage = `Invalid JSON syntax: ${(parseErr as Error).message}`;
        currentUserPrompt = `${opts.userPrompt}\n\nYour previous response failed JSON parsing (${lastFailureMessage}). Return ONLY a valid JSON object matching all required fields.`;
        continue;
      }

      const validated = opts.schema.safeParse(parsedObj);
      if (validated.success) {
        return validated.data;
      }

      const issueSummary = validated.error.issues
        .map((issue) => `${issue.path.map(String).join('.') || '<root>'}: ${issue.message}`)
        .join('; ');
      lastFailureMessage = `Schema validation failed: ${issueSummary}`;
      currentUserPrompt = `${opts.userPrompt}\n\nYour previous JSON object failed schema validation (${issueSummary}). Fix those fields and return ONLY the corrected JSON object.`;
    }

    throw new Error(`AegisOpenRouterClient.completeJson failed after retry (${lastFailureMessage})`);
  }

  public async streamText(opts: StreamTextOptions): Promise<string> {
    const apiKey = this.resolveApiKey();
    const model =
      opts.tier === 'ORCHESTRATOR' ? this.orchestratorModel : this.subagentModel;
    const temperature = opts.temperature ?? 0.2;
    const endpointUrl = `${this.baseUrl}/chat/completions`;

    const res = await fetch(endpointUrl, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
        Accept: 'text/event-stream',
        'HTTP-Referer': this.appReferer,
        'X-Title': this.appTitle,
      },
      body: JSON.stringify({
        model,
        temperature,
        stream: true,
        messages: [
          { role: 'system', content: opts.systemPrompt },
          ...opts.messages.map((m) => ({ role: m.role, content: m.content })),
        ],
      }),
    });

    if (!res.ok || !res.body) {
      const rawErr = await res.text().catch(() => '');
      const trimmedErr = rawErr.trim();
      let parsedErr: OpenRouterChatCompletionEnvelope | undefined;
      try {
        parsedErr = trimmedErr
          ? (JSON.parse(trimmedErr) as OpenRouterChatCompletionEnvelope)
          : undefined;
      } catch {
        parsedErr = undefined;
      }

      const fallbackMsg =
        trimmedErr.slice(0, 300) || res.statusText || 'OpenRouter stream request failed';
      const info = extractOpenRouterErrorInfo(
        parsedErr?.error ?? parsedErr?.choices?.[0]?.error,
        fallbackMsg,
      );
      const effectiveStatus = !res.ok
        ? res.status
        : typeof info.code === 'number'
          ? info.code
          : 502;

      throw new OpenRouterApiError(
        `OpenRouter API error (${effectiveStatus}): ${info.message}`,
        effectiveStatus,
        info.code,
      );
    }

    const reader = res.body.getReader();
    const decoder = new TextDecoder('utf-8');
    const thinkFilter = createThinkTagStreamFilter();
    let buffer = '';
    let fullText = '';
    let doneReceived = false;

    const processSseLine = async (rawLine: string): Promise<boolean> => {
      const line = rawLine.trim();
      if (!line || line.startsWith(':')) {
        return false;
      }

      if (line.startsWith('{')) {
        let bareEnvelope: OpenRouterStreamChunkEnvelope | undefined;
        try {
          bareEnvelope = JSON.parse(line) as OpenRouterStreamChunkEnvelope;
        } catch {
          bareEnvelope = undefined;
        }
        const bareErr = bareEnvelope?.error ?? bareEnvelope?.choices?.[0]?.error;
        if (bareErr) {
          const info = extractOpenRouterErrorInfo(bareErr, line.slice(0, 300));
          const status = typeof info.code === 'number' ? info.code : 502;
          throw new OpenRouterApiError(
            `OpenRouter stream error (${status}): ${info.message}`,
            status,
            info.code,
          );
        }
      }

      if (!line.startsWith('data:')) {
        return false;
      }

      const payload = line.slice(5).trim();
      if (!payload) {
        return false;
      }
      if (payload === '[DONE]') {
        return true;
      }

      let parsed: OpenRouterStreamChunkEnvelope;
      try {
        parsed = JSON.parse(payload) as OpenRouterStreamChunkEnvelope;
      } catch (err) {
        throw new OpenRouterApiError(
          `OpenRouter returned malformed SSE JSON chunk: ${(err as Error).message}`,
          502,
        );
      }

      const streamErr = parsed.error ?? parsed.choices?.[0]?.error;
      if (streamErr) {
        const info = extractOpenRouterErrorInfo(streamErr, payload.slice(0, 300));
        const status = typeof info.code === 'number' ? info.code : 502;
        throw new OpenRouterApiError(
          `OpenRouter stream error (${status}): ${info.message}`,
          status,
          info.code,
        );
      }

      const deltaContent = parsed.choices?.[0]?.delta?.content;
      const rawDelta =
        typeof deltaContent === 'string'
          ? deltaContent
          : Array.isArray(deltaContent)
            ? deltaContent
                .map((part) => (typeof part?.text === 'string' ? part.text : ''))
                .join('')
            : '';

      if (rawDelta.length > 0) {
        const delta = thinkFilter.push(rawDelta);
        if (delta.length > 0) {
          fullText += delta;
          if (opts.onDelta) {
            await opts.onDelta(delta);
          }
        }
      }

      return false;
    };

    try {
      while (!doneReceived) {
        const { done, value } = await reader.read();
        if (done) {
          break;
        }

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split(/\r?\n/);
        buffer = lines.pop() ?? '';

        for (const line of lines) {
          if (await processSseLine(line)) {
            doneReceived = true;
            break;
          }
        }
      }

      buffer += decoder.decode();
      if (!doneReceived && buffer.trim().length > 0) {
        for (const line of buffer.split(/\r?\n/)) {
          if (await processSseLine(line)) {
            doneReceived = true;
            break;
          }
        }
      }

      const tail = thinkFilter.flush();
      if (tail.length > 0) {
        fullText += tail;
        if (opts.onDelta) {
          await opts.onDelta(tail);
        }
      }

      if (doneReceived) {
        await reader.cancel().catch(() => undefined);
      }
    } finally {
      reader.releaseLock();
    }

    return fullText;
  }
}
