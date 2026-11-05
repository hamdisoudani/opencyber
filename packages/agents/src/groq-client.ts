import Groq from 'groq-sdk';
import type { z } from 'zod';

export type AegisModelTier = 'ORCHESTRATOR' | 'SUBAGENT';
export type LlmProviderName = 'openrouter' | 'groq';

export interface AegisGroqClientOptions {
  apiKey?: string;
  orchestratorModel?: string;
  subagentModel?: string;
  promptGuardModel?: string;
}

export interface CompleteJsonOptions<T> {
  tier: AegisModelTier;
  systemPrompt: string;
  userPrompt: string;
  schema: z.ZodType<T>;
  temperature?: number;
}

export interface ChatTurnMessage {
  role: 'user' | 'assistant';
  content: string;
}

export interface StreamTextOptions {
  tier: AegisModelTier;
  systemPrompt: string;
  messages: ChatTurnMessage[];
  temperature?: number;
  onDelta?: (delta: string) => void | Promise<void>;
}

export interface StructuredLlmClient {
  readonly orchestratorProvider?: LlmProviderName;
  readonly subagentProvider?: LlmProviderName;
  readonly orchestratorModel: string;
  readonly subagentModel: string;
  readonly promptGuardModel?: string;
  completeJson<T>(opts: CompleteJsonOptions<T>): Promise<T>;
  streamText?(opts: StreamTextOptions): Promise<string>;
  scorePromptInjection?(chunk: string): Promise<number>;
}

export interface ThinkTagStreamFilter {
  push(chunk: string): string;
  flush(): string;
}

function findPartialTagSuffixLength(text: string, tagLower: string): number {
  const maxLen = Math.min(text.length, tagLower.length - 1);
  for (let len = maxLen; len >= 1; len -= 1) {
    const suffix = text.slice(text.length - len).toLowerCase();
    if (tagLower.startsWith(suffix)) {
      return len;
    }
  }
  return 0;
}

export function createThinkTagStreamFilter(): ThinkTagStreamFilter {
  const OPEN_TAG = '<think>';
  const CLOSE_TAG = '</think>';
  let inThink = false;
  let carry = '';
  let emittedVisible = false;
  let trimLeadingAfterClose = false;

  return {
    push(chunk: string): string {
      if (!chunk) {
        return '';
      }

      let buf = carry + chunk;
      carry = '';
      let out = '';

      while (buf.length > 0) {
        if (!inThink) {
          if (trimLeadingAfterClose && !emittedVisible) {
            buf = buf.replace(/^\s+/, '');
            if (buf.length === 0) {
              break;
            }
            trimLeadingAfterClose = false;
          }

          const lower = buf.toLowerCase();
          const openIdx = lower.indexOf(OPEN_TAG);
          if (openIdx !== -1) {
            const before = buf.slice(0, openIdx);
            if (before.length > 0) {
              out += before;
              emittedVisible = true;
            }
            buf = buf.slice(openIdx + OPEN_TAG.length);
            inThink = true;
            continue;
          }

          const partialLen = findPartialTagSuffixLength(buf, OPEN_TAG);
          if (partialLen > 0) {
            const safePart = buf.slice(0, buf.length - partialLen);
            if (safePart.length > 0) {
              out += safePart;
              emittedVisible = true;
            }
            carry = buf.slice(buf.length - partialLen);
          } else {
            out += buf;
            emittedVisible = true;
          }
          break;
        } else {
          const lower = buf.toLowerCase();
          const closeIdx = lower.indexOf(CLOSE_TAG);
          if (closeIdx !== -1) {
            buf = buf.slice(closeIdx + CLOSE_TAG.length);
            inThink = false;
            if (!emittedVisible) {
              trimLeadingAfterClose = true;
            }
            continue;
          }

          const partialLen = findPartialTagSuffixLength(buf, CLOSE_TAG);
          carry = partialLen > 0 ? buf.slice(buf.length - partialLen) : '';
          break;
        }
      }

      return out;
    },

    flush(): string {
      if (!inThink && carry.length > 0) {
        const remaining = carry;
        carry = '';
        emittedVisible = true;
        return remaining;
      }
      carry = '';
      return '';
    },
  };
}

export function stripFencesAndReasoning(raw: string): string {
  let cleaned = raw.replace(/<think>[\s\S]*?<\/think>/gi, '').trim();

  const fenceMatch = cleaned.match(/^```(?:json)?\s*([\s\S]*?)\s*```$/i);
  if (fenceMatch && fenceMatch[1] !== undefined) {
    cleaned = fenceMatch[1].trim();
  }

  const firstBrace = cleaned.indexOf('{');
  const lastBrace = cleaned.lastIndexOf('}');
  if (firstBrace !== -1 && lastBrace > firstBrace) {
    cleaned = cleaned.slice(firstBrace, lastBrace + 1);
  }

  return cleaned;
}

export class AegisGroqClient implements StructuredLlmClient {
  public readonly orchestratorProvider: LlmProviderName = 'groq';
  public readonly subagentProvider: LlmProviderName = 'groq';
  public readonly orchestratorModel: string;
  public readonly subagentModel: string;
  public readonly promptGuardModel: string;

  private readonly configuredApiKey?: string;
  private cachedClient?: Groq;

  constructor(opts?: AegisGroqClientOptions) {
    this.configuredApiKey = opts?.apiKey;
    this.orchestratorModel =
      opts?.orchestratorModel ||
      process.env.GROQ_ORCHESTRATOR_MODEL ||
      'openai/gpt-oss-120b';
    this.subagentModel =
      opts?.subagentModel ||
      process.env.GROQ_SUBAGENT_MODEL ||
      'qwen/qwen3.8-27b';
    this.promptGuardModel =
      opts?.promptGuardModel ||
      process.env.GROQ_PROMPT_GUARD_MODEL ||
      'meta-llama/llama-prompt-guard-2-86m';
  }

  private getClient(): Groq {
    if (this.cachedClient) {
      return this.cachedClient;
    }

    const apiKey = (this.configuredApiKey ?? process.env.GROQ_API_KEY)?.trim();
    if (!apiKey) {
      throw new Error(
        'Missing Groq API key: provide `apiKey` to AegisGroqClient or set `process.env.GROQ_API_KEY`.',
      );
    }

    this.cachedClient = new Groq({ apiKey });
    return this.cachedClient;
  }

  public async completeJson<T>(opts: CompleteJsonOptions<T>): Promise<T> {
    const groq = this.getClient();
    const model =
      opts.tier === 'ORCHESTRATOR' ? this.orchestratorModel : this.subagentModel;
    const temperature = opts.temperature ?? 0.1;

    const systemPrompt = /json/i.test(opts.systemPrompt) || /json/i.test(opts.userPrompt)
      ? opts.systemPrompt
      : `${opts.systemPrompt}\nRespond strictly with a valid JSON object.`;

    let currentUserPrompt = opts.userPrompt;
    let lastFailureMessage = 'Unknown validation error';

    for (let attempt = 0; attempt < 2; attempt += 1) {
      const completion = await groq.chat.completions.create({
        model,
        temperature,
        response_format: { type: 'json_object' },
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: currentUserPrompt },
        ],
      });

      const rawContent = completion.choices[0]?.message?.content ?? '';
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

    throw new Error(`AegisGroqClient.completeJson failed after retry (${lastFailureMessage})`);
  }

  public async streamText(opts: StreamTextOptions): Promise<string> {
    const groq = this.getClient();
    const model =
      opts.tier === 'ORCHESTRATOR' ? this.orchestratorModel : this.subagentModel;
    const temperature = opts.temperature ?? 0.2;

    const stream = await groq.chat.completions.create({
      model,
      temperature,
      stream: true,
      messages: [
        { role: 'system', content: opts.systemPrompt },
        ...opts.messages.map((m) => ({ role: m.role, content: m.content })),
      ],
    });

    const thinkFilter = createThinkTagStreamFilter();
    let fullText = '';

    for await (const chunk of stream) {
      const rawDelta = chunk.choices?.[0]?.delta?.content ?? '';
      if (rawDelta.length > 0) {
        const delta = thinkFilter.push(rawDelta);
        if (delta.length > 0) {
          fullText += delta;
          if (opts.onDelta) {
            await opts.onDelta(delta);
          }
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

    return fullText;
  }

  public async scorePromptInjection(chunk: string): Promise<number> {
    const bounded = chunk.slice(0, 1000);
    if (!bounded.trim()) {
      return 0;
    }

    const groq = this.getClient();
    const completion = await groq.chat.completions.create({
      model: this.promptGuardModel,
      temperature: 0,
      messages: [{ role: 'user', content: bounded }],
    });

    const raw = completion.choices[0]?.message?.content?.trim() ?? '0';
    const numeric = Number.parseFloat(raw);
    if (Number.isFinite(numeric)) {
      return Math.min(1, Math.max(0, numeric));
    }

    const floatMatch = raw.match(/-?\d+(?:\.\d+)?(?:e[+-]?\d+)?/i);
    if (floatMatch) {
      const extracted = Number.parseFloat(floatMatch[0]);
      if (Number.isFinite(extracted)) {
        return Math.min(1, Math.max(0, extracted));
      }
    }

    if (/inject|jailbreak|unsafe|malicious/i.test(raw)) {
      return 1;
    }
    return 0;
  }
}
