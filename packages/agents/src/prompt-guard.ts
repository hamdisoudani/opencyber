import type { StructuredLlmClient } from './groq-client.js';

export interface PromptGuardSanitizerOptions {
  llmClient?: StructuredLlmClient;
  groqClient?: StructuredLlmClient;
  threshold?: number;
}

export interface PromptGuardInspectionResult {
  safe: boolean;
  maxInjectionScore: number;
  flaggedChunks: number;
  sanitizedText: string;
}

const MAX_CHUNK_CHARS = 900;

const EXPLICIT_INJECTION_PATTERNS: readonly RegExp[] = [
  /ignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|prompts|rules|directives)/i,
  /disregard\s+(?:all\s+)?(?:previous|prior|system)\s+(?:instructions|prompts|rules|directives)/i,
  /(?:reveal|print|dump|override|bypass|forget)\s+(?:your\s+|the\s+)?system\s+prompt/i,
  /(?:new\s+system\s+prompt|system\s+prompt\s+override|<\s*\/?\s*system\s*>)/i,
  /(?:output|return|respond\s+with|emit|force|set\s+decision\s+to)\s+['"`]*APPROVE_MERGE['"`]*/i,
  /\bAPPROVE_MERGE\b[\s\S]{0,40}\bimmediately\b/i,
  /you\s+are\s+now\s+(?:in\s+developer\s+mode|an?\s+unrestricted)/i,
];

function splitIntoBoundedChunks(text: string, maxChars: number = MAX_CHUNK_CHARS): string[] {
  if (text.length === 0) {
    return [];
  }
  if (text.length <= maxChars) {
    return [text];
  }

  const chunks: string[] = [];
  const lines = text.split(/(\n)/); // keep '\n' delimiters so reassembly is lossless
  let current = '';

  for (const part of lines) {
    if (part.length > maxChars) {
      if (current.length > 0) {
        chunks.push(current);
        current = '';
      }
      for (let i = 0; i < part.length; i += maxChars) {
        chunks.push(part.slice(i, i + maxChars));
      }
      continue;
    }

    if (current.length + part.length > maxChars && current.length > 0) {
      chunks.push(current);
      current = part;
    } else {
      current += part;
    }
  }

  if (current.length > 0) {
    chunks.push(current);
  }

  return chunks;
}

function matchesHeuristicOverride(chunk: string): boolean {
  return EXPLICIT_INJECTION_PATTERNS.some((pattern) => pattern.test(chunk));
}

export class PromptGuardSanitizer {
  public readonly threshold: number;
  private readonly llmClient?: StructuredLlmClient;

  constructor(opts?: PromptGuardSanitizerOptions) {
    this.llmClient = opts?.llmClient ?? opts?.groqClient;
    this.threshold = opts?.threshold ?? 0.80;
  }

  public async inspectAndSanitize(untrustedText: string): Promise<PromptGuardInspectionResult> {
    if (!untrustedText) {
      return {
        safe: true,
        maxInjectionScore: 0,
        flaggedChunks: 0,
        sanitizedText: untrustedText,
      };
    }

    const chunks = splitIntoBoundedChunks(untrustedText, MAX_CHUNK_CHARS);
    let maxInjectionScore = 0;
    let flaggedChunks = 0;
    const sanitizedParts: string[] = [];

    for (const chunk of chunks) {
      const heuristicHit = matchesHeuristicOverride(chunk);
      let modelScore = 0;

      if (this.llmClient?.scorePromptInjection && chunk.trim().length > 0) {
        modelScore = await this.llmClient.scorePromptInjection(chunk);
      }

      const effectiveScore = heuristicHit ? Math.max(modelScore, 0.99) : modelScore;
      if (effectiveScore > maxInjectionScore) {
        maxInjectionScore = effectiveScore;
      }

      if (heuristicHit || modelScore >= this.threshold) {
        flaggedChunks += 1;
        sanitizedParts.push('[REDACTED_BY_PROMPT_GUARD]');
      } else {
        sanitizedParts.push(chunk);
      }
    }

    return {
      safe: flaggedChunks === 0,
      maxInjectionScore,
      flaggedChunks,
      sanitizedText: sanitizedParts.join(''),
    };
  }
}
