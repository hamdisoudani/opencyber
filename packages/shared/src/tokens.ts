import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { z } from 'zod';

export function sha256Hex(content: string | Uint8Array): string {
  return createHash('sha256').update(content).digest('hex');
}

export const TaskProxyTokenPayloadSchema = z.object({
  taskId: z.string().min(1),
  engagementId: z.string().min(1),
  fencingToken: z.number().int().nonnegative(),
  allowedAuthProfiles: z.array(z.string()).default([]),
  expiresAtMs: z.number().int().positive(),
});

export type TaskProxyTokenPayload = z.infer<typeof TaskProxyTokenPayloadSchema>;

export type VerifyTaskProxyTokenResult =
  | { valid: true; payload: TaskProxyTokenPayload }
  | { valid: false; reason: string };

const BASE64URL_SEGMENT_RE = /^[A-Za-z0-9_-]+$/;

export function signTaskProxyToken(
  payload: TaskProxyTokenPayload,
  secret: string,
): string {
  if (typeof secret !== 'string' || secret.length < 16) {
    throw new Error('Task proxy token secret must be at least 16 characters');
  }

  const validated = TaskProxyTokenPayloadSchema.parse(payload);
  const encodedPayload = Buffer.from(JSON.stringify(validated), 'utf8').toString('base64url');
  const signature = createHmac('sha256', secret)
    .update(encodedPayload, 'utf8')
    .digest('base64url');

  return `${encodedPayload}.${signature}`;
}

export function verifyTaskProxyToken(
  token: string,
  secret: string,
  nowMs: number = Date.now(),
): VerifyTaskProxyTokenResult {
  if (typeof secret !== 'string' || secret.length < 16) {
    return { valid: false, reason: 'INVALID_SECRET' };
  }

  if (typeof token !== 'string' || token.length === 0) {
    return { valid: false, reason: 'MALFORMED_TOKEN' };
  }

  const parts = token.split('.');
  if (parts.length !== 2) {
    return { valid: false, reason: 'MALFORMED_TOKEN' };
  }

  const [encodedPayload, providedSignature] = parts;
  if (
    !encodedPayload ||
    !providedSignature ||
    !BASE64URL_SEGMENT_RE.test(encodedPayload) ||
    !BASE64URL_SEGMENT_RE.test(providedSignature)
  ) {
    return { valid: false, reason: 'MALFORMED_TOKEN' };
  }

  const expectedSigBuf = createHmac('sha256', secret)
    .update(encodedPayload, 'utf8')
    .digest();
  const providedSigBuf = Buffer.from(providedSignature, 'base64url');

  if (
    expectedSigBuf.byteLength !== providedSigBuf.byteLength ||
    !timingSafeEqual(expectedSigBuf, providedSigBuf)
  ) {
    return { valid: false, reason: 'INVALID_SIGNATURE' };
  }

  let parsedJson: unknown;
  try {
    const decodedStr = Buffer.from(encodedPayload, 'base64url').toString('utf8');
    parsedJson = JSON.parse(decodedStr);
  } catch {
    return { valid: false, reason: 'INVALID_PAYLOAD' };
  }

  const parsedPayload = TaskProxyTokenPayloadSchema.safeParse(parsedJson);
  if (!parsedPayload.success) {
    return { valid: false, reason: 'INVALID_PAYLOAD' };
  }

  if (parsedPayload.data.expiresAtMs <= nowMs) {
    return { valid: false, reason: 'TOKEN_EXPIRED' };
  }

  return { valid: true, payload: parsedPayload.data };
}
