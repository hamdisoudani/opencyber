export interface ParsedSseFrame {
  event: string;
  data: unknown;
  rawData: string;
}

/**
 * Incrementally parses Server-Sent Events (SSE) blocks separated by \n\n (or \r\n\r\n).
 * Safely preserves incomplete trailing frames and split \r\n sequences across chunks.
 */
export function consumeSseBuffer(
  rawBuffer: string,
  flushRemainder = false,
): { frames: ParsedSseFrame[]; remainder: string } {
  let normalized = rawBuffer;
  let trailingCr = '';

  if (!flushRemainder && normalized.endsWith('\r')) {
    trailingCr = '\r';
    normalized = normalized.slice(0, -1);
  }

  normalized = normalized.replace(/\r\n/g, '\n');

  const frames: ParsedSseFrame[] = [];
  const blocks = normalized.split('\n\n');
  const tail = flushRemainder ? '' : (blocks.pop() ?? '') + trailingCr;

  for (const block of blocks) {
    if (!block.trim()) continue;

    let eventName = 'message';
    const dataLines: string[] = [];

    for (const line of block.split('\n')) {
      if (line.startsWith(':')) {
        continue;
      }
      if (line.startsWith('event:')) {
        eventName = line.slice(6).trim() || 'message';
      } else if (line.startsWith('data:')) {
        const value = line.slice(5);
        dataLines.push(value.startsWith(' ') ? value.slice(1) : value);
      }
    }

    if (dataLines.length === 0) continue;

    const rawData = dataLines.join('\n');
    let parsed: unknown = rawData;
    try {
      parsed = JSON.parse(rawData);
    } catch {
      parsed = rawData;
    }

    frames.push({
      event: eventName,
      data: parsed,
      rawData,
    });
  }

  return { frames, remainder: tail };
}
