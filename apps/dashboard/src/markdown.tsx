import React from 'react';

function renderInlineMarkdown(text: string): React.ReactNode[] {
  const nodes: React.ReactNode[] = [];
  const tokenRegex = /(\*\*[^*]+\*\*|`[^`]+`)/g;
  let lastIdx = 0;
  let match: RegExpExecArray | null = null;
  let key = 0;

  while ((match = tokenRegex.exec(text)) !== null) {
    if (match.index > lastIdx) {
      nodes.push(text.slice(lastIdx, match.index));
    }
    const token = match[0];
    if (token.startsWith('**') && token.endsWith('**')) {
      nodes.push(
        <strong key={`b-${key++}`} className="oc-md-strong">
          {token.slice(2, -2)}
        </strong>,
      );
    } else if (token.startsWith('`') && token.endsWith('`')) {
      nodes.push(
        <code key={`c-${key++}`} className="oc-md-code">
          {token.slice(1, -1)}
        </code>,
      );
    }
    lastIdx = match.index + token.length;
  }

  if (lastIdx < text.length) {
    nodes.push(text.slice(lastIdx));
  }

  return nodes;
}

function splitTableRow(line: string): string[] {
  const trimmed = line.trim().replace(/^\|/, '').replace(/\|$/, '');
  return trimmed.split('|').map((cell) => cell.trim());
}

function isSeparatorRow(line: string): boolean {
  const trimmed = line.trim();
  if (!trimmed.includes('|')) return false;
  const cells = splitTableRow(trimmed);
  return (
    cells.length > 0 &&
    cells.every((cell) => /^:?-{2,}:?$/.test(cell))
  );
}

/**
 * Safe GFM Markdown block renderer (headings h2-h4, fenced code blocks, tables, lists).
 * Never uses dangerouslySetInnerHTML so untrusted HTTP payloads cannot inject XSS,
 * and maps # headings to h2+ so the page maintains a single semantic <h1>.
 */
export function renderMarkdownBlocks(markdown: string): React.ReactNode[] {
  const lines = markdown.replace(/\r\n/g, '\n').split('\n');
  const blocks: React.ReactNode[] = [];
  let i = 0;
  let blockKey = 0;

  while (i < lines.length) {
    const line = lines[i] ?? '';
    const trimmed = line.trim();

    if (!trimmed) {
      i += 1;
      continue;
    }

    // Fenced code block
    if (trimmed.startsWith('```')) {
      const lang = trimmed.slice(3).trim() || 'code';
      const codeLines: string[] = [];
      i += 1;
      while (i < lines.length && !(lines[i] ?? '').trim().startsWith('```')) {
        codeLines.push(lines[i] ?? '');
        i += 1;
      }
      if (i < lines.length) i += 1;
      blocks.push(
        <div key={`code-${blockKey++}`} className="oc-code-box">
          <div className="oc-code-header">
            <span className="mono" style={{ color: 'var(--text-muted)' }}>
              {lang}
            </span>
          </div>
          <pre className="oc-code-pre">{codeLines.join('\n')}</pre>
        </div>,
      );
      continue;
    }

    // GFM Table
    if (
      trimmed.includes('|') &&
      i + 1 < lines.length &&
      isSeparatorRow(lines[i + 1] ?? '')
    ) {
      const headers = splitTableRow(trimmed);
      i += 2;
      const rows: string[][] = [];
      while (i < lines.length && (lines[i] ?? '').trim().includes('|')) {
        rows.push(splitTableRow(lines[i] ?? ''));
        i += 1;
      }
      blocks.push(
        <div key={`tbl-${blockKey++}`} className="oc-table-wrap">
          <table className="oc-table">
            <thead>
              <tr>
                {headers.map((h, hIdx) => (
                  <th key={hIdx}>{renderInlineMarkdown(h)}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((r, rIdx) => (
                <tr key={rIdx}>
                  {headers.map((_, cIdx) => (
                    <td key={cIdx}>{renderInlineMarkdown(r[cIdx] ?? '')}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>,
      );
      continue;
    }

    // Headings (mapped to h2/h3/h4 to preserve single page h1)
    const headingMatch = /^(#{1,4})\s+(.+)$/.exec(trimmed);
    if (headingMatch) {
      const hashes = headingMatch[1]?.length ?? 2;
      const content = headingMatch[2] ?? '';
      if (hashes <= 2) {
        blocks.push(
          <h2 key={`h2-${blockKey++}`}>{renderInlineMarkdown(content)}</h2>,
        );
      } else if (hashes === 3) {
        blocks.push(
          <h3 key={`h3-${blockKey++}`}>{renderInlineMarkdown(content)}</h3>,
        );
      } else {
        blocks.push(
          <h4 key={`h4-${blockKey++}`}>{renderInlineMarkdown(content)}</h4>,
        );
      }
      i += 1;
      continue;
    }

    // Unordered list
    if (/^[-*]\s+/.test(trimmed)) {
      const items: string[] = [];
      while (i < lines.length && /^[-*]\s+/.test((lines[i] ?? '').trim())) {
        items.push((lines[i] ?? '').trim().replace(/^[-*]\s+/, ''));
        i += 1;
      }
      blocks.push(
        <ul key={`ul-${blockKey++}`}>
          {items.map((item, idx) => (
            <li key={idx}>{renderInlineMarkdown(item)}</li>
          ))}
        </ul>,
      );
      continue;
    }

    // Paragraph
    const paraLines: string[] = [trimmed];
    i += 1;
    while (i < lines.length) {
      const next = (lines[i] ?? '').trim();
      if (
        !next ||
        next.startsWith('```') ||
        /^#{1,4}\s+/.test(next) ||
        /^[-*]\s+/.test(next) ||
        (next.includes('|') &&
          i + 1 < lines.length &&
          isSeparatorRow(lines[i + 1] ?? ''))
      ) {
        break;
      }
      paraLines.push(next);
      i += 1;
    }

    blocks.push(
      <p key={`p-${blockKey++}`}>{renderInlineMarkdown(paraLines.join(' '))}</p>,
    );
  }

  return blocks;
}
