import React, { useMemo, useState } from 'react';
import {
  Check,
  CheckCircle2,
  Copy,
  FileCode2,
  FileDiff,
  FileText,
  FolderGit2,
  GitBranch,
  GitPullRequest,
  Search,
  XCircle,
} from 'lucide-react';
import type { GitOpsSectionTab } from '../dashboardController';
import type {
  GitOpsHistoryResponse,
  RepoFileEntry,
  TrafficDecision,
  TrafficEntry,
} from '../types';
import { formatShortClock } from './OperationsView';

export interface GitOpsEgressViewProps {
  sectionTab: GitOpsSectionTab;
  history: GitOpsHistoryResponse;
  selectedCommitSha: string | null;
  selectedCommitDiff: string;
  repoFiles: RepoFileEntry[];
  selectedFilePath: string;
  selectedFileContent: string;
  trafficEntries: TrafficEntry[];
  onSelectSectionTab: (tab: GitOpsSectionTab) => void;
  onSelectCommit: (sha: string) => void;
  onSelectRepoFile: (path: string) => void;
}

type TrafficFilter =
  | 'ALL'
  | 'ALLOWED'
  | 'BLOCKED_SCOPE_451'
  | 'BLOCKED_RPS_429'
  | 'BLOCKED_OTHER';

function classifyDiffLine(line: string): string {
  if (
    line.startsWith('+++') ||
    line.startsWith('---') ||
    line.startsWith('diff --git')
  ) {
    return 'oc-diff-line is-meta';
  }
  if (line.startsWith('@@')) return 'oc-diff-line is-hunk';
  if (line.startsWith('+')) return 'oc-diff-line is-add';
  if (line.startsWith('-')) return 'oc-diff-line is-del';
  return 'oc-diff-line';
}

function decisionMeta(
  decision: TrafficDecision,
  status?: number,
): { label: string; badgeClass: string } {
  switch (decision) {
    case 'ALLOWED':
      return {
        label: `ALLOWED · ${status ?? 200}`,
        badgeClass: 'oc-badge oc-badge-emerald mono',
      };
    case 'BLOCKED_SCOPE_451':
      return {
        label: 'SCOPE BLOCKED · 451',
        badgeClass: 'oc-badge oc-badge-coral mono',
      };
    case 'BLOCKED_RPS_429':
      return {
        label: 'RATE LIMITED · 429',
        badgeClass: 'oc-badge oc-badge-amber mono',
      };
    case 'BLOCKED_METHOD_405':
      return {
        label: 'METHOD BLOCKED · 405',
        badgeClass: 'oc-badge oc-badge-coral mono',
      };
    case 'BLOCKED_AUTH_403':
      return {
        label: 'EPOCH / AUTH · 403',
        badgeClass: 'oc-badge oc-badge-amber mono',
      };
  }
}

export const GitOpsEgressView: React.FC<GitOpsEgressViewProps> = ({
  sectionTab,
  history,
  selectedCommitSha,
  selectedCommitDiff,
  repoFiles,
  selectedFilePath,
  selectedFileContent,
  trafficEntries,
  onSelectSectionTab,
  onSelectCommit,
  onSelectRepoFile,
}) => {
  const [fileQuery, setFileQuery] = useState<string>('');
  const [copiedFile, setCopiedFile] = useState<boolean>(false);
  const [trafficFilter, setTrafficFilter] = useState<TrafficFilter>('ALL');
  const [trafficSearch, setTrafficSearch] = useState<string>('');

  const diffLines = useMemo(
    () => selectedCommitDiff.split('\n'),
    [selectedCommitDiff],
  );

  const filteredFiles = useMemo(() => {
    const q = fileQuery.trim().toLowerCase();
    if (!q) return repoFiles;
    return repoFiles.filter((f) => f.path.toLowerCase().includes(q));
  }, [repoFiles, fileQuery]);

  const filteredTraffic = useMemo(() => {
    const q = trafficSearch.trim().toLowerCase();
    return trafficEntries.filter((tx) => {
      if (trafficFilter === 'ALLOWED' && tx.decision !== 'ALLOWED')
        return false;
      if (
        trafficFilter === 'BLOCKED_SCOPE_451' &&
        tx.decision !== 'BLOCKED_SCOPE_451'
      ) {
        return false;
      }
      if (
        trafficFilter === 'BLOCKED_RPS_429' &&
        tx.decision !== 'BLOCKED_RPS_429'
      ) {
        return false;
      }
      if (
        trafficFilter === 'BLOCKED_OTHER' &&
        tx.decision !== 'BLOCKED_METHOD_405' &&
        tx.decision !== 'BLOCKED_AUTH_403'
      ) {
        return false;
      }
      if (q) {
        const hay = `${tx.method} ${tx.url} ${tx.taskId} ${tx.decision}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [trafficEntries, trafficFilter, trafficSearch]);

  const blocked451Count = useMemo(
    () =>
      trafficEntries.filter((t) => t.decision === 'BLOCKED_SCOPE_451').length,
    [trafficEntries],
  );

  return (
    <div
      className="oc-view-scroll"
      style={{ display: 'flex', flexDirection: 'column', gap: 16 }}
    >
      {/* Sub-Navigation Bar */}
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
        <button
          type="button"
          id="gitops-tab-prs"
          className={`oc-segmented-btn${sectionTab === 'prs' ? ' is-active' : ''}`}
          onClick={() => onSelectSectionTab('prs')}
        >
          Worktree PRs &amp; Unified Diffs ({history.reviews.length})
        </button>
        <button
          type="button"
          id="gitops-tab-files"
          className={`oc-segmented-btn${sectionTab === 'files' ? ' is-active' : ''}`}
          onClick={() => onSelectSectionTab('files')}
        >
          engagement-repo Explorer ({repoFiles.length})
        </button>
        <button
          type="button"
          id="gitops-tab-egress"
          className={`oc-segmented-btn${sectionTab === 'egress' ? ' is-active' : ''}`}
          onClick={() => onSelectSectionTab('egress')}
        >
          Mandatory Egress Traffic ({trafficEntries.length} · {blocked451Count}{' '}
          451 Blocked)
        </button>
      </div>

      {/* TAB 1: Subagent git worktree PR Review Cards + Unified Diff Viewer */}
      {sectionTab === 'prs' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {/* Unified Diff Viewer */}
          <div className="oc-code-box">
            <div className="oc-code-header">
              <span
                className="mono"
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 6,
                  fontWeight: 600,
                }}
              >
                <FileDiff size={14} style={{ color: 'var(--cyan-fg)' }} />
                <span>
                  {selectedCommitSha
                    ? `git show ${selectedCommitSha.slice(0, 8)}`
                    : 'Unified Commit Diff'}
                </span>
              </span>

              {history.commits.length > 0 && (
                <select
                  aria-label="Select commit to inspect unified diff"
                  className="oc-select mono"
                  style={{ height: 26, fontSize: '11.5px' }}
                  value={selectedCommitSha ?? ''}
                  onChange={(e) => onSelectCommit(e.target.value)}
                >
                  {history.commits.map((c) => (
                    <option key={c.sha} value={c.sha}>
                      {c.sha.slice(0, 8)} — {c.message.slice(0, 54)}
                    </option>
                  ))}
                </select>
              )}
            </div>

            <div style={{ maxHeight: 280, overflowY: 'auto', padding: '6px 0' }}>
              {diffLines.map((ln, idx) => (
                <div key={idx} className={classifyDiffLine(ln)}>
                  {ln || ' '}
                </div>
              ))}
            </div>
          </div>

          {/* Subagent Worktree PR Review Cards */}
          <section aria-label="Subagent Worktree PR Reviews">
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 7,
                marginBottom: 10,
              }}
            >
              <GitPullRequest size={15} style={{ color: 'var(--cyan-fg)' }} />
              <h2 style={{ margin: 0, fontSize: '14px', fontWeight: 600 }}>
                Subagent git worktree PR Reviews ({history.reviews.length})
              </h2>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {history.reviews.map((rev) => {
                const merged = rev.decision === 'APPROVE_MERGE';
                return (
                  <div
                    key={rev.id}
                    className="oc-section-card"
                    style={{
                      cursor: rev.commitSha ? 'pointer' : 'default',
                    }}
                    onClick={() => {
                      if (rev.commitSha) onSelectCommit(rev.commitSha);
                    }}
                  >
                    <div
                      style={{
                        display: 'flex',
                        flexWrap: 'wrap',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        gap: 8,
                      }}
                    >
                      <span
                        className="mono"
                        style={{
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: 6,
                          fontWeight: 600,
                        }}
                      >
                        <GitBranch size={13} style={{ color: 'var(--cyan-fg)' }} />
                        {rev.branchName}
                      </span>

                      <div
                        style={{
                          display: 'flex',
                          flexWrap: 'wrap',
                          alignItems: 'center',
                          gap: 6,
                        }}
                      >
                        <span
                          className={`oc-badge mono ${
                            rev.ciPassed
                              ? 'oc-badge-emerald'
                              : 'oc-badge-coral'
                          }`}
                        >
                          {rev.ciPassed ? 'CI PASSED' : 'CI FAILED'}
                        </span>
                        <span
                          className={`oc-badge mono ${
                            merged ? 'oc-badge-emerald' : ''
                          }`}
                        >
                          {merged ? (
                            <CheckCircle2 size={11} />
                          ) : (
                            <XCircle size={11} />
                          )}
                          {rev.decision}
                        </span>
                        {rev.commitSha && (
                          <span className="oc-badge oc-badge-cyan mono">
                            {rev.commitSha.slice(0, 8)}
                          </span>
                        )}
                      </div>
                    </div>

                    <p
                      style={{
                        margin: '7px 0 0',
                        fontSize: '12.25px',
                        color: 'var(--text-secondary)',
                      }}
                    >
                      {rev.rationale}
                    </p>
                  </div>
                );
              })}
            </div>
          </section>
        </div>
      )}

      {/* TAB 2: engagement-repo File Explorer */}
      {sectionTab === 'files' && (
        <div className="oc-files-split">
          <div className="oc-files-tree">
            <div style={{ padding: 8, borderBottom: '1px solid var(--border-subtle)' }}>
              <div className="oc-rail-search" style={{ margin: 0 }}>
                <Search size={12} />
                <input
                  type="search"
                  placeholder="Filter engagement-repo…"
                  aria-label="Filter repository files"
                  value={fileQuery}
                  onChange={(e) => setFileQuery(e.target.value)}
                />
              </div>
            </div>

            <div
              style={{
                padding: '7px 10px 4px',
                fontSize: '11px',
                fontWeight: 600,
                color: 'var(--text-muted)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
              }}
            >
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}>
                <FolderGit2 size={12} />
                engagement-repo/
              </span>
              <span className="mono">{filteredFiles.length}</span>
            </div>

            <div style={{ flex: 1, overflowY: 'auto', padding: '4px 6px 10px' }}>
              {filteredFiles.map((file) => {
                const selected = file.path === selectedFilePath;
                return (
                  <button
                    key={file.path}
                    type="button"
                    className={`oc-nav-item${selected ? ' is-active' : ''}`}
                    style={{ height: 30, fontSize: '11.5px' }}
                    onClick={() => onSelectRepoFile(file.path)}
                  >
                    <span className="oc-nav-item-left">
                      {file.path.endsWith('.py') ||
                      file.path.endsWith('.json') ? (
                        <FileCode2 size={12} />
                      ) : (
                        <FileText size={12} />
                      )}
                      <span className="mono truncate">{file.path}</span>
                    </span>
                  </button>
                );
              })}
            </div>
          </div>

          <div className="oc-files-viewer">
            <div className="oc-code-header">
              <span className="mono" style={{ fontWeight: 600 }}>
                {selectedFilePath}
              </span>
              <button
                type="button"
                className="oc-btn"
                style={{ height: 24, fontSize: '11px', padding: '0 8px' }}
                onClick={() => {
                  if (
                    typeof navigator !== 'undefined' &&
                    navigator.clipboard
                  ) {
                    void navigator.clipboard.writeText(selectedFileContent);
                    setCopiedFile(true);
                    setTimeout(() => setCopiedFile(false), 1400);
                  }
                }}
              >
                {copiedFile ? <Check size={11} /> : <Copy size={11} />}
                <span>{copiedFile ? 'Copied' : 'Copy'}</span>
              </button>
            </div>

            <pre
              className="oc-code-pre"
              style={{ flex: 1, overflow: 'auto', maxHeight: 440 }}
            >
              {selectedFileContent}
            </pre>
          </div>
        </div>
      )}

      {/* TAB 3: Mandatory Egress Gateway HTTP Traffic Ledger */}
      {sectionTab === 'egress' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <div
            style={{
              display: 'flex',
              flexWrap: 'wrap',
              alignItems: 'center',
              justifyContent: 'space-between',
              gap: 10,
            }}
          >
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
              {(
                [
                  ['ALL', `All (${trafficEntries.length})`],
                  ['ALLOWED', 'Allowed 200'],
                  ['BLOCKED_SCOPE_451', `451 Scope Blocked (${blocked451Count})`],
                  ['BLOCKED_RPS_429', '429 Rate Limited'],
                  ['BLOCKED_OTHER', '403/405 Method & Epoch'],
                ] as const
              ).map(([key, label]) => (
                <button
                  key={key}
                  type="button"
                  className={`oc-segmented-btn${trafficFilter === key ? ' is-active' : ''}`}
                  onClick={() => setTrafficFilter(key)}
                >
                  {label}
                </button>
              ))}
            </div>

            <div className="oc-rail-search" style={{ margin: 0, width: 220 }}>
              <Search size={12} />
              <input
                type="search"
                placeholder="Filter URL or task…"
                aria-label="Filter HTTP egress traffic"
                value={trafficSearch}
                onChange={(e) => setTrafficSearch(e.target.value)}
              />
            </div>
          </div>

          <div className="oc-table-wrap">
            <table className="oc-table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Gateway Decision</th>
                  <th>Method &amp; URL</th>
                  <th>Auth Profile &amp; Fencing Epoch</th>
                  <th>Latency</th>
                </tr>
              </thead>
              <tbody>
                {filteredTraffic.map((tx) => {
                  const meta = decisionMeta(tx.decision, tx.upstreamStatus);
                  return (
                    <tr key={tx.id}>
                      <td className="mono">{formatShortClock(tx.timestamp)}</td>
                      <td>
                        <span className={meta.badgeClass}>{meta.label}</span>
                      </td>
                      <td
                        className="mono"
                        style={{ color: 'var(--text-primary)' }}
                      >
                        <strong>{tx.method}</strong> {tx.url}
                      </td>
                      <td className="mono">
                        {tx.authProfile ?? 'unauthenticated'} · epoch #
                        {tx.fencingToken}
                      </td>
                      <td className="mono">{tx.durationMs}ms</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
