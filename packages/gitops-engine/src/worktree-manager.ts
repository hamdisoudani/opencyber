import { promises as fs } from 'node:fs';
import path from 'node:path';
import { type ScopeConfig, serializeScopeYaml } from '@opencyber/shared';
import { simpleGit, type SimpleGit } from 'simple-git';

export interface WorktreeManagerOptions {
  repoDir: string;
  worktreesDir?: string;
}

export interface TaskWorktreeInfo {
  branchName: string;
  worktreePath: string;
}

export interface CommitWorktreeResult {
  committed: boolean;
  commitSha?: string;
  changedFiles: string[];
}

export interface BranchDiffFileContent {
  relativePath: string;
  sizeBytes: number;
  content: string;
}

export interface BranchDiffInspection {
  changedFiles: string[];
  diffText: string;
  filesWithContent: BranchDiffFileContent[];
}

export interface RepoCommitSummary {
  sha: string;
  date: string;
  message: string;
  author: string;
}

export interface RepoHistorySnapshot {
  branches: string[];
  commits: RepoCommitSummary[];
}

function buildDefaultPolicyMarkdown(scope: ScopeConfig): string {
  return [
    `# Engagement Policy — ${scope.programName} (${scope.engagementId})`,
    '',
    '## Defensive Posture & Scope Rules',
    '- Strictly read-only HTTP posture checks (`GET`, `HEAD`, `OPTIONS` only).',
    '- `scope.yaml` and `POLICY.md` are immutable and MUST NOT be modified by task branches.',
    '- Large artifacts (>50 KB) MUST be stored in the content-addressed BlobVault, never committed to Git.',
    '- Subagents may only commit structured artifacts under `observations/`, `schemas/`, and `reports/`.',
    '',
  ].join('\n');
}

function sanitizeBranchSlug(slug: string, fallback: string): string {
  const cleaned = slug
    .trim()
    .replace(/[^a-zA-Z0-9_-]+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^[-_]+|[-_]+$/g, '');
  if (cleaned.length > 0) {
    return cleaned;
  }
  const fallbackCleaned = fallback
    .trim()
    .replace(/[^a-zA-Z0-9_-]+/g, '-')
    .replace(/^[-_]+|[-_]+$/g, '');
  return fallbackCleaned || 'task';
}

export class WorktreeManager {
  public readonly repoDir: string;
  public readonly worktreesDir: string;

  constructor(options: WorktreeManagerOptions) {
    this.repoDir = path.resolve(options.repoDir);
    this.worktreesDir = options.worktreesDir
      ? path.resolve(options.worktreesDir)
      : `${this.repoDir}-worktrees`;
  }

  private getMainGit(): SimpleGit {
    return simpleGit(this.repoDir);
  }

  private async configureLocalIdentity(git: SimpleGit): Promise<void> {
    await git.raw(['config', '--local', 'user.name', 'Aegis Maintainer']);
    await git.raw([
      'config',
      '--local',
      'user.email',
      'maintainer@aegis-gitops.local',
    ]);
    await git.raw(['config', '--local', 'commit.gpgsign', 'false']);
  }

  private resolveSafeRepoPath(relativePath: string): string {
    const normalizedRel = relativePath.replace(/\\/g, '/').replace(/^\/+/, '');
    const resolved = path.resolve(this.repoDir, normalizedRel);
    const relCheck = path.relative(this.repoDir, resolved);
    if (relCheck.startsWith('..') || path.isAbsolute(relCheck)) {
      throw new Error(`Unsafe repository path traversal: ${relativePath}`);
    }
    return resolved;
  }

  private resolveSafeWorktreePath(taskId: string): string {
    if (!taskId || taskId.includes('/') || taskId.includes('\\') || taskId === '..' || taskId === '.') {
      throw new Error(`Invalid taskId for worktree path: ${taskId}`);
    }
    const resolved = path.join(this.worktreesDir, taskId);
    const relCheck = path.relative(this.worktreesDir, resolved);
    if (relCheck.startsWith('..') || path.isAbsolute(relCheck)) {
      throw new Error(`Unsafe worktree path traversal: ${taskId}`);
    }
    return resolved;
  }

  async initEngagementRepo(
    scope: ScopeConfig,
    policyMarkdown?: string,
  ): Promise<void> {
    await fs.mkdir(this.repoDir, { recursive: true });
    await fs.mkdir(this.worktreesDir, { recursive: true });

    const git = this.getMainGit();
    try {
      await git.raw(['init', '-b', 'main']);
    } catch {
      await git.init();
      await git.raw(['symbolic-ref', 'HEAD', 'refs/heads/main']);
    }

    await this.configureLocalIdentity(git);

    const scopeContent = serializeScopeYaml(scope);
    const policyContent = policyMarkdown ?? buildDefaultPolicyMarkdown(scope);

    await fs.writeFile(
      path.join(this.repoDir, 'scope.yaml'),
      scopeContent,
      'utf8',
    );
    await fs.writeFile(
      path.join(this.repoDir, 'POLICY.md'),
      policyContent,
      'utf8',
    );

    const gitkeepDirs = [
      'surface/hosts',
      'observations',
      'schemas',
      'evaluated',
      'reports',
    ];
    for (const relDir of gitkeepDirs) {
      const fullDir = path.join(this.repoDir, relDir);
      await fs.mkdir(fullDir, { recursive: true });
      await fs.writeFile(path.join(fullDir, '.gitkeep'), '', 'utf8');
    }

    await git.add('.');
    const status = await git.status();
    if (!status.isClean()) {
      await git.commit('chore: initialize engagement repository');
    }
  }

  async createTaskWorktree(
    taskId: string,
    branchSlug: string,
  ): Promise<TaskWorktreeInfo> {
    await fs.mkdir(this.worktreesDir, { recursive: true });

    const sanitizedSlug = sanitizeBranchSlug(branchSlug, taskId);
    const branchName = `task/${sanitizedSlug}`;
    const worktreePath = this.resolveSafeWorktreePath(taskId);

    const git = this.getMainGit();
    await git.raw(['worktree', 'add', '-b', branchName, worktreePath, 'main']);

    const wtGit = simpleGit(worktreePath);
    await this.configureLocalIdentity(wtGit);

    return {
      branchName,
      worktreePath,
    };
  }

  async commitWorktreeChanges(
    worktreePath: string,
    commitMessage: string,
  ): Promise<CommitWorktreeResult> {
    const wtGit = simpleGit(path.resolve(worktreePath));
    const preStatus = await wtGit.status(['-uall']);
    if (preStatus.isClean()) {
      return { committed: false, changedFiles: [] };
    }

    await wtGit.add('.');

    const stagedOutput = await wtGit.raw([
      '-c',
      'core.quotepath=false',
      'diff',
      '--cached',
      '--name-only',
    ]);
    const changedFiles = stagedOutput
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line.length > 0);

    if (changedFiles.length === 0) {
      return { committed: false, changedFiles: [] };
    }

    await wtGit.commit(commitMessage);
    const commitSha = (await wtGit.revparse(['HEAD'])).trim();

    return {
      committed: true,
      commitSha,
      changedFiles,
    };
  }

  async inspectBranchDiff(branchName: string): Promise<BranchDiffInspection> {
    const git = this.getMainGit();

    const namesOutput = await git.raw([
      '-c',
      'core.quotepath=false',
      'diff',
      '--name-only',
      `main...${branchName}`,
    ]);
    const changedFiles = namesOutput
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line.length > 0);

    const diffText = await git.raw([
      '-c',
      'core.quotepath=false',
      'diff',
      `main...${branchName}`,
    ]);

    const filesWithContent: BranchDiffFileContent[] = [];
    for (const relativePath of changedFiles) {
      const objectSpec = `${branchName}:${relativePath}`;
      let rawSize: number | null = null;
      try {
        const sizeStr = await git.raw(['cat-file', '-s', objectSpec]);
        const parsedSize = Number.parseInt(sizeStr.trim(), 10);
        if (Number.isFinite(parsedSize)) {
          rawSize = parsedSize;
        }
      } catch {
        // File was deleted on the branch; keep in changedFiles for policy checks, skip content load.
        continue;
      }

      const content = await git.raw(['show', objectSpec]);
      const sizeBytes = rawSize ?? Buffer.byteLength(content, 'utf8');
      filesWithContent.push({
        relativePath,
        sizeBytes,
        content,
      });
    }

    return {
      changedFiles,
      diffText,
      filesWithContent,
    };
  }

  private async ensureOnMain(git: SimpleGit): Promise<void> {
    const currentBranch = (
      await git.revparse(['--abbrev-ref', 'HEAD'])
    ).trim();
    if (currentBranch !== 'main') {
      await git.checkout('main');
    }
  }

  async mergeBranchToMain(
    branchName: string,
    mergeMessage: string,
  ): Promise<{ mergeCommitSha: string }> {
    const git = this.getMainGit();
    await this.ensureOnMain(git);
    await git.raw(['merge', '--no-ff', branchName, '-m', mergeMessage]);
    const mergeCommitSha = (await git.revparse(['HEAD'])).trim();
    return { mergeCommitSha };
  }

  async commitFilesOnMain(
    files: Array<{ relativePath: string; content: string }>,
    commitMessage: string,
  ): Promise<{ commitSha: string }> {
    const git = this.getMainGit();
    await this.ensureOnMain(git);

    for (const file of files) {
      const fullPath = this.resolveSafeRepoPath(file.relativePath);
      await fs.mkdir(path.dirname(fullPath), { recursive: true });
      await fs.writeFile(fullPath, file.content, 'utf8');
    }

    if (files.length > 0) {
      await git.add(files.map((f) => f.relativePath));
    }

    const status = await git.status();
    if (!status.isClean()) {
      await git.commit(commitMessage);
    }

    const commitSha = (await git.revparse(['HEAD'])).trim();
    return { commitSha };
  }

  async cleanupWorktree(
    taskId: string,
    branchName?: string,
    deleteBranch: boolean = false,
  ): Promise<void> {
    const worktreePath = this.resolveSafeWorktreePath(taskId);
    const git = this.getMainGit();

    try {
      await git.raw(['worktree', 'remove', '--force', worktreePath]);
    } catch {
      // Ignore if worktree was already removed; ensure directory is cleaned up.
      await fs.rm(worktreePath, { recursive: true, force: true }).catch(() => {
        // Ignore cleanup errors.
      });
    }

    await git.raw(['worktree', 'prune']);

    if (deleteBranch && branchName) {
      try {
        await git.raw(['branch', '-D', branchName]);
      } catch {
        // Ignore if branch was already deleted or does not exist.
      }
    }
  }

  async getHistory(limit: number = 30): Promise<RepoHistorySnapshot> {
    const git = this.getMainGit();
    const branchSummary = await git.branchLocal();

    let commits: RepoCommitSummary[] = [];
    try {
      const logResult = await git.log({ maxCount: limit, '--all': null });
      commits = logResult.all.map((entry) => ({
        sha: entry.hash,
        date: entry.date,
        message: entry.message,
        author: entry.author_name,
      }));
    } catch {
      commits = [];
    }

    return {
      branches: branchSummary.all,
      commits,
    };
  }
}
