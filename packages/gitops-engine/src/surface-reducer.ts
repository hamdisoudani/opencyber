import { promises as fs } from 'node:fs';
import path from 'node:path';
import {
  buildEndpointKey,
  type CanonicalEndpoint,
  CanonicalEndpointSchema,
  type HostEntity,
  HostEntitySchema,
  HttpMethodSchema,
  normalizeHostname,
  type RouteObservationBatch,
} from '@opencyber/shared';
import { parse as parseYaml, stringify as stringifyYaml } from 'yaml';
import type { StateDb } from './state-db.js';
import type { WorktreeManager } from './worktree-manager.js';

export interface ReduceObservationsInput {
  repoDir: string;
  worktreeManager: WorktreeManager;
  batches: RouteObservationBatch[];
  stateDb?: StateDb;
  engagementId: string;
}

export interface ReduceObservationsResult {
  hosts: HostEntity[];
  endpoints: CanonicalEndpoint[];
  commitSha?: string;
}

function compareCodeUnits(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function uniqueSorted(items: Iterable<string>): string[] {
  const set = new Set<string>();
  for (const item of items) {
    const trimmed = item.trim();
    if (trimmed.length > 0) {
      set.add(trimmed);
    }
  }
  return Array.from(set).sort(compareCodeUnits);
}

function sortRecordKeys(record: Record<string, string>): Record<string, string> {
  const sorted: Record<string, string> = {};
  for (const key of Object.keys(record).sort(compareCodeUnits)) {
    const value = record[key];
    if (value !== undefined) {
      sorted[key] = value;
    }
  }
  return sorted;
}

function mergeAuthRequired(
  existing: boolean | undefined,
  incoming: boolean | undefined,
): boolean | undefined {
  if (existing === undefined) {
    return incoming;
  }
  if (incoming === undefined) {
    return existing;
  }
  return existing || incoming;
}

function minTimestamp(a: string, b: string): string {
  return compareCodeUnits(a, b) <= 0 ? a : b;
}

function maxTimestamp(a: string, b: string): string {
  return compareCodeUnits(a, b) >= 0 ? a : b;
}

export async function reduceObservationsToSurface(
  input: ReduceObservationsInput,
): Promise<ReduceObservationsResult> {
  const repoDir = path.resolve(input.repoDir);
  const hostsMap = new Map<string, HostEntity>();
  const endpointsMap = new Map<
    string,
    { endpoint: CanonicalEndpoint; repoRelativePath: string }
  >();
  const existingFileContents = new Map<string, string>();

  const surfaceHostsDir = path.join(repoDir, 'surface', 'hosts');
  let hostDirEntries: Array<{ name: string; isDir: boolean }> = [];
  try {
    const dirents = await fs.readdir(surfaceHostsDir, { withFileTypes: true });
    hostDirEntries = dirents.map((d) => ({
      name: d.name,
      isDir: d.isDirectory(),
    }));
  } catch (err: unknown) {
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') {
      throw err;
    }
  }

  for (const entry of hostDirEntries) {
    if (!entry.isDir) {
      continue;
    }

    const hostRelPath = `surface/hosts/${entry.name}/host.yaml`;
    const hostFullPath = path.join(repoDir, hostRelPath);
    try {
      const rawYaml = await fs.readFile(hostFullPath, 'utf8');
      existingFileContents.set(hostRelPath, rawYaml);
      const parsedHost = HostEntitySchema.parse(parseYaml(rawYaml));
      const normalized = normalizeHostname(parsedHost.hostname);
      if (normalized) {
        hostsMap.set(normalized, {
          ...parsedHost,
          hostname: normalized,
          sources: uniqueSorted(parsedHost.sources),
          fingerprints: uniqueSorted(parsedHost.fingerprints),
          securityHeaders: sortRecordKeys(parsedHost.securityHeaders),
        });
      }
    } catch (err: unknown) {
      if ((err as NodeJS.ErrnoException).code !== 'ENOENT') {
        throw err;
      }
    }

    const endpointsDirFull = path.join(
      surfaceHostsDir,
      entry.name,
      'endpoints',
    );
    let epFiles: string[] = [];
    try {
      const dirents = await fs.readdir(endpointsDirFull, {
        withFileTypes: true,
      });
      epFiles = dirents
        .filter(
          (d) =>
            d.isFile() &&
            (d.name.endsWith('.yaml') || d.name.endsWith('.yml')),
        )
        .map((d) => d.name);
    } catch (err: unknown) {
      if ((err as NodeJS.ErrnoException).code !== 'ENOENT') {
        throw err;
      }
    }

    for (const fileName of epFiles) {
      const epRelPath = `surface/hosts/${entry.name}/endpoints/${fileName}`;
      const epFullPath = path.join(repoDir, epRelPath);
      const rawYaml = await fs.readFile(epFullPath, 'utf8');
      existingFileContents.set(epRelPath, rawYaml);

      const parsedEp = CanonicalEndpointSchema.parse(parseYaml(rawYaml));
      const key = buildEndpointKey(
        parsedEp.host,
        parsedEp.method,
        parsedEp.canonicalPath,
      );
      endpointsMap.set(key.endpointId, {
        endpoint: {
          ...parsedEp,
          endpointId: key.endpointId,
          host: key.host,
          method: HttpMethodSchema.parse(key.method),
          canonicalPath: key.canonicalPath,
          observedRawPaths: uniqueSorted(parsedEp.observedRawPaths),
          sources: uniqueSorted(parsedEp.sources),
          parameters: uniqueSorted(parsedEp.parameters),
          responseContentTypes: uniqueSorted(parsedEp.responseContentTypes),
        },
        repoRelativePath: key.repoRelativePath,
      });
    }
  }

  for (const batch of input.batches) {
    for (const incomingHost of batch.hosts) {
      const normalized = normalizeHostname(incomingHost.hostname);
      if (!normalized) {
        continue;
      }

      const existingHost = hostsMap.get(normalized);
      const incomingSources =
        incomingHost.sources.length > 0
          ? incomingHost.sources
          : [batch.agentRole];

      if (!existingHost) {
        const created: HostEntity = {
          hostname: normalized,
          discoveredAt: incomingHost.discoveredAt || batch.createdAt,
          sources: uniqueSorted(incomingSources),
          securityHeaders: sortRecordKeys(incomingHost.securityHeaders),
          fingerprints: uniqueSorted(incomingHost.fingerprints),
        };
        if (incomingHost.statusCode !== undefined) {
          created.statusCode = incomingHost.statusCode;
        }
        if (incomingHost.serverHeader !== undefined) {
          created.serverHeader = incomingHost.serverHeader;
        }
        hostsMap.set(normalized, created);
      } else {
        const merged: HostEntity = {
          hostname: normalized,
          discoveredAt: minTimestamp(
            existingHost.discoveredAt,
            incomingHost.discoveredAt || batch.createdAt,
          ),
          sources: uniqueSorted([
            ...existingHost.sources,
            ...incomingSources,
          ]),
          securityHeaders: sortRecordKeys({
            ...existingHost.securityHeaders,
            ...incomingHost.securityHeaders,
          }),
          fingerprints: uniqueSorted([
            ...existingHost.fingerprints,
            ...incomingHost.fingerprints,
          ]),
        };
        const statusCode = incomingHost.statusCode ?? existingHost.statusCode;
        if (statusCode !== undefined) {
          merged.statusCode = statusCode;
        }
        const serverHeader =
          incomingHost.serverHeader ?? existingHost.serverHeader;
        if (serverHeader !== undefined) {
          merged.serverHeader = serverHeader;
        }
        hostsMap.set(normalized, merged);
      }
    }

    for (const item of batch.endpoints) {
      const key = buildEndpointKey(item.host, item.method, item.rawPath);
      if (!key.host) {
        continue;
      }

      const existingHost = hostsMap.get(key.host);
      if (!existingHost) {
        hostsMap.set(key.host, {
          hostname: key.host,
          discoveredAt: batch.createdAt,
          sources: uniqueSorted([item.source]),
          securityHeaders: {},
          fingerprints: [],
        });
      } else {
        hostsMap.set(key.host, {
          ...existingHost,
          discoveredAt: minTimestamp(existingHost.discoveredAt, batch.createdAt),
          sources: uniqueSorted([...existingHost.sources, item.source]),
        });
      }

      const existingEntry = endpointsMap.get(key.endpointId);
      const method = HttpMethodSchema.parse(key.method);

      if (!existingEntry) {
        const createdEp: CanonicalEndpoint = {
          endpointId: key.endpointId,
          host: key.host,
          method,
          canonicalPath: key.canonicalPath,
          observedRawPaths: uniqueSorted([item.rawPath]),
          sources: uniqueSorted([item.source]),
          parameters: uniqueSorted(item.parameters),
          responseContentTypes: uniqueSorted(
            item.responseContentType ? [item.responseContentType] : [],
          ),
          firstSeenAt: batch.createdAt,
          lastUpdatedAt: batch.createdAt,
        };
        if (item.authRequired !== undefined) {
          createdEp.authRequired = item.authRequired;
        }
        endpointsMap.set(key.endpointId, {
          endpoint: createdEp,
          repoRelativePath: key.repoRelativePath,
        });
      } else {
        const prev = existingEntry.endpoint;
        const mergedAuth = mergeAuthRequired(
          prev.authRequired,
          item.authRequired,
        );
        const mergedEp: CanonicalEndpoint = {
          endpointId: key.endpointId,
          host: key.host,
          method,
          canonicalPath: key.canonicalPath,
          observedRawPaths: uniqueSorted([
            ...prev.observedRawPaths,
            item.rawPath,
          ]),
          sources: uniqueSorted([...prev.sources, item.source]),
          parameters: uniqueSorted([...prev.parameters, ...item.parameters]),
          responseContentTypes: uniqueSorted([
            ...prev.responseContentTypes,
            ...(item.responseContentType ? [item.responseContentType] : []),
          ]),
          firstSeenAt: minTimestamp(prev.firstSeenAt, batch.createdAt),
          lastUpdatedAt: maxTimestamp(prev.lastUpdatedAt, batch.createdAt),
        };
        if (mergedAuth !== undefined) {
          mergedEp.authRequired = mergedAuth;
        }
        endpointsMap.set(key.endpointId, {
          endpoint: mergedEp,
          repoRelativePath: key.repoRelativePath,
        });
      }
    }
  }

  const mergedHosts = Array.from(hostsMap.values()).sort((a, b) =>
    compareCodeUnits(a.hostname, b.hostname),
  );
  const sortedEndpointEntries = Array.from(endpointsMap.values()).sort((a, b) =>
    compareCodeUnits(a.endpoint.endpointId, b.endpoint.endpointId),
  );
  const mergedEndpoints = sortedEndpointEntries.map((entry) => entry.endpoint);

  const filesToCommit: Array<{ relativePath: string; content: string }> = [];

  for (const host of mergedHosts) {
    const relPath = `surface/hosts/${host.hostname}/host.yaml`;
    const serialized = stringifyYaml(HostEntitySchema.parse(host));
    if (existingFileContents.get(relPath) !== serialized) {
      filesToCommit.push({ relativePath: relPath, content: serialized });
    }
  }

  for (const entry of sortedEndpointEntries) {
    const serialized = stringifyYaml(
      CanonicalEndpointSchema.parse(entry.endpoint),
    );
    if (existingFileContents.get(entry.repoRelativePath) !== serialized) {
      filesToCommit.push({
        relativePath: entry.repoRelativePath,
        content: serialized,
      });
    }
  }

  let commitSha: string | undefined;
  if (filesToCommit.length > 0) {
    const commitResult = await input.worktreeManager.commitFilesOnMain(
      filesToCommit,
      `chore(surface): reduce ${input.batches.length} observation batch(es) into canonical surface`,
    );
    commitSha = commitResult.commitSha;
  }

  if (input.stateDb) {
    await input.stateDb.syncSurface(
      input.engagementId,
      mergedHosts,
      mergedEndpoints,
    );
  }

  const result: ReduceObservationsResult = {
    hosts: mergedHosts,
    endpoints: mergedEndpoints,
  };
  if (commitSha !== undefined) {
    result.commitSha = commitSha;
  }
  return result;
}
