import { randomUUID } from 'node:crypto';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { sha256Hex } from '@opencyber/shared';

const SHA256_HEX_RE = /^[a-f0-9]{64}$/i;

export interface StoredBlobMetadata {
  sha256: string;
  mediaType: string;
  sizeBytes: number;
  createdAt: string;
  metadata: Record<string, string>;
}

export interface PutBlobResult {
  sha256: string;
  blobPath: string;
  sizeBytes: number;
}

export interface RetrievedBlob {
  content: Buffer;
  mediaType: string;
  sizeBytes: number;
  metadata: Record<string, string>;
}

export class BlobVault {
  private readonly vaultRootDir: string;

  constructor(vaultRootDir: string) {
    this.vaultRootDir = path.resolve(vaultRootDir);
  }

  private resolveObjectPaths(sha256: string): {
    bucketDir: string;
    blobPath: string;
    metaPath: string;
  } | null {
    const normalized = sha256.trim().toLowerCase();
    if (!SHA256_HEX_RE.test(normalized)) {
      return null;
    }

    const bucketDir = path.join(
      this.vaultRootDir,
      'objects',
      normalized.slice(0, 2),
    );
    return {
      bucketDir,
      blobPath: path.join(bucketDir, `${normalized}.blob`),
      metaPath: path.join(bucketDir, `${normalized}.meta.json`),
    };
  }

  async put(
    content: string | Uint8Array,
    mediaType: string = 'application/octet-stream',
    metadata: Record<string, string> = {},
  ): Promise<PutBlobResult> {
    const rawBuffer =
      typeof content === 'string'
        ? Buffer.from(content, 'utf8')
        : Buffer.from(content);
    const sha256 = sha256Hex(rawBuffer);
    const sizeBytes = rawBuffer.byteLength;

    const bucketDir = path.join(
      this.vaultRootDir,
      'objects',
      sha256.slice(0, 2),
    );
    const blobPath = path.join(bucketDir, `${sha256}.blob`);
    const metaPath = path.join(bucketDir, `${sha256}.meta.json`);

    await fs.mkdir(bucketDir, { recursive: true });

    const tmpSuffix = randomUUID();
    const tmpBlobPath = path.join(bucketDir, `.${sha256}.${tmpSuffix}.blob.tmp`);
    const tmpMetaPath = path.join(bucketDir, `.${sha256}.${tmpSuffix}.meta.tmp`);

    const metaRecord: StoredBlobMetadata = {
      sha256,
      mediaType,
      sizeBytes,
      createdAt: new Date().toISOString(),
      metadata: { ...metadata },
    };

    await fs.writeFile(tmpBlobPath, rawBuffer);
    await fs.rename(tmpBlobPath, blobPath);

    await fs.writeFile(tmpMetaPath, JSON.stringify(metaRecord, null, 2), 'utf8');
    await fs.rename(tmpMetaPath, metaPath);

    return {
      sha256,
      blobPath,
      sizeBytes,
    };
  }

  async get(sha256: string): Promise<RetrievedBlob | null> {
    const paths = this.resolveObjectPaths(sha256);
    if (!paths) {
      return null;
    }

    let content: Buffer;
    try {
      content = await fs.readFile(paths.blobPath);
    } catch (err: unknown) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
        return null;
      }
      throw err;
    }

    let mediaType = 'application/octet-stream';
    let metadata: Record<string, string> = {};

    try {
      const rawMeta = await fs.readFile(paths.metaPath, 'utf8');
      const parsed = JSON.parse(rawMeta) as Partial<StoredBlobMetadata>;
      if (typeof parsed.mediaType === 'string' && parsed.mediaType.length > 0) {
        mediaType = parsed.mediaType;
      }
      if (parsed.metadata && typeof parsed.metadata === 'object') {
        metadata = parsed.metadata;
      }
    } catch (err: unknown) {
      if ((err as NodeJS.ErrnoException).code !== 'ENOENT') {
        throw err;
      }
    }

    return {
      content,
      mediaType,
      sizeBytes: content.byteLength,
      metadata,
    };
  }

  async has(sha256: string): Promise<boolean> {
    const paths = this.resolveObjectPaths(sha256);
    if (!paths) {
      return false;
    }

    try {
      await fs.access(paths.blobPath);
      return true;
    } catch {
      return false;
    }
  }
}
