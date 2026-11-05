export interface LockRecord {
  resourceKey: string;
  ownerTaskId: string;
  fencingToken: number;
  acquiredAtMs: number;
  expiresAtMs: number;
}

export type AcquireLockResult =
  | { acquired: true; lock: LockRecord }
  | { acquired: false; holderTaskId: string; expiresAtMs: number };

export interface FencingValidationResult {
  valid: boolean;
  reason?: string;
}

export class LockManager {
  private epochCounter = 0;
  private readonly activeLocks = new Map<string, LockRecord>();
  private readonly highestTokenByResource = new Map<string, number>();

  acquire(
    resourceKey: string,
    ownerTaskId: string,
    ttlMs: number = 300_000,
    nowMs: number = Date.now(),
  ): AcquireLockResult {
    const existing = this.activeLocks.get(resourceKey);
    if (
      existing !== undefined &&
      existing.expiresAtMs > nowMs &&
      existing.ownerTaskId !== ownerTaskId
    ) {
      return {
        acquired: false,
        holderTaskId: existing.ownerTaskId,
        expiresAtMs: existing.expiresAtMs,
      };
    }

    this.epochCounter += 1;
    const fencingToken = this.epochCounter;
    const lock: LockRecord = {
      resourceKey,
      ownerTaskId,
      fencingToken,
      acquiredAtMs: nowMs,
      expiresAtMs: nowMs + ttlMs,
    };

    this.activeLocks.set(resourceKey, lock);
    this.highestTokenByResource.set(resourceKey, fencingToken);

    return {
      acquired: true,
      lock: { ...lock },
    };
  }

  heartbeat(
    resourceKey: string,
    ownerTaskId: string,
    fencingToken: number,
    ttlMs: number = 300_000,
    nowMs: number = Date.now(),
  ): boolean {
    const existing = this.activeLocks.get(resourceKey);
    if (
      !existing ||
      existing.expiresAtMs <= nowMs ||
      existing.ownerTaskId !== ownerTaskId ||
      existing.fencingToken !== fencingToken
    ) {
      return false;
    }

    existing.expiresAtMs = nowMs + ttlMs;
    return true;
  }

  validateFencingToken(
    resourceKey: string,
    fencingToken: number,
    nowMs: number = Date.now(),
  ): FencingValidationResult {
    const highest = this.highestTokenByResource.get(resourceKey);
    if (highest !== undefined && fencingToken < highest) {
      return { valid: false, reason: 'SUPERSEDED_FENCING_TOKEN' };
    }

    const lock = this.activeLocks.get(resourceKey);
    if (
      !lock ||
      lock.expiresAtMs <= nowMs ||
      lock.fencingToken !== fencingToken
    ) {
      return { valid: false, reason: 'LOCK_EXPIRED_OR_MISSING' };
    }

    return { valid: true };
  }

  release(
    resourceKey: string,
    ownerTaskId: string,
    fencingToken: number,
  ): boolean {
    const existing = this.activeLocks.get(resourceKey);
    if (
      !existing ||
      existing.ownerTaskId !== ownerTaskId ||
      existing.fencingToken !== fencingToken
    ) {
      return false;
    }

    this.activeLocks.delete(resourceKey);
    return true;
  }

  listActiveLocks(nowMs: number = Date.now()): LockRecord[] {
    const active: LockRecord[] = [];
    for (const lock of this.activeLocks.values()) {
      if (lock.expiresAtMs > nowMs) {
        active.push({ ...lock });
      }
    }
    return active;
  }
}
