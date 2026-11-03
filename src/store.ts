import { TableClient, RestError } from "@azure/data-tables";
import { DefaultAzureCredential } from "@azure/identity";
import { Sealer } from "./crypto.js";

export type Kind = "client" | "txn" | "grant" | "code" | "access" | "refresh" | "refreshFamily" | "revoked";

/**
 * Expiring key-value storage; refresh-family expiry is a review deadline while its grant is live.
 * Every value is JSON, encrypted with AES-GCM and bound to
 * its kind and key, so a storage leak exposes neither mailbox tokens nor client secrets.
 */
export interface Store {
  put(kind: Kind, key: string, value: object, ttlSeconds: number): Promise<void>;
  /** Atomically changes an existing live record; the pure callback may run again on conflicts. */
  update<T extends object>(kind: Kind, key: string, change: (value: T) => T, ttlSeconds: number): Promise<boolean>;
  get<T>(kind: Kind, key: string): Promise<T | undefined>;
  /** Removes and returns the value; resolves undefined if another caller consumed it first. */
  take<T>(kind: Kind, key: string): Promise<T | undefined>;
  delete(kind: Kind, key: string): Promise<void>;
  /** Performs one bounded cleanup batch; concurrent callers share the same batch. */
  cleanupExpired(): Promise<number>;
  close(): void;
}

interface Row {
  sealed: string;
  expiresAt: number;
  etag?: string;
}

const CLEANUP_BATCH_SIZE = 100;
const CLEANUP_INTERVAL_MS = 60_000;

abstract class SealedStore implements Store {
  private readonly cleanupTimer: ReturnType<typeof setInterval>;
  private cleaning: Promise<number> | undefined;

  constructor(private readonly sealer: Sealer) {
    this.cleanupTimer = setInterval(() => {
      void this.cleanupExpired().catch((error: unknown) => {
        console.error("Expired storage cleanup failed; will retry.", error instanceof Error ? error.name : "UnknownError");
      });
    }, CLEANUP_INTERVAL_MS);
    this.cleanupTimer.unref();
  }

  protected abstract write(kind: Kind, key: string, row: Row): Promise<void>;
  protected abstract read(kind: Kind, key: string): Promise<Row | undefined>;
  protected abstract replace(kind: Kind, key: string, expected: Row, row: Row): Promise<boolean>;
  /** Deletes a row only if it exists; reports whether this call removed it. */
  protected abstract remove(kind: Kind, key: string, expected?: Row): Promise<boolean>;
  protected abstract cleanupBatch(): Promise<number>;

  cleanupExpired(): Promise<number> {
    this.cleaning ??= this.cleanupBatch().finally(() => { this.cleaning = undefined; });
    return this.cleaning;
  }

  close(): void {
    clearInterval(this.cleanupTimer);
  }

  async put(kind: Kind, key: string, value: object, ttlSeconds: number): Promise<void> {
    await this.write(kind, key, {
      sealed: this.sealer.seal(JSON.stringify(value), `${kind}/${key}`),
      expiresAt: Date.now() + ttlSeconds * 1000,
    });
  }

  private async familyRetentionUntil(key: string, row: Row): Promise<number | undefined> {
    const family = JSON.parse(this.sealer.open(row.sealed, `refreshFamily/${key}`)) as { grantId?: string };
    if (typeof family.grantId !== "string") return undefined;
    for (let attempt = 0; attempt < 8; attempt++) {
      const grant = await this.read("grant", family.grantId);
      const revoked = await this.read("revoked", family.grantId);
      if (!grant || (revoked && revoked.expiresAt > Date.now())) return undefined;
      const value = JSON.parse(this.sealer.open(grant.sealed, `grant/${family.grantId}`)) as { expiresAt?: number };
      const expiresAt = Math.min(grant.expiresAt, value.expiresAt ?? Infinity);
      if (expiresAt > Date.now()) return expiresAt;
      // Fence delayed CAS renewals before discarding their historical relationships.
      if (await this.remove("grant", family.grantId, grant)) return undefined;
    }
    throw new Error("Storage family lifecycle conflict retry limit exceeded.");
  }

  protected async collectExpired(kind: Kind, key: string, row: Row): Promise<boolean> {
    if (kind === "refreshFamily") {
      const expiresAt = await this.familyRetentionUntil(key, row);
      if (expiresAt !== undefined) {
        await this.replace(kind, key, row, { sealed: row.sealed, expiresAt });
        return false;
      }
    }
    return this.remove(kind, key, row);
  }

  private async liveRow(kind: Kind, key: string): Promise<Row | undefined> {
    for (let attempt = 0; attempt < 8; attempt++) {
      const row = await this.read(kind, key);
      if (!row || row.expiresAt > Date.now()) return row;
      if (await this.collectExpired(kind, key, row) || kind !== "refreshFamily") return undefined;
      // Reread after retention or an ETag conflict, including the replacement ETag.
    }
    throw new Error("Storage family retention conflict retry limit exceeded.");
  }

  async update<T extends object>(kind: Kind, key: string, change: (value: T) => T, ttlSeconds: number): Promise<boolean> {
    const expiresAt = Date.now() + ttlSeconds * 1000;
    for (let attempt = 0; attempt < 8; attempt++) {
      const row = await this.liveRow(kind, key);
      if (!row) return false;
      const value = JSON.parse(this.sealer.open(row.sealed, `${kind}/${key}`)) as T;
      const next = {
        sealed: this.sealer.seal(JSON.stringify(change(value)), `${kind}/${key}`),
        expiresAt: Math.max(row.expiresAt, expiresAt),
      };
      if (await this.replace(kind, key, row, next)) return true;
    }
    throw new Error("Storage update conflict retry limit exceeded.");
  }

  async get<T>(kind: Kind, key: string): Promise<T | undefined> {
    const row = await this.liveRow(kind, key);
    if (!row) return undefined;
    return JSON.parse(this.sealer.open(row.sealed, `${kind}/${key}`)) as T;
  }

  async take<T>(kind: Kind, key: string): Promise<T | undefined> {
    const row = await this.liveRow(kind, key);
    if (!row) return undefined;
    return await this.remove(kind, key, row) ?
      JSON.parse(this.sealer.open(row.sealed, `${kind}/${key}`)) as T : undefined;
  }

  async delete(kind: Kind, key: string): Promise<void> {
    await this.remove(kind, key);
  }
}

export class MemoryStore extends SealedStore {
  private readonly rows = new Map<string, Row>();
  private cleanupCursor: { entries: MapIterator<[string, Row]>; remaining: number } | undefined;

  protected async write(kind: Kind, key: string, row: Row): Promise<void> {
    this.rows.set(`${kind}/${key}`, row);
  }

  protected async read(kind: Kind, key: string): Promise<Row | undefined> {
    return this.rows.get(`${kind}/${key}`);
  }

  protected async replace(kind: Kind, key: string, expected: Row, row: Row): Promise<boolean> {
    const id = `${kind}/${key}`;
    if (this.rows.get(id) !== expected) return false;
    this.rows.set(id, row);
    return true;
  }

  protected async remove(kind: Kind, key: string, expected?: Row): Promise<boolean> {
    const id = `${kind}/${key}`;
    if (expected && this.rows.get(id) !== expected) return false;
    return this.rows.delete(id);
  }

  protected async cleanupBatch(): Promise<number> {
    // Map iterators include future insertions; cap each sweep at its initial population.
    const cursor = this.cleanupCursor ??= { entries: this.rows.entries(), remaining: this.rows.size };
    const cutoff = Date.now();
    let removed = 0;
    for (let scanned = 0; scanned < CLEANUP_BATCH_SIZE && cursor.remaining > 0; scanned++) {
      const entry = cursor.entries.next();
      if (entry.done) {
        cursor.remaining = 0;
        break;
      }
      cursor.remaining--;
      const [id, row] = entry.value;
      if (row.expiresAt > cutoff) continue;
      const separator = id.indexOf("/");
      if (await this.collectExpired(id.slice(0, separator) as Kind, id.slice(separator + 1), row)) removed++;
    }
    if (cursor.remaining === 0) this.cleanupCursor = undefined;
    return removed;
  }
}

/** Azure Table storage, authenticated with the app's managed identity (no connection strings). */
export class TableStore extends SealedStore {
  private ready: Promise<void> | undefined;
  private cleanupCursor: { cutoff: number; continuationToken?: string } | undefined;

  constructor(sealer: Sealer, private readonly table: TableClient) {
    super(sealer);
  }

  static create(sealer: Sealer, endpoint: string, tableName: string): TableStore {
    return new TableStore(sealer, new TableClient(endpoint, tableName, new DefaultAzureCredential()));
  }

  private init(): Promise<void> {
    this.ready ??= this.table.createTable().catch((error: unknown) => {
      this.ready = undefined;
      throw error;
    });
    return this.ready;
  }

  protected async write(kind: Kind, key: string, row: Row): Promise<void> {
    await this.init();
    await this.table.upsertEntity({ partitionKey: kind, rowKey: key, ...row }, "Replace");
  }

  protected async read(kind: Kind, key: string): Promise<Row | undefined> {
    await this.init();
    try {
      const entity = await this.table.getEntity<Row>(kind, key);
      return { sealed: entity.sealed, expiresAt: Number(entity.expiresAt), etag: entity.etag };
    } catch (error) {
      if (error instanceof RestError && error.statusCode === 404) return undefined;
      throw error;
    }
  }

  protected async replace(kind: Kind, key: string, expected: Row, row: Row): Promise<boolean> {
    await this.init();
    if (!expected.etag) throw new Error("Storage record is missing its ETag.");
    try {
      await this.table.updateEntity({ partitionKey: kind, rowKey: key, ...row }, "Replace", { etag: expected.etag });
      return true;
    } catch (error) {
      if (error instanceof RestError && (error.statusCode === 404 || error.statusCode === 412)) return false;
      throw error;
    }
  }

  protected async remove(kind: Kind, key: string, expected?: Row): Promise<boolean> {
    await this.init();
    if (expected && !expected.etag) throw new Error("Storage record is missing its ETag.");
    try {
      await this.table.deleteEntity(kind, key, expected ? { etag: expected.etag! } : {});
      return true;
    } catch (error) {
      if (error instanceof RestError && (error.statusCode === 404 || error.statusCode === 412)) return false;
      throw error;
    }
  }

  protected async cleanupBatch(): Promise<number> {
    await this.init();
    const cursor = this.cleanupCursor ??= { cutoff: Date.now() };
    const pages = this.table.listEntities<Row>({
      queryOptions: { filter: `expiresAt le ${cursor.cutoff}` },
    }).byPage({ maxPageSize: CLEANUP_BATCH_SIZE, continuationToken: cursor.continuationToken });
    const { value: page, done } = await pages.next();
    let removed = 0;
    if (!done) {
      for (const entity of page) {
        if (Number(entity.expiresAt) <= cursor.cutoff &&
            await this.collectExpired(entity.partitionKey as Kind, entity.rowKey!, {
              sealed: entity.sealed, expiresAt: Number(entity.expiresAt), etag: entity.etag,
            })) removed++;
      }
    }
    this.cleanupCursor = !done && page.continuationToken ?
      { cutoff: cursor.cutoff, continuationToken: page.continuationToken } : undefined;
    return removed;
  }
}
