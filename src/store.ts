import { TableClient, RestError } from "@azure/data-tables";
import { DefaultAzureCredential } from "@azure/identity";
import { Sealer } from "./crypto.js";

export type Kind = "client" | "txn" | "grant" | "code" | "access" | "refresh" | "refreshFamily" | "revoked";

/**
 * Expiring key-value storage. Every value is JSON, encrypted with AES-GCM and bound to
 * its kind and key, so a storage leak exposes neither mailbox tokens nor client secrets.
 */
export interface Store {
  put(kind: Kind, key: string, value: object, ttlSeconds: number): Promise<void>;
  get<T>(kind: Kind, key: string): Promise<T | undefined>;
  /** Removes and returns the value; resolves undefined if another caller consumed it first. */
  take<T>(kind: Kind, key: string): Promise<T | undefined>;
  delete(kind: Kind, key: string): Promise<void>;
}

interface Row {
  sealed: string;
  expiresAt: number;
}

abstract class SealedStore implements Store {
  constructor(private readonly sealer: Sealer) {}

  protected abstract write(kind: Kind, key: string, row: Row): Promise<void>;
  protected abstract read(kind: Kind, key: string): Promise<Row | undefined>;
  /** Deletes a row only if it exists; reports whether this call removed it. */
  protected abstract remove(kind: Kind, key: string): Promise<boolean>;

  async put(kind: Kind, key: string, value: object, ttlSeconds: number): Promise<void> {
    await this.write(kind, key, {
      sealed: this.sealer.seal(JSON.stringify(value), `${kind}/${key}`),
      expiresAt: Date.now() + ttlSeconds * 1000,
    });
  }

  async get<T>(kind: Kind, key: string): Promise<T | undefined> {
    const row = await this.read(kind, key);
    if (!row) return undefined;
    if (row.expiresAt <= Date.now()) {
      await this.remove(kind, key);
      return undefined;
    }
    return JSON.parse(this.sealer.open(row.sealed, `${kind}/${key}`)) as T;
  }

  async take<T>(kind: Kind, key: string): Promise<T | undefined> {
    const value = await this.get<T>(kind, key);
    return value !== undefined && await this.remove(kind, key) ? value : undefined;
  }

  async delete(kind: Kind, key: string): Promise<void> {
    await this.remove(kind, key);
  }
}

export class MemoryStore extends SealedStore {
  private readonly rows = new Map<string, Row>();

  protected async write(kind: Kind, key: string, row: Row): Promise<void> {
    this.rows.set(`${kind}/${key}`, row);
  }

  protected async read(kind: Kind, key: string): Promise<Row | undefined> {
    return this.rows.get(`${kind}/${key}`);
  }

  protected async remove(kind: Kind, key: string): Promise<boolean> {
    return this.rows.delete(`${kind}/${key}`);
  }
}

/** Azure Table storage, authenticated with the app's managed identity (no connection strings). */
export class TableStore extends SealedStore {
  private ready: Promise<void> | undefined;

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
      return { sealed: entity.sealed, expiresAt: Number(entity.expiresAt) };
    } catch (error) {
      if (error instanceof RestError && error.statusCode === 404) return undefined;
      throw error;
    }
  }

  protected async remove(kind: Kind, key: string): Promise<boolean> {
    await this.init();
    try {
      await this.table.deleteEntity(kind, key);
      return true;
    } catch (error) {
      if (error instanceof RestError && error.statusCode === 404) return false;
      throw error;
    }
  }
}
