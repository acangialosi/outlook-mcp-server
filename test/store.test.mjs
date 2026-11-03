import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { describe, it } from "node:test";
import { RestError } from "@azure/data-tables";
import { Sealer } from "../dist/crypto.js";
import { MemoryStore, TableStore } from "../dist/store.js";

function fakeTable() {
  const rows = new Map();
  let version = 0;
  const calls = { pages: [], deletes: [], updates: [] };
  const failure = (statusCode) => new RestError("Synthetic storage failure", { statusCode });
  const table = {
    beforeDelete: undefined,
    beforeUpdate: undefined,
    async createTable() {},
    async upsertEntity(entity) {
      rows.set(`${entity.partitionKey}/${entity.rowKey}`, { ...entity, etag: `${++version}` });
    },
    async getEntity(kind, key) {
      const row = rows.get(`${kind}/${key}`);
      if (!row) throw failure(404);
      return { ...row };
    },
    async updateEntity(entity, mode, options) {
      calls.updates.push(options);
      await table.beforeUpdate?.(entity);
      const id = `${entity.partitionKey}/${entity.rowKey}`;
      const row = rows.get(id);
      if (!row) throw failure(404);
      assert.equal(mode, "Replace");
      assert.ok(options.etag && options.etag !== "*", "updates must use the observed ETag");
      if (row.etag !== options.etag) throw failure(412);
      rows.set(id, { ...entity, etag: `${++version}` });
    },
    async deleteEntity(kind, key, options) {
      calls.deletes.push({ kind, key, options });
      await table.beforeDelete?.(kind, key);
      const id = `${kind}/${key}`;
      const row = rows.get(id);
      if (!row) throw failure(404);
      if (options.etag && options.etag !== row.etag) throw failure(412);
      rows.delete(id);
    },
    listEntities({ queryOptions }) {
      const cutoff = Number(/^expiresAt le (\d+)$/.exec(queryOptions.filter)[1]);
      return {
        byPage(options) {
          return {
            async next() {
              calls.pages.push({ ...options, cutoff });
              const eligible = [...rows.entries()].sort(([a], [b]) => a.localeCompare(b))
                .filter(([id, row]) => row.expiresAt <= cutoff && (!options.continuationToken || id > options.continuationToken));
              const selected = eligible.slice(0, options.maxPageSize);
              const page = selected.map(([, row]) => ({ ...row }));
              page.continuationToken = eligible.length > selected.length ? selected.at(-1)[0] : undefined;
              return { value: page, done: false };
            },
          };
        },
      };
    },
  };
  return { table, rows, calls };
}

function pair(backend) {
  const sealer = new Sealer(randomBytes(32));
  const fake = fakeTable();
  const first = backend === "memory" ? new MemoryStore(sealer) : new TableStore(sealer, fake.table);
  const second = backend === "memory" ? first : new TableStore(sealer, fake.table);
  return { first, second, ...fake };
}

describe("bounded expired-record collection", () => {
  for (const backend of ["memory", "table"]) {
    it(`collects expired-only rows in bounded batches, preserving live access, families and revocations (${backend})`, async (t) => {
      const { first, second, calls } = pair(backend);
      t.after(() => { first.close(); second.close(); });
      for (let i = 0; i < 105; i++) {
        await first.put("refresh", `synthetic-expired-${i.toString().padStart(3, "0")}`, {}, -1);
      }
      for (const kind of ["access", "refreshFamily", "revoked"]) {
        await second.put(kind, "synthetic-live", { retained: true }, 3600);
      }
      assert.equal(await first.cleanupExpired(), 100);
      assert.equal(await first.cleanupExpired(), 5);
      assert.equal(await first.cleanupExpired(), 0);
      for (const kind of ["access", "refreshFamily", "revoked"]) {
        assert.deepEqual(await second.get(kind, "synthetic-live"), { retained: true });
      }
      if (backend === "table") {
        assert.equal(calls.pages.length, 3, "each call requests only one page");
        assert.equal(calls.pages[0].maxPageSize, 100);
        assert.ok(calls.pages[1].continuationToken);
        assert.equal(calls.pages[1].cutoff, calls.pages[0].cutoff, "continuations keep the original query cutoff");
        assert.ok(calls.deletes.every(({ options }) => options.etag && options.etag !== "*"));
      }
    });

    for (const operation of ["get", "cleanupExpired"]) {
      it(`does not remove a concurrently renewed row during ${operation} (${backend})`, async (t) => {
        const { first, second } = pair(backend);
        t.after(() => { first.close(); second.close(); });
        await first.put("revoked", "synthetic-renewed", { generation: 1 }, -1);
        let release;
        let entered;
        const pending = new Promise((resolve) => { release = resolve; });
        const started = new Promise((resolve) => { entered = resolve; });
        const remove = first.remove.bind(first);
        first.remove = async (...args) => {
          entered();
          await pending;
          return remove(...args);
        };
        const deleting = operation === "get" ? first.get("revoked", "synthetic-renewed") : first.cleanupExpired();
        await started;
        await second.put("revoked", "synthetic-renewed", { generation: 2 }, 3600);
        release();
        assert.equal(await deleting, operation === "get" ? undefined : 0);
        assert.deepEqual(await second.get("revoked", "synthetic-renewed"), { generation: 2 });
      });
    }

    it(`retries atomic renewal against current credentials and never recreates a deleted grant (${backend})`, async (t) => {
      const { first, second, calls } = pair(backend);
      t.after(() => { first.close(); second.close(); });
      await first.put("grant", "synthetic-grant", { credentials: "synthetic-old", lifetime: 1 }, 60);
      const replace = first.replace.bind(first);
      let release;
      let entered;
      const pending = new Promise((resolve) => { release = resolve; });
      const started = new Promise((resolve) => { entered = resolve; });
      let deferred = true;
      first.replace = async (...args) => {
        if (deferred) {
          deferred = false;
          entered();
          await pending;
        }
        return replace(...args);
      };
      const renewing = first.update("grant", "synthetic-grant", (latest) => ({ ...latest, lifetime: 2 }), 120);
      await started;
      assert.equal(await second.update("grant", "synthetic-grant",
        (latest) => ({ ...latest, credentials: "synthetic-new" }), 180), true);
      release();
      assert.equal(await renewing, true);
      assert.deepEqual(await second.get("grant", "synthetic-grant"), { credentials: "synthetic-new", lifetime: 2 });
      if (backend === "table") assert.ok(calls.updates.length >= 3, "ETag conflict must be retried");

      first.replace = async (...args) => {
        await second.delete("grant", "synthetic-grant");
        return replace(...args);
      };
      assert.equal(await first.update("grant", "synthetic-grant", (latest) => ({ ...latest, lifetime: 3 }), 240), false);
      assert.equal(await second.get("grant", "synthetic-grant"), undefined);
      await first.put("grant", "synthetic-expired", {}, -1);
      assert.equal(await first.update("grant", "synthetic-expired", (latest) => latest, 60), false);
    });
  }

  it("resumes Azure continuations even when a filtered page is empty", async (t) => {
    const { first, second, table } = pair("table");
    t.after(() => { first.close(); second.close(); });
    await first.put("code", "synthetic-expired", {}, -1);
    const list = table.listEntities.bind(table);
    let queries = 0;
    table.listEntities = (query) => ({
      byPage(options) {
        queries++;
        if (queries === 1) {
          const page = Object.assign([], { continuationToken: "synthetic-continuation" });
          return { async next() { return { done: false, value: page }; } };
        }
        assert.equal(options.continuationToken, "synthetic-continuation");
        return list(query).byPage({ ...options, continuationToken: undefined });
      },
    });
    assert.equal(await first.cleanupExpired(), 0);
    assert.equal(queries, 1, "an empty page must not trigger an unbounded page loop");
    assert.equal(await first.cleanupExpired(), 1);
    assert.equal(queries, 2);
  });

  it("shares an in-flight batch and logs automatic cleanup failures without holding the process open", async (t) => {
    const liveStore = new MemoryStore(new Sealer(randomBytes(32)));
    assert.equal(liveStore.cleanupTimer.hasRef(), false);
    liveStore.close();
    t.mock.timers.enable({ apis: ["setInterval"] });
    const store = new MemoryStore(new Sealer(randomBytes(32)));
    t.after(() => store.close());
    const logged = t.mock.method(console, "error", () => {});
    let attempts = 0;
    store.cleanupBatch = async () => {
      attempts++;
      if (attempts <= 2) throw new Error("Synthetic cleanup failure");
      return 0;
    };
    const a = store.cleanupExpired();
    const b = store.cleanupExpired();
    assert.equal(a, b);
    await assert.rejects(a, /Synthetic cleanup failure/);
    t.mock.timers.tick(60_000);
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(attempts, 2);
    const cleanupErrors = logged.mock.calls.filter(({ arguments: args }) => /cleanup failed/.test(args[0]));
    assert.equal(cleanupErrors.length, 1);
    t.mock.timers.tick(60_000);
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(attempts, 3, "a failed automatic batch must not stop subsequent cleanup");
    store.close();
    t.mock.timers.tick(60_000);
    assert.equal(attempts, 3);
  });
});
