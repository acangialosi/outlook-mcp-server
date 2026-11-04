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
  it("revisits previously live records despite sustained insertion between every batch", async (t) => {
    let now = Date.now();
    t.mock.method(Date, "now", () => now);
    const store = new MemoryStore(new Sealer(randomBytes(32)));
    t.after(() => store.close());
    await store.put("refreshFamily", "synthetic-expiring", {}, 1);
    for (let i = 0; i < 200; i++) await store.put("access", `synthetic-initial-${i}`, {}, 3600);
    assert.equal(await store.cleanupExpired(), 0);
    now += 2000;
    let removed = 0;
    for (let batch = 0; batch < 3; batch++) {
      for (let i = 0; i < 100; i++) await store.put("access", `synthetic-new-${batch}-${i}`, {}, 3600);
      removed += await store.cleanupExpired();
    }
    assert.equal(removed, 1, "the next finite sweep must revisit the now-expired record");
    assert.equal(await store.read("refreshFamily", "synthetic-expiring"), undefined);
  });

  for (const backend of ["memory", "table"]) {
    for (const operation of ["get", "take", "update", "cleanupExpired"]) {
      it(`retains historical families after downtime during ${operation}, beyond the original grant deadline (${backend})`, async (t) => {
        let now = Date.now();
        t.mock.method(Date, "now", () => now);
        const day = 24 * 60 * 60 * 1000;
        const { first, second } = pair(backend);
        t.after(() => { first.close(); second.close(); });
        const family = { grantId: "synthetic-active", clientId: "synthetic-client" };
        await first.put("grant", family.grantId, { expiresAt: now + 90 * day }, 90 * 86400);
        await first.put("refreshFamily", "synthetic-history", family, 30 * 86400);
        now += 80 * day;
        assert.equal(await second.update("grant", family.grantId,
          (grant) => ({ ...grant, expiresAt: now + 90 * day }), 90 * 86400), true);
        now += 20 * day;
        if (operation === "cleanupExpired") {
          assert.equal(await first.cleanupExpired(), 0);
        } else if (operation === "update") {
          assert.equal(await second.update("refreshFamily", "synthetic-history",
            (value) => ({ ...value, reviewed: true }), 30 * 86400), true);
        } else {
          assert.deepEqual(await second[operation]("refreshFamily", "synthetic-history"), family);
        }
        assert.deepEqual(await first.get("refreshFamily", "synthetic-history"),
          operation === "take" ? undefined : { ...family, ...(operation === "update" ? { reviewed: true } : {}) });
        if (operation !== "take") {
          assert.ok((await first.read("refreshFamily", "synthetic-history")).expiresAt > now);
        }
        if (operation === "cleanupExpired") {
          now += 71 * day;
          assert.ok(await first.cleanupExpired());
          assert.equal(await second.read("refreshFamily", "synthetic-history"), undefined,
            "retained history must be collected once the sliding session ends");
        }
      });
    }

    it(`eventually collects missing, revoked, expired and logically expired families (${backend})`, async (t) => {
      const { first, second } = pair(backend);
      t.after(() => { first.close(); second.close(); });
      const now = Date.now();
      for (const state of ["missing", "revoked", "expired", "logical"]) {
        const grantId = `synthetic-${state}`;
        if (state !== "missing") {
          await first.put("grant", grantId, { expiresAt: state === "logical" ? now - 1 : now + 3600000 },
            state === "expired" ? -1 : 3600);
        }
        if (state === "revoked") await first.put("revoked", grantId, {}, 3600);
        await first.put("refreshFamily", grantId, { grantId, clientId: "synthetic-client" }, -1);
      }
      await first.cleanupExpired();
      await first.cleanupExpired();
      for (const state of ["missing", "revoked", "expired", "logical"]) {
        assert.equal(await second.read("refreshFamily", `synthetic-${state}`), undefined);
      }
      assert.ok(await first.get("revoked", "synthetic-revoked"));
      assert.equal(await first.get("grant", "synthetic-logical"), undefined);
    });

    it(`fences a delayed grant renewal when session-end collection wins (${backend})`, async (t) => {
      let now = Date.now();
      t.mock.method(Date, "now", () => now);
      const { first, second } = pair(backend);
      t.after(() => { first.close(); second.close(); });
      const family = { grantId: "synthetic-ending", clientId: "synthetic-client" };
      await first.put("grant", family.grantId, { expiresAt: now + 1000 }, 1);
      await first.put("refreshFamily", "synthetic-history", family, 1);
      let release, entered;
      const gate = new Promise((resolve) => { release = resolve; });
      const started = new Promise((resolve) => { entered = resolve; });
      const replace = first.replace.bind(first);
      first.replace = async (...args) => {
        entered();
        await gate;
        return replace(...args);
      };
      const renewing = first.update("grant", family.grantId,
        (grant) => ({ ...grant, expiresAt: now + 120000 }), 120);
      await started;
      now += 2000;
      assert.equal(await second.get("refreshFamily", "synthetic-history"), undefined);
      release();
      assert.equal(await renewing, false);
      assert.equal(await second.get("grant", family.grantId), undefined);
      assert.equal(await second.read("refreshFamily", "synthetic-history"), undefined);
    });

    for (const operation of ["get", "cleanupExpired"]) {
      it(`preserves family history when deferred grant renewal wins expiration cleanup during ${operation} (${backend})`, async (t) => {
        let now = Date.now();
        t.mock.method(Date, "now", () => now);
        const { first, second } = pair(backend);
        t.after(() => { first.close(); second.close(); });
        const family = { grantId: "synthetic-renewal", clientId: "synthetic-client" };
        await first.put("refreshFamily", "synthetic-history", family, 1);
        await first.put("grant", family.grantId, { expiresAt: now + 1000 }, 1);
        let releaseRenewal, renewalEntered, releaseDeletion, deletionEntered;
        const renewalGate = new Promise((resolve) => { releaseRenewal = resolve; });
        const renewalStarted = new Promise((resolve) => { renewalEntered = resolve; });
        const deletionGate = new Promise((resolve) => { releaseDeletion = resolve; });
        const deletionStarted = new Promise((resolve) => { deletionEntered = resolve; });
        const replace = first.replace.bind(first);
        first.replace = async (...args) => {
          if (args[0] === "grant") {
            renewalEntered();
            await renewalGate;
          }
          return replace(...args);
        };
        const renewing = first.update("grant", family.grantId,
          (grant) => ({ ...grant, expiresAt: now + 120000 }), 120);
        await renewalStarted;
        now += 2000;
        const remove = second.remove.bind(second);
        second.remove = async (...args) => {
          if (args[0] === "grant") {
            deletionEntered();
            await deletionGate;
          }
          return remove(...args);
        };
        const collecting = operation === "get" ?
          second.get("refreshFamily", "synthetic-history") : second.cleanupExpired();
        await deletionStarted;
        releaseRenewal();
        assert.equal(await renewing, true);
        releaseDeletion();
        assert.deepEqual(await collecting, operation === "get" ? family : 0);
        assert.deepEqual(await first.get("refreshFamily", "synthetic-history"), family);
      });

      it(`preserves concurrently replaced family metadata during retention ${operation} (${backend})`, async (t) => {
        const { first, second, calls } = pair(backend);
        t.after(() => { first.close(); second.close(); });
        const family = { grantId: "synthetic-active", clientId: "synthetic-client" };
        await first.put("grant", family.grantId, {}, 3600);
        await first.put("refreshFamily", "synthetic-history", family, -1);
        const replace = first.replace.bind(first);
        let raced = false;
        first.replace = async (...args) => {
          if (!raced && args[0] === "refreshFamily") {
            raced = true;
            await second.put("refreshFamily", "synthetic-history", { ...family, generation: 2 }, 3600);
          }
          return replace(...args);
        };
        const result = operation === "get" ?
          await first.get("refreshFamily", "synthetic-history") : await first.cleanupExpired();
        assert.deepEqual(result, operation === "get" ? { ...family, generation: 2 } : 0);
        assert.deepEqual(await second.get("refreshFamily", "synthetic-history"), { ...family, generation: 2 });
        if (backend === "table") assert.ok(calls.updates.length > 0, "retention must use an ETag-conditional write");
      });
    }

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
