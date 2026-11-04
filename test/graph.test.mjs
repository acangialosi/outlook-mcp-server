import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { GraphClient } from "../dist/graph.js";

function client() {
  const requests = [];
  const graph = new GraphClient(async () => "synthetic-graph-token", async (url) => {
    requests.push(url.href);
    return Response.json({ value: [{ id: "m1" }] });
  });
  return { graph, requests };
}

describe("Graph nextLink collection isolation", () => {
  it("accepts equivalent slash/OData paths and route casing without changing identifier case", async () => {
    const { graph, requests } = client();
    for (const [path, nextLink] of [
      ["/me/mailFolders/AbCd/messages", "https://graph.microsoft.com/v1.0/ME/MAILFOLDERS('AbCd')/MESSAGES?$skip=1"],
      ["/me/mailFolders('AbCd')/messages", "https://graph.microsoft.com/v1.0/me/mailFolders/AbCd/messages?$skip=1"],
      ["/me/mailFolders/MeSsAgEs/messages", "https://graph.microsoft.com/v1.0/ME/MAILFOLDERS('MeSsAgEs')/MESSAGES"],
      ["/me/mailFolders/O'Brian/messages", "https://graph.microsoft.com/v1.0/me/mailFolders('O''Brian')/messages"],
      ["/me/mailFolders/AbC%2FDeF/messages", "https://graph.microsoft.com/v1.0/me/mailFolders('AbC%2FDeF')/messages"],
      ["/me/messages", "https://graph.microsoft.com/v1.0/ME/MESSAGES?$skip=1"],
      ["/me/calendarView", "https://graph.microsoft.com/v1.0/ME/CALENDARVIEW?$skip=1"],
    ]) {
      assert.deepEqual((await graph.page(path, {}, nextLink)).items, [{ id: "m1" }]);
      assert.equal(requests.at(-1), new URL(nextLink).href);
    }
  });

  it("rejects different case-sensitive folder IDs before requesting a token or sending a request", async () => {
    let tokens = 0;
    const graph = new GraphClient(async () => { tokens++; return "synthetic-graph-token"; },
      async () => { throw new Error("No request expected"); });
    for (const nextLink of [
      "https://graph.microsoft.com/v1.0/me/mailFolders/aBcD/messages",
      "https://graph.microsoft.com/v1.0/me/mailFolders('aBcD')/messages",
    ]) {
      await assert.rejects(graph.page("/me/mailFolders/AbCd/messages", {}, nextLink),
        /nextLink does not belong to this tool's collection/);
    }
    assert.equal(tokens, 0);
  });

  it("does not mistake identifier text for route names or encoded slashes for path separators", async () => {
    const { graph, requests } = client();
    for (const [path, nextLink] of [
      ["/me/mailFolders/MeSsAgEs/messages", "https://graph.microsoft.com/v1.0/me/mailFolders/messages/messages"],
      ["/me/mailFolders/AbC%2Fmessages/messages", "https://graph.microsoft.com/v1.0/me/mailFolders/AbC/messages/messages"],
    ]) {
      await assert.rejects(graph.page(path, {}, nextLink), /nextLink does not belong to this tool's collection/);
    }
    assert.deepEqual(requests, []);
  });
});
