import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { onenoteHtmlToText } from "../dist/onenote.js";

describe("OneNote HTML to text", () => {
  it("decodes entities safely and keeps unknown or invalid ones literal", () => {
    const { text } = onenoteHtmlToText("<p>a &lt;b&gt; &#x1F600; &#128512; &bogus; &#0; &#xD800; &#99999999;</p>", 1000);
    assert.equal(text, "a <b> 😀 😀 &bogus; &#0; &#xD800; &#99999999;");
  });
  it("does not turn decoded text into tags", () => {
    const { text } = onenoteHtmlToText("<p>&lt;script&gt;alert(1)&lt;/script&gt;</p>", 1000);
    assert.equal(text, "<script>alert(1)</script>", "shown as text, never parsed as markup");
  });
  it("cuts on a code point boundary and reports the full length", () => {
    const page = onenoteHtmlToText(`<p>${"😀".repeat(10)}</p>`, 3);
    assert.deepEqual(page, { text: "😀😀😀", truncated: true, totalChars: 10 });
  });
  it("drops scripts, styles and comments, and copes with stray angle brackets", () => {
    const { text } = onenoteHtmlToText("<p>1 < 2</p><script>x()</script><style>p{}</style><!-- c --><p>ok</p>", 1000);
    assert.equal(text, "1 < 2\nok");
  });
});
