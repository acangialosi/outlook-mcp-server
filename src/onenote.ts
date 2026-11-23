/**
 * Plain-text rendering of OneNote page HTML (GET /me/onenote/pages/{id}/content).
 *
 * Agents need the words, not the markup: text is several times smaller than the HTML and carries no
 * active content. Structure that matters for reading survives: paragraphs and headings become lines,
 * list items become "- ", to-do tags become "[ ]"/"[x]", tables become tab-separated rows, links keep
 * their http(s) target, and images/attachments leave a short placeholder. Scripts, styles and every
 * other tag are dropped. This is a text extractor, not a sanitizer for re-rendering HTML.
 */

const BLOCK = new Set(["p", "div", "br", "h1", "h2", "h3", "h4", "h5", "h6", "li", "tr", "table", "ul", "ol",
  "blockquote", "pre", "hr", "title", "body", "html", "head"]);

const NAMED: Record<string, string> = { amp: "&", lt: "<", gt: ">", quot: "\"", apos: "'", nbsp: " ", "#39": "'" };

function decode(text: string): string {
  return text.replace(/&(#x[0-9a-f]{1,6}|#[0-9]{1,7}|[a-z]{2,8});/gi, (match, entity: string) => {
    const lower = entity.toLowerCase();
    if (lower.startsWith("#x") || lower.startsWith("#")) {
      const code = lower.startsWith("#x") ? parseInt(lower.slice(2), 16) : parseInt(lower.slice(1), 10);
      return Number.isFinite(code) && code > 0 && code <= 0x10ffff && !(code >= 0xd800 && code <= 0xdfff)
        ? String.fromCodePoint(code) : match;
    }
    return NAMED[lower] ?? match;
  });
}

function attribute(tag: string, name: string): string | undefined {
  const match = new RegExp(`\\s${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, "i").exec(tag);
  const value = match?.[1] ?? match?.[2] ?? match?.[3];
  return value === undefined ? undefined : decode(value);
}

export interface PageText {
  text: string;
  /** True when the text was cut at `maxChars`. */
  truncated: boolean;
  /** Length of the full rendered text, before any truncation. */
  totalChars: number;
}

export function onenoteHtmlToText(html: string, maxChars: number): PageText {
  const out: string[] = [];
  const links: string[] = [];
  // Drop non-content elements wholesale (with their contents) and comments.
  const source = html
    .replace(/<!--[\s\S]*?-->/g, "")
    .replace(/<![^>]*>|<\?[^>]*\?>/g, "") // <!DOCTYPE …>, <![CDATA[…]]>-style and <?xml …?> declarations
    .replace(/<(script|style|head|noscript|template)\b[\s\S]*?<\/\1\s*>/gi, (m, tag: string) => tag.toLowerCase() === "head" ? (/<title\b[^>]*>([\s\S]*?)<\/title>/i.exec(m)?.[0] ?? "") : "");

  const pattern = /<\/?([a-zA-Z][a-zA-Z0-9]*)\b[^>]*>|([^<]+)|(<)/g;
  for (const match of source.matchAll(pattern)) {
    const [whole, rawTag, text] = match;
    if (text !== undefined || match[3]) { out.push(decode(text ?? "<").replace(/\s+/g, " ")); continue; }
    const tag = rawTag!.toLowerCase();
    const closing = whole.startsWith("</");
    if (!closing && tag === "li") { out.push("\n- "); continue; }
    if (!closing && (tag === "td" || tag === "th")) { out.push("\t"); continue; }
    if (!closing && (tag === "p" || tag === "div" || /^h[1-6]$/.test(tag))) {
      const dataTag = attribute(whole, "data-tag") ?? "";
      out.push("\n");
      if (/\bto-do:completed\b/.test(dataTag)) out.push("[x] ");
      else if (/\bto-do\b/.test(dataTag)) out.push("[ ] ");
      continue;
    }
    if (!closing && tag === "img") {
      const alt = attribute(whole, "alt")?.trim();
      out.push(alt ? ` [image: ${alt}] ` : " [image] ");
      continue;
    }
    if (!closing && tag === "object") {
      const name = attribute(whole, "data-attachment")?.trim();
      out.push(name ? ` [attachment: ${name}] ` : " [attachment] ");
      continue;
    }
    if (tag === "a") {
      if (!closing) links.push(attribute(whole, "href") ?? "");
      else {
        const href = links.pop() ?? "";
        if (/^https?:\/\//i.test(href)) out.push(` (${href})`);
      }
      continue;
    }
    if (BLOCK.has(tag)) out.push("\n");
  }

  const full = out.join("")
    .split("\n").map((line) => line.replace(/[ \t]*\t[ \t]*/g, "\t").replace(/ {2,}/g, " ").trim()).join("\n")
    .replace(/\n{2,}/g, "\n").trim(); // one line per block; blank lines only waste tokens
  // Cut on a code point boundary so a surrogate pair is never split.
  const chars = Array.from(full);
  return chars.length > maxChars
    ? { text: chars.slice(0, maxChars).join(""), truncated: true, totalChars: chars.length }
    : { text: full, truncated: false, totalChars: chars.length };
}
