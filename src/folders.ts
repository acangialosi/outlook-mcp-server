import type { GraphClient } from "./graph.js";

/** Folder names Graph accepts in place of an ID. */
export const WELL_KNOWN_FOLDERS = [
  "inbox", "archive", "deleteditems", "drafts", "junkemail", "sentitems", "outbox", "clutter",
  "conversationhistory", "scheduled", "msgfolderroot",
] as const;
const WELL_KNOWN = new Set<string>(WELL_KNOWN_FOLDERS);

/** Graph folder IDs are long base64-style strings; display names essentially never look like this. */
const FOLDER_ID = /^[A-Za-z0-9_=+-]{40,}$/;

/** Most folders a mailbox walk will visit, so a huge tree can't turn one call into hundreds. */
const MAX_FOLDERS = 1000;

export interface FolderInfo {
  id: string;
  displayName: string;
  /** Rooted, slash-separated path, e.g. "/Projects/Scouting" or "/Travel". Always usable as a folder reference. */
  path: string;
  parentFolderId?: string;
  totalItemCount?: number;
  unreadItemCount?: number;
  childFolderCount?: number;
}

export class FolderError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "FolderError";
  }
}

const FOLDER_SELECT = "id,displayName,parentFolderId,totalItemCount,unreadItemCount,childFolderCount";
const norm = (value: string) => value.trim().toLowerCase();
const pathKey = (path: string) => path.split("/").map(norm).filter(Boolean).join("/");

/** Lists every mail folder (breadth-first, capped) with its path. Cached for the life of the instance. */
export class FolderDirectory {
  private tree?: Promise<{ folders: FolderInfo[]; truncated: boolean }>;

  constructor(private readonly graph: GraphClient) {}

  /** Every folder (up to MAX_FOLDERS); `truncated` means the mailbox has more. */
  directory(): Promise<{ folders: FolderInfo[]; truncated: boolean }> {
    this.tree ??= this.load().catch((error) => { this.tree = undefined; throw error; });
    return this.tree;
  }

  async all(): Promise<FolderInfo[]> {
    return (await this.directory()).folders;
  }

  /** Forget the cached tree (after creating a folder). */
  invalidate(): void {
    this.tree = undefined;
  }

  /**
   * Resolves a folder reference to something Graph accepts:
   * - a well-known name (inbox, archive, …);
   * - the ID of a listed folder;
   * - a path such as "/Projects/Scouting" or "/Travel" (as list_mail_folders returns them), refused if a
   *   folder name containing "/" makes two folders share a path;
   * - a bare display name, only when exactly one folder in the whole mailbox has it.
   * Names match case-insensitively. An unlisted ID-shaped reference is passed through for Graph to judge.
   */
  async resolve(reference: string): Promise<string> {
    const ref = reference.trim();
    if (WELL_KNOWN.has(norm(ref))) return norm(ref);
    const { folders, truncated } = await this.directory();
    const byId = folders.find((f) => f.id === ref);
    if (byId) return byId.id;

    // Listed paths and requested paths are compared in one normal form (segments trimmed, lower-cased),
    // so a listed path always round-trips. If two folders share a normal form, require the ID.
    const capNote = truncated ? ` This mailbox has more than ${MAX_FOLDERS} folders, so not all were checked; use the folder ID.` : "";
    if (ref.startsWith("/") || ref.includes("/")) {
      const hits = folders.filter((f) => pathKey(f.path) === pathKey(ref));
      if (hits.length === 1) return hits[0]!.id;
      if (hits.length > 1) {
        throw new FolderError(`"${ref}" matches more than one folder (a folder name contains "/" or extra spaces). ` +
          `Use the folder ID: ${hits.map((f) => `${f.path} = ${f.id}`).join("; ")}.`);
      }
      throw new FolderError(`No folder at path "${ref}". Use list_mail_folders to see folder paths.${capNote}`);
    }

    const matches = folders.filter((f) => norm(f.displayName) === norm(ref));
    if (matches.length > 1) {
      throw new FolderError(`More than one folder is named "${ref}": ${matches.map((f) => f.path).join(", ")}. ` +
        `Use the path instead (e.g. "${matches[0]!.path}"), or the folder ID.`);
    }
    if (matches.length === 1) {
      if (truncated) throw new FolderError(`Can't confirm "${ref}" is the only folder with that name.${capNote} Or use its path.`);
      return matches[0]!.id;
    }
    if (FOLDER_ID.test(ref)) return ref;
    throw new FolderError(`No folder named "${ref}". Use list_mail_folders to see folder names and paths.${capNote}`);
  }

  private async load(): Promise<{ folders: FolderInfo[]; truncated: boolean }> {
    const out: FolderInfo[] = [];
    let truncated = false;
    let level: { listPath: string; parentPath: string }[] = [{ listPath: "/me/mailFolders", parentPath: "" }];
    walk: while (level.length) {
      const next: typeof level = [];
      for (const { listPath, parentPath } of level) {
        if (out.length >= MAX_FOLDERS) { truncated = true; break walk; }
        let page = await this.graph.page(listPath, { $top: "100", $select: FOLDER_SELECT });
        for (;;) {
          for (const raw of page.items as Record<string, unknown>[]) {
            if (typeof raw.id !== "string" || typeof raw.displayName !== "string") continue;
            if (out.length >= MAX_FOLDERS) { truncated = true; break walk; }
            const folder: FolderInfo = {
              id: raw.id,
              displayName: raw.displayName,
              path: `${parentPath}/${raw.displayName}`,
              ...(typeof raw.parentFolderId === "string" ? { parentFolderId: raw.parentFolderId } : {}),
              ...(typeof raw.totalItemCount === "number" ? { totalItemCount: raw.totalItemCount } : {}),
              ...(typeof raw.unreadItemCount === "number" ? { unreadItemCount: raw.unreadItemCount } : {}),
              ...(typeof raw.childFolderCount === "number" ? { childFolderCount: raw.childFolderCount } : {}),
            };
            out.push(folder);
            if ((folder.childFolderCount ?? 0) > 0) {
              next.push({ listPath: `/me/mailFolders/${encodeURIComponent(folder.id)}/childFolders`, parentPath: folder.path });
            }
          }
          if (!page.nextLink) break;
          if (out.length >= MAX_FOLDERS) { truncated = true; break walk; }
          page = await this.graph.page(listPath, {}, page.nextLink);
        }
      }
      level = next;
    }
    return { folders: out, truncated };
  }
}
