import { createCipheriv, createDecipheriv, createHash, randomBytes, timingSafeEqual } from "node:crypto";

/** A 256-bit random, URL-safe token. */
export function randomToken(): string {
  return randomBytes(32).toString("base64url");
}

/** Storage key for a bearer secret: tokens and codes are never stored in the clear. */
export function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

export function safeEqual(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}

/** RFC 7636 S256: BASE64URL(SHA256(verifier)). */
export function pkceChallenge(verifier: string): string {
  return createHash("sha256").update(verifier).digest("base64url");
}

export function verifyPkce(verifier: string, challenge: string): boolean {
  return /^[A-Za-z0-9._~-]{43,128}$/.test(verifier) && safeEqual(pkceChallenge(verifier), challenge);
}

/** AES-256-GCM authenticated encryption. `context` binds a ciphertext to its storage location. */
export class Sealer {
  constructor(private readonly key: Buffer) {
    if (key.length !== 32) throw new Error("Encryption key must be 32 bytes.");
  }

  seal(plaintext: string, context: string): string {
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.key, iv);
    cipher.setAAD(Buffer.from(context));
    const body = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
    return Buffer.concat([iv, cipher.getAuthTag(), body]).toString("base64");
  }

  open(sealed: string, context: string): string {
    const data = Buffer.from(sealed, "base64");
    // iv (12) + tag (16) + body; reject anything shorter so a truncated tag can never be accepted.
    if (data.length < 28) throw new Error("Sealed value is too short.");
    const decipher = createDecipheriv("aes-256-gcm", this.key, data.subarray(0, 12), { authTagLength: 16 });
    decipher.setAAD(Buffer.from(context));
    decipher.setAuthTag(data.subarray(12, 28));
    return Buffer.concat([decipher.update(data.subarray(28)), decipher.final()]).toString("utf8");
  }
}
