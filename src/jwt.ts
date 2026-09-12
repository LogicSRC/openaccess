/**
 * Just enough JOSE: Ed25519 JWS, compact form, and the JWK shapes for a hub's
 * signing key and an app's descriptor key. node:crypto does the work.
 */
import { createPrivateKey, createPublicKey, generateKeyPairSync, sign as cryptoSign, verify as cryptoVerify, createHash, type KeyObject } from "node:crypto";
import type { Jwk } from "./spec.ts";

export const b64url = (data: Buffer | string): string => Buffer.from(data).toString("base64url");
export const fromB64url = (text: string): Buffer => Buffer.from(text, "base64url");

export interface SigningKey {
  kid: string;
  privateKey: KeyObject;
  publicKey: KeyObject;
  /** The public half as a JWK, for jwks.json. */
  jwk: Jwk;
}

const kidOf = (x: string): string => createHash("sha256").update(x).digest("base64url").slice(0, 12);

/** A fresh Ed25519 pair. */
export function generateSigningKey(): SigningKey {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return fromPrivateJwk(privateKey.export({ format: "jwk" }) as Jwk);
}

/** Rebuild a key from its private JWK (what a hub persists). */
export function fromPrivateJwk(jwk: Jwk): SigningKey {
  const privateKey = createPrivateKey({ key: jwk as never, format: "jwk" });
  const publicKey = createPublicKey(privateKey);
  const pub = publicKey.export({ format: "jwk" }) as Jwk;
  const kid = typeof jwk.kid === "string" ? jwk.kid : kidOf(String(pub.x));
  return { kid, privateKey, publicKey, jwk: { kty: "OKP", crv: "Ed25519", kid, x: pub.x, alg: "EdDSA", use: "sig" } };
}

export const exportPrivateJwk = (key: SigningKey): Jwk => ({ ...(key.privateKey.export({ format: "jwk" }) as Jwk), kid: key.kid });

export function publicKeyFromJwk(jwk: Jwk): KeyObject | null {
  if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || typeof jwk.x !== "string") return null;
  try {
    return createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: jwk.x } as never, format: "jwk" });
  } catch {
    return null;
  }
}

/** Sign claims into a compact JWS with EdDSA. */
export function signJwt(claims: Record<string, unknown>, key: SigningKey): string {
  const header = b64url(JSON.stringify({ alg: "EdDSA", typ: "JWT", kid: key.kid }));
  const payload = b64url(JSON.stringify(claims));
  const signature = cryptoSign(null, Buffer.from(`${header}.${payload}`), key.privateKey);
  return `${header}.${payload}.${b64url(signature)}`;
}

export interface DecodedJwt {
  header: { alg?: string; kid?: string; typ?: string };
  claims: Record<string, unknown>;
  signingInput: string;
  signature: Buffer;
}

/** Split without verifying. Null when it is not a JWS. */
export function decodeJwt(token: string): DecodedJwt | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  try {
    const header = JSON.parse(fromB64url(parts[0] as string).toString("utf8")) as DecodedJwt["header"];
    const claims = JSON.parse(fromB64url(parts[1] as string).toString("utf8")) as Record<string, unknown>;
    if (typeof claims !== "object" || claims === null) return null;
    return { header, claims, signingInput: `${parts[0]}.${parts[1]}`, signature: fromB64url(parts[2] as string) };
  } catch {
    return null;
  }
}

/** Verify against a set of public JWKs, matching kid when the token names one. */
export function verifyJwt(token: string, keys: Jwk[], now = Date.now()): { claims: Record<string, unknown> } | { error: string } {
  const decoded = decodeJwt(token);
  if (!decoded) return { error: "not a JWT" };
  if (decoded.header.alg !== "EdDSA") return { error: `alg ${decoded.header.alg ?? "missing"}; only EdDSA` };
  const candidates = decoded.header.kid ? keys.filter((key) => key.kid === decoded.header.kid) : keys;
  if (!candidates.length) return { error: decoded.header.kid ? `no key ${decoded.header.kid}` : "no keys" };
  const good = candidates.some((jwk) => {
    const key = publicKeyFromJwk(jwk);
    return key ? cryptoVerify(null, Buffer.from(decoded.signingInput), key, decoded.signature) : false;
  });
  if (!good) return { error: "bad signature" };
  const exp = decoded.claims.exp;
  if (typeof exp === "number" && exp * 1000 < now - 30_000) return { error: "expired" };
  const nbf = decoded.claims.nbf;
  if (typeof nbf === "number" && nbf * 1000 > now + 30_000) return { error: "not yet valid" };
  return { claims: decoded.claims };
}

/** Sign raw bytes (a webhook body) and verify them: `ed25519=<base64url>`. */
export const signBody = (body: string, key: SigningKey): string => `ed25519=${b64url(cryptoSign(null, Buffer.from(body), key.privateKey))}`;

export function verifyBody(body: string, header: string | null | undefined, keys: Jwk[]): boolean {
  if (!header?.startsWith("ed25519=")) return false;
  const signature = fromB64url(header.slice(8).trim());
  return keys.some((jwk) => {
    const key = publicKeyFromJwk(jwk);
    return key ? cryptoVerify(null, Buffer.from(body), key, signature) : false;
  });
}

export const sha256url = (value: string): string => createHash("sha256").update(value).digest("base64url");
