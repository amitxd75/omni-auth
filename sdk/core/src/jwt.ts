/**
 * @file jwt.ts
 * Lightweight JWT utilities that work without any external dependencies.
 * NOTE: These helpers decode without verifying the signature — never use
 * them as a security boundary on untrusted inputs.
 */

/**
 * Decode a JWT payload without verifying the signature.
 *
 * @param token - A compact serialisation JWT (header.payload.signature).
 * @returns The decoded payload parsed as JSON.
 * @throws {Error} If the token does not have exactly three dot-separated parts.
 *
 * @example
 * const claims = decodeJwtPayload<JwtClaims>(accessToken);
 * console.log(claims.sub); // user ID
 */
export function decodeJwtPayload<T = Record<string, unknown>>(token: string): T {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid JWT format');
  }

  // Convert URL-safe base64 → standard base64, then decode.
  const base64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
  const raw = atob(base64);
  return JSON.parse(raw) as T;
}

/** Standard claims present in all OmniAuth-issued JWTs. */
export interface JwtClaims {
  /** Subject — the authenticated user's ID. */
  sub: string;
  /** The project this token was issued for. */
  project_id: string;
  /** Session ID that can be used with the sessions API. */
  sid: string;
  /** Expiry time as a Unix timestamp (seconds). */
  exp: number;
  /** Issued-at time as a Unix timestamp (seconds). */
  iat: number;
}
