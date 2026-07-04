/**
 * @file errors.ts
 * Typed error classes for the OmniAuth core SDK.
 *
 * All errors extend `OmniAuthError` so callers can use a single catch clause:
 *
 * ```ts
 * try {
 *   await client.login(email, password);
 * } catch (err) {
 *   if (err instanceof MfaRequiredError) { ... }
 *   if (err instanceof OmniAuthError) { console.error(err.statusCode); }
 * }
 * ```
 */

// ── Base ──────────────────────────────────────────────────────────────────────

/**
 * Root error class for all OmniAuth SDK errors.
 * All specialized errors extend this class.
 */
export class OmniAuthError extends Error {
  constructor(
    message: string,
    /** HTTP status code associated with the error, if applicable. */
    public readonly statusCode?: number,
    /** Machine-readable error code (e.g. `"MFA_REQUIRED"`). */
    public readonly code?: string
  ) {
    super(message);
    this.name = 'OmniAuthError';
    // Maintain proper prototype chain for `instanceof` checks in transpiled code.
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

// ── Specialised errors ────────────────────────────────────────────────────────

/** Thrown when credentials are invalid or the user is not authenticated. */
export class AuthenticationError extends OmniAuthError {
  constructor(message = 'Authentication failed', statusCode?: number) {
    super(message, statusCode, 'AUTHENTICATION_ERROR');
    this.name = 'AuthenticationError';
  }
}

/** Thrown when an action requires a verified email address. */
export class EmailNotVerifiedError extends OmniAuthError {
  constructor(message = 'Email address has not been verified') {
    super(message, 403, 'EMAIL_NOT_VERIFIED');
    this.name = 'EmailNotVerifiedError';
  }
}

/**
 * Thrown when a login attempt succeeds but the server requires MFA
 * before issuing a full session token.
 */
export class MfaRequiredError extends OmniAuthError {
  constructor(
    /** Opaque MFA ticket — pass this to `client.verifyMfa()`. */
    public readonly mfaTicket: string
  ) {
    super('MFA verification required', 403, 'MFA_REQUIRED');
    this.name = 'MfaRequiredError';
  }
}

/** Thrown when a network-level failure prevents the request from completing. */
export class NetworkError extends OmniAuthError {
  constructor(message = 'A network error occurred') {
    super(message, undefined, 'NETWORK_ERROR');
    this.name = 'NetworkError';
  }
}

/** Thrown when the server returns HTTP 429 Too Many Requests. */
export class RateLimitError extends OmniAuthError {
  constructor() {
    super('Too many requests', 429, 'RATE_LIMITED');
    this.name = 'RateLimitError';
  }
}

/** Thrown when the server returns HTTP 401 and the session cannot be renewed. */
export class SessionExpiredError extends OmniAuthError {
  constructor() {
    super('Session has expired', 401, 'SESSION_EXPIRED');
    this.name = 'SessionExpiredError';
  }
}
