/**
 * @file client.ts
 * OmniAuthClient — the single entry-point for all OmniAuth API interactions.
 *
 * Zero external dependencies; relies only on the standard Fetch API.
 */

import type {
  OmniAuthConfig,
  User,
  AuthResponse,
  MfaChallengeResponse,
  MfaEnrollResponse,
  Organization,
  UserOrg,
  OrgMember,
  OrgRole,
  UserSession,
  AdminProject,
  WebhookEndpoint,
  MessageResponse,
} from './types';

import {
  OmniAuthError,
  RateLimitError,
  SessionExpiredError,
  NetworkError,
} from './errors';

import { decodeJwtPayload, type JwtClaims } from './jwt';

// Re-export types that were previously exported directly from this file so that
// existing imports (`import { User } from './client'`) continue to work.
export type {
  OmniAuthConfig,
  User,
  AuthResponse,
  MfaChallengeResponse,
  MfaEnrollResponse,
  Organization,
  UserOrg,
  OrgMember,
  OrgRole,
  UserSession,
  AdminProject,
  WebhookEndpoint,
  MessageResponse,
};

// ── OmniAuthClient ────────────────────────────────────────────────────────────

export class OmniAuthClient {
  private readonly config: OmniAuthConfig;
  private accessToken: string | null = null;

  // ── Constructor ─────────────────────────────────────────────────────────────

  /**
   * Create a new client using a config object.
   *
   * @example
   * const client = new OmniAuthClient({
   *   baseUrl: 'https://auth.example.com',
   *   projectId: 'proj_abc123',
   *   onTokenRefreshed: (token) => localStorage.setItem('token', token),
   *   onSessionExpired: () => router.push('/login'),
   * });
   */
  constructor(config: OmniAuthConfig);

  /**
   * @deprecated Use the config-object overload instead.
   * Kept for backward compatibility with `new OmniAuthClient(baseUrl, projectId)`.
   */
  constructor(baseUrl: string, projectId: string);

  constructor(configOrBaseUrl: OmniAuthConfig | string, projectId?: string) {
    if (typeof configOrBaseUrl === 'string') {
      // Legacy positional-argument overload
      this.config = {
        baseUrl: configOrBaseUrl,
        projectId: projectId!,
      };
    } else {
      this.config = configOrBaseUrl;
    }

    // Strip trailing slash so path concatenation is always consistent.
    this.config = {
      ...this.config,
      baseUrl: this.config.baseUrl.replace(/\/$/, ''),
    };
  }

  // ── Token management ────────────────────────────────────────────────────────

  /** Manually set (or clear) the in-memory access token. */
  setAccessToken(token: string | null): void {
    this.accessToken = token;
  }

  /** Return the currently stored access token (may be `null`). */
  getAccessToken(): string | null {
    return this.accessToken;
  }

  /**
   * Start an automatic token-refresh interval.
   *
   * @param intervalMs - How often (in milliseconds) to call `refresh()`.
   * @returns A cleanup function — call it to stop the interval.
   *
   * @example
   * const stop = client.setAutoRefresh(4 * 60 * 1000); // refresh every 4 min
   * // later…
   * stop();
   */
  setAutoRefresh(intervalMs: number): () => void {
    const handle = setInterval(async () => {
      try {
        const token = await this.refresh();
        this.config.onTokenRefreshed?.(token);
      } catch {
        // If refresh fails we leave the existing token in place; callers
        // can rely on onSessionExpired (fired inside refresh()) for UX.
      }
    }, intervalMs);

    return () => clearInterval(handle);
  }

  // ── Private helpers ─────────────────────────────────────────────────────────

  /**
   * Internal HTTP wrapper.  Handles auth headers, error mapping, and empty
   * response bodies (e.g. HTTP 204).
   */
  private async request<T>(path: string, options: RequestInit = {}): Promise<T> {
    const url = `${this.config.baseUrl}${path}`;
    const headers = new Headers(options.headers as HeadersInit | undefined);

    // Required project scoping header
    headers.set('X-Project-Id', this.config.projectId);

    // Default to JSON if the body is not FormData
    if (!headers.has('Content-Type') && !(options.body instanceof FormData)) {
      headers.set('Content-Type', 'application/json');
    }

    // Attach bearer token when available
    if (this.accessToken) {
      headers.set('Authorization', `Bearer ${this.accessToken}`);
    }

    let response: Response;
    try {
      response = await fetch(url, {
        ...options,
        headers,
        // Ensure the httpOnly refresh-token cookie is sent/received
        credentials: 'include',
      });
    } catch (cause) {
      throw new NetworkError(
        cause instanceof Error ? cause.message : 'A network error occurred'
      );
    }

    if (!response.ok) {
      // Special-case well-known status codes
      if (response.status === 429) throw new RateLimitError();
      if (response.status === 401) {
        this.config.onSessionExpired?.();
        throw new SessionExpiredError();
      }

      // Parse the error body for a human-readable message
      let errorMessage = `HTTP error ${response.status}`;
      let errorCode: string | undefined;
      try {
        const errBody = await response.json() as Record<string, unknown>;
        if (typeof errBody.error === 'string') errorMessage = errBody.error;
        else if (typeof errBody.message === 'string') errorMessage = errBody.message;
        if (typeof errBody.code === 'string') errorCode = errBody.code;
      } catch {
        // Body was not JSON; fall back to plain text
        try {
          const text = await response.text();
          if (text) errorMessage = text;
        } catch { /* ignore */ }
      }

      throw new OmniAuthError(errorMessage, response.status, errorCode);
    }

    // Handle empty response bodies (204, some DELETEs, etc.)
    const text = await response.text();
    if (!text) return {} as T;

    try {
      return JSON.parse(text) as T;
    } catch {
      return text as unknown as T;
    }
  }

  // ── Auth ────────────────────────────────────────────────────────────────────

  /**
   * Create a new user account.  The returned `access_token` is stored
   * automatically.
   *
   * @param idempotencyKey - Optional idempotency key to prevent duplicate
   *   accounts if the request is retried.
   */
  async signup(
    email: string,
    password: string,
    idempotencyKey?: string
  ): Promise<AuthResponse> {
    const headers: Record<string, string> = {};
    if (idempotencyKey) headers['Idempotency-Key'] = idempotencyKey;

    const res = await this.request<AuthResponse>('/v1/auth/signup', {
      method: 'POST',
      headers,
      body: JSON.stringify({ email, password }),
    });

    if (res.access_token) this.setAccessToken(res.access_token);
    return res;
  }

  /** Confirm an email address using the code sent to the user's inbox. */
  async verifyEmail(email: string, code: string): Promise<MessageResponse> {
    return this.request<MessageResponse>('/v1/auth/verify-email', {
      method: 'POST',
      body: JSON.stringify({ email, code }),
    });
  }

  /** Re-send the email verification code. */
  async resendVerification(email: string): Promise<MessageResponse> {
    return this.request<MessageResponse>('/v1/auth/resend-verification', {
      method: 'POST',
      body: JSON.stringify({ email }),
    });
  }

  /**
   * Authenticate with email and password.
   *
   * - Returns `AuthResponse` (with `access_token`) when login succeeds.
   * - Returns `MfaChallengeResponse` (with `mfa_ticket`) when MFA is required.
   */
  async login(
    email: string,
    password: string
  ): Promise<AuthResponse | MfaChallengeResponse> {
    const res = await this.request<AuthResponse | MfaChallengeResponse>(
      '/v1/auth/login',
      { method: 'POST', body: JSON.stringify({ email, password }) }
    );

    if ('access_token' in res) this.setAccessToken(res.access_token);
    return res;
  }

  /** Invalidate the current session and clear the stored access token. */
  async logout(): Promise<void> {
    await this.request<void>('/v1/auth/logout', { method: 'POST' });
    this.setAccessToken(null);
  }

  /**
   * Exchange the httpOnly refresh-token cookie for a new access token.
   * The new token is stored automatically and `config.onTokenRefreshed` is
   * **not** called here — that is the responsibility of `setAutoRefresh`.
   */
  async refresh(): Promise<string> {
    const res = await this.request<{ access_token: string }>('/v1/auth/refresh', {
      method: 'POST',
    });
    this.setAccessToken(res.access_token);
    return res.access_token;
  }

  /**
   * Fetch the authenticated user's profile from the server.
   * Falls back to decoding the stored JWT if the server returns 404.
   */
  async fetchProfile(): Promise<User> {
    try {
      return await this.request<User>('/v1/auth/me', { method: 'GET' });
    } catch (err) {
      // Graceful fallback: extract the user ID from the local JWT
      if (
        err instanceof OmniAuthError &&
        err.statusCode === 404 &&
        this.accessToken
      ) {
        const claims = decodeJwtPayload<JwtClaims>(this.accessToken);
        return {
          id: claims.sub,
          email: '',
          email_verified: false,
          mfa_enabled: false,
        };
      }
      throw err;
    }
  }

  // ── MFA ─────────────────────────────────────────────────────────────────────

  /**
   * Begin a TOTP enrolment flow.  Returns the shared secret and an
   * `otpauth://` URI suitable for generating a QR code.
   */
  async enrollMfa(): Promise<MfaEnrollResponse> {
    return this.request<MfaEnrollResponse>('/v1/auth/mfa/enroll', {
      method: 'POST',
    });
  }

  /**
   * Confirm and activate MFA after enrolment.
   *
   * @param secret - The shared secret returned by `enrollMfa`.
   * @param code   - A one-time code generated by the authenticator app.
   */
  async enableMfa(secret: string, code: string): Promise<MessageResponse> {
    return this.request<MessageResponse>('/v1/auth/mfa/enable', {
      method: 'POST',
      body: JSON.stringify({ secret, code }),
    });
  }

  /**
   * Disable MFA for the authenticated user.
   *
   * @param code - A valid one-time code to confirm intent.
   */
  async disableMfa(code: string): Promise<MessageResponse> {
    return this.request<MessageResponse>('/v1/auth/mfa/disable', {
      method: 'POST',
      body: JSON.stringify({ code }),
    });
  }

  /**
   * Complete a login that was interrupted by an MFA challenge.
   * On success the new access token is stored automatically.
   *
   * @param mfaTicket - The opaque ticket from `MfaChallengeResponse`.
   * @param code      - The current TOTP code from the authenticator app.
   */
  async verifyMfa(mfaTicket: string, code: string): Promise<AuthResponse> {
    const res = await this.request<AuthResponse>('/v1/auth/mfa/verify', {
      method: 'POST',
      body: JSON.stringify({ mfa_ticket: mfaTicket, code }),
    });

    if (res.access_token) this.setAccessToken(res.access_token);
    return res;
  }

  // ── Sessions ─────────────────────────────────────────────────────────────────

  /** List all active sessions for the authenticated user. */
  async listSessions(): Promise<UserSession[]> {
    return this.request<UserSession[]>('/v1/sessions', { method: 'GET' });
  }

  /** Revoke a specific session by its ID. */
  async revokeSession(sessionId: string): Promise<MessageResponse> {
    return this.request<MessageResponse>(`/v1/sessions/${sessionId}`, {
      method: 'DELETE',
    });
  }

  /** Revoke all sessions for the authenticated user (sign out everywhere). */
  async revokeAllSessions(): Promise<MessageResponse> {
    return this.request<MessageResponse>('/v1/sessions', { method: 'DELETE' });
  }

  // ── Organizations ─────────────────────────────────────────────────────────

  /** Create a new organization owned by the authenticated user. */
  async createOrg(name: string): Promise<Organization> {
    return this.request<Organization>('/v1/orgs', {
      method: 'POST',
      body: JSON.stringify({ name }),
    });
  }

  /** List all organizations the authenticated user belongs to. */
  async listOrgs(): Promise<UserOrg[]> {
    return this.request<UserOrg[]>('/v1/orgs', { method: 'GET' });
  }

  /** List all members of a specific organization. */
  async listMembers(orgId: string): Promise<OrgMember[]> {
    return this.request<OrgMember[]>(`/v1/orgs/${orgId}/members`, {
      method: 'GET',
    });
  }

  /** Invite a user to an organization by email. */
  async addMember(
    orgId: string,
    email: string,
    role: OrgRole | string
  ): Promise<MessageResponse> {
    return this.request<MessageResponse>(`/v1/orgs/${orgId}/members`, {
      method: 'POST',
      body: JSON.stringify({ email, role }),
    });
  }

  /** Change the role of an existing organization member. */
  async updateMember(
    orgId: string,
    userId: string,
    role: OrgRole | string
  ): Promise<MessageResponse> {
    return this.request<MessageResponse>(`/v1/orgs/${orgId}/members/${userId}`, {
      method: 'PATCH',
      body: JSON.stringify({ role }),
    });
  }

  /** Remove a member from an organization. */
  async removeMember(orgId: string, userId: string): Promise<MessageResponse> {
    return this.request<MessageResponse>(`/v1/orgs/${orgId}/members/${userId}`, {
      method: 'DELETE',
    });
  }

  // ── Admin ─────────────────────────────────────────────────────────────────

  /**
   * Create a new project via the admin API.
   * Requires an admin-scoped access token.
   */
  async createAdminProject(name: string): Promise<AdminProject> {
    return this.request<AdminProject>('/v1/admin/projects', {
      method: 'POST',
      body: JSON.stringify({ name }),
    });
  }

  /**
   * Register a webhook endpoint for a project via the admin API.
   * Requires an admin-scoped access token.
   */
  async registerAdminWebhook(
    projectId: string,
    url: string,
    secret: string
  ): Promise<WebhookEndpoint> {
    return this.request<WebhookEndpoint>('/v1/admin/webhooks', {
      method: 'POST',
      body: JSON.stringify({ project_id: projectId, url, secret }),
    });
  }

  // ── Password Reset / Change ───────────────────────────────────────────────

  /**
   * Initiate a password reset for the given email.
   * Always returns 200 regardless of whether the email exists (prevents enumeration).
   * A reset token is emailed to the user (or logged to console in dev).
   */
  async forgotPassword(email: string): Promise<MessageResponse> {
    return this.request<MessageResponse>('/v1/auth/forgot-password', {
      method: 'POST',
      body: JSON.stringify({ email }),
    });
  }

  /**
   * Complete a password reset using the token received by email.
   * Invalidates all existing sessions for the user after reset.
   *
   * @param email     The user's email address
   * @param token     The reset token from the email
   * @param newPassword  The new password (min 8 characters)
   */
  async resetPassword(
    email: string,
    token: string,
    newPassword: string
  ): Promise<MessageResponse> {
    return this.request<MessageResponse>('/v1/auth/reset-password', {
      method: 'POST',
      body: JSON.stringify({ email, token, new_password: newPassword }),
    });
  }

  /**
   * Change password while authenticated.
   * Requires the current password to confirm identity.
   * Revokes all other sessions after the change.
   *
   * @param currentPassword  The user's existing password
   * @param newPassword      The new password (min 8 characters)
   */
  async changePassword(
    currentPassword: string,
    newPassword: string
  ): Promise<MessageResponse> {
    return this.request<MessageResponse>('/v1/auth/change-password', {
      method: 'POST',
      body: JSON.stringify({
        current_password: currentPassword,
        new_password: newPassword,
      }),
    });
  }

  // ── Magic Link ────────────────────────────────────────────────────────────

  /**
   * Request a magic sign-in link for the given email.
   * The link is emailed to the user (or logged to console in dev).
   * Always returns 200 — no email enumeration.
   *
   * The user must already have a verified account; magic link is login only.
   */
  async requestMagicLink(email: string): Promise<MessageResponse> {
    return this.request<MessageResponse>('/v1/auth/magic-link', {
      method: 'POST',
      body: JSON.stringify({ email }),
    });
  }

  /**
   * Verify a magic link token (from URL params after the user clicks the email link).
   * On success returns an AuthResponse with access_token + user and sets the refresh cookie.
   *
   * @param email  The user's email address (from `magic_email` URL param)
   * @param token  The one-time token (from `magic_token` URL param)
   */
  async verifyMagicLink(email: string, token: string): Promise<AuthResponse> {
    return this.request<AuthResponse>('/v1/auth/magic-link/verify', {
      method: 'POST',
      body: JSON.stringify({ email, token }),
    });
  }
}
