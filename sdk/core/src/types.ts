/**
 * @file types.ts
 * Shared interfaces and type aliases used across the OmniAuth core SDK.
 */

// ── Primitive helpers ─────────────────────────────────────────────────────────

/** Valid roles a user can hold within an organization. */
export type OrgRole = 'owner' | 'admin' | 'member';

// ── Domain models ─────────────────────────────────────────────────────────────

/** A fully resolved OmniAuth user object. */
export interface User {
  id: string;
  email: string;
  email_verified: boolean;
  mfa_enabled: boolean;
  /** ISO-8601 timestamp of when the account was created. */
  created_at?: string;
}

/** Returned on successful signup / login (when MFA is not required). */
export interface AuthResponse {
  access_token: string;
  user: User;
}

/** Returned on login when the account has MFA enabled. */
export interface MfaChallengeResponse {
  mfa_required: boolean;
  /** Opaque ticket that must be passed to `verifyMfa`. */
  mfa_ticket: string;
}

/** Returned when initiating a TOTP enrollment. */
export interface MfaEnrollResponse {
  secret: string;
  /** `otpauth://` URI suitable for a QR-code generator. */
  otpauth_url: string;
}

/** A full Organization record (returned to admin / owner callers). */
export interface Organization {
  id: string;
  project_id: string;
  name: string;
  created_at: string;
  updated_at: string;
}

/** A slim organization summary as seen from the perspective of a member. */
export interface UserOrg {
  id: string;
  name: string;
  role: OrgRole | string;
}

/** A member of an organization. */
export interface OrgMember {
  user_id: string;
  email: string;
  role: OrgRole | string;
  created_at: string;
}

/** An active session belonging to the authenticated user. */
export interface UserSession {
  id: string;
  user_agent: string | null;
  ip_address: string | null;
  expires_at: string;
  created_at: string;
  /** Whether this session is the one currently in use. */
  is_current: boolean;
}

/** A project record returned by the admin API. */
export interface AdminProject {
  id: string;
  name: string;
  jwt_public_key: string;
  jwt_private_key: string;
}

/** A registered webhook endpoint. */
export interface WebhookEndpoint {
  id: string;
  project_id: string;
  url: string;
  secret: string;
}

/** Generic server message response (e.g. success confirmations). */
export interface MessageResponse {
  message: string;
}

// ── Client configuration ──────────────────────────────────────────────────────

/** Configuration object accepted by `OmniAuthClient`. */
export interface OmniAuthConfig {
  /** Base URL of the OmniAuth server, e.g. `https://auth.example.com`. */
  baseUrl: string;
  /** The project ID that scopes all requests. */
  projectId: string;
  /**
   * Called after a successful token refresh with the new access token.
   * Use this to persist the token in your storage layer.
   */
  onTokenRefreshed?: (token: string) => void;
  /**
   * Called when the session has definitively expired (e.g. refresh returned
   * 401). Use this to redirect the user to a login page.
   */
  onSessionExpired?: () => void;
}
