"use client";
export { AuthProvider, useAuth } from "./context";
export type { AuthContextType, AuthProviderProps } from "./context";

export { useSessions } from "./useSessions";
export type { UseSessionsReturn } from "./useSessions";

export { useOrgs, useOrgMembers } from "./useOrgs";
export type { UseOrgsReturn, UseOrgMembersReturn } from "./useOrgs";

export { useMfa } from "./useMfa";
export type { UseMfaReturn, MfaEnrollState } from "./useMfa";

export { useEmailVerification } from "./useEmailVerification";
export type { UseEmailVerificationReturn } from "./useEmailVerification";

export { useForgotPassword, useResetPassword, useChangePassword, useMagicLink } from "./usePasswordReset";
export type { UseForgotPasswordReturn, UseResetPasswordReturn, UseChangePasswordReturn, UseMagicLinkReturn } from "./usePasswordReset";

// Re-export core types so consumers only need one import
export type {
  User,
  AuthResponse,
  MfaChallengeResponse,
  UserSession,
  UserOrg,
  OrgMember,
  OrgRole,
  Organization,
  AdminProject,
  WebhookEndpoint,
  OmniAuthConfig,
} from "../../core/src/index";

export {
  OmniAuthClient,
  OmniAuthError,
  AuthenticationError,
  EmailNotVerifiedError,
  MfaRequiredError,
  NetworkError,
  RateLimitError,
  SessionExpiredError,
} from "../../core/src/index";
