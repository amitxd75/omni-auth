"use client";
import { useState, useCallback } from "react";
import { useAuth } from "./context";

export interface UseForgotPasswordReturn {
  loading: boolean;
  error: string | null;
  /** True once the server has acknowledged the request */
  sent: boolean;
  /** Send a reset email to the given address */
  send: (email: string) => Promise<void>;
  reset: () => void;
}

export interface UseResetPasswordReturn {
  loading: boolean;
  error: string | null;
  success: boolean;
  /** Complete the reset using the token from email */
  submit: (email: string, token: string, newPassword: string) => Promise<void>;
  reset: () => void;
}

export interface UseChangePasswordReturn {
  loading: boolean;
  error: string | null;
  success: boolean;
  /** Change password while authenticated */
  submit: (currentPassword: string, newPassword: string) => Promise<void>;
  reset: () => void;
}

/**
 * Hook for the "Forgot password?" flow.
 * Call `send(email)` → user receives reset token by email.
 *
 * @example
 * const { send, sent, loading, error } = useForgotPassword();
 */
export function useForgotPassword(): UseForgotPasswordReturn {
  const { client } = useAuth();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [sent, setSent] = useState(false);

  const send = useCallback(
    async (email: string) => {
      setLoading(true);
      setError(null);
      try {
        await client.forgotPassword(email);
        setSent(true);
      } catch (err: any) {
        setError(err.message ?? "Failed to send reset email");
        throw err;
      } finally {
        setLoading(false);
      }
    },
    [client]
  );

  const reset = useCallback(() => {
    setError(null);
    setSent(false);
  }, []);

  return { loading, error, sent, send, reset };
}

/**
 * Hook for the password reset confirmation form.
 * The user arrives here with a token from their email.
 *
 * @example
 * const { submit, success, loading, error } = useResetPassword();
 */
export function useResetPassword(): UseResetPasswordReturn {
  const { client } = useAuth();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  const submit = useCallback(
    async (email: string, token: string, newPassword: string) => {
      if (newPassword.length < 8) {
        setError("Password must be at least 8 characters");
        return;
      }
      setLoading(true);
      setError(null);
      try {
        await client.resetPassword(email, token, newPassword);
        setSuccess(true);
      } catch (err: any) {
        setError(err.message ?? "Invalid or expired reset token");
        throw err;
      } finally {
        setLoading(false);
      }
    },
    [client]
  );

  const reset = useCallback(() => {
    setError(null);
    setSuccess(false);
  }, []);

  return { loading, error, success, submit, reset };
}

/**
 * Hook for changing password while authenticated.
 * Requires the current password for verification.
 * All other sessions are revoked after a successful change.
 *
 * @example
 * const { submit, success, loading, error } = useChangePassword();
 */
export function useChangePassword(): UseChangePasswordReturn {
  const { client } = useAuth();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  const submit = useCallback(
    async (currentPassword: string, newPassword: string) => {
      if (newPassword.length < 8) {
        setError("New password must be at least 8 characters");
        return;
      }
      setLoading(true);
      setError(null);
      try {
        await client.changePassword(currentPassword, newPassword);
        setSuccess(true);
      } catch (err: any) {
        setError(err.message ?? "Failed to change password");
        throw err;
      } finally {
        setLoading(false);
      }
    },
    [client]
  );

  const reset = useCallback(() => {
    setError(null);
    setSuccess(false);
  }, []);

  return { loading, error, success, submit, reset };
}

// ── Magic Link ─────────────────────────────────────────────────────────────────

export interface UseMagicLinkReturn {
  loading: boolean;
  error: string | null;
  /** True once the magic link email has been dispatched */
  sent: boolean;
  /** Request a magic sign-in link for the given email */
  request: (email: string) => Promise<void>;
  /**
   * Verify the token from URL params — call this on page load when
   * `magic_token` and `magic_email` are in the URL.
   */
  verify: (email: string, token: string) => Promise<AuthResponse | null>;
  reset: () => void;
}

import type { AuthResponse } from "../../core/src/index";

/**
 * Hook for the passwordless magic link login flow.
 *
 * - `request(email)` → sends a sign-in link to the user's email
 * - `verify(email, token)` → exchanges URL params for a full session
 *
 * @example
 * const { request, verify, sent, loading, error } = useMagicLink();
 */
export function useMagicLink(): UseMagicLinkReturn {
  const { client } = useAuth();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [sent, setSent] = useState(false);

  const request = useCallback(
    async (email: string) => {
      setLoading(true);
      setError(null);
      try {
        await client.requestMagicLink(email);
        setSent(true);
      } catch (err: any) {
        setError(err.message ?? "Failed to send magic link");
        throw err;
      } finally {
        setLoading(false);
      }
    },
    [client]
  );

  const verify = useCallback(
    async (email: string, token: string): Promise<AuthResponse | null> => {
      setLoading(true);
      setError(null);
      try {
        return await client.verifyMagicLink(email, token);
      } catch (err: any) {
        setError(err.message ?? "Invalid or expired magic link");
        return null;
      } finally {
        setLoading(false);
      }
    },
    [client]
  );

  const reset = useCallback(() => {
    setError(null);
    setSent(false);
  }, []);

  return { loading, error, sent, request, verify, reset };
}
