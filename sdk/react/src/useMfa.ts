"use client";
import { useState, useCallback } from "react";
import { useAuth } from "./context";

export interface MfaEnrollState {
  secret: string;
  otpauthUrl: string;
}

export interface UseMfaReturn {
  /** Populated when enrollment is in progress */
  enrollState: MfaEnrollState | null;
  loading: boolean;
  error: string | null;
  /** Step 1: generate TOTP secret and otpauth:// URL */
  enroll: () => Promise<MfaEnrollState>;
  /** Step 2: confirm with first TOTP code to permanently enable MFA */
  enable: (secret: string, code: string) => Promise<void>;
  /** Disable MFA by providing the current TOTP code */
  disable: (code: string) => Promise<void>;
  /** Clear enrollment state (e.g. user cancelled) */
  cancelEnroll: () => void;
}

/**
 * Hook for managing TOTP MFA enrollment and disabling.
 *
 * @example
 * const { enroll, enable, enrollState } = useMfa();
 * // 1. call enroll() → show QR code from enrollState.otpauthUrl
 * // 2. call enable(secret, userCode) → MFA is active
 */
export function useMfa(): UseMfaReturn {
  const { client, fetchProfile } = useAuth();
  const [enrollState, setEnrollState] = useState<MfaEnrollState | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const enroll = useCallback(async (): Promise<MfaEnrollState> => {
    setLoading(true);
    setError(null);
    try {
      const res = await client.enrollMfa();
      const state: MfaEnrollState = {
        secret: res.secret,
        otpauthUrl: res.otpauth_url,
      };
      setEnrollState(state);
      return state;
    } catch (err: any) {
      setError(err.message ?? "Failed to start MFA enrollment");
      throw err;
    } finally {
      setLoading(false);
    }
  }, [client]);

  const enable = useCallback(
    async (secret: string, code: string): Promise<void> => {
      setLoading(true);
      setError(null);
      try {
        await client.enableMfa(secret, code);
        setEnrollState(null);
        // Refresh user profile so mfa_enabled reflects true
        await fetchProfile();
      } catch (err: any) {
        setError(err.message ?? "Failed to enable MFA");
        throw err;
      } finally {
        setLoading(false);
      }
    },
    [client, fetchProfile]
  );

  const disable = useCallback(
    async (code: string): Promise<void> => {
      setLoading(true);
      setError(null);
      try {
        await client.disableMfa(code);
        await fetchProfile();
      } catch (err: any) {
        setError(err.message ?? "Failed to disable MFA");
        throw err;
      } finally {
        setLoading(false);
      }
    },
    [client, fetchProfile]
  );

  const cancelEnroll = useCallback(() => {
    setEnrollState(null);
    setError(null);
  }, []);

  return { enrollState, loading, error, enroll, enable, disable, cancelEnroll };
}
