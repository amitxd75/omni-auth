"use client";
import { useState, useCallback } from "react";
import { useAuth } from "./context";

export interface UseEmailVerificationReturn {
  loading: boolean;
  error: string | null;
  success: boolean;
  /** Verify the 6-digit OTP code */
  verify: (email: string, code: string) => Promise<void>;
  /** Request a new OTP code to be sent */
  resend: (email: string) => Promise<void>;
  reset: () => void;
}

/**
 * Hook for handling email OTP verification after signup.
 *
 * @example
 * const { verify, resend, loading, success, error } = useEmailVerification();
 */
export function useEmailVerification(): UseEmailVerificationReturn {
  const { verifyEmail, resendVerification } = useAuth();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  const verify = useCallback(
    async (email: string, code: string) => {
      setLoading(true);
      setError(null);
      try {
        await verifyEmail(email, code);
        setSuccess(true);
      } catch (err: any) {
        setError(err.message ?? "Invalid or expired verification code");
        throw err;
      } finally {
        setLoading(false);
      }
    },
    [verifyEmail]
  );

  const resend = useCallback(
    async (email: string) => {
      setLoading(true);
      setError(null);
      try {
        await resendVerification(email);
      } catch (err: any) {
        setError(err.message ?? "Failed to resend verification code");
        throw err;
      } finally {
        setLoading(false);
      }
    },
    [resendVerification]
  );

  const reset = useCallback(() => {
    setError(null);
    setSuccess(false);
  }, []);

  return { loading, error, success, verify, resend, reset };
}
