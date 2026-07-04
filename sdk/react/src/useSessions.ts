"use client";
import { useState, useCallback } from "react";
import { useAuth } from "./context";
import { UserSession } from "../../core/src/index";

export interface UseSessionsReturn {
  sessions: UserSession[];
  loading: boolean;
  error: string | null;
  /** Manually re-fetch the active session list */
  refresh: () => Promise<void>;
  /** Revoke a specific session by ID */
  revoke: (sessionId: string) => Promise<void>;
  /** Revoke all sessions except the current one */
  revokeAll: () => Promise<void>;
}

/**
 * Hook for managing active sessions (device list).
 * Fetches sessions immediately on first call to `refresh()`.
 *
 * @example
 * const { sessions, revoke, revokeAll } = useSessions();
 * useEffect(() => { refresh(); }, []);
 */
export function useSessions(): UseSessionsReturn {
  const { listSessions, revokeSession, revokeAllSessions } = useAuth();
  const [sessions, setSessions] = useState<UserSession[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await listSessions();
      setSessions(data);
    } catch (err: any) {
      setError(err.message ?? "Failed to load sessions");
    } finally {
      setLoading(false);
    }
  }, [listSessions]);

  const revoke = useCallback(
    async (sessionId: string) => {
      await revokeSession(sessionId);
      setSessions((prev) => prev.filter((s) => s.id !== sessionId));
    },
    [revokeSession]
  );

  const revokeAll = useCallback(async () => {
    await revokeAllSessions();
    // Re-fetch so only the current session remains in state
    await refresh();
  }, [revokeAllSessions, refresh]);

  return { sessions, loading, error, refresh, revoke, revokeAll };
}
