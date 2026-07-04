"use client";
import React, {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
  useRef,
  ReactNode,
} from "react";
import {
  OmniAuthClient,
  OmniAuthConfig,
  User,
  AuthResponse,
  MfaChallengeResponse,
  UserSession,
  UserOrg,
  OrgMember,
  OrgRole,
} from "../../core/src/index";
import { decodeJwtPayload, JwtClaims } from "../../core/src/index";
import { SessionExpiredError } from "../../core/src/index";

// ─────────────────────────────────────────────
// Context type — everything exposed to consumers
// ─────────────────────────────────────────────
export interface AuthContextType {
  /** The underlying client — use for advanced/raw calls */
  client: OmniAuthClient;

  // ── State ──
  user: User | null;
  /** True during initial session restore and explicit auth actions */
  loading: boolean;
  /** True when the server returned mfa_required: true */
  mfaRequired: boolean;
  mfaTicket: string | null;

  // ── Auth actions ──
  login: (
    email: string,
    password: string,
  ) => Promise<AuthResponse | MfaChallengeResponse>;
  signup: (
    email: string,
    password: string,
    idempotencyKey?: string,
  ) => Promise<User>;
  logout: () => Promise<void>;
  fetchProfile: () => Promise<void>;

  // ── Email verification ──
  verifyEmail: (email: string, code: string) => Promise<{ message: string }>;
  resendVerification: (email: string) => Promise<{ message: string }>;

  // ── MFA ──
  verifyMfa: (code: string) => Promise<AuthResponse>;
  clearMfaChallenge: () => void;

  // ── Sessions ──
  listSessions: () => Promise<UserSession[]>;
  revokeSession: (sessionId: string) => Promise<{ message: string }>;
  revokeAllSessions: () => Promise<{ message: string }>;

  // ── Organizations ──
  listOrgs: () => Promise<UserOrg[]>;
  createOrg: (name: string) => Promise<{ id: string; name: string }>;
  listMembers: (orgId: string) => Promise<OrgMember[]>;
  addMember: (
    orgId: string,
    email: string,
    role: OrgRole,
  ) => Promise<{ message: string }>;
  updateMember: (
    orgId: string,
    userId: string,
    role: OrgRole,
  ) => Promise<{ message: string }>;
  removeMember: (orgId: string, userId: string) => Promise<{ message: string }>;

  // ── Admin ──
  createAdminProject: (name: string) => Promise<any>;
  registerAdminWebhook: (
    projectId: string,
    url: string,
    secret: string,
  ) => Promise<any>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

// ─────────────────────────────────────────────
// Provider
// ─────────────────────────────────────────────
export interface AuthProviderProps {
  baseUrl: string;
  projectId: string;
  /**
   * Auto-refresh the access token before it expires.
   * Pass interval in milliseconds. Default: 12 minutes (720_000).
   * Set to 0 to disable auto-refresh.
   */
  autoRefreshInterval?: number;
  children: ReactNode;
}

export const AuthProvider: React.FC<AuthProviderProps> = ({
  baseUrl,
  projectId,
  autoRefreshInterval = 720_000, // 12 min — well under 15 min token TTL
  children,
}) => {
  const config: OmniAuthConfig = {
    baseUrl,
    projectId,
    onSessionExpired: () => {
      setUser(null);
      setMfaRequired(false);
      setMfaTicket(null);
    },
  };

  const [client] = useState(() => new OmniAuthClient(config));
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [mfaRequired, setMfaRequired] = useState<boolean>(false);
  const [mfaTicket, setMfaTicket] = useState<string | null>(null);
  const refreshTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // ── Fetch full user profile from /v1/auth/me (or fallback: decode JWT) ──
  const fetchProfile = useCallback(async (): Promise<void> => {
    try {
      const profile = await client.fetchProfile();
      setUser(profile);
    } catch {
      // Best-effort fallback: decode the JWT sub
      const token = client.getAccessToken();
      if (token) {
        try {
          const claims = decodeJwtPayload<JwtClaims>(token);
          setUser({
            id: claims.sub,
            email: "",
            email_verified: false,
            mfa_enabled: false,
          });
        } catch {
          setUser(null);
        }
      } else {
        setUser(null);
      }
    }
  }, [client]);

  // ── Auto-refresh on an interval ──
  const startAutoRefresh = useCallback(() => {
    if (autoRefreshInterval <= 0) return;
    if (refreshTimerRef.current) clearInterval(refreshTimerRef.current);
    refreshTimerRef.current = setInterval(async () => {
      try {
        await client.refresh();
      } catch {
        // Session expired — onSessionExpired callback handles state reset
        if (refreshTimerRef.current) clearInterval(refreshTimerRef.current);
      }
    }, autoRefreshInterval);
  }, [client, autoRefreshInterval]);

  const stopAutoRefresh = useCallback(() => {
    if (refreshTimerRef.current) {
      clearInterval(refreshTimerRef.current);
      refreshTimerRef.current = null;
    }
  }, []);

  // ── Restore session on mount ──
  useEffect(() => {
    const restoreSession = async () => {
      setLoading(true);
      try {
        await client.refresh();
        await fetchProfile();
        startAutoRefresh();
      } catch {
        // No valid session cookie — stay logged out
        client.setAccessToken(null);
        setUser(null);
      } finally {
        setLoading(false);
      }
    };
    restoreSession();
    return () => stopAutoRefresh();
  }, []);

  // ─────────────────────────────────────────────
  // Auth actions
  // ─────────────────────────────────────────────
  const login = useCallback(
    async (
      email: string,
      password: string,
    ): Promise<AuthResponse | MfaChallengeResponse> => {
      setLoading(true);
      try {
        const res = await client.login(email, password);
        if ("mfa_required" in res && res.mfa_required) {
          setMfaRequired(true);
          setMfaTicket(res.mfa_ticket);
          setUser(null);
          return res;
        }
        const authRes = res as AuthResponse;
        setUser(authRes.user);
        setMfaRequired(false);
        setMfaTicket(null);
        startAutoRefresh();
        return authRes;
      } catch (err) {
        setUser(null);
        throw err;
      } finally {
        setLoading(false);
      }
    },
    [client, startAutoRefresh],
  );

  const signup = useCallback(
    async (
      email: string,
      password: string,
      idempotencyKey?: string,
    ): Promise<User> => {
      setLoading(true);
      try {
        const res = await client.signup(email, password, idempotencyKey);
        // Don't auto-login — user must verify email first
        return res.user;
      } catch (err) {
        throw err;
      } finally {
        setLoading(false);
      }
    },
    [client],
  );

  const logout = useCallback(async (): Promise<void> => {
    setLoading(true);
    stopAutoRefresh();
    try {
      await client.logout();
    } finally {
      setUser(null);
      setMfaRequired(false);
      setMfaTicket(null);
      setLoading(false);
    }
  }, [client, stopAutoRefresh]);

  const verifyMfa = useCallback(
    async (code: string): Promise<AuthResponse> => {
      if (!mfaTicket) throw new Error("No pending MFA challenge ticket");
      setLoading(true);
      try {
        const res = await client.verifyMfa(mfaTicket, code);
        setUser(res.user);
        setMfaRequired(false);
        setMfaTicket(null);
        startAutoRefresh();
        return res;
      } finally {
        setLoading(false);
      }
    },
    [client, mfaTicket, startAutoRefresh],
  );

  const clearMfaChallenge = useCallback(() => {
    setMfaRequired(false);
    setMfaTicket(null);
  }, []);

  // ─────────────────────────────────────────────
  // Thin wrappers — delegate straight to client
  // ─────────────────────────────────────────────
  const verifyEmail = useCallback(
    (email: string, code: string) => client.verifyEmail(email, code),
    [client],
  );
  const resendVerification = useCallback(
    (email: string) => client.resendVerification(email),
    [client],
  );
  const listSessions = useCallback(() => client.listSessions(), [client]);
  const revokeSession = useCallback(
    (sessionId: string) => client.revokeSession(sessionId),
    [client],
  );
  const revokeAllSessions = useCallback(
    () => client.revokeAllSessions(),
    [client],
  );
  const listOrgs = useCallback(() => client.listOrgs(), [client]);
  const createOrg = useCallback(
    (name: string) => client.createOrg(name),
    [client],
  );
  const listMembers = useCallback(
    (orgId: string) => client.listMembers(orgId),
    [client],
  );
  const addMember = useCallback(
    (orgId: string, email: string, role: OrgRole) =>
      client.addMember(orgId, email, role),
    [client],
  );
  const updateMember = useCallback(
    (orgId: string, userId: string, role: OrgRole) =>
      client.updateMember(orgId, userId, role),
    [client],
  );
  const removeMember = useCallback(
    (orgId: string, userId: string) => client.removeMember(orgId, userId),
    [client],
  );
  const createAdminProject = useCallback(
    (name: string) => client.createAdminProject(name),
    [client],
  );
  const registerAdminWebhook = useCallback(
    (projectId: string, url: string, secret: string) =>
      client.registerAdminWebhook(projectId, url, secret),
    [client],
  );

  return (
    <AuthContext.Provider
      value={{
        client,
        user,
        loading,
        mfaRequired,
        mfaTicket,
        login,
        signup,
        logout,
        fetchProfile,
        verifyEmail,
        resendVerification,
        verifyMfa,
        clearMfaChallenge,
        listSessions,
        revokeSession,
        revokeAllSessions,
        listOrgs,
        createOrg,
        listMembers,
        addMember,
        updateMember,
        removeMember,
        createAdminProject,
        registerAdminWebhook,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

// ─────────────────────────────────────────────
// Base hook
// ─────────────────────────────────────────────
export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an <AuthProvider>");
  }
  return context;
};
