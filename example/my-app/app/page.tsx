"use client";

import { useState, useEffect } from "react";
import {
  useAuth,
  useMfa,
  useOrgs,
  useOrgMembers,
  useSessions,
  useChangePassword,
  useForgotPassword,
  useResetPassword,
  useMagicLink,
  type UserOrg,
  type OrgMember,
  type UserSession,
  type OrgRole,
} from "@omni-auth/react";

/* ── tiny reusable primitives ─────────────────────────────────────────── */

function Input(props: React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      {...props}
      className={[
        "w-full px-3 py-2 bg-black border border-[#222] rounded-md text-white text-sm",
        "placeholder:text-[#444] focus:outline-none focus:border-[#555] transition-colors",
        props.className ?? "",
      ].join(" ")}
    />
  );
}

function Label({ children }: { children: React.ReactNode }) {
  return (
    <label className="block text-[10px] font-bold uppercase tracking-widest text-[#555] mb-1.5">
      {children}
    </label>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-1">
      <Label>{label}</Label>
      {children}
    </div>
  );
}

function Card({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <div className={["bg-[#0a0a0a] border border-[#1e1e1e] rounded-lg p-6", className ?? ""].join(" ")}>
      {children}
    </div>
  );
}

function CardTitle({ children }: { children: React.ReactNode }) {
  return (
    <h3 className="text-sm font-bold text-white mb-4 pb-3 border-b border-[#1a1a1a]">
      {children}
    </h3>
  );
}

function BtnPrimary({ children, ...props }: React.ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button
      {...props}
      className="w-full py-2 px-4 bg-white text-black text-sm font-bold rounded-md hover:bg-[#e0e0e0] transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
    >
      {children}
    </button>
  );
}

function BtnSecondary({ children, className, ...props }: React.ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button
      {...props}
      className={[
        "py-1.5 px-3 bg-[#111] border border-[#222] text-[#aaa] text-xs font-semibold rounded-md",
        "hover:bg-[#1a1a1a] hover:text-white transition-colors disabled:opacity-40",
        className ?? "",
      ].join(" ")}
    >
      {children}
    </button>
  );
}

function BtnDanger({ children, ...props }: React.ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button
      {...props}
      className="py-1.5 px-3 bg-[#1a0000] border border-[#330000] text-[#ff5555] text-xs font-semibold rounded-md hover:bg-[#250000] transition-colors"
    >
      {children}
    </button>
  );
}

function BtnGhost({ children, ...props }: React.ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button {...props} className="text-[#555] text-xs hover:text-[#aaa] transition-colors bg-transparent border-none p-0">
      {children}
    </button>
  );
}

function Badge({ children, variant = "dim" }: { children: React.ReactNode; variant?: "white" | "green" | "red" | "dim" }) {
  const cls = {
    white: "bg-[#1a1a1a] border-[#333] text-white",
    green: "bg-[#001a08] border-[#003316] text-[#44ff88]",
    red:   "bg-[#1a0000] border-[#330000] text-[#ff5555]",
    dim:   "bg-[#111] border-[#1a1a1a] text-[#555]",
  }[variant];
  return (
    <span className={`inline-block px-2 py-0.5 border rounded text-[10px] font-bold uppercase tracking-wide ${cls}`}>
      {children}
    </span>
  );
}

function Mono({ children }: { children: React.ReactNode }) {
  return (
    <div className="font-mono text-[11px] text-[#888] bg-black border border-[#1a1a1a] rounded px-2 py-1.5 break-all select-all">
      {children}
    </div>
  );
}

function Divider({ label }: { label: string }) {
  return (
    <div className="flex items-center gap-3 my-4">
      <div className="flex-1 h-px bg-[#1a1a1a]" />
      <span className="text-[10px] font-bold uppercase tracking-widest text-[#333]">{label}</span>
      <div className="flex-1 h-px bg-[#1a1a1a]" />
    </div>
  );
}

function Spinner() {
  return (
    <div className="w-5 h-5 border-2 border-[#222] border-t-white rounded-full animate-spin" />
  );
}

/* ── page ─────────────────────────────────────────────────────────────── */

export default function Home() {
  const { user, loading, mfaRequired, login, signup, logout, verifyMfa, client, fetchProfile } = useAuth();

  const [isLogin, setIsLogin] = useState(true);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [globalError, setGlobalError] = useState("");
  const [globalSuccess, setGlobalSuccess] = useState("");
  const [mfaCode, setMfaCode] = useState("");
  const [isVerifyingEmail, setIsVerifyingEmail] = useState(false);
  const [emailVerifyCode, setEmailVerifyCode] = useState("");
  const [activeTab, setActiveTab] = useState<"orgs" | "sessions" | "security" | "admin">("orgs");
  const [selectedOrgId, setSelectedOrgId] = useState<string | null>(null);

  const alert = (type: "ok" | "err", msg: string) => {
    if (type === "ok") { setGlobalSuccess(msg); setGlobalError(""); }
    else { setGlobalError(msg); setGlobalSuccess(""); }
  };

  /* ── URL param detection (magic link + password reset) ── */
  const magicLink = useMagicLink();
  useEffect(() => {
    if (typeof window === "undefined") return;
    const params = new URLSearchParams(window.location.search);
    const magicToken = params.get("magic_token");
    const magicEmailParam = params.get("magic_email");
    const resetToken = params.get("reset_token");
    const resetEmailParam = params.get("reset_email");

    const clean = () => {
      const url = new URL(window.location.href);
      ["magic_token", "magic_email", "reset_token", "reset_email"].forEach(k => url.searchParams.delete(k));
      window.history.replaceState({}, "", url.toString());
    };

    if (magicToken && magicEmailParam) {
      clean();
      alert("ok", "Verifying magic link…");
      magicLink.verify(decodeURIComponent(magicEmailParam), magicToken).then(res => {
        if (res) { (client as any).accessToken = res.access_token; fetchProfile().catch(() => {}); alert("ok", "Signed in via magic link."); }
        else alert("err", "Magic link is invalid or expired.");
      });
    } else if (resetToken && resetEmailParam) {
      clean();
      setActiveTab("security");
      alert("ok", "Link detected — set your new password below.");
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  /* ── auth handlers ── */
  const handleAuth = async (e: React.FormEvent) => {
    e.preventDefault(); setGlobalError(""); setGlobalSuccess("");
    try {
      if (isLogin) {
        const res = await login(email, password);
        if ("mfa_required" in res && res.mfa_required) alert("ok", "Credentials accepted. Complete 2FA.");
        else alert("ok", "Logged in.");
      } else {
        await signup(email, password, `signup-${Date.now()}`);
        alert("ok", "Signed up! Check your email or server logs for the code.");
        setIsVerifyingEmail(true);
      }
    } catch (err: any) { alert("err", err.message || "Authentication error."); }
  };

  const handleVerifyEmail = async (e: React.FormEvent) => {
    e.preventDefault(); setGlobalError(""); setGlobalSuccess("");
    try {
      await client.verifyEmail(email, emailVerifyCode);
      alert("ok", "Email verified. You can now sign in.");
      setIsVerifyingEmail(false); setIsLogin(true); setEmailVerifyCode("");
    } catch (err: any) { alert("err", err.message || "Failed to verify email."); }
  };

  const handleVerifyMfa = async (e: React.FormEvent) => {
    e.preventDefault(); setGlobalError(""); setGlobalSuccess("");
    try { await verifyMfa(mfaCode); alert("ok", "2FA verified."); setMfaCode(""); }
    catch (err: any) { alert("err", err.message || "Invalid or expired code."); }
  };

  /* ── OAuth ── */
  const triggerOAuth = (provider: string) => {
    const projId = process.env.NEXT_PUBLIC_OMNI_PROJECT_ID || "00000000-0000-0000-0000-000000000000";
    const base = process.env.NEXT_PUBLIC_OMNI_AUTH_URL || "http://localhost:8080";
    const callback = encodeURIComponent(window.location.origin + "/");
    window.location.href = `${base}/v1/auth/oauth/${provider}/authorize?project_id=${projId}&redirect_uri=${callback}`;
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-black flex items-center justify-center gap-3">
        <Spinner />
        <span className="text-[#444] text-sm">Loading…</span>
      </div>
    );
  }

  /* ══════════════════════════════════════════════════════════════════════
     Sub-views
  ══════════════════════════════════════════════════════════════════════ */

  /* ── Auth form ── */
  function AuthPanel() {
    const ml = useMagicLink();
    const [magicEmail, setMagicEmail] = useState("");
    const [magicSent, setMagicSent] = useState(false);

    return (
      <div className="max-w-sm w-full mx-auto">
        <Card>
          {/* toggle */}
          <div className="flex bg-black border border-[#1a1a1a] rounded-md p-0.5 mb-6">
            {(["Sign In", "Sign Up"] as const).map((label, i) => {
              const active = i === 0 ? isLogin : !isLogin;
              return (
                <button
                  key={label}
                  onClick={() => setIsLogin(i === 0)}
                  className={`flex-1 py-1.5 rounded text-xs font-bold transition-all ${active ? "bg-white text-black" : "text-[#555] hover:text-[#aaa]"}`}
                >
                  {label}
                </button>
              );
            })}
          </div>

          <form onSubmit={handleAuth} className="flex flex-col gap-4">
            <Field label="Email">
              <Input type="email" required value={email} onChange={e => setEmail(e.target.value)} placeholder="you@example.com" />
            </Field>
            <Field label="Password">
              <Input type="password" required value={password} onChange={e => setPassword(e.target.value)} placeholder="••••••••" />
            </Field>
            <BtnPrimary type="submit">{isLogin ? "Sign In" : "Create Account"}</BtnPrimary>
          </form>

          <Divider label="or" />

          <div className="grid grid-cols-2 gap-2">
            <button
              onClick={() => triggerOAuth("github")}
              className="flex items-center justify-center gap-2 py-2 px-3 bg-[#111] border border-[#222] text-[#aaa] text-xs font-semibold rounded-md hover:bg-[#1a1a1a] hover:text-white transition-colors"
            >
              <svg width="13" height="13" viewBox="0 0 24 24" fill="currentColor">
                <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
              </svg>
              GitHub
            </button>
            <button
              onClick={() => triggerOAuth("google")}
              className="flex items-center justify-center gap-2 py-2 px-3 bg-[#111] border border-[#222] text-[#aaa] text-xs font-semibold rounded-md hover:bg-[#1a1a1a] hover:text-white transition-colors"
            >
              <svg width="13" height="13" viewBox="0 0 24 24" fill="currentColor">
                <path d="M12.24 10.285V14.4h6.887c-.648 2.41-2.519 4.114-5.187 4.114-3.567 0-6.46-2.893-6.46-6.46s2.893-6.46 6.46-6.46c1.63 0 3.11.604 4.25 1.6l3.1-3.1C18.66 1.7 15.63 0 12.24 0 5.48 0 0 5.48 0 12.24s5.48 12.24 12.24 12.24c6.7 0 12.24-5.48 12.24-12.24 0-.825-.098-1.62-.266-2.39H12.24z"/>
              </svg>
              Google
            </button>
          </div>

          {isLogin && (
            <>
              <Divider label="passwordless" />
              {magicSent ? (
                <div className="text-center p-4 bg-black border border-[#1a1a1a] rounded-md">
                  <div className="text-xl mb-1">✉</div>
                  <p className="text-xs text-[#aaa] mb-1">Check your inbox</p>
                  <p className="text-[11px] text-[#555] mb-3">Link sent to {magicEmail || email}</p>
                  <BtnGhost onClick={() => { setMagicSent(false); setMagicEmail(""); ml.reset(); }}>
                    Try different address
                  </BtnGhost>
                </div>
              ) : (
                <div className="flex gap-2">
                  <Input type="email" value={magicEmail || email} onChange={e => setMagicEmail(e.target.value)} placeholder="your@email.com" className="flex-1" />
                  <button
                    type="button"
                    disabled={ml.loading}
                    onClick={async () => {
                      const addr = magicEmail || email;
                      if (!addr) { alert("err", "Enter an email first."); return; }
                      try { await ml.request(addr); setMagicSent(true); setMagicEmail(addr); }
                      catch (err: any) { alert("err", err.message || "Failed to send magic link."); }
                    }}
                    className="py-2 px-3 bg-[#111] border border-[#222] text-[#aaa] text-xs font-semibold rounded-md hover:bg-[#1a1a1a] whitespace-nowrap disabled:opacity-40 transition-colors"
                  >
                    {ml.loading ? "Sending…" : "Magic Link"}
                  </button>
                </div>
              )}
            </>
          )}
        </Card>
      </div>
    );
  }

  /* ── Email verification ── */
  function EmailVerifyPanel() {
    return (
      <div className="max-w-sm w-full mx-auto">
        <Card>
          <h2 className="text-base font-bold mb-1">Verify Email</h2>
          <p className="text-xs text-[#555] mb-5">
            A 6-digit code was sent to <strong className="text-[#aaa]">{email}</strong>. Check server logs if email isn't configured.
          </p>
          <form onSubmit={handleVerifyEmail} className="flex flex-col gap-4">
            <Field label="Verification Code">
              <Input type="text" required maxLength={6} value={emailVerifyCode} onChange={e => setEmailVerifyCode(e.target.value)} placeholder="123456" className="text-center tracking-widest font-mono text-lg" />
            </Field>
            <BtnPrimary type="submit">Verify Email</BtnPrimary>
            <div className="flex justify-between">
              <BtnGhost type="button" onClick={async () => {
                try { await client.resendVerification(email); alert("ok", "Code resent."); }
                catch (err: any) { alert("err", err.message); }
              }}>Resend code</BtnGhost>
              <BtnGhost type="button" onClick={() => setIsVerifyingEmail(false)}>Back to sign in</BtnGhost>
            </div>
          </form>
        </Card>
      </div>
    );
  }

  /* ── MFA challenge ── */
  function MfaPanel() {
    return (
      <div className="max-w-sm w-full mx-auto">
        <Card>
          <h2 className="text-base font-bold mb-1">Two-Factor Auth</h2>
          <p className="text-xs text-[#555] mb-5">Enter the 6-digit code from your authenticator app.</p>
          <form onSubmit={handleVerifyMfa} className="flex flex-col gap-4">
            <Field label="Code">
              <Input type="text" required maxLength={6} value={mfaCode} onChange={e => setMfaCode(e.target.value)} placeholder="123456" className="text-center tracking-widest font-mono text-lg" />
            </Field>
            <BtnPrimary type="submit">Verify</BtnPrimary>
          </form>
        </Card>
      </div>
    );
  }

  /* ── Orgs tab ── */
  function OrgsTab() {
    const mfa = useMfa();
    const orgs = useOrgs();
    const members = useOrgMembers();
    const [newOrgName, setNewOrgName] = useState("");
    const [inviteEmail, setInviteEmail] = useState("");
    const [inviteRole, setInviteRole] = useState<OrgRole>("member");
    const [mfaEnrollCode, setMfaEnrollCode] = useState("");

    useEffect(() => { orgs.refresh(); }, []);
    useEffect(() => { if (selectedOrgId) members.refresh(selectedOrgId); }, [selectedOrgId]);

    return (
      <div className="grid grid-cols-[1fr_2fr] gap-6 items-start">
        {/* left */}
        <div className="flex flex-col gap-4">
          <Card>
            <CardTitle>Profile</CardTitle>
            <div className="flex flex-col gap-3">
              <div>
                <Label>User ID</Label>
                <Mono>{user!.id}</Mono>
              </div>
              <div>
                <Label>Email</Label>
                <div className="text-sm text-[#aaa]">{user!.email || "—"}</div>
              </div>
              <div>
                <Label>MFA</Label>
                <Badge variant={user!.mfa_enabled ? "green" : "dim"}>
                  {user!.mfa_enabled ? "Enabled" : "Disabled"}
                </Badge>
              </div>
            </div>
          </Card>

          <Card>
            <CardTitle>MFA Settings</CardTitle>
            {mfa.error && <p className="text-xs text-[#ff5555] mb-3">{mfa.error}</p>}

            {!user!.mfa_enabled && !mfa.enrollState && (
              <BtnPrimary onClick={() => mfa.enroll()} disabled={mfa.loading}>
                {mfa.loading ? "Loading…" : "Setup TOTP Authenticator"}
              </BtnPrimary>
            )}

            {!user!.mfa_enabled && mfa.enrollState && (
              <div className="flex flex-col gap-4">
                <div>
                  <Label>Secret Key (Base32)</Label>
                  <Mono>{mfa.enrollState.secret}</Mono>
                </div>
                <p className="text-[11px] text-[#555]">Scan with Google Authenticator or use the code above.</p>
                <Field label="Confirm Code">
                  <Input type="text" maxLength={6} value={mfaEnrollCode} onChange={e => setMfaEnrollCode(e.target.value)} placeholder="123456" className="text-center tracking-widest font-mono" />
                </Field>
                <div className="flex gap-2">
                  <BtnPrimary onClick={async () => {
                    try { await mfa.enable(mfa.enrollState!.secret, mfaEnrollCode); alert("ok", "MFA enabled."); }
                    catch (err: any) { alert("err", err.message); }
                  }} disabled={mfa.loading}>Enable MFA</BtnPrimary>
                  <BtnSecondary onClick={() => { mfa.cancelEnroll(); setMfaEnrollCode(""); }}>Cancel</BtnSecondary>
                </div>
              </div>
            )}

            {user!.mfa_enabled && (
              <div>
                <p className="text-xs text-[#555] mb-3">MFA is active on this account.</p>
                <BtnDanger onClick={async () => {
                  const code = prompt("Enter your current 2FA code to disable MFA:");
                  if (!code) return;
                  try { await mfa.disable(code); alert("ok", "MFA disabled."); }
                  catch (err: any) { alert("err", err.message); }
                }}>
                  Disable MFA
                </BtnDanger>
              </div>
            )}
          </Card>
        </div>

        {/* right */}
        <div className="flex flex-col gap-4">
          <Card>
            <div className="flex items-center justify-between mb-4 pb-3 border-b border-[#1a1a1a]">
              <h3 className="text-sm font-bold text-white">Organizations</h3>
              <form onSubmit={async e => { e.preventDefault(); if (!newOrgName.trim()) return; try { await orgs.create(newOrgName); setNewOrgName(""); } catch (err: any) { alert("err", err.message); } }} className="flex gap-2">
                <Input type="text" required value={newOrgName} onChange={e => setNewOrgName(e.target.value)} placeholder="New org name" className="w-40" />
                <BtnSecondary type="submit">Create</BtnSecondary>
              </form>
            </div>

            {orgs.loading ? (
              <div className="flex justify-center py-4"><Spinner /></div>
            ) : orgs.orgs.length === 0 ? (
              <p className="text-xs text-[#333] italic">No organizations yet.</p>
            ) : (
              <div className="grid grid-cols-2 gap-2">
                {orgs.orgs.map((org: UserOrg) => (
                  <button
                    key={org.id}
                    onClick={() => setSelectedOrgId(org.id)}
                    className={`p-3 text-left border rounded-md transition-all ${selectedOrgId === org.id ? "bg-[#111] border-[#333]" : "bg-black border-[#1a1a1a] hover:border-[#2a2a2a]"}`}
                  >
                    <div className="text-xs font-semibold text-white mb-1.5">{org.name}</div>
                    <Badge variant="dim">{org.role}</Badge>
                  </button>
                ))}
              </div>
            )}
          </Card>

          {selectedOrgId && (
            <Card>
              <div className="flex items-center justify-between mb-4 pb-3 border-b border-[#1a1a1a]">
                <div>
                  <h3 className="text-sm font-bold text-white">Members</h3>
                  <div className="font-mono text-[10px] text-[#333] mt-0.5">{selectedOrgId}</div>
                </div>
                <form onSubmit={async e => {
                  e.preventDefault();
                  try { await members.invite(selectedOrgId, inviteEmail, inviteRole); setInviteEmail(""); alert("ok", "Member added."); }
                  catch (err: any) { alert("err", err.message); }
                }} className="flex gap-2">
                  <Input type="email" required value={inviteEmail} onChange={e => setInviteEmail(e.target.value)} placeholder="email@example.com" className="w-48" />
                  <select value={inviteRole} onChange={e => setInviteRole(e.target.value as OrgRole)} className="px-2 py-1.5 bg-black border border-[#222] rounded-md text-[#aaa] text-xs outline-none">
                    <option value="member">Member</option>
                    <option value="admin">Admin</option>
                  </select>
                  <BtnSecondary type="submit">Add</BtnSecondary>
                </form>
              </div>

              {members.loading ? (
                <div className="flex justify-center py-4"><Spinner /></div>
              ) : (
                <table className="w-full border-collapse">
                  <thead>
                    <tr>
                      {["User ID", "Email", "Role", "Actions"].map((h, i) => (
                        <th key={h} className={`py-2 px-3 text-[10px] font-bold uppercase tracking-wider text-[#444] border-b border-[#1a1a1a] ${i === 3 ? "text-right" : "text-left"}`}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {members.members.map((m: OrgMember) => (
                      <tr key={m.user_id} className="border-b border-[#111]">
                        <td className="py-2.5 px-3 font-mono text-[10px] text-[#555]">{m.user_id}</td>
                        <td className="py-2.5 px-3 text-xs text-[#aaa]">{m.email}</td>
                        <td className="py-2.5 px-3">
                          <Badge variant={m.role === "owner" ? "white" : m.role === "admin" ? "white" : "dim"}>{m.role}</Badge>
                        </td>
                        <td className="py-2.5 px-3">
                          <div className="flex justify-end gap-2">
                            <BtnSecondary onClick={async () => {
                              const newRole: OrgRole = m.role === "admin" ? "member" : "admin";
                              try { await members.update(selectedOrgId, m.user_id, newRole); alert("ok", "Role updated."); }
                              catch (err: any) { alert("err", err.message); }
                            }}>Toggle Admin</BtnSecondary>
                            <BtnDanger onClick={async () => {
                              if (!confirm("Remove this member?")) return;
                              try { await members.remove(selectedOrgId, m.user_id); alert("ok", "Removed."); }
                              catch (err: any) { alert("err", err.message); }
                            }}>Remove</BtnDanger>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </Card>
          )}
        </div>
      </div>
    );
  }

  /* ── Sessions tab ── */
  function SessionsTab() {
    const s = useSessions();
    useEffect(() => { s.refresh(); }, []);

    return (
      <div className="flex flex-col gap-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-bold">Active Sessions</h3>
            <p className="text-[11px] text-[#444] mt-0.5">Devices signed into your account</p>
          </div>
          <div className="flex gap-2">
            <BtnSecondary onClick={() => s.refresh()} disabled={s.loading}>{s.loading ? "Refreshing…" : "Refresh"}</BtnSecondary>
            <BtnDanger onClick={async () => { try { await s.revokeAll(); alert("ok", "All other sessions revoked."); } catch (err: any) { alert("err", err.message); } }}>
              Log Out All Other Devices
            </BtnDanger>
          </div>
        </div>

        {s.loading ? (
          <div className="flex justify-center py-10"><Spinner /></div>
        ) : s.sessions.length === 0 ? (
          <Card className="text-center text-[#333] text-xs">No sessions found.</Card>
        ) : (
          <div className="flex flex-col gap-2">
            {s.sessions.map((sess: UserSession) => (
              <div key={sess.id} className={`p-4 border rounded-lg flex items-start justify-between gap-4 ${sess.is_current ? "bg-[#0a0a0a] border-[#2a2a2a]" : "bg-[#050505] border-[#111]"}`}>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    {sess.is_current && <Badge variant="white">This Device</Badge>}
                    <span className="font-mono text-[11px] text-[#555]">{sess.ip_address ?? "Unknown IP"}</span>
                  </div>
                  <p className="text-[11px] text-[#444] truncate">{sess.user_agent ?? "Unknown client"}</p>
                  <div className="flex gap-4 text-[10px] text-[#333] mt-1">
                    <span>Created: {new Date(sess.created_at).toLocaleString()}</span>
                    <span>Expires: {new Date(sess.expires_at).toLocaleString()}</span>
                  </div>
                </div>
                {!sess.is_current && (
                  <BtnDanger onClick={async () => { try { await s.revoke(sess.id); alert("ok", "Session revoked."); } catch (err: any) { alert("err", err.message); } }}>
                    Revoke
                  </BtnDanger>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    );
  }

  /* ── Security tab ── */
  function SecurityTab() {
    const [view, setView] = useState<"change" | "forgot" | "reset">("change");
    const changePw = useChangePassword();
    const forgotPw = useForgotPassword();
    const resetPw = useResetPassword();

    const [currentPw, setCurrentPw] = useState("");
    const [newPw, setNewPw] = useState("");
    const [confirmPw, setConfirmPw] = useState("");
    const [forgotEmail, setForgotEmail] = useState("");
    const [resetEmail, setResetEmail] = useState("");
    const [resetToken, setResetToken] = useState("");
    const [resetNewPw, setResetNewPw] = useState("");

    useEffect(() => {
      if (changePw.success) { alert("ok", "Password changed. Other sessions signed out."); changePw.reset(); setCurrentPw(""); setNewPw(""); setConfirmPw(""); }
      if (changePw.error) { alert("err", changePw.error); changePw.reset(); }
    }, [changePw.success, changePw.error]);

    useEffect(() => {
      if (forgotPw.sent) { alert("ok", "Reset token sent — check email or server logs."); setView("reset"); forgotPw.reset(); }
      if (forgotPw.error) { alert("err", forgotPw.error); forgotPw.reset(); }
    }, [forgotPw.sent, forgotPw.error]);

    useEffect(() => {
      if (resetPw.success) { alert("ok", "Password reset. Please sign in again."); resetPw.reset(); setResetEmail(""); setResetToken(""); setResetNewPw(""); }
      if (resetPw.error) { alert("err", resetPw.error); resetPw.reset(); }
    }, [resetPw.success, resetPw.error]);

    const subTabs: Array<[typeof view, string]> = [["change", "Change Password"], ["forgot", "Forgot Password"], ["reset", "Reset with Token"]];

    return (
      <div className="max-w-lg w-full mx-auto flex flex-col gap-4">
        <div className="flex bg-[#050505] border border-[#1a1a1a] rounded-md p-0.5 gap-0.5">
          {subTabs.map(([v, label]) => (
            <button key={v} onClick={() => setView(v)} className={`flex-1 py-1.5 px-2 rounded text-xs font-semibold transition-all ${view === v ? "bg-[#1a1a1a] text-white" : "text-[#444] hover:text-[#aaa]"}`}>
              {label}
            </button>
          ))}
        </div>

        {view === "change" && (
          <Card>
            <CardTitle>Change Password</CardTitle>
            <p className="text-[11px] text-[#555] mb-4">Other sessions will be signed out after changing.</p>
            <div className="flex flex-col gap-4">
              <Field label="Current Password"><Input type="password" value={currentPw} onChange={e => setCurrentPw(e.target.value)} placeholder="Current password" /></Field>
              <Field label="New Password"><Input type="password" value={newPw} onChange={e => setNewPw(e.target.value)} placeholder="Min. 8 characters" /></Field>
              <Field label="Confirm New Password"><Input type="password" value={confirmPw} onChange={e => setConfirmPw(e.target.value)} placeholder="Repeat new password" /></Field>
              <BtnPrimary onClick={async () => {
                if (newPw !== confirmPw) { alert("err", "Passwords do not match."); return; }
                await changePw.submit(currentPw, newPw);
              }} disabled={changePw.loading}>
                {changePw.loading ? "Updating…" : "Update Password"}
              </BtnPrimary>
            </div>
          </Card>
        )}

        {view === "forgot" && (
          <Card>
            <CardTitle>Forgot Password</CardTitle>
            <p className="text-[11px] text-[#555] mb-4">A reset token will be sent to your email. Check server logs if email isn't configured.</p>
            <div className="flex flex-col gap-4">
              <Field label="Email Address"><Input type="email" value={forgotEmail} onChange={e => setForgotEmail(e.target.value)} placeholder="your@email.com" /></Field>
              <BtnPrimary onClick={() => forgotPw.send(forgotEmail)} disabled={forgotPw.loading}>
                {forgotPw.loading ? "Sending…" : "Send Reset Token"}
              </BtnPrimary>
            </div>
          </Card>
        )}

        {view === "reset" && (
          <Card>
            <CardTitle>Reset Password</CardTitle>
            <p className="text-[11px] text-[#555] mb-4">Paste your reset token and set a new password.</p>
            <div className="flex flex-col gap-4">
              <Field label="Email Address"><Input type="email" value={resetEmail} onChange={e => setResetEmail(e.target.value)} placeholder="your@email.com" /></Field>
              <Field label="Reset Token"><Input value={resetToken} onChange={e => setResetToken(e.target.value)} placeholder="Paste token from email" className="font-mono" /></Field>
              <Field label="New Password"><Input type="password" value={resetNewPw} onChange={e => setResetNewPw(e.target.value)} placeholder="Min. 8 characters" /></Field>
              <BtnPrimary onClick={() => resetPw.submit(resetEmail, resetToken, resetNewPw)} disabled={resetPw.loading}>
                {resetPw.loading ? "Resetting…" : "Reset Password"}
              </BtnPrimary>
            </div>
          </Card>
        )}
      </div>
    );
  }

  /* ── Admin tab ── */
  function AdminTab() {
    const [projectName, setProjectName] = useState("");
    const [createdProject, setCreatedProject] = useState<any>(null);
    const [whProjId, setWhProjId] = useState("");
    const [whUrl, setWhUrl] = useState("");
    const [whSecret, setWhSecret] = useState("");

    return (
      <div className="grid grid-cols-[1fr_2fr] gap-6 items-start">
        <Card>
          <CardTitle>Create Tenant Project</CardTitle>
          <form onSubmit={async e => {
            e.preventDefault();
            try { const r = await client.createAdminProject(projectName); setCreatedProject(r); alert("ok", `Project "${projectName}" created.`); setProjectName(""); }
            catch (err: any) { alert("err", err.message); }
          }} className="flex flex-col gap-4">
            <Field label="Project Name">
              <Input type="text" required value={projectName} onChange={e => setProjectName(e.target.value)} placeholder="My App" />
            </Field>
            <BtnPrimary type="submit">Create Project</BtnPrimary>
          </form>
        </Card>

        <div className="flex flex-col gap-4">
          {createdProject && (
            <Card className="border-[#1e2a1e]">
              <CardTitle>Project Created</CardTitle>
              <div className="flex flex-col gap-3">
                <div><Label>Project ID</Label><Mono>{createdProject.id}</Mono></div>
                <div><Label>Name</Label><div className="text-sm text-white">{createdProject.name}</div></div>
                <div><Label>JWT Public Key (Ed25519)</Label><div className="font-mono text-[11px] text-[#888] bg-black border border-[#1a1a1a] rounded px-2 py-1.5 break-all max-h-20 overflow-y-auto">{createdProject.jwt_public_key}</div></div>
              </div>
            </Card>
          )}

          <Card>
            <CardTitle>Register Webhook</CardTitle>
            <form onSubmit={async e => {
              e.preventDefault();
              try { await client.registerAdminWebhook(whProjId, whUrl, whSecret); alert("ok", "Webhook registered."); setWhProjId(""); setWhUrl(""); setWhSecret(""); }
              catch (err: any) { alert("err", err.message); }
            }} className="flex flex-col gap-4">
              <div className="grid grid-cols-2 gap-4">
                <Field label="Project ID"><Input type="text" required value={whProjId} onChange={e => setWhProjId(e.target.value)} placeholder="00000000-…" /></Field>
                <Field label="Signing Secret"><Input type="text" required value={whSecret} onChange={e => setWhSecret(e.target.value)} placeholder="secret_key" /></Field>
              </div>
              <Field label="Payload URL"><Input type="url" required value={whUrl} onChange={e => setWhUrl(e.target.value)} placeholder="https://myapp.com/webhooks" /></Field>
              <BtnPrimary type="submit">Register Endpoint</BtnPrimary>
            </form>
          </Card>
        </div>
      </div>
    );
  }

  /* ── root render ── */
  return (
    <div className="min-h-screen bg-black text-white flex flex-col items-center justify-center p-8">
      <div className="w-full max-w-5xl flex flex-col gap-7">

        {/* header */}
        <div className="flex items-center justify-between pb-5 border-b border-[#1a1a1a]">
          <div>
            <h1 className="text-lg font-extrabold tracking-tight">OmniAuth</h1>
            <p className="text-[11px] text-[#333] mt-0.5">Multi-tenant · OAuth · Orgs · RBAC · TOTP MFA</p>
          </div>
          {user && (
            <div className="flex items-center gap-3">
              <span className="text-xs text-[#444]">{user.email}</span>
              <BtnSecondary onClick={() => logout()}>Sign Out</BtnSecondary>
            </div>
          )}
        </div>

        {/* alerts */}
        {globalError && <div className="p-3 bg-[#1a0000] border border-[#330000] rounded-md text-[#ff6666] text-sm">⚠ {globalError}</div>}
        {globalSuccess && <div className="p-3 bg-[#001a08] border border-[#003316] rounded-md text-[#44ff88] text-sm">✓ {globalSuccess}</div>}

        {/* views */}
        {!user && !mfaRequired && !isVerifyingEmail && <AuthPanel />}
        {!user && isVerifyingEmail && <EmailVerifyPanel />}
        {!user && mfaRequired && <MfaPanel />}

        {user && (
          <>
            <div className="flex border-b border-[#1a1a1a]">
              {(["orgs", "sessions", "security", "admin"] as const).map(tab => (
                <button
                  key={tab}
                  onClick={() => setActiveTab(tab)}
                  className={`px-5 py-2.5 text-xs font-bold transition-all border-b-2 -mb-px capitalize ${activeTab === tab ? "border-white text-white" : "border-transparent text-[#444] hover:text-[#aaa]"}`}
                >
                  {tab === "orgs" ? "Organizations" : tab === "admin" ? "Admin" : tab.charAt(0).toUpperCase() + tab.slice(1)}
                </button>
              ))}
            </div>
            {activeTab === "orgs" && <OrgsTab />}
            {activeTab === "sessions" && <SessionsTab />}
            {activeTab === "security" && <SecurityTab />}
            {activeTab === "admin" && <AdminTab />}
          </>
        )}
      </div>
    </div>
  );
}
