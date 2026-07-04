"use client";
import { useState, useCallback } from "react";
import { useAuth } from "./context";
import { UserOrg, OrgMember, OrgRole } from "../../core/src/index";

export interface UseOrgsReturn {
  orgs: UserOrg[];
  loading: boolean;
  error: string | null;
  /** Fetch the user's org list */
  refresh: () => Promise<void>;
  /** Create a new organization */
  create: (name: string) => Promise<void>;
}

export interface UseOrgMembersReturn {
  members: OrgMember[];
  loading: boolean;
  error: string | null;
  /** Fetch members for an org */
  refresh: (orgId: string) => Promise<void>;
  /** Invite a user by email */
  invite: (orgId: string, email: string, role: OrgRole) => Promise<void>;
  /** Update a member's role */
  update: (orgId: string, userId: string, role: OrgRole) => Promise<void>;
  /** Remove a member */
  remove: (orgId: string, userId: string) => Promise<void>;
}

/**
 * Hook for listing and creating organizations the current user belongs to.
 *
 * @example
 * const { orgs, refresh, create } = useOrgs();
 * useEffect(() => { refresh(); }, []);
 */
export function useOrgs(): UseOrgsReturn {
  const { listOrgs, createOrg } = useAuth();
  const [orgs, setOrgs] = useState<UserOrg[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await listOrgs();
      setOrgs(data);
    } catch (err: any) {
      setError(err.message ?? "Failed to load organizations");
    } finally {
      setLoading(false);
    }
  }, [listOrgs]);

  const create = useCallback(
    async (name: string) => {
      await createOrg(name);
      await refresh();
    },
    [createOrg, refresh]
  );

  return { orgs, loading, error, refresh, create };
}

/**
 * Hook for managing members inside a single organization.
 *
 * @example
 * const { members, refresh, invite, remove } = useOrgMembers();
 * useEffect(() => { refresh(orgId); }, [orgId]);
 */
export function useOrgMembers(): UseOrgMembersReturn {
  const { listMembers, addMember, updateMember, removeMember } = useAuth();
  const [members, setMembers] = useState<OrgMember[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(
    async (orgId: string) => {
      setLoading(true);
      setError(null);
      try {
        const data = await listMembers(orgId);
        setMembers(data);
      } catch (err: any) {
        setError(err.message ?? "Failed to load members");
      } finally {
        setLoading(false);
      }
    },
    [listMembers]
  );

  const invite = useCallback(
    async (orgId: string, email: string, role: OrgRole) => {
      await addMember(orgId, email, role);
      await refresh(orgId);
    },
    [addMember, refresh]
  );

  const update = useCallback(
    async (orgId: string, userId: string, role: OrgRole) => {
      await updateMember(orgId, userId, role);
      await refresh(orgId);
    },
    [updateMember, refresh]
  );

  const remove = useCallback(
    async (orgId: string, userId: string) => {
      await removeMember(orgId, userId);
      setMembers((prev) => prev.filter((m) => m.user_id !== userId));
    },
    [removeMember]
  );

  return { members, loading, error, refresh, invite, update, remove };
}
