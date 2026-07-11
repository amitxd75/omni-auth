-- Remove the nil UUID sentinel project and its associated data that was seeded
-- in migration 0004 purely to satisfy CI foreign key constraints.
--
-- Projects should be created at deployment time via the admin API (POST /api/admin/projects),
-- not hardcoded in migrations. The install.sh script handles this automatically.
--
-- This is safe because ON DELETE CASCADE propagates to:
--   oauth_accounts, sessions, users, project_redirect_uris, webhooks
DELETE FROM projects WHERE id = '00000000-0000-0000-0000-000000000000';
