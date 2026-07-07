-- Add api_key column to projects
ALTER TABLE projects ADD COLUMN IF NOT EXISTS api_key VARCHAR(255) NOT NULL DEFAULT '';

-- Populate a default api_key for the default project if it exists
UPDATE projects 
SET api_key = 'oa_proj_default_project_api_key_replace_me'
WHERE id = '00000000-0000-0000-0000-000000000000';
