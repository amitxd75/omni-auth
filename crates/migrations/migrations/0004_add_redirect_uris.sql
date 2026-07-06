-- Seed the default project if it doesn't exist yet (to satisfy foreign key constraints during migrations)
INSERT INTO projects (id, name, jwt_private_key, jwt_public_key, api_key)
VALUES ('00000000-0000-0000-0000-000000000000', 'Default Project', 'MFECAQEwBQYDK2VwBCIEIErD6Qcr2ChE/1NnYKCfF8wSS7QELQ2WJUGKa/zmzA9ZgSEAQY8aMom4aHxWTmeRSp5UB8lUv0uXju1INYYbSeen6vA=', 'QY8aMom4aHxWTmeRSp5UB8lUv0uXju1INYYbSeen6vA=', 'oa_proj_default_project_api_key_replace_me')
ON CONFLICT (id) DO UPDATE SET api_key = EXCLUDED.api_key;

-- Create project_redirect_uris table
CREATE TABLE IF NOT EXISTS project_redirect_uris (
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    redirect_uri TEXT NOT NULL,
    PRIMARY KEY (project_id, redirect_uri)
);

-- Seed with default redirect_uris for the default nil UUID project
INSERT INTO project_redirect_uris (project_id, redirect_uri)
VALUES ('00000000-0000-0000-0000-000000000000', 'http://localhost:3000/callback'),
       ('00000000-0000-0000-0000-000000000000', 'http://127.0.0.1:3000/callback')
ON CONFLICT DO NOTHING;
