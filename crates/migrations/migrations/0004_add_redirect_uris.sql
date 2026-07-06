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
