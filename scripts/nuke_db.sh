#!/bin/bash
set -e

# Load environment file if it exists
if [ -f .env ]; then
    export $(grep -v '^#' .env | xargs)
fi

DB_URL=${DATABASE_URL:-"postgres://postgres:postgres@127.0.0.1:5432/omni_auth"}

echo "⚠️ Nuking database: $DB_URL"
echo "Dropping and recreating public schema..."

# Connect and drop/recreate public schema
psql "$DB_URL" -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public; GRANT ALL ON SCHEMA public TO public;"

echo "✅ Database schema cleared successfully. Re-run migrations or restart the API server to seed fresh."
