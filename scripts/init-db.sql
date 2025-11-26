-- PKI Platform Database Initialization
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Vault Storage Backend Table
CREATE TABLE IF NOT EXISTS vault_kv_store (
  parent_path TEXT COLLATE "C" NOT NULL,
  path        TEXT COLLATE "C",
  key         TEXT COLLATE "C",
  value       BYTEA,
  CONSTRAINT pkey PRIMARY KEY (path, key)
);

CREATE INDEX IF NOT EXISTS parent_path_idx ON vault_kv_store (parent_path);

-- Create indexes for better performance
-- (These will be created by Alembic migrations, but added here for reference)

\echo 'Database initialized successfully';
