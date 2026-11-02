-- oxicloud-init (Portcullis): close OxiCloud's first-run setup endpoint.
--
-- POST /api/setup creates a password owner account for whoever calls it
-- while auth.admin_settings has no system_initialized = 'true' row
-- (src/interfaces/api/handlers/auth_handler.rs setup_admin, v0.10.0). With
-- Portcullis every account is an OIDC account, so the instance is marked
-- initialized before OxiCloud ever starts. The schema and table are created
-- exactly as OxiCloud's first migration does (IF NOT EXISTS), so the
-- migration still applies on a fresh database. Runs at every start; any
-- error stops OxiCloud from starting (fail closed).
\set ON_ERROR_STOP on

BEGIN;

CREATE SCHEMA IF NOT EXISTS auth;

CREATE TABLE IF NOT EXISTS auth.admin_settings (
    key VARCHAR(255) PRIMARY KEY,
    value TEXT NOT NULL,
    category VARCHAR(50) NOT NULL DEFAULT 'general',
    is_secret BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID
);

INSERT INTO auth.admin_settings (key, value, category, is_secret, updated_by, updated_at)
VALUES ('system_initialized', 'true', 'system', false, NULL, NOW())
ON CONFLICT (key) DO UPDATE SET value = 'true';

DO $$
BEGIN
    IF (SELECT value FROM auth.admin_settings WHERE key = 'system_initialized') IS DISTINCT FROM 'true' THEN
        RAISE EXCEPTION 'portcullis: system_initialized is not set';
    END IF;
END
$$;

COMMIT;

\echo portcullis-init: OxiCloud setup endpoint closed (system_initialized = true)
