-- Firefox Sync + own accounts: the Sync database's roles and node
-- (firefox-sync-fxa-init, every start, before the Sync server). Applied with
-- psql -X -v ON_ERROR_STOP=1 --single-transaction: any error rolls
-- everything back and the init exits non-zero, so the Sync server
-- (depends_on: service_completed_successfully) does not start.
--
-- firefox-sync/guard.sql without its allowlist (sync_allowed_accounts and
-- its users trigger): here the tokenserver verifies OAuth tokens with this
-- instance's own accounts server only (SYNC_TOKENSERVER__FXA_OAUTH_SERVER_URL
-- http://fxa-auth:9000/v1), and who may have an account is decided there
-- (the sign-up allowlist of the access group). Everything else is as in
-- firefox-sync: the internet-facing role owns nothing, is no superuser, has
-- the minimum grants and may create no database object; the node is this
-- instance's hostname, with the largest capacity and a recounted load; the
-- admin UI's roles are exactly firefox-sync's.
--
-- Values come from the environment (\getenv), never from argv:
--   FIREFOX_SYNC_NODE_URL           https://<this instance's Sync hostname>
--   FIREFOX_SYNC_APP_DB_PASSWORD    the Sync server's role
--   FIREFOX_SYNC_ADMIN_DB_PASSWORD  the admin UI's two roles
\getenv node_url FIREFOX_SYNC_NODE_URL
\getenv app_password FIREFOX_SYNC_APP_DB_PASSWORD
\getenv admin_password FIREFOX_SYNC_ADMIN_DB_PASSWORD

-- The roles' passwords are in statements below: never put statement text in
-- the server log, not even on an error (this runs as the superuser).
SET LOCAL log_statement = 'none';
SET LOCAL log_min_error_statement = 'panic';

-- An unset variable stays as the literal text :'node_url' (and so on): it
-- fails the checks below (fail closed).
CREATE TEMP TABLE portcullis_node ON COMMIT DROP AS SELECT :'node_url'::text AS url;
CREATE TEMP TABLE portcullis_pw ON COMMIT DROP AS SELECT length(:'app_password') AS len, length(:'admin_password') AS admin_len;

DO $$
BEGIN
    IF (SELECT len FROM portcullis_pw) < 16 THEN
        RAISE EXCEPTION 'portcullis: FIREFOX_SYNC_APP_DB_PASSWORD is missing or too short';
    END IF;
    IF (SELECT admin_len FROM portcullis_pw) < 16 THEN
        RAISE EXCEPTION 'portcullis: FIREFOX_SYNC_ADMIN_DB_PASSWORD is missing or too short';
    END IF;
    IF (SELECT url FROM portcullis_node) !~ '^https://[a-z0-9.-]+$' THEN
        RAISE EXCEPTION 'portcullis: FIREFOX_SYNC_NODE_URL is not https://<hostname>';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM services WHERE service = 'sync-1.5') THEN
        RAISE EXCEPTION 'portcullis: the tokenserver tables are missing (firefox-sync-fxa-migrate did not run)';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM nodes n JOIN services s ON s.id = n.service AND s.service = 'sync-1.5'
                   JOIN portcullis_node p ON n.node = p.url) THEN
        RAISE EXCEPTION 'portcullis: no sync node for this hostname (firefox-sync-fxa-migrate did not run)';
    END IF;
END $$;

-- One sync node, this instance's hostname. After a hostname change
-- firefox-sync-fxa-migrate added a node for the new one (INIT_NODE_URL): move
-- the users to it and take the old nodes out of rotation (as
-- porelli/firefox-sync's db_init.sql does).
UPDATE nodes n SET downed = 0, available = n.capacity
FROM services s, portcullis_node p
WHERE s.service = 'sync-1.5' AND n.service = s.id AND n.node = p.url AND n.downed = 1;

UPDATE users u SET nodeid = n.id
FROM services s, nodes n, portcullis_node p
WHERE s.service = 'sync-1.5' AND u.service = s.id AND n.service = s.id AND n.node = p.url
  AND u.nodeid <> n.id;

UPDATE nodes n SET available = 0, downed = 1
FROM services s, portcullis_node p
WHERE s.service = 'sync-1.5' AND n.service = s.id AND n.node <> p.url;

-- The tokenserver adds one to a node's load before it inserts a new account
-- (add_user_to_node, then post_user, separately), and a failed INSERT does
-- not take it back: replayed token requests could fill the node until it
-- takes nobody new. The node of this hostname gets the largest capacity the
-- column holds, and the load is counted again from the accounts on every
-- start.
UPDATE nodes n SET capacity = 2147483647
FROM services s, portcullis_node p
WHERE s.service = 'sync-1.5' AND n.service = s.id AND n.node = p.url;

UPDATE nodes n
SET current_load = r.real_load,
    available = CASE WHEN n.downed = 0 THEN GREATEST(0, n.capacity - r.real_load) ELSE n.available END
FROM (SELECT n2.id, COUNT(DISTINCT u.email)::INT AS real_load
      FROM nodes n2 JOIN services s ON s.service = 'sync-1.5' AND n2.service = s.id
      LEFT JOIN users u ON u.nodeid = n2.id AND u.replaced_at IS NULL
      GROUP BY n2.id) r
WHERE r.id = n.id;

-- The internet-facing server connects as firefoxsync_app: not the owner of
-- any table (no DROP / DISABLE TRIGGER, no ALTER), not a superuser (no
-- session_replication_role). Only firefox-sync-fxa-migrate and this job use
-- the owner. It needs CREATE on public: syncstorage-rs runs diesel's
-- migration check at every start, and its CREATE TABLE IF NOT EXISTS
-- __diesel_schema_migrations needs the schema privilege even when the table
-- exists (PostgreSQL checks it first, namespace.c
-- RangeVarGetAndCheckCreationNamespace). So that it can't use it to plant
-- anything (a function another session would resolve to), an event trigger
-- refuses every object it would actually create outside its own temporary
-- schema: the no-op IF NOT EXISTS passes, nothing else does.
CREATE OR REPLACE FUNCTION public.portcullis_app_no_ddl() RETURNS event_trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF session_user = 'firefoxsync_app' AND EXISTS (
        SELECT 1 FROM pg_catalog.pg_event_trigger_ddl_commands() c
        WHERE c.schema_name IS NULL OR c.schema_name NOT LIKE 'pg\_temp%') THEN
        RAISE EXCEPTION 'portcullis: firefoxsync_app may not create database objects'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
END;
$$;
REVOKE ALL ON FUNCTION public.portcullis_app_no_ddl() FROM PUBLIC;
DROP EVENT TRIGGER IF EXISTS portcullis_app_no_ddl;
CREATE EVENT TRIGGER portcullis_app_no_ddl ON ddl_command_end
EXECUTE FUNCTION public.portcullis_app_no_ddl();

SELECT NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'firefoxsync_app') AS portcullis_new_role \gset
\if :portcullis_new_role
CREATE ROLE firefoxsync_app;
\endif
ALTER ROLE firefoxsync_app WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS
    PASSWORD :'app_password';
ALTER ROLE firefoxsync_app SET search_path = public;
-- Exactly what the server's queries need (syncstorage-rs 0.25.1,
-- tokenserver-postgres/src/db/db_impl.rs, syncstorage-postgres): users rows
-- are read and added, and only generation, keys_changed_at and replaced_at
-- change (put_user, replace_user(s), post_user; never deleted); of nodes only
-- the load columns change (add_user_to_node, get_best_node); services and the
-- migration record are read only. The node row itself is created by
-- firefox-sync-fxa-migrate (INIT_NODE_URL is not set on the public server:
-- its INSERT ... ON CONFLICT DO NOTHING needs INSERT on nodes). No sequence
-- privilege at all: every key is an identity column, whose sequence an
-- INSERT uses without one (so no nextval / setval by hand). Every other
-- table of public is syncstorage's own (the encrypted records), read and
-- written in full. porelli's tables (sync_allowed_accounts, made by its
-- init and unused here, sync_refused_accounts, ffs_*) get nothing but the
-- config row below.
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM firefoxsync_app;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM firefoxsync_app;
GRANT USAGE, CREATE ON SCHEMA public TO firefoxsync_app;
DO $$
DECLARE
    t TEXT;
BEGIN
    FOR t IN SELECT c.relname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
             WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')
               AND c.relname NOT IN ('users', 'nodes', 'services', '__diesel_schema_migrations',
                                     'sync_allowed_accounts', 'config', 'sync_refused_accounts')
               AND c.relname NOT LIKE 'ffs\_%'
    LOOP
        EXECUTE pg_catalog.format('GRANT SELECT, INSERT, UPDATE, DELETE ON public.%I TO firefoxsync_app', t);
    END LOOP;
END $$;
GRANT SELECT, INSERT ON public.users TO firefoxsync_app;
GRANT UPDATE (generation, keys_changed_at, replaced_at) ON public.users TO firefoxsync_app;
GRANT SELECT ON public.nodes TO firefoxsync_app;
GRANT UPDATE (current_load, available) ON public.nodes TO firefoxsync_app;
GRANT SELECT ON public.services, public.__diesel_schema_migrations TO firefoxsync_app;
-- firefox-sync's max-users trigger (check_user_limit, run as the inserting
-- role) reads its config row FOR UPDATE: that needs an UPDATE privilege on
-- some column. updated_at only: the server can't change a value.
GRANT SELECT, UPDATE (updated_at) ON public.config TO firefoxsync_app;
-- The image's maintenance databases: the owner only (PUBLIC's default
-- CONNECT revoked; nothing of the stack uses them). Each role connects to its
-- own database alone (below and admin-db.sql).
REVOKE CONNECT, TEMPORARY ON DATABASE postgres, template1 FROM PUBLIC;

-- The admin UI (ffs-admin, porelli/firefox-sync's admin UI) has two roles of
-- its own, both with FIREFOX_SYNC_ADMIN_DB_PASSWORD, never the Sync roles'
-- passwords (docs/reference/database-users.md there, "The admin UI's own
-- database"):
--   firefoxsync_admin       owns the database firefoxsync_admin (its event
--                           log, audit trail, notes; admin-db.sql) and has
--                           nothing on this one (no CONNECT).
--   firefoxsync_admin_sync  reads the Sync data here. It writes only what
--                           the per-account tools and the storage purge
--                           delete: rows of users and of the storage tables.
-- Neither owns a table, is a superuser or may create anything here (no
-- CREATE on public): neither can change the nodes or the user limit or
-- write porelli's allowlist table. A deleted users row only ends that
-- account's tokens: its next token request (a token of this instance's
-- accounts server) inserts a new row.
-- firefox-sync-fxa-db-init (before this) made both roles and granted them
-- its set (admin_grants.sql); everything is revoked here and given again,
-- less: not INSERT / UPDATE on users, anything on nodes or services, UPDATE
-- of config (max users) or any write on sync_allowed_accounts, and not
-- ffs_allow_account, ffs_remove_allowed_account or ffs_reject_account:
-- SECURITY DEFINER functions of the owner that write that table, which the
-- admin UI refuses to call with access managed elsewhere but its role could.
-- Kept: ffs_resync_node_load (recounts a node's load), ffs_mark_refusal_
-- reported and ffs_drop_admin_tables (the admin UI's own old tables).
SELECT NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'firefoxsync_admin') AS portcullis_new_admin,
       NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'firefoxsync_admin_sync') AS portcullis_new_admin_sync \gset
\if :portcullis_new_admin
CREATE ROLE firefoxsync_admin;
\endif
\if :portcullis_new_admin_sync
CREATE ROLE firefoxsync_admin_sync;
\endif
ALTER ROLE firefoxsync_admin WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS
    PASSWORD :'admin_password';
ALTER ROLE firefoxsync_admin_sync WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS
    PASSWORD :'admin_password';
ALTER ROLE firefoxsync_admin_sync SET search_path = public;
-- This database: only the Sync server's role and the admin UI's reader may
-- connect (PUBLIC's default CONNECT and TEMPORARY revoked; the Sync role
-- keeps both, as it had them through PUBLIC).
DO $$
BEGIN
    EXECUTE pg_catalog.format('REVOKE ALL ON DATABASE %I FROM PUBLIC', pg_catalog.current_database());
    EXECUTE pg_catalog.format('REVOKE ALL ON DATABASE %I FROM firefoxsync_admin', pg_catalog.current_database());
    EXECUTE pg_catalog.format('GRANT CONNECT, TEMPORARY ON DATABASE %I TO firefoxsync_app', pg_catalog.current_database());
    EXECUTE pg_catalog.format('REVOKE ALL ON DATABASE %I FROM firefoxsync_admin_sync', pg_catalog.current_database());
    EXECUTE pg_catalog.format('GRANT CONNECT ON DATABASE %I TO firefoxsync_admin_sync', pg_catalog.current_database());
END $$;
REVOKE ALL ON SCHEMA public FROM firefoxsync_admin, firefoxsync_admin_sync;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM firefoxsync_admin, firefoxsync_admin_sync;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM firefoxsync_admin, firefoxsync_admin_sync;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM firefoxsync_admin, firefoxsync_admin_sync;
GRANT USAGE ON SCHEMA public TO firefoxsync_admin_sync;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO firefoxsync_admin_sync;
-- A reset or a deletion of an account's Sync data, and the purge of
-- expired storage (syncstorage-postgres' tables; the ones this version has).
DO $$
DECLARE
    t TEXT;
BEGIN
    FOR t IN SELECT c.relname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
             WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')
               AND c.relname IN ('users', 'bsos', 'user_collections', 'batches', 'batch_bsos')
    LOOP
        EXECUTE pg_catalog.format('GRANT DELETE ON public.%I TO firefoxsync_admin_sync', t);
    END LOOP;
    FOR t IN SELECT p.oid::pg_catalog.regprocedure::pg_catalog.text FROM pg_catalog.pg_proc p
             JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
             WHERE n.nspname = 'public'
               AND p.proname IN ('ffs_resync_node_load', 'ffs_mark_refusal_reported', 'ffs_drop_admin_tables')
    LOOP
        EXECUTE 'GRANT EXECUTE ON FUNCTION ' || t || ' TO firefoxsync_admin_sync';
    END LOOP;
END $$;

SELECT 'portcullis-guard: node ' || (SELECT url FROM portcullis_node) || ', '
       || (SELECT count(DISTINCT email) FROM users) || ' account(s) with Sync data on this server' AS status;
