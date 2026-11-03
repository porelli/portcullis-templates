-- Firefox Sync: who may sync (firefox-sync-init, every start, before the
-- Sync server). Applied with psql -X -v ON_ERROR_STOP=1 --single-transaction:
-- any error rolls everything back and the init exits non-zero, so the Sync
-- server (depends_on: service_completed_successfully) does not start.
--
-- The tokenserver (syncstorage-rs 0.24.0, tokenserver-postgres) knows a
-- Mozilla account only as "<uid>@<FXA_EMAIL_DOMAIN>" in users.email: uid is
-- the account's permanent id, 32 hex characters; the email never reaches
-- this server. A new account is a new users row (post_user, INSERT ...
-- RETURNING uid); a keys change of a known account adds a row for the same
-- email. The allowlist below is the only way onto this server: an account
-- whose uid is not on it gets no row, so no token, so no storage.
--
-- Who may sync comes from the Hub's data file allowlist.json (contract
-- §13.7, mounted read-only at /portcullis): the union of
--   entries.mozilla_uid[].value  the uids access-group members entered on
--                                My apps (only current members' are in it)
--   values.extra_accounts        the admin's "Other allowed accounts"
-- A missing or unparsable file, or one of another shape, stops the start.
-- The other values come from the environment (\getenv), never from argv:
--   FIREFOX_SYNC_NODE_URL          https://<this instance's hostname>
--   PORTCULLIS_INSTANCE            the instance id the file must name
\set allowlist_doc `cat /portcullis/allowlist.json`
\getenv node_url FIREFOX_SYNC_NODE_URL
\getenv instance PORTCULLIS_INSTANCE
\getenv app_password FIREFOX_SYNC_APP_DB_PASSWORD

-- The app role's password is in a statement below: never put statement text
-- in the server log, not even on an error (this runs as the superuser).
SET LOCAL log_statement = 'none';
SET LOCAL log_min_error_statement = 'panic';

-- An unset variable would stay as the literal text :'allowlist_doc' (a
-- failed cat, no file) and an empty one is no JSON either: both fail the
-- cast (fail closed).
CREATE TEMP TABLE portcullis_doc ON COMMIT DROP AS SELECT :'allowlist_doc'::jsonb AS doc;

-- An absent list, or JSON null (nobody entered a uid, no other accounts), is
-- the empty list; any other non-array is refused below before this is used.
CREATE FUNCTION pg_temp.portcullis_list(j jsonb) RETURNS jsonb
LANGUAGE sql IMMUTABLE AS $$ SELECT CASE WHEN jsonb_typeof(j) = 'array' THEN j ELSE '[]'::jsonb END $$;

DO $$
DECLARE
    d jsonb := (SELECT doc FROM portcullis_doc);
BEGIN
    IF jsonb_typeof(d) <> 'object' OR d->'version' IS DISTINCT FROM '1'::jsonb THEN
        RAISE EXCEPTION 'portcullis: allowlist.json is not a version 1 data file';
    END IF;
    IF jsonb_typeof(d->'entries') NOT IN ('object', 'null')
       OR jsonb_typeof(d->'entries'->'mozilla_uid') NOT IN ('array', 'null')
       OR jsonb_typeof(d->'values') NOT IN ('object', 'null')
       OR jsonb_typeof(d->'values'->'extra_accounts') NOT IN ('array', 'null') THEN
        RAISE EXCEPTION 'portcullis: allowlist.json: entries.mozilla_uid and values.extra_accounts must be lists';
    END IF;
    IF EXISTS (SELECT 1 FROM jsonb_array_elements(pg_temp.portcullis_list(d->'entries'->'mozilla_uid')) e
               WHERE jsonb_typeof(e) <> 'object' OR jsonb_typeof(e->'value') IS DISTINCT FROM 'string'
                  OR jsonb_typeof(e->'user') IS DISTINCT FROM 'string')
       OR EXISTS (SELECT 1 FROM jsonb_array_elements(pg_temp.portcullis_list(d->'values'->'extra_accounts')) e
                  WHERE jsonb_typeof(e) <> 'string') THEN
        RAISE EXCEPTION 'portcullis: allowlist.json: an entry is not {user, value} or an account is not a string';
    END IF;
END $$;

-- uid -> who listed it (an entry's LLDAP username wins over the admin list).
CREATE TEMP TABLE portcullis_wanted ON COMMIT DROP AS
SELECT DISTINCT ON (uid) uid, added_by
FROM (
    SELECT e->>'value' AS uid, e->>'user' AS added_by, 0 AS pref
    FROM portcullis_doc, jsonb_array_elements(pg_temp.portcullis_list(doc->'entries'->'mozilla_uid')) e
    UNION ALL
    SELECT a #>> '{}', 'Other allowed accounts setting', 1
    FROM portcullis_doc, jsonb_array_elements(pg_temp.portcullis_list(doc->'values'->'extra_accounts')) a
) x
ORDER BY uid, pref, added_by;

CREATE TEMP TABLE portcullis_instance ON COMMIT DROP AS SELECT :'instance'::text AS id;
CREATE TEMP TABLE portcullis_node ON COMMIT DROP AS SELECT :'node_url'::text AS url;
CREATE TEMP TABLE portcullis_pw ON COMMIT DROP AS SELECT length(:'app_password') AS len;

DO $$
DECLARE
    bad TEXT;
BEGIN
    SELECT string_agg(left(uid, 40), ', ') INTO bad FROM portcullis_wanted WHERE uid !~ '^[0-9a-f]{32}$';
    IF bad IS NOT NULL THEN
        RAISE EXCEPTION 'portcullis: allowlist.json: % is not a Mozilla account uid (32 lowercase hexadecimal characters)', bad;
    END IF;
    IF (SELECT doc->>'instance' FROM portcullis_doc) IS DISTINCT FROM (SELECT id FROM portcullis_instance)
       OR (SELECT id FROM portcullis_instance) = '' THEN
        RAISE EXCEPTION 'portcullis: allowlist.json is not the data file of this instance';
    END IF;
    IF (SELECT len FROM portcullis_pw) < 16 THEN
        RAISE EXCEPTION 'portcullis: FIREFOX_SYNC_APP_DB_PASSWORD is missing or too short';
    END IF;
    IF (SELECT url FROM portcullis_node) !~ '^https://[a-z0-9.-]+$' THEN
        RAISE EXCEPTION 'portcullis: FIREFOX_SYNC_NODE_URL is not https://<hostname>';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM services WHERE service = 'sync-1.5') THEN
        RAISE EXCEPTION 'portcullis: the tokenserver tables are missing (firefox-sync-migrate did not run)';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM nodes n JOIN services s ON s.id = n.service AND s.service = 'sync-1.5'
                   JOIN portcullis_node p ON n.node = p.url) THEN
        RAISE EXCEPTION 'portcullis: no sync node for this hostname (firefox-sync-migrate did not run)';
    END IF;
END $$;

-- The allowlist, replaced on every start: the data file is authoritative.
-- Table as porelli/firefox-sync's invite-only Sync has it (db/postgres/init/
-- allowlist.sql: sync_allowed_accounts uid, note, added_at, added_by), so
-- its admin UI reads the same rows; added_by = the LLDAP user who entered
-- the uid, or the admin list.
CREATE TABLE IF NOT EXISTS sync_allowed_accounts (
    uid VARCHAR(32) PRIMARY KEY CHECK (uid ~ '^[0-9a-f]{32}$'),
    note VARCHAR(255) NOT NULL DEFAULT '',
    added_at BIGINT NOT NULL,
    added_by VARCHAR(255) NOT NULL
);
DELETE FROM sync_allowed_accounts;
INSERT INTO sync_allowed_accounts (uid, note, added_at, added_by)
SELECT uid, '', (EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::BIGINT, left(added_by, 255)
FROM portcullis_wanted;

-- Every row the tokenserver writes must belong to a listed account. Raising
-- makes post_user fail: the tokenserver answers 500 and issues no token (the
-- same path as the MAX_USERS trigger of porelli/firefox-sync). Stricter than
-- firefox-sync's own invite-only trigger (ffs_check_allowed_account), which
-- skips the row (RETURN NULL) to keep a record of the refusal and relies on
-- the tokenserver failing on the missing RETURNING row; it is also off with
-- an empty list, ours refuses everybody then. The uid of a refused account
-- shows in the database log, for the admin to list.
-- Runs as the caller (the app role). search_path is pg_catalog only and
-- the table is schema-qualified: the app role may create objects in public
-- (below), so an unqualified call could resolve to a function it planted
-- (e.g. a better-matching split_part(varchar, ...)).
CREATE OR REPLACE FUNCTION public.portcullis_check_allowed_account() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE
    account pg_catalog.text := pg_catalog.lower(pg_catalog.split_part(NEW.email::pg_catalog.text, '@', 1));
BEGIN
    IF NOT EXISTS (SELECT 1 FROM public.sync_allowed_accounts a WHERE a.uid::pg_catalog.text = account) THEN
        RAISE EXCEPTION 'portcullis: Firefox account % is not on the allowlist (no access-group member entered it, not in Other allowed accounts): refused', pg_catalog.left(account, 64)
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION public.portcullis_check_allowed_account() FROM PUBLIC;

DROP TRIGGER IF EXISTS portcullis_allowed_account ON users;
CREATE TRIGGER portcullis_allowed_account
BEFORE INSERT OR UPDATE OF email ON users
FOR EACH ROW EXECUTE FUNCTION public.portcullis_check_allowed_account();

-- Accounts taken off the list lose their tokenserver rows: their next token
-- request finds no user, tries to create one and is refused by the trigger.
-- Tokens already issued stay valid until they expire (token_duration, 1 h).
-- Their encrypted Sync data stays in the storage tables, unreachable; listed
-- again later, the account starts with empty storage and Firefox uploads its
-- local data again.
DELETE FROM users
WHERE lower(split_part(email, '@', 1)) NOT IN (SELECT uid FROM sync_allowed_accounts);

-- One sync node, this instance's hostname. After a hostname change
-- firefox-sync-migrate added a node for the new one (INIT_NODE_URL): move the
-- users to it and take the old nodes out of rotation (as porelli/firefox-sync's
-- db_init.sql does).
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
-- (add_user_to_node, then post_user, separately), and a refused INSERT does
-- not take it back: one valid Mozilla token, replayed, would fill the node
-- until it takes nobody new. The node of this hostname gets the largest
-- capacity the column holds, and the load is counted again from the
-- accounts on every start.
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
-- session_replication_role), read-only on the allowlist. Only
-- firefox-sync-migrate and this job use the owner. It needs CREATE on
-- public: syncstorage-rs runs diesel's migration check at every start, and
-- its CREATE TABLE IF NOT EXISTS __diesel_schema_migrations needs the
-- schema privilege even when the table exists (PostgreSQL checks it first,
-- namespace.c RangeVarGetAndCheckCreationNamespace). So that it can't use
-- it to plant anything (a function another session would resolve to), an
-- event trigger refuses every object it would actually create outside its
-- own temporary schema: the no-op IF NOT EXISTS passes, nothing else does.
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
-- Exactly what the server's queries need (syncstorage-rs 0.24.0,
-- tokenserver-postgres/src/db/db_impl.rs, syncstorage-postgres): users rows
-- are read and added, and only generation, keys_changed_at and replaced_at
-- change (put_user, replace_user(s), post_user; never deleted); of nodes only the load
-- columns change (add_user_to_node, get_best_node); services, the migration
-- record and the allowlist are read only. The node row itself is created by
-- firefox-sync-migrate (INIT_NODE_URL is not set on the public server: its
-- INSERT ... ON CONFLICT DO NOTHING needs INSERT on nodes). No sequence
-- privilege at all: every key is an identity column, whose sequence an
-- INSERT uses without one (so no nextval / setval by hand). Every other
-- table of public is syncstorage's own (the encrypted records), read and
-- written in full.
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
                                     'sync_allowed_accounts', 'config')
    LOOP
        EXECUTE pg_catalog.format('GRANT SELECT, INSERT, UPDATE, DELETE ON public.%I TO firefoxsync_app', t);
    END LOOP;
END $$;
GRANT SELECT, INSERT ON public.users TO firefoxsync_app;
GRANT UPDATE (generation, keys_changed_at, replaced_at) ON public.users TO firefoxsync_app;
GRANT SELECT ON public.nodes TO firefoxsync_app;
GRANT UPDATE (current_load, available) ON public.nodes TO firefoxsync_app;
GRANT SELECT ON public.services, public.__diesel_schema_migrations, public.sync_allowed_accounts TO firefoxsync_app;

SELECT 'portcullis-guard: ' || (SELECT count(*) FROM sync_allowed_accounts) || ' allowed account(s), '
       || (SELECT count(DISTINCT email) FROM users) || ' with Sync data on this server' AS status;
