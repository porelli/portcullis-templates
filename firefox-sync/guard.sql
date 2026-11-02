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
-- Values come from the environment (\getenv), never from argv:
--   FIREFOX_SYNC_ALLOWED_ACCOUNTS  the Allowed accounts setting (uids)
--   FIREFOX_SYNC_NODE_URL          https://<this instance's hostname>
\getenv allowed FIREFOX_SYNC_ALLOWED_ACCOUNTS
\getenv node_url FIREFOX_SYNC_NODE_URL

-- An unset variable would stay as the literal text :'allowed' and fail the
-- statement below (fail closed); an empty setting is a valid empty list.
CREATE TEMP TABLE portcullis_wanted ON COMMIT DROP AS
SELECT DISTINCT lower(x) AS uid
FROM regexp_split_to_table(:'allowed', '[,;[:space:]]+') AS x
WHERE x <> '';

CREATE TEMP TABLE portcullis_node ON COMMIT DROP AS SELECT :'node_url'::text AS url;

DO $$
DECLARE
    bad TEXT;
BEGIN
    SELECT string_agg(left(uid, 40), ', ') INTO bad FROM portcullis_wanted WHERE uid !~ '^[0-9a-f]{32}$';
    IF bad IS NOT NULL THEN
        RAISE EXCEPTION 'portcullis: Allowed accounts: % is not a Mozilla account uid (32 hexadecimal characters)', bad;
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

-- The allowlist, replaced on every start: the setting is authoritative.
CREATE TABLE IF NOT EXISTS portcullis_allowed_accounts (
    uid VARCHAR(32) PRIMARY KEY CHECK (uid ~ '^[0-9a-f]{32}$')
);
DELETE FROM portcullis_allowed_accounts;
INSERT INTO portcullis_allowed_accounts (uid) SELECT uid FROM portcullis_wanted;

-- Every row the tokenserver writes must belong to a listed account. Raising
-- makes post_user fail: the tokenserver answers 500 and issues no token (the
-- same path as the upstream MAX_USERS trigger of porelli/firefox-sync). The
-- uid of a refused account shows in the database log, for the admin to list.
CREATE OR REPLACE FUNCTION portcullis_check_allowed_account() RETURNS trigger
LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
DECLARE
    account TEXT := lower(split_part(NEW.email, '@', 1));
BEGIN
    IF NOT EXISTS (SELECT 1 FROM portcullis_allowed_accounts WHERE uid = account) THEN
        RAISE EXCEPTION 'portcullis: Firefox account % is not in the Allowed accounts setting: refused', left(account, 64)
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS portcullis_allowed_account ON users;
CREATE TRIGGER portcullis_allowed_account
BEFORE INSERT OR UPDATE OF email ON users
FOR EACH ROW EXECUTE FUNCTION portcullis_check_allowed_account();

-- Accounts taken off the list lose their tokenserver rows: their next token
-- request finds no user, tries to create one and is refused by the trigger.
-- Tokens already issued stay valid until they expire (token_duration, 1 h).
-- Their encrypted Sync data stays in the storage tables, unreachable; listed
-- again later, the account starts with empty storage and Firefox uploads its
-- local data again.
DELETE FROM users
WHERE lower(split_part(email, '@', 1)) NOT IN (SELECT uid FROM portcullis_allowed_accounts);

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
-- not take it back: count the load again from the accounts it holds.
UPDATE nodes n
SET current_load = r.real_load,
    available = CASE WHEN n.downed = 0 THEN GREATEST(0, n.capacity - r.real_load) ELSE n.available END
FROM (SELECT n2.id, COUNT(DISTINCT u.email)::INT AS real_load
      FROM nodes n2 JOIN services s ON s.service = 'sync-1.5' AND n2.service = s.id
      LEFT JOIN users u ON u.nodeid = n2.id AND u.replaced_at IS NULL
      GROUP BY n2.id) r
WHERE r.id = n.id;

SELECT 'portcullis-guard: ' || (SELECT count(*) FROM portcullis_allowed_accounts) || ' allowed account(s), '
       || (SELECT count(DISTINCT email) FROM users) || ' with Sync data on this server' AS status;
