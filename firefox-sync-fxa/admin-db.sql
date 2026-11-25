-- Firefox Sync + own accounts: the admin UI's own database
-- (firefox-sync-fxa-init, every start, after guard.sql, which created its
-- role firefoxsync_admin). As firefox-sync/admin-db.sql. Not in guard.sql's
-- transaction: CREATE DATABASE can't run inside one. As the database owner
-- (the image's superuser), with only pg_catalog in the search path: nothing
-- here runs code another role could have planted.
--
-- firefoxsync_admin owns it and is the only role that may connect: the
-- Sync server's role (firefoxsync_app) and the admin UI's reader of the
-- Sync data (firefoxsync_admin_sync) have no grant on it, so a Sync server
-- that is broken into can't read or rewrite the admin UI's event log and
-- audit trail. A copy of template0, as porelli/firefox-sync makes it: no
-- object of template1 comes along.
SET search_path = pg_catalog, pg_temp;
SELECT 'CREATE DATABASE firefoxsync_admin OWNER firefoxsync_admin TEMPLATE template0 ENCODING ''UTF8'''
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'firefoxsync_admin') \gexec
ALTER DATABASE firefoxsync_admin OWNER TO firefoxsync_admin;
REVOKE ALL ON DATABASE firefoxsync_admin FROM PUBLIC;
REVOKE ALL ON DATABASE firefoxsync_admin FROM firefoxsync_app, firefoxsync_admin_sync;
GRANT CONNECT, TEMPORARY ON DATABASE firefoxsync_admin TO firefoxsync_admin;
SELECT 'portcullis-guard: admin UI database firefoxsync_admin ready' AS status;
