-- Firefox Sync: the first step of firefox-sync-init, every start, in a
-- transaction of its own BEFORE guard.sql (whose single transaction rolls
-- back on any error, e.g. an invalid allowlist.json): it must hold even
-- when guard.sql then refuses to start the instance.
--
-- firefox-sync-db-init (porelli's init, which runs just before) grants the
-- admin UI's reader EXECUTE on its SECURITY DEFINER functions, which run as
-- the tables' owner; some write the allowlist (ffs_allow_account,
-- ffs_remove_allowed_account, ffs_reject_account). Portcullis owns who
-- syncs: take EXECUTE on every SECURITY DEFINER function of public away from
-- PUBLIC, the admin UI's roles and the Sync server's role, and every write on
-- sync_allowed_accounts from all of them. guard.sql gives the admin UI's
-- reader back only the harmless ones (node load, refusal marks, its old
-- tables). As the database owner, with only pg_catalog in the search path.
SET search_path = pg_catalog, pg_temp;
DO $$
DECLARE
    f TEXT;
    r TEXT;
    roles TEXT := 'PUBLIC';
BEGIN
    FOR r IN SELECT rolname FROM pg_catalog.pg_roles
             WHERE rolname IN ('firefoxsync_admin', 'firefoxsync_admin_sync', 'firefoxsync_app') ORDER BY rolname
    LOOP
        roles := roles || ', ' || pg_catalog.quote_ident(r);
    END LOOP;
    FOR f IN SELECT p.oid::pg_catalog.regprocedure::pg_catalog.text FROM pg_catalog.pg_proc p
             JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
             WHERE n.nspname = 'public' AND (p.prosecdef OR p.proname LIKE 'ffs\_%')
    LOOP
        EXECUTE 'REVOKE EXECUTE ON FUNCTION ' || f || ' FROM ' || roles;
    END LOOP;
    IF pg_catalog.to_regclass('public.sync_allowed_accounts') IS NOT NULL THEN
        EXECUTE 'REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON public.sync_allowed_accounts FROM ' || roles;
    END IF;
END $$;
SELECT 'portcullis-guard: SECURITY DEFINER functions and allowlist writes revoked' AS status;
