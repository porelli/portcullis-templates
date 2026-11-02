"""Portcullis guard for Mealie: no password logins, no account takeover.

Run by the mealie-init one-shot before the app starts (every start), and
with --check by the app's healthcheck (Traefik routes only healthy
containers).

Why (Mealie v3.30.0, mealie-recipes/mealie):
- ALLOW_PASSWORD_LOGIN=false only hides the form. POST /api/auth/token
  (routes/auth/auth.py get_token -> CredentialsProvider) still accepts the
  password of every account whose auth_method is "Mealie", including the
  admin that init_db seeds on an empty database with the well-known password
  "MyPassword" (repos/seed/init_users.py). Traefik path matching must not be
  what protects it, so the database refuses password accounts instead:
  CredentialsProvider rejects every account whose auth_method is not Mealie.
- OIDC logins find the account by OIDC_USER_CLAIM (preferred_username) in
  the username column, then in the email column (AuthProvider.try_get_user),
  and adopt it (and set its admin flag from the groups). Users may edit
  their own username and email (PUT /api/users/{id}), so a member could
  take the name of someone who hasn't signed in yet and receive that
  person's first login (and admin rights). The username and email of an
  SSO account are therefore fixed. The email of a NEW account comes from
  the user-editable LLDAP mail, so a member could also set it to a
  not-yet-signed-in username before their first login; the email lookup
  would then hand that user's login to the member. Emails without '@'
  (LLDAP usernames never contain one) and any username/email overlap
  between accounts are therefore refused, on INSERT too.

The guard (one transaction, so a running app never sees it half-applied):
1. runs Mealie's own database init (migrations, first-boot seed) before the
   app does;
2. installs a trigger on users: every row gets auth_method OIDC (no password
   login, whatever the API or an admin does), and the username / email of an
   OIDC account can't change (except letter case), every email contains
   '@', and no account's email equals another's username (or vice versa);
3. gives every account that wasn't OIDC yet (the seeded admin) a username
   and email no LLDAP username can match (':' is not allowed there) and an
   unusable password.

Nothing secret is printed.
"""

import os
import sys

GUARD_FUNCTION = r"""
CREATE OR REPLACE FUNCTION portcullis_users_guard() RETURNS trigger
LANGUAGE plpgsql AS $guard$
BEGIN
  -- No password logins: CredentialsProvider refuses non-Mealie accounts.
  NEW.auth_method := 'OIDC';
  -- SSO logins are matched on username, then email: keep both fixed.
  IF TG_OP = 'UPDATE' AND OLD.auth_method = 'OIDC' AND (
       lower(NEW.username) IS DISTINCT FROM lower(OLD.username)
    OR lower(NEW.email) IS DISTINCT FROM lower(OLD.email)) THEN
    RAISE EXCEPTION 'portcullis: the username and email of a Mealie account are fixed (SSO logins are matched on them)';
  END IF;
  -- The email lookup must never find an account for another user's
  -- preferred_username: the email of a new account comes from the
  -- user-editable LLDAP mail. LLDAP/Hub usernames never contain '@', so an
  -- email with '@' can't equal one; also refuse any username/email overlap.
  IF NEW.email IS NULL OR position('@' in NEW.email) = 0 THEN
    RAISE EXCEPTION 'portcullis: a Mealie account email must contain @ (SSO logins are matched on username, then email)';
  END IF;
  IF EXISTS (SELECT 1 FROM users u WHERE u.id IS DISTINCT FROM NEW.id
             AND (lower(u.username) = lower(NEW.email) OR lower(u.email) = lower(NEW.username))) THEN
    RAISE EXCEPTION 'portcullis: a Mealie account username or email equals another account''s email or username';
  END IF;
  RETURN NEW;
END
$guard$
"""

GUARD_STATEMENTS = [
    GUARD_FUNCTION,
    "DROP TRIGGER IF EXISTS portcullis_users_guard ON users",
    "CREATE TRIGGER portcullis_users_guard BEFORE INSERT OR UPDATE ON users "
    "FOR EACH ROW EXECUTE FUNCTION portcullis_users_guard()",
    # Accounts created before the trigger (the seeded admin): unmatchable by
    # an SSO login, unusable password. The trigger sets auth_method OIDC.
    "UPDATE users SET username = 'portcullis-local:' || id::text, "
    "email = 'portcullis-local:' || id::text || '@invalid', password = 'OIDC' "
    "WHERE auth_method <> 'OIDC'",
]

CHECK_SQL = (
    "SELECT (SELECT count(*) FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid "
    "        WHERE t.tgname = 'portcullis_users_guard' AND c.relname = 'users' AND t.tgenabled <> 'D'), "
    "       (SELECT count(*) FROM users WHERE auth_method <> 'OIDC')"
)


def fail(msg: str) -> "None":
    print(f"portcullis-guard: {msg}", file=sys.stderr)
    sys.exit(1)


def check() -> None:
    """Healthcheck: the trigger is in place and no account has a password login."""
    import psycopg2

    if os.environ.get("ALLOW_PASSWORD_LOGIN", "").lower() != "false":
        fail("ALLOW_PASSWORD_LOGIN must be false")
    conn = psycopg2.connect(
        host=os.environ["POSTGRES_SERVER"],
        port=os.environ.get("POSTGRES_PORT", "5432"),
        dbname=os.environ["POSTGRES_DB"],
        user=os.environ["POSTGRES_USER"],
        password=os.environ["POSTGRES_PASSWORD"],
        connect_timeout=5,
    )
    try:
        with conn.cursor() as cur:
            cur.execute(CHECK_SQL)
            triggers, local = cur.fetchone()
    finally:
        conn.close()
    if triggers != 1:
        fail("users guard trigger missing")
    if local != 0:
        fail(f"{local} account(s) with a password login")


def guard() -> None:
    if os.environ.get("DB_ENGINE") != "postgres":
        fail("DB_ENGINE must be postgres (the guard is a PostgreSQL trigger)")

    # Mealie's own startup init: migrations, then the first-boot seed.
    from mealie.db import init_db

    init_db.main()

    from mealie.core.config import get_app_settings
    from sqlalchemy import create_engine

    engine = create_engine(get_app_settings().DB_URL)
    try:
        with engine.begin() as conn:
            for stmt in GUARD_STATEMENTS:
                conn.exec_driver_sql(stmt)
            triggers, local = conn.exec_driver_sql(CHECK_SQL).one()
            if triggers != 1 or local != 0:
                raise RuntimeError(f"guard not effective (triggers={triggers}, password accounts={local})")
            total = conn.exec_driver_sql("SELECT count(*) FROM users").scalar_one()
    finally:
        engine.dispose()
    print(f"portcullis-guard: users guard in place, {total} account(s), none with a password login")


if __name__ == "__main__":
    if sys.argv[1:] == ["--check"]:
        check()
    elif not sys.argv[1:]:
        guard()
    else:
        fail("usage: guard.py [--check]")
