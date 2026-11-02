"""Portcullis setup for Paperless-ngx (service paperless-init).

Runs to completion on every `compose up`, before Paperless itself starts
(depends_on: service_completed_successfully). Any failure exits non-zero, so
Paperless never starts in a half-configured state (fail closed):

1. Upstream's compatibility check, then the database migrations (the ones
   Paperless would run at start, under the same lock file), with every
   volume of the main container mounted: data migrations may read the
   stored documents, and a migration recorded here is never rerun.
2. No password logins. Paperless' DISABLE_REGULAR_LOGIN only removes the
   allauth login form; HTTP Basic auth on /api/, POST /api/token/ and a
   password a user sets on their own profile page keep working. A trigger on
   auth_user therefore replaces every password hash with Django's unusable
   marker ("!" prefix), so check_password() never succeeds for anyone:
   accounts are OpenID Connect only (django-allauth).
3. A placeholder account (inactive, no password). While the database has
   no user, Paperless opens /accounts/signup/ to anyone (fresh-install
   signup, ignoring ACCOUNT_ALLOW_SIGNUPS) and makes the first account a
   superuser; with the placeholder that never happens.
4. The instance's access group as a Paperless group with a regular-user
   role (created once, later edits by an admin are kept). Groups come from
   the OIDC "groups" claim at every login (SOCIAL_ACCOUNT_SYNC_GROUPS).

Never prints secrets. Instance values come from environment: only.
"""

import fcntl
import os
import sys

SRC = "/usr/src/paperless/src"
sys.path.insert(0, SRC)
os.chdir(SRC)
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "paperless.settings")

import django  # noqa: E402

django.setup()

from django.contrib.auth.models import Group, Permission, User  # noqa: E402
from django.core.management import call_command  # noqa: E402
from django.db import connection, transaction  # noqa: E402

PLACEHOLDER = "paperless-bootstrap"
UNUSABLE = "!portcullis-sso-only"
# Regular-user role for the access group: documents and the objects that
# have an owner in Paperless (object permissions still apply), read-only
# custom fields (global objects) and tasks, own UI settings. No users,
# groups, mail, workflows, share links, app config, logs or history.
ROLE = (
    [f"{a}_{m}" for m in ("document", "tag", "correspondent", "documenttype", "storagepath", "savedview", "note")
     for a in ("view", "add", "change", "delete")]
    + ["view_customfield", "view_paperlesstask", "view_uisettings", "add_uisettings", "change_uisettings"]
)

SQL_TRIGGER = f"""
CREATE OR REPLACE FUNCTION portcullis_sso_only_password() RETURNS trigger
LANGUAGE plpgsql AS $fn$
BEGIN
  IF NEW.password IS NULL OR left(NEW.password, 1) <> '!' THEN
    NEW.password := '{UNUSABLE}';
  END IF;
  RETURN NEW;
END
$fn$;
CREATE OR REPLACE TRIGGER portcullis_sso_only_password
  BEFORE INSERT OR UPDATE OF password ON auth_user
  FOR EACH ROW EXECUTE FUNCTION portcullis_sso_only_password();
UPDATE auth_user SET password = '{UNUSABLE}' WHERE password IS NULL OR left(password, 1) <> '!';
"""


def die(msg: str) -> None:
    print(f"[portcullis-init] ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


def main() -> None:
    access_group = os.environ.get("PORTCULLIS_ACCESS_GROUP", "").strip()
    if not access_group:
        die("PORTCULLIS_ACCESS_GROUP is empty")

    print("[portcullis-init] Checking compatibility...")
    call_command("check", "paperless", tags=["compatibility"])
    print("[portcullis-init] Running database migrations...")
    data_dir = os.environ.get("PAPERLESS_DATA_DIR", "/usr/src/paperless/data")
    with open(os.path.join(data_dir, "migration_lock"), "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        call_command("migrate", interactive=False, skip_checks=True, verbosity=1)

    with transaction.atomic():
        with connection.cursor() as cur:
            cur.execute(SQL_TRIGGER)

        user, created = User.objects.get_or_create(username=PLACEHOLDER, defaults={"is_active": False})
        if created or user.is_active or user.is_superuser or user.is_staff:
            user.is_active = False
            user.is_superuser = False
            user.is_staff = False
            user.set_unusable_password()
            user.save()

        group, created = Group.objects.get_or_create(name=access_group)
        if created:
            perms = list(Permission.objects.filter(content_type__app_label="documents", codename__in=ROLE))
            missing = sorted(set(ROLE) - {p.codename for p in perms})
            if missing:
                die(f"permissions not found: {', '.join(missing)}")
            group.permissions.set(perms)
            print(f"[portcullis-init] Created group {access_group} with the regular-user role")

    # Verify the end state; any deviation keeps Paperless down.
    with connection.cursor() as cur:
        cur.execute(
            "SELECT count(*) FROM pg_trigger WHERE tgname = 'portcullis_sso_only_password' "
            "AND tgrelid = 'auth_user'::regclass AND tgenabled <> 'D'"
        )
        if cur.fetchone()[0] != 1:
            die("password trigger on auth_user is missing or disabled")
        cur.execute("SELECT count(*) FROM auth_user WHERE password IS NULL OR left(password, 1) <> '!'")
        if cur.fetchone()[0] != 0:
            die("an account still has a usable password")
    if not User.objects.exclude(username__in=["consumer", "AnonymousUser"]).exists():
        die("no account exists: Paperless would offer the fresh-install signup")
    if any(u.has_usable_password() for u in User.objects.all()):
        die("an account still has a usable password")
    print("[portcullis-init] Paperless is SSO-only: no password logins, no local signup.")


if __name__ == "__main__":
    main()
