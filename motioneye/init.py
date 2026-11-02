#!/usr/bin/env python3
"""motioneye-init: before every motionEye start (one-shot, same image).

motionEye ships with two local accounts, ``admin`` and ``user``, both with an
empty password (a well-known default). This sets each account whose password
is empty to the instance's generated password (MOTIONEYE_ADMIN_PASSWORD /
MOTIONEYE_USER_PASSWORD), hashed by motionEye itself (argon2), so motionEye
never runs with an empty password. A password an administrator later set in
motionEye's settings is kept. The passwords only come from the environment.
Fails closed: any error, or an account still without a password, exits 1
and motionEye doesn't start.
"""
import os
import re
import shutil
import sys

CONF_DIR = "/etc/motioneye"
CONF = os.path.join(CONF_DIR, "motioneye.conf")
SAMPLE = "/etc/motioneye.conf.sample"


def die(msg: str) -> None:
    print(f"motioneye-init: {msg}", file=sys.stderr)
    sys.exit(1)


def secret(name: str) -> str:
    val = os.environ.get(name, "")
    if not re.fullmatch(r"[A-Za-z0-9]{16,}", val):
        die(f"{name} must be at least 16 letters/digits")
    return val


def main() -> None:
    admin_pw = secret("MOTIONEYE_ADMIN_PASSWORD")
    user_pw = secret("MOTIONEYE_USER_PASSWORD")
    if admin_pw == user_pw:
        die("MOTIONEYE_ADMIN_PASSWORD and MOTIONEYE_USER_PASSWORD must differ")
    if not os.path.exists(CONF):
        # What the image's entrypoint does on a fresh volume.
        shutil.copy2(SAMPLE, CONF)

    from motioneye import settings  # noqa: PLC0415 - needs CONF_PATH first

    settings.CONF_PATH = CONF_DIR
    from motioneye import config  # noqa: PLC0415

    main_cfg = config.get_main()
    changed = []
    if not main_cfg.get("@admin_password"):
        config.set_admin_password(admin_pw)
        changed.append(main_cfg.get("@admin_username") or "admin")
        main_cfg = config.get_main()
    if not main_cfg.get("@normal_password"):
        config.set_normal_password(user_pw)
        changed.append(main_cfg.get("@normal_username") or "user")

    # Re-read from disk: what motionEye will load.
    config._main_config_cache = None  # noqa: SLF001
    main_cfg = config.get_main()
    for key in ("@admin_password", "@normal_password"):
        if not main_cfg.get(key):
            die(f"{key} is still empty in motion.conf")
    print("motioneye-init: passwords set for " + (", ".join(changed) if changed else "nobody (both already set)"))


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001 - fail closed on anything
        die(f"{type(e).__name__}: {e}")
