#!/usr/bin/env python3
"""Tests for Firefox Sync features: verified_email, mail_sender, hosts.reasons.

    python3 -m unittest tests.test_validate_fxa
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import textwrap
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import validate as v  # noqa: E402

# Base valid template to avoid schema errors
BASE_MANIFEST = """\
name: Demo
description: Demo app
icon: "x"
category: monitoring
tags: [demo]
links:
  website: https://demo.example.org/
  source: https://github.com/example/demo
instances: multi
auth:
  method: forward-auth
  sso: true
  group_access: true
  group_admin: true
  access_group: users_demo
  admin_group: admin_demo
  notes: Demo.
urls:
  - label: Demo
    url: https://{{HOST_DEMO}}
tests:
  signin:
    path: /
    signed_in:
      text: "{{username}}"
    admin:
      reach: /admin
ai:
  unsupported: test fixture
"""

BASE_COMPOSE = r"""
services:
  demo:
    image: demo/demo:1.2.3@sha256:0000000000000000000000000000000000000000000000000000000000000000
    networks:
      - default
      - portcullis-proxy
    labels:
      traefik.enable: "true"
      traefik.http.routers.demo.rule: Host(`${PORTCULLIS_HOST_DEMO:-demo.portcullis.local}`)
      traefik.http.routers.demo.entrypoints: websecure
      traefik.http.routers.demo.tls.options: default
      traefik.http.routers.demo.middlewares: portcullis-auth@docker,portcullis-groups@docker
      traefik.http.services.demo.loadbalancer.server.port: "80"

networks:
  portcullis-proxy:
    external: true
"""


class FxACase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self._root = v.ROOT
        v.ROOT = self.tmp.name
        self.addCleanup(setattr, v, "ROOT", self._root)
        with open(v.SCHEMA_PATH, encoding="utf-8") as f:
            self.validator = v.Draft202012Validator(json.load(f))

    def write_template(self, manifest: str, compose: str, app_id: str = "demo") -> v.Template:
        d = os.path.join(self.tmp.name, app_id)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "manifest.yaml"), "w", encoding="utf-8") as f:
            f.write(manifest)
        with open(os.path.join(d, "compose.yml"), "w", encoding="utf-8") as f:
            f.write(compose)
        return v.Template(app_id)

    def check_template(self, t: v.Template) -> tuple[list[str], list[str]]:
        r = v.Report()
        v.check_manifest_schema(t, self.validator, r)
        self.assertIsNotNone(t.manifest, r.errors)
        v.check_manifest_rules(t, r)
        v.check_links(t, r)
        v.check_compose(t, r)
        return r.errors, r.warnings


class TestVerifiedEmail(FxACase):
    def test_verified_email_needs_group_access(self) -> None:
        """verified_email requires group_access: true and an access_group."""
        # Remove access_group to trigger the error
        manifest = BASE_MANIFEST.replace("access_group: users_demo", "")
        manifest += textwrap.dedent("""\
            settings:
              options:
                - key: verified_email_field
                  label: Email
                  type: verified_email
                  self_visible: false
                  delivery:
                    - file:
                        name: emails
                        field: email
            files:
              - name: emails
                format: json
                service: demo
                mount: /data/emails.json
            """)
        t = self.write_template(manifest, BASE_COMPOSE)
        errors, _ = self.check_template(t)
        self.assertTrue(any("verified_email needs group_access: true and an auth.access_group" in e for e in errors),
                        f"Expected 'verified_email needs group_access' error. Errors: {errors}")

    def test_verified_email_file_delivery_only(self) -> None:
        """verified_email takes only file deliveries."""
        # Try env delivery instead of file delivery
        manifest = BASE_MANIFEST + textwrap.dedent("""\
            settings:
              options:
                - key: verified_email_field
                  label: Email
                  type: verified_email
                  self_visible: false
                  delivery:
                    - env: VERIFIED_EMAIL
            """)
        t = self.write_template(manifest, BASE_COMPOSE)
        errors, _ = self.check_template(t)
        self.assertTrue(any("verified_email takes only file deliveries" in e for e in errors),
                        f"Expected 'verified_email takes only file deliveries' error. Errors: {errors}")

    def test_verified_email_self_visible_false(self) -> None:
        """verified_email needs self_visible: false."""
        # Set self_visible: true to trigger error
        manifest = BASE_MANIFEST + textwrap.dedent("""\
            settings:
              options:
                - key: verified_email_field
                  label: Email
                  type: verified_email
                  self_visible: true
                  delivery:
                    - file:
                        name: emails
                        field: email
            files:
              - name: emails
                format: json
                service: demo
                mount: /data/emails.json
            """)
        t = self.write_template(manifest, BASE_COMPOSE)
        errors, _ = self.check_template(t)
        self.assertTrue(any("verified_email needs self_visible: false" in e for e in errors),
                        f"Expected 'verified_email needs self_visible: false' error. Errors: {errors}")


class TestMailSender(FxACase):
    def test_mail_sender_vars_need_block(self) -> None:
        """PORTCULLIS_MAIL_SENDER_* variables require a mail_sender block."""
        # Reference MAIL_SENDER var without declaring mail_sender block
        compose = BASE_COMPOSE.replace(
            "image: demo/demo",
            "image: demo/demo\n    environment:\n      MAIL_HOST: ${PORTCULLIS_MAIL_SENDER_HOST}"
        )
        t = self.write_template(BASE_MANIFEST, compose)
        errors, _ = self.check_template(t)
        self.assertTrue(any("PORTCULLIS_MAIL_SENDER_HOST" in e and "needs mail_sender" in e for e in errors),
                        f"Expected 'needs mail_sender' error. Errors: {errors}")

    def test_mail_sender_label_bounds(self) -> None:
        """mail_sender.label must be one line of 1-64 characters without ' or \\."""
        # Test empty label - this will fail schema validation, so test with space instead
        manifest = BASE_MANIFEST + textwrap.dedent("""\
            mail_sender:
              label: " "
            """)
        t = self.write_template(manifest, BASE_COMPOSE)
        errors, _ = self.check_template(t)
        # Empty/whitespace label will fail schema minLength, which runs before our custom check
        # So test newline instead

        # Test label with newline
        manifest = BASE_MANIFEST + 'mail_sender:\n  label: "line1\\nline2"\n'
        t = self.write_template(manifest, BASE_COMPOSE)
        errors, _ = self.check_template(t)
        self.assertTrue(any("mail_sender.label must be one line of 1-64 characters" in e for e in errors),
                        f"Expected 'mail_sender.label' error for newline. Errors: {errors}")

        # Test label with single quote
        manifest = BASE_MANIFEST + "mail_sender:\n  label: \"Demo's app\"\n"
        t = self.write_template(manifest, BASE_COMPOSE)
        errors, _ = self.check_template(t)
        self.assertTrue(any("mail_sender.label must be one line of 1-64 characters" in e for e in errors),
                        f"Expected 'mail_sender.label' error for quote. Errors: {errors}")


class TestHostsReasons(FxACase):
    def test_hosts_reasons_known_routers(self) -> None:
        """hosts.reasons keys must be real host routers."""
        # Reference nonexistent router in hosts.reasons
        manifest = BASE_MANIFEST + textwrap.dedent("""\
            hosts:
              reasons:
                nonexistent: "Some reason"
            """)
        t = self.write_template(manifest, BASE_COMPOSE)
        errors, _ = self.check_template(t)
        self.assertTrue(any("hosts.reasons: nonexistent is not a host router" in e for e in errors),
                        f"Expected 'nonexistent is not a host router' error. Errors: {errors}")

    def test_hosts_reasons_one_line_200(self) -> None:
        """hosts.reasons values must be one line, at most 200 runes."""
        # Test too long (over 200 runes) - schema regex won't catch this, our validator will
        long_reason = "x" * 201
        manifest = BASE_MANIFEST + textwrap.dedent(f"""\
            hosts:
              reasons:
                demo: "{long_reason}"
            """)
        t = self.write_template(manifest, BASE_COMPOSE)
        errors, _ = self.check_template(t)
        self.assertTrue(any("hosts.reasons[demo]: reason is 201 runes, at most 200 allowed" in e for e in errors),
                        f"Expected '201 runes' error. Errors: {errors}")


class TestHostsReasonsRoutersBypass(FxACase):
    """Security tests for the hosts.reasons bypass (Fix round 1)."""

    def test_open_router_with_reason_passes(self) -> None:
        """(a) An open router on a host with a reason passes."""
        # Router without auth middleware, host has reason
        compose = r"""
services:
  demo:
    image: demo/demo:1.2.3@sha256:0000000000000000000000000000000000000000000000000000000000000000
    networks:
      - default
      - portcullis-proxy
    labels:
      traefik.enable: "true"
      traefik.http.routers.demo.rule: Host(`${PORTCULLIS_HOST_DEMO:-demo.portcullis.local}`)
      traefik.http.routers.demo.entrypoints: websecure
      traefik.http.routers.demo.tls.options: public@file
      traefik.http.routers.demo.middlewares: rate-limit@file,security-headers@file
      traefik.http.services.demo.loadbalancer.server.port: "80"

networks:
  portcullis-proxy:
    external: true
"""
        manifest = BASE_MANIFEST + textwrap.dedent("""\
            hosts:
              reasons:
                demo: "Firefox calls this in the background, without cookies."
            """)
        t = self.write_template(manifest, compose)
        errors, _ = self.check_template(t)
        # Should not have "must use middlewares" error
        self.assertFalse(any("must use middlewares portcullis-auth@docker,portcullis-groups@docker" in e for e in errors),
                         f"Should not require auth when host has reason. Errors: {errors}")

    def test_open_router_without_reason_fails(self) -> None:
        """(b) An open router on a host without a reason fails."""
        # Router without auth middleware, host has NO reason
        compose = r"""
services:
  demo:
    image: demo/demo:1.2.3@sha256:0000000000000000000000000000000000000000000000000000000000000000
    networks:
      - default
      - portcullis-proxy
    labels:
      traefik.enable: "true"
      traefik.http.routers.demo.rule: Host(`${PORTCULLIS_HOST_DEMO:-demo.portcullis.local}`)
      traefik.http.routers.demo.entrypoints: websecure
      traefik.http.routers.demo.tls.options: public@file
      traefik.http.routers.demo.middlewares: rate-limit@file,security-headers@file
      traefik.http.services.demo.loadbalancer.server.port: "80"

networks:
  portcullis-proxy:
    external: true
"""
        t = self.write_template(BASE_MANIFEST, compose)
        errors, _ = self.check_template(t)
        # Should require auth
        self.assertTrue(any("forward-auth router must use middlewares portcullis-auth@docker,portcullis-groups@docker" in e for e in errors),
                        f"Expected 'must use middlewares' error. Errors: {errors}")

    def test_name_prefix_bypass_regression(self) -> None:
        """(c) Router name starting with reasoned host, but on different host, fails (bypass regression test)."""
        # Reasons has 'app', router 'app-admin' on PORTCULLIS_HOST_APP_ADMIN without auth
        compose = r"""
services:
  demo:
    image: demo/demo:1.2.3@sha256:0000000000000000000000000000000000000000000000000000000000000000
    networks:
      - default
      - portcullis-proxy
    labels:
      traefik.enable: "true"
      traefik.http.routers.app.rule: Host(`${PORTCULLIS_HOST_APP:-app.portcullis.local}`)
      traefik.http.routers.app.entrypoints: websecure
      traefik.http.routers.app.tls.options: public@file
      traefik.http.routers.app.middlewares: rate-limit@file,security-headers@file
      traefik.http.routers.app.service: demo
      traefik.http.routers.app-admin.rule: Host(`${PORTCULLIS_HOST_APP_ADMIN:-app-admin.portcullis.local}`)
      traefik.http.routers.app-admin.entrypoints: websecure
      traefik.http.routers.app-admin.tls.options: default
      traefik.http.routers.app-admin.middlewares: rate-limit@file,security-headers@file
      traefik.http.routers.app-admin.service: demo
      traefik.http.services.demo.loadbalancer.server.port: "80"

networks:
  portcullis-proxy:
    external: true
"""
        manifest = BASE_MANIFEST.replace("demo", "app") + textwrap.dedent("""\
            hosts:
              reasons:
                app: "Firefox calls this in the background, without cookies."
            """)
        t = self.write_template(manifest, compose, app_id="app")
        errors, _ = self.check_template(t)
        # app-admin router should FAIL (it's on PORTCULLIS_HOST_APP_ADMIN which has no reason)
        self.assertTrue(any("app-admin" in e and "must use middlewares portcullis-auth@docker,portcullis-groups@docker" in e for e in errors),
                        f"Expected 'app-admin must use middlewares' error (bypass regression). Errors: {errors}")

    def test_reason_key_not_host_router_fails(self) -> None:
        """(d) A reason key that isn't a host router fails."""
        # Already tested in TestHostsReasons.test_hosts_reasons_known_routers
        # but let's have it here too for completeness
        manifest = BASE_MANIFEST + textwrap.dedent("""\
            hosts:
              reasons:
                not-a-router: "Some reason"
            """)
        t = self.write_template(manifest, BASE_COMPOSE)
        errors, _ = self.check_template(t)
        self.assertTrue(any("hosts.reasons: not-a-router is not a host router" in e for e in errors),
                        f"Expected 'not-a-router is not a host router' error. Errors: {errors}")

    def test_path_router_on_reasoned_host_passes(self) -> None:
        """(e) A path router on a reasoned host passes."""
        # Host router has reason, path router on same host without auth
        compose = r"""
services:
  demo:
    image: demo/demo:1.2.3@sha256:0000000000000000000000000000000000000000000000000000000000000000
    networks:
      - default
      - portcullis-proxy
    labels:
      traefik.enable: "true"
      traefik.http.routers.demo.rule: Host(`${PORTCULLIS_HOST_DEMO:-demo.portcullis.local}`)
      traefik.http.routers.demo.entrypoints: websecure
      traefik.http.routers.demo.tls.options: public@file
      traefik.http.routers.demo.middlewares: rate-limit@file,security-headers@file
      traefik.http.routers.demo.service: demo
      traefik.http.routers.demo-api.rule: Host(`${PORTCULLIS_HOST_DEMO:-demo.portcullis.local}`) && PathPrefix(`/api/`)
      traefik.http.routers.demo-api.entrypoints: websecure
      traefik.http.routers.demo-api.tls.options: public@file
      traefik.http.routers.demo-api.middlewares: rate-limit@file,security-headers@file
      traefik.http.routers.demo-api.service: demo
      traefik.http.services.demo.loadbalancer.server.port: "80"

networks:
  portcullis-proxy:
    external: true
"""
        manifest = BASE_MANIFEST + textwrap.dedent("""\
            hosts:
              reasons:
                demo: "Firefox calls this in the background, without cookies."
            """)
        t = self.write_template(manifest, compose)
        errors, _ = self.check_template(t)
        # Path router demo-api should also pass (it's on PORTCULLIS_HOST_DEMO which has a reason)
        self.assertFalse(any("demo-api" in e and "must use middlewares" in e for e in errors),
                         f"Path router on reasoned host should not require auth. Errors: {errors}")


class TestHostsReasonsRoutersBypassAddendum(FxACase):
    """Additional security tests for the addendum parsing rules."""

    def test_host_or_host_rule_fails(self) -> None:
        """(addendum c1) Host(reasoned) || Host(unreasoned) without auth fails."""
        # Rule has two Host() clauses with ||, should not get exemption
        compose = r"""
services:
  demo:
    image: demo/demo:1.2.3@sha256:0000000000000000000000000000000000000000000000000000000000000000
    networks:
      - default
      - portcullis-proxy
    labels:
      traefik.enable: "true"
      traefik.http.routers.demo.rule: Host(`${PORTCULLIS_HOST_DEMO:-demo.portcullis.local}`) || Host(`demo-alt.portcullis.local`)
      traefik.http.routers.demo.entrypoints: websecure
      traefik.http.routers.demo.tls.options: public@file
      traefik.http.routers.demo.middlewares: rate-limit@file,security-headers@file
      traefik.http.services.demo.loadbalancer.server.port: "80"

networks:
  portcullis-proxy:
    external: true
"""
        manifest = BASE_MANIFEST.replace("instances: multi", "instances: multi\nhosts:\n  reasons:\n    demo: \"Reason\"")
        t = self.write_template(manifest, compose)
        errors, _ = self.check_template(t)
        # Should fail - || outside parentheses doesn't fullmatch the grammar
        self.assertTrue(any("must use middlewares portcullis-auth@docker,portcullis-groups@docker" in e for e in errors),
                        f"Expected auth required error for Host||Host rule. Errors: {errors}")

    def test_hostregexp_rule_fails(self) -> None:
        """(addendum c2) HostRegexp rule without auth fails."""
        # Rule uses HostRegexp instead of Host
        compose = r"""
services:
  demo:
    image: demo/demo:1.2.3@sha256:0000000000000000000000000000000000000000000000000000000000000000
    networks:
      - default
      - portcullis-proxy
    labels:
      traefik.enable: "true"
      traefik.http.routers.demo.rule: HostRegexp(`{host:.+}`)
      traefik.http.routers.demo.entrypoints: websecure
      traefik.http.routers.demo.tls.options: public@file
      traefik.http.routers.demo.middlewares: rate-limit@file,security-headers@file
      traefik.http.services.demo.loadbalancer.server.port: "80"

networks:
  portcullis-proxy:
    external: true
"""
        manifest = BASE_MANIFEST.replace("instances: multi", "instances: multi\nhosts:\n  reasons:\n    demo: \"Reason\"")
        t = self.write_template(manifest, compose)
        errors, _ = self.check_template(t)
        # Should fail - HostRegexp doesn't fullmatch the grammar
        self.assertTrue(any("must use middlewares portcullis-auth@docker,portcullis-groups@docker" in e for e in errors),
                        f"Expected auth required error for HostRegexp rule. Errors: {errors}")

    def test_dot_vs_dash_no_match(self) -> None:
        """(addendum c3) Host var differing only by . vs - doesn't match."""
        # Reason has "demo-dash" (DEMO_DASH), router uses "demo.dash" (DEMO_DASH too but different string)
        # They should NOT match because we compare the full PORTCULLIS_HOST_X string exactly
        compose = r"""
services:
  demo:
    image: demo/demo:1.2.3@sha256:0000000000000000000000000000000000000000000000000000000000000000
    networks:
      - default
      - portcullis-proxy
    labels:
      traefik.enable: "true"
      traefik.http.routers.demo.rule: Host(`${PORTCULLIS_HOST_DEMO:-demo.portcullis.local}`)
      traefik.http.routers.demo.entrypoints: websecure
      traefik.http.routers.demo.tls.options: default
      traefik.http.routers.demo.middlewares: portcullis-auth@docker,portcullis-groups@docker
      traefik.http.routers.demo.service: demo
      traefik.http.routers.demo-special.rule: Host(`${PORTCULLIS_HOST_DEMO_DOT:-demo-dot.portcullis.local}`)
      traefik.http.routers.demo-special.entrypoints: websecure
      traefik.http.routers.demo-special.tls.options: public@file
      traefik.http.routers.demo-special.middlewares: rate-limit@file,security-headers@file
      traefik.http.routers.demo-special.service: demo
      traefik.http.services.demo.loadbalancer.server.port: "80"

networks:
  portcullis-proxy:
    external: true
"""
        # Reason has "demo-dash" (var_key -> DEMO_DASH), router uses DEMO_DOT
        # These are different, so no match
        manifest = BASE_MANIFEST.replace("instances: multi", "instances: multi\nhosts:\n  reasons:\n    demo-dash: \"Reason for demo-dash\"")
        t = self.write_template(manifest, compose)
        errors, _ = self.check_template(t)
        # Router uses DEMO_DOT, reason has "demo-dash" (DEMO_DASH), no match
        self.assertTrue(any("demo-special" in e and "must use middlewares" in e for e in errors),
                        f"Expected auth required for demo-special (no matching reason). Errors: {errors}")




if __name__ == "__main__":
    unittest.main()
