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


if __name__ == "__main__":
    unittest.main()
