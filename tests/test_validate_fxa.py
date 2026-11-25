#!/usr/bin/env python3
"""Tests for Firefox Sync features: verified_email, mail_sender, hosts.reasons.

    python3 -m pytest tests/test_validate.py -k 'verified_email or mail_sender or hosts_reasons'
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
        manifest = textwrap.dedent("""\
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
              group_access: false
              notes: Demo.
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
            ai:
              unsupported: test fixture
            """)
        compose = textwrap.dedent("""\
            services:
              demo:
                image: demo/demo:1.2.3@sha256:0000000000000000000000000000000000000000000000000000000000000000
                networks:
                  - default
            """)
        t = self.write_template(manifest, compose)
        errors, _ = self.check_template(t)
        self.assertTrue(any("verified_email needs group_access: true and an auth.access_group" in e for e in errors), errors)

    def test_verified_email_file_delivery_only(self) -> None:
        """verified_email takes only file deliveries."""
        manifest = textwrap.dedent("""\
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
              access_group: users_demo
              notes: Demo.
            settings:
              options:
                - key: verified_email_field
                  label: Email
                  type: verified_email
                  self_visible: false
                  delivery:
                    - env: VERIFIED_EMAIL
            ai:
              unsupported: test fixture
            """)
        compose = textwrap.dedent("""\
            services:
              demo:
                image: demo/demo:1.2.3@sha256:0000000000000000000000000000000000000000000000000000000000000000
                networks:
                  - default
            """)
        t = self.write_template(manifest, compose)
        errors, _ = self.check_template(t)
        self.assertTrue(any("verified_email takes only file deliveries" in e for e in errors), errors)

    def test_verified_email_self_visible_false(self) -> None:
        """verified_email needs self_visible: false."""
        manifest = textwrap.dedent("""\
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
              access_group: users_demo
              notes: Demo.
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
            ai:
              unsupported: test fixture
            """)
        compose = textwrap.dedent("""\
            services:
              demo:
                image: demo/demo:1.2.3@sha256:0000000000000000000000000000000000000000000000000000000000000000
                networks:
                  - default
            """)
        t = self.write_template(manifest, compose)
        errors, _ = self.check_template(t)
        self.assertTrue(any("verified_email needs self_visible: false" in e for e in errors), errors)


class TestMailSender(FxACase):
    def test_mail_sender_vars_need_block(self) -> None:
        """PORTCULLIS_MAIL_SENDER_* variables require a mail_sender block."""
        manifest = textwrap.dedent("""\
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
              access_group: users_demo
              notes: Demo.
            ai:
              unsupported: test fixture
            """)
        compose = textwrap.dedent("""\
            services:
              demo:
                image: demo/demo:1.2.3@sha256:0000000000000000000000000000000000000000000000000000000000000000
                environment:
                  MAIL_HOST: ${PORTCULLIS_MAIL_SENDER_HOST}
                networks:
                  - default
            """)
        t = self.write_template(manifest, compose)
        errors, _ = self.check_template(t)
        self.assertTrue(any("PORTCULLIS_MAIL_SENDER_" in e and "needs mail_sender" in e for e in errors), errors)

    def test_mail_sender_label_bounds(self) -> None:
        """mail_sender.label must be one line of 1-64 characters without ' or \\."""
        # Test empty label
        manifest = textwrap.dedent("""\
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
              access_group: users_demo
              notes: Demo.
            mail_sender:
              label: ""
            ai:
              unsupported: test fixture
            """)
        compose = textwrap.dedent("""\
            services:
              demo:
                image: demo/demo:1.2.3@sha256:0000000000000000000000000000000000000000000000000000000000000000
                networks:
                  - default
            """)
        t = self.write_template(manifest, compose)
        errors, _ = self.check_template(t)
        self.assertTrue(any("mail_sender.label must be one line of 1-64 characters" in e for e in errors), errors)

        # Test label with newline
        manifest = manifest.replace('label: ""', 'label: "line1\\nline2"')
        t = self.write_template(manifest, compose)
        errors, _ = self.check_template(t)
        self.assertTrue(any("mail_sender.label must be one line of 1-64 characters" in e for e in errors), errors)

        # Test label with quote
        manifest = manifest.replace('label: "line1\\nline2"', 'label: "Demo\'s app"')
        t = self.write_template(manifest, compose)
        errors, _ = self.check_template(t)
        self.assertTrue(any("mail_sender.label must be one line of 1-64 characters" in e for e in errors), errors)


class TestHostsReasons(FxACase):
    def test_hosts_reasons_known_routers(self) -> None:
        """hosts.reasons keys must be real host routers."""
        manifest = textwrap.dedent("""\
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
              access_group: users_demo
              notes: Demo.
            hosts:
              reasons:
                nonexistent: "Some reason"
            ai:
              unsupported: test fixture
            """)
        compose = textwrap.dedent("""\
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
            """)
        t = self.write_template(manifest, compose)
        errors, _ = self.check_template(t)
        self.assertTrue(any("hosts.reasons: nonexistent is not a host router" in e for e in errors), errors)

    def test_hosts_reasons_one_line_200(self) -> None:
        """hosts.reasons values must be one line, at most 200 runes."""
        manifest = textwrap.dedent("""\
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
              access_group: users_demo
              notes: Demo.
            hosts:
              reasons:
                demo: "Line one\\nLine two"
            ai:
              unsupported: test fixture
            """)
        compose = textwrap.dedent("""\
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
            """)
        t = self.write_template(manifest, compose)
        errors, _ = self.check_template(t)
        self.assertTrue(any("hosts.reasons[demo]: reason has a control character (newlines are not allowed)" in e for e in errors), errors)

        # Test too long (over 200 runes)
        long_reason = "x" * 201
        manifest = manifest.replace('"Line one\\nLine two"', f'"{long_reason}"')
        t = self.write_template(manifest, compose)
        errors, _ = self.check_template(t)
        self.assertTrue(any("hosts.reasons[demo]: reason is 201 runes, at most 200 allowed" in e for e in errors), errors)


if __name__ == "__main__":
    unittest.main()
