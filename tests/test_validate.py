#!/usr/bin/env python3
"""Unit tests for tests/validate.py (contract v2 rules).

    python3 -m unittest discover -s tests -p 'test_*.py'

Each test writes one template into a temporary repo root and runs the
per-template checks of validate.py on it.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import textwrap
import unittest
from typing import List, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import validate as v  # noqa: E402

MANIFEST = """\
name: Demo
description: Demo app
icon: "x"
category: monitoring
tags: [demo]
instances: {instances}
auth:
  method: header-auth
  sso: true
  group_access: true
  group_admin: true
  access_group: users_demo
  admin_group: admin_demo
  notes: Demo.{notes}
env:
  - key: DEMO_SECRET
    description: secret
    generate: random
urls:
  - label: Demo
    url: "{url}"
"""

ROUTER = """\
      traefik.http.routers.demo.rule: {rule}
      traefik.http.routers.demo.entrypoints: websecure
      traefik.http.routers.demo.tls.options: authaware@file
      traefik.http.routers.demo.middlewares: portcullis-auth@docker,portcullis-groups@docker,security-headers@file
"""

COMPOSE = """\
services:
  demo:
    image: demo/demo:1.2.3@sha256:{digest}
    environment:
      DEMO_URL: {url}
      TRUSTED_PROXY: ${{PORTCULLIS_TRAEFIK_IP:-172.31.250.2}}
      DEMO_SECRET: ${{DEMO_SECRET:?DEMO_SECRET must be set}}
{env}    volumes:
      - demo-data:/data
    networks:
      - default
      - portcullis-proxy
    labels:
      traefik.enable: "true"
{routers}      traefik.http.services.demo.loadbalancer.server.port: "80"

volumes:
  demo-data:{volume}

networks:
  portcullis-proxy:
    external: true
"""

V2_RULE = "Host(`${PORTCULLIS_HOST_DEMO:-demo.portcullis.local}`)"
V1_RULE = "Host(`demo.${PORTCULLIS_DOMAIN:-portcullis.local}`)"
V2_URL = "https://${PORTCULLIS_HOST_DEMO:-demo.portcullis.local}"
V1_URL = "https://demo.${PORTCULLIS_DOMAIN:-portcullis.local}"


def router(name: str, rule: str, gated: bool = True) -> str:
    out = ROUTER.replace("routers.demo.", f"routers.{name}.").format(rule=rule)
    if not gated:
        out = out.replace("portcullis-auth@docker,portcullis-groups@docker,", "")
    return out


class Case(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self._root = v.ROOT
        v.ROOT = self.tmp.name
        self.addCleanup(setattr, v, "ROOT", self._root)
        with open(v.SCHEMA_PATH, encoding="utf-8") as f:
            self.validator = v.Draft202012Validator(json.load(f))

    def run_template(self, *, instances: str = "multi", rules: Tuple[Tuple[str, str], ...] = (("demo", V2_RULE),),
                     url: str = V2_URL, manifest_url: str = "https://{{HOST_DEMO}}", volume: str = " {}",
                     env: str = "", notes: str = "", extra_files: Tuple[Tuple[str, str], ...] = (),
                     app_id: str = "demo") -> Tuple[List[str], List[str]]:
        d = os.path.join(self.tmp.name, app_id)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "manifest.yaml"), "w", encoding="utf-8") as f:
            f.write(MANIFEST.format(instances=instances, url=manifest_url, notes=notes))
        routers = "".join(router(n, r) for n, r in rules)
        with open(os.path.join(d, "compose.yml"), "w", encoding="utf-8") as f:
            f.write(COMPOSE.format(digest="0" * 64, url=url, env=env, routers=routers, volume=volume))
        for name, text in extra_files:
            with open(os.path.join(d, name), "w", encoding="utf-8") as f:
                f.write(text)
        t = v.Template(app_id)
        r = v.Report()
        v.check_manifest_schema(t, self.validator, r)
        self.assertIsNotNone(t.manifest, r.errors)
        v.check_manifest_rules(t, r)
        v.check_compose(t, r)
        self.template = t
        return r.errors, r.warnings

    def assertClean(self, errors: List[str]) -> None:
        self.assertEqual(errors, [], "\n".join(errors))

    def assertError(self, errors: List[str], needle: str) -> None:
        self.assertTrue(any(needle in e for e in errors), f"no error containing {needle!r} in:\n" + "\n".join(errors))


class TestV2Accepts(Case):
    def test_multi_v2_template_is_clean(self) -> None:
        errors, _ = self.run_template()
        self.assertClean(errors)
        self.assertEqual(self.template.subdomains, {"demo"})
        self.assertEqual(self.template.volume_names, {"portcullis_demo-data": "demo-data"})

    def test_path_router_reuses_host_variable(self) -> None:
        errors, _ = self.run_template(rules=(
            ("demo", V2_RULE),
            ("demo-admin", "Host(`${PORTCULLIS_HOST_DEMO:-demo.portcullis.local}`) && PathPrefix(`/admin`)"),
            ("demo-login", "Host(`${PORTCULLIS_HOST_DEMO:-demo.portcullis.local}`) && (PathPrefix(`/a`) || Path(`/b`))"),
        ))
        self.assertClean(errors)

    def test_instance_variables_with_default_instance_values(self) -> None:
        env = ("      GROUPS: \"${PORTCULLIS_ACCESS_GROUP:-users_demo},${PORTCULLIS_ADMIN_GROUP:-admin_demo}\"\n"
               "      INSTANCE: ${PORTCULLIS_INSTANCE:-demo}\n")
        errors, _ = self.run_template(env=env)
        self.assertClean(errors)

    def test_single_template_may_keep_the_old_form(self) -> None:
        errors, _ = self.run_template(instances="single", rules=(("demo", V1_RULE),), url=V1_URL,
                                      manifest_url="https://demo.{{DOMAIN}}",
                                      volume="\n    name: portcullis_demo-data", notes=" Single instance for the test.")
        self.assertClean(errors)
        self.assertEqual(self.template.subdomains, {"demo"})

    def test_single_template_may_use_the_v2_form(self) -> None:
        errors, _ = self.run_template(instances="single", volume="\n    name: portcullis_demo-data",
                                      notes=" Single instance for the test.")
        self.assertClean(errors)


class TestV2Refuses(Case):
    def test_multi_with_domain_in_router_rule(self) -> None:
        errors, _ = self.run_template(rules=(("demo", V1_RULE),), url=V1_URL, manifest_url="https://demo.{{DOMAIN}}")
        self.assertError(errors, "instances: multi template uses ${PORTCULLIS_DOMAIN} in router demo")

    def test_multi_with_volume_name(self) -> None:
        errors, _ = self.run_template(volume="\n    name: portcullis_demo-data")
        self.assertError(errors, "volumes.demo-data: an instances: multi template must not declare name:")

    def test_single_volume_name_must_match_key(self) -> None:
        errors, _ = self.run_template(instances="single", volume="\n    name: portcullis_other", notes=" Single instance.")
        self.assertError(errors, "must be exactly 'portcullis_demo-data'")

    def test_rule_must_be_exact_form(self) -> None:
        for rule in (
            "Host(`demo.example.org`)",
            "Host(`${PORTCULLIS_HOST_DEMO}`)",
            "Host(`${PORTCULLIS_HOST_DEMO:-demo.example.org}`)",
            "Host(`${PORTCULLIS_HOST_DEMO:-a.b.portcullis.local}`)",
            "Host(`${PORTCULLIS_HOST_DEMO:-demo.portcullis.local}`) || PathPrefix(`/x`)",
            "Host(`${PORTCULLIS_HOST_DEMO:-demo.portcullis.local}`) && Method(`GET`)",
            "PathPrefix(`/x`) && Host(`${PORTCULLIS_HOST_DEMO:-demo.portcullis.local}`)",
            "HostRegexp(`.+`)",
        ):
            with self.subTest(rule=rule):
                errors, _ = self.run_template(rules=(("demo", rule),))
                self.assertError(errors, "router demo: rule must be")

    def test_host_variable_must_match_router_name(self) -> None:
        errors, _ = self.run_template(rules=(("demo", "Host(`${PORTCULLIS_HOST_OTHER:-demo.portcullis.local}`)"),),
                                      url="https://${PORTCULLIS_HOST_OTHER:-demo.portcullis.local}")
        self.assertError(errors, "host router demo must use PORTCULLIS_HOST_DEMO")

    def test_path_router_needs_a_host_router(self) -> None:
        errors, _ = self.run_template(rules=(
            ("demo", V2_RULE),
            ("demo-admin", "Host(`${PORTCULLIS_HOST_ADMIN:-admin.portcullis.local}`) && PathPrefix(`/admin`)"),
        ))
        self.assertError(errors, "no host router uses PORTCULLIS_HOST_ADMIN")

    def test_path_router_must_reuse_the_same_default(self) -> None:
        errors, _ = self.run_template(rules=(
            ("demo", V2_RULE),
            ("demo-admin", "Host(`${PORTCULLIS_HOST_DEMO:-other.portcullis.local}`) && PathPrefix(`/admin`)"),
        ))
        self.assertError(errors, "PORTCULLIS_HOST_DEMO default must be demo.portcullis.local")

    def test_two_host_routers_for_one_hostname(self) -> None:
        errors, _ = self.run_template(rules=(
            ("demo", V2_RULE),
            ("demo2", "Host(`${PORTCULLIS_HOST_DEMO2:-demo.portcullis.local}`)"),
        ))
        self.assertError(errors, "hostname demo has more than one host router")

    def test_two_host_routers_for_one_variable(self) -> None:
        errors, _ = self.run_template(rules=(
            ("demo-a", "Host(`${PORTCULLIS_HOST_DEMO_A:-demo.portcullis.local}`)"),
            ("demo_a", "Host(`${PORTCULLIS_HOST_DEMO_A:-demo-a.portcullis.local}`)"),
        ), url="https://${PORTCULLIS_HOST_DEMO_A:-demo.portcullis.local}", manifest_url="https://{{HOST_DEMO_A}}")
        self.assertError(errors, "map to the same variable PORTCULLIS_HOST_DEMO_A")

    def test_no_mixed_rule_forms(self) -> None:
        errors, _ = self.run_template(instances="single", volume="\n    name: portcullis_demo-data", notes=" Single.",
                                      rules=(("demo", V2_RULE), ("other", "Host(`other.${PORTCULLIS_DOMAIN:-portcullis.local}`)")))
        self.assertError(errors, "mixes the PORTCULLIS_HOST_<ROUTER> and ${PORTCULLIS_DOMAIN} rule forms")

    def test_underscore_in_names(self) -> None:
        errors, _ = self.run_template(rules=(("demo_x", "Host(`${PORTCULLIS_HOST_DEMO_X:-demo.portcullis.local}`)"),),
                                      url="https://${PORTCULLIS_HOST_DEMO_X:-demo.portcullis.local}",
                                      manifest_url="https://{{HOST_DEMO_X}}")
        self.assertError(errors, "router name demo_x contains '_'")

    def test_portcullis_prefix_in_multi_names(self) -> None:
        errors, _ = self.run_template(rules=(("portcullis-demo", "Host(`${PORTCULLIS_HOST_PORTCULLIS_DEMO:-demo.portcullis.local}`)"),),
                                      url="https://${PORTCULLIS_HOST_PORTCULLIS_DEMO:-demo.portcullis.local}",
                                      manifest_url="https://{{HOST_PORTCULLIS_DEMO}}")
        self.assertError(errors, "router name portcullis-demo starts with 'portcullis-'")

    def test_own_host_url_must_use_the_variable(self) -> None:
        errors, _ = self.run_template(url=V1_URL)
        self.assertError(errors, "names its own host demo.${PORTCULLIS_DOMAIN}")

    def test_own_host_in_support_file(self) -> None:
        errors, _ = self.run_template(extra_files=(("app.conf", "url = https://demo.${PORTCULLIS_DOMAIN}/\n"),))
        self.assertError(errors, "demo/app.conf: names its own host demo.${PORTCULLIS_DOMAIN}")

    def test_core_host_keeps_the_domain(self) -> None:
        errors, _ = self.run_template(env="      ISSUER: https://auth.${PORTCULLIS_DOMAIN:-portcullis.local}/realms/portcullis\n")
        self.assertClean(errors)

    def test_manifest_url_must_use_host_placeholder(self) -> None:
        errors, _ = self.run_template(manifest_url="https://demo.{{DOMAIN}}")
        self.assertError(errors, "use {{HOST_DEMO}} for its own host")

    def test_unknown_host_placeholder(self) -> None:
        errors, _ = self.run_template(manifest_url="https://{{HOST_NOPE}}")
        self.assertError(errors, "{{HOST_NOPE}} names no host router")

    def test_instance_variable_needs_default_form(self) -> None:
        errors, _ = self.run_template(env="      GROUP: ${PORTCULLIS_ACCESS_GROUP}\n")
        self.assertError(errors, "${PORTCULLIS_ACCESS_GROUP} must use the default form ${PORTCULLIS_ACCESS_GROUP:-users_demo}")

    def test_instance_variable_default_is_the_default_instance_value(self) -> None:
        errors, _ = self.run_template(env="      GROUP: ${PORTCULLIS_ACCESS_GROUP:-users_other}\n")
        self.assertError(errors, "${PORTCULLIS_ACCESS_GROUP} default must be users_demo")

    def test_host_variable_default_must_match_everywhere(self) -> None:
        errors, _ = self.run_template(url="https://${PORTCULLIS_HOST_DEMO:-other.portcullis.local}")
        self.assertError(errors, "${PORTCULLIS_HOST_DEMO} default must be demo.portcullis.local")

    def test_oidc_client_variable_without_clients(self) -> None:
        errors, _ = self.run_template(env="      CID: ${PORTCULLIS_OIDC_CLIENT_ID:-demo}\n")
        self.assertError(errors, "${PORTCULLIS_OIDC_CLIENT_ID} is not set for this template")

    def test_hard_coded_group_in_multi_compose(self) -> None:
        errors, _ = self.run_template(env="      GROUPS: users_demo\n")
        self.assertError(errors, "hard-codes group users_demo")

    def test_reserved_variable_in_manifest(self) -> None:
        errors, _ = self.run_template(extra_files=())
        self.assertClean(errors)
        d = os.path.join(self.tmp.name, "demo", "manifest.yaml")
        with open(d, encoding="utf-8") as f:
            text = f.read()
        with open(d, "w", encoding="utf-8") as f:
            f.write(text.replace("key: DEMO_SECRET", "key: PORTCULLIS_HOST_DEMO"))
        t = v.Template("demo")
        r = v.Report()
        v.check_manifest_schema(t, self.validator, r)
        v.check_manifest_rules(t, r)
        self.assertError(r.errors, "PORTCULLIS_HOST_DEMO is reserved for the Hub's instance variables")

    def test_oauth2_paths_are_portcullis(self) -> None:
        errors, _ = self.run_template(rules=(
            ("demo", V2_RULE),
            ("demo-cb", "Host(`${PORTCULLIS_HOST_DEMO:-demo.portcullis.local}`) && PathPrefix(`/oauth2/callback`)"),
        ))
        self.assertError(errors, "serves /oauth2/callback")

    def test_support_mount_must_be_read_only_for_multi(self) -> None:
        env = ""
        errors, _ = self.run_template(env=env, extra_files=(("app.conf", "x\n"),))
        self.assertClean(errors)
        path = os.path.join(self.tmp.name, "demo", "compose.yml")
        with open(path, encoding="utf-8") as f:
            text = f.read()
        with open(path, "w", encoding="utf-8") as f:
            f.write(text.replace("      - demo-data:/data\n", "      - demo-data:/data\n      - ./templates/demo/app.conf:/app.conf\n"))
        t = v.Template("demo")
        r = v.Report()
        v.check_manifest_schema(t, self.validator, r)
        v.check_manifest_rules(t, r)
        v.check_compose(t, r)
        self.assertError(r.errors, "is shared by every instance and must be read-only (:ro)")


class TestCross(Case):
    def test_multi_volume_keys_must_be_unique_across_templates(self) -> None:
        self.run_template(app_id="demo")
        a = self.template
        self.run_template(app_id="other", rules=(("other", "Host(`${PORTCULLIS_HOST_OTHER:-other.portcullis.local}`)"),),
                          url="https://${PORTCULLIS_HOST_OTHER:-other.portcullis.local}", manifest_url="https://{{HOST_OTHER}}")
        b = self.template
        r = v.Report()
        v.check_cross([a, b], r)
        self.assertError(r.errors, "volume name 'portcullis_demo-data' is also used by demo")


class TestRealTemplates(unittest.TestCase):
    def test_all_templates_in_repo_validate(self) -> None:
        self.assertEqual(v.main([]), 0)


if __name__ == "__main__":
    unittest.main()
