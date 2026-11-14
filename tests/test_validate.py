#!/usr/bin/env python3
"""Unit tests for tests/validate.py (template contract v2 and v3 rules).

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
from unittest import mock
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import validate as v  # noqa: E402

MANIFEST = """\
name: Demo
description: Demo app
icon: "x"
category: monitoring
tags: [demo]
links:
  website: https://demo.example.org/
  source: https://github.com/example/demo
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
        v.check_links(t, r)
        v.check_compose(t, r)
        self.template = t
        return r.errors, r.warnings

    def _rewrite(self, name: str, old: str, new: str) -> None:
        path = os.path.join(self.tmp.name, "demo", name)
        with open(path, encoding="utf-8") as f:
            text = f.read()
        self.assertIn(old, text)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text.replace(old, new, 1))

    def rewrite_compose(self, old: str, new: str) -> None:
        self._rewrite("compose.yml", old, new)

    def rewrite_manifest(self, old: str, new: str) -> None:
        self._rewrite("manifest.yaml", old, new)

    def recheck(self) -> List[str]:
        t = v.Template("demo")
        r = v.Report()
        v.check_manifest_schema(t, self.validator, r)
        v.check_manifest_rules(t, r)
        v.check_links(t, r)
        v.check_compose(t, r)
        return r.errors

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
        v.check_links(t, r)
        v.check_compose(t, r)
        self.assertError(r.errors, "is shared by every instance and must be read-only (:ro)")


    def test_literal_own_host_outside_the_variable(self) -> None:
        errors, _ = self.run_template(env="      OVERWRITEHOST: demo.portcullis.local\n")
        self.assertError(errors, "names its own host demo.portcullis.local literally")

    def test_literal_own_host_in_support_file(self) -> None:
        errors, _ = self.run_template(extra_files=(("app.conf", "host = https://demo.portcullis.local/\n"),))
        self.assertError(errors, "demo/app.conf: names its own host demo.portcullis.local literally")

    def test_instance_variable_in_support_file_needs_environment(self) -> None:
        errors, _ = self.run_template(extra_files=(("app.conf", "group = ${PORTCULLIS_ACCESS_GROUP}\n"),))
        self.assertError(errors, "demo/app.conf: uses PORTCULLIS_ACCESS_GROUP, which no service gets through environment:")

    def test_instance_variable_in_support_file_passed_through_environment(self) -> None:
        errors, _ = self.run_template(env="      PORTCULLIS_ACCESS_GROUP: ${PORTCULLIS_ACCESS_GROUP:-users_demo}\n",
                                      extra_files=(("app.conf", "group = ${PORTCULLIS_ACCESS_GROUP}\n"),))
        self.assertClean(errors)

    def test_instance_variable_in_support_file_must_exist(self) -> None:
        errors, _ = self.run_template(env="      PORTCULLIS_OIDC_CLIENT_ID: x\n",
                                      extra_files=(("app.conf", "id = ${PORTCULLIS_OIDC_CLIENT_ID}\n"),))
        self.assertError(errors, "demo/app.conf: ${PORTCULLIS_OIDC_CLIENT_ID} is not set for this template")

    def test_multi_template_cannot_be_privileged(self) -> None:
        errors, _ = self.run_template(env="")
        self.assertClean(errors)
        self.rewrite_compose("    networks:\n      - default\n", "    privileged: true\n    networks:\n      - default\n")
        self.assertError(self.recheck(), "privileged: true can't be per instance")

    def test_multi_host_network_port_must_be_used(self) -> None:
        self.run_template()
        self.rewrite_manifest("env:\n", "ports:\n  - key: DEMO_UDP_PORT\n    label: UDP\n    container: 9999\n"
                              "    protocol: udp\n    default: 9999\n    service: demo\n    network_mode_host: true\nenv:\n")
        self.assertError(self.recheck(), "host-network port DEMO_UDP_PORT is not used in compose.yml")
        self.rewrite_compose("      DEMO_URL:", "      DEMO_PORT: ${DEMO_UDP_PORT:-9999}\n      DEMO_URL:")
        self.assertFalse(any("DEMO_UDP_PORT" in e for e in self.recheck()))


class TestIdentityRules(Case):
    def test_nextcloud_uid_mapping_must_not_be_email(self) -> None:
        errors, _ = self.run_template(extra_files=(("setup.sh", "occ user_oidc:provider P --mapping-uid=email\n"),))
        self.assertError(errors, "user_oidc keys users on email")
        errors, _ = self.run_template(extra_files=(("setup.sh", "occ user_oidc:provider P --mapping-uid=preferred_username\n"),))
        self.assertClean(errors)

    def test_nextcloud_soft_auto_provision_must_stay_off(self) -> None:
        errors, _ = self.run_template(extra_files=(("setup.sh", "occ config:system:set user_oidc soft_auto_provision --type=boolean --value=true\n"),))
        self.assertError(errors, "soft auto-provisioning")
        errors, _ = self.run_template(extra_files=(("setup.sh", "occ config:system:set user_oidc soft_auto_provision --type=boolean --value=false\n"),))
        self.assertClean(errors)

    def test_dokuwiki_oauth_mail_claim_must_not_be_email(self) -> None:
        errors, _ = self.run_template(extra_files=(("init.sh", '  "json-mail" => "email",\n'),))
        self.assertError(errors, "json-mail")

    def test_pihole_without_password_needs_acl_and_domain(self) -> None:
        errors, _ = self.run_template(env='      FTLCONF_webserver_api_password: ""\n')
        self.assertError(errors, "FTLCONF_webserver_acl")
        self.assertError(errors, "FTLCONF_webserver_domain")
        errors, _ = self.run_template(env='      FTLCONF_webserver_api_password: ""\n'
                                          "      FTLCONF_webserver_acl: +${PORTCULLIS_TRAEFIK_IP:-172.31.250.2},+127.0.0.1,+[::1]\n"
                                          "      FTLCONF_webserver_domain: ${PORTCULLIS_HOST_DEMO:-demo.portcullis.local}\n")
        self.assertClean(errors)
        errors, _ = self.run_template(env='      FTLCONF_webserver_api_password: ""\n'
                                          "      FTLCONF_webserver_acl: +172.31.250.0/24\n"
                                          "      FTLCONF_webserver_domain: ${PORTCULLIS_HOST_DEMO:-demo.portcullis.local}\n")
        self.assertError(errors, "FTLCONF_webserver_acl")


    def test_paperless_sso_needs_regular_login_off(self) -> None:
        errors, _ = self.run_template(env='      PAPERLESS_SOCIALACCOUNT_PROVIDERS: "{}"\n')
        self.assertError(errors, "PAPERLESS_DISABLE_REGULAR_LOGIN")
        errors, _ = self.run_template(env='      PAPERLESS_SOCIALACCOUNT_PROVIDERS: "{}"\n'
                                          '      PAPERLESS_DISABLE_REGULAR_LOGIN: "true"\n')
        self.assertClean(errors)
        errors, _ = self.run_template(env='      PAPERLESS_AUTO_LOGIN_USERNAME: admin\n')
        self.assertError(errors, "remote-user auth bypasses SSO")

    def test_gitea_never_links_accounts(self) -> None:
        errors, _ = self.run_template(env="      GITEA__oauth2_client__ENABLE_AUTO_REGISTRATION: \"true\"\n"
                                          "      GITEA__oauth2_client__ACCOUNT_LINKING: auto\n")
        self.assertError(errors, "Gitea links OAuth logins")
        self.assertError(errors, "ACCOUNT_LINKING=disabled")
        errors, _ = self.run_template(env="      GITEA__oauth2_client__ENABLE_AUTO_REGISTRATION: \"true\"\n"
                                          "      GITEA__oauth2_client__ACCOUNT_LINKING: disabled\n")
        self.assertClean(errors)
        errors, _ = self.run_template(env="      GITEA__oauth2_client__USERNAME: email\n")
        self.assertError(errors, "Gitea OAuth username is the email")

    def test_mealie_oidc_needs_password_login_off_and_username_claim(self) -> None:
        errors, _ = self.run_template(env='      OIDC_AUTH_ENABLED: "true"\n')
        self.assertError(errors, "ALLOW_PASSWORD_LOGIN")
        self.assertError(errors, "OIDC_USER_CLAIM: preferred_username")
        errors, _ = self.run_template(env='      OIDC_AUTH_ENABLED: "true"\n      ALLOW_PASSWORD_LOGIN: "false"\n'
                                          "      OIDC_USER_CLAIM: preferred_username\n")
        self.assertClean(errors)

    def test_oxicloud_oidc_needs_no_email_linking_and_oidc_only(self) -> None:
        errors, _ = self.run_template(env='      OXICLOUD_OIDC_ENABLED: "true"\n')
        self.assertError(errors, "OXICLOUD_OIDC_AUTO_LINK_EMAIL_MATCH")
        self.assertError(errors, "OXICLOUD_AUTH_METHODS: oidc")
        errors, _ = self.run_template(env='      OXICLOUD_OIDC_ENABLED: "true"\n      OXICLOUD_OIDC_AUTO_LINK_EMAIL_MATCH: "true"\n'
                                          "      OXICLOUD_AUTH_METHODS: password,oidc\n")
        self.assertError(errors, "OXICLOUD_OIDC_AUTO_LINK_EMAIL_MATCH")
        self.assertError(errors, "OXICLOUD_AUTH_METHODS: oidc")
        errors, _ = self.run_template(env='      OXICLOUD_OIDC_ENABLED: "true"\n      OXICLOUD_OIDC_AUTO_LINK_EMAIL_MATCH: "false"\n'
                                          "      OXICLOUD_AUTH_METHODS: oidc\n")
        self.assertClean(errors)

    def test_mattermost_image_needs_email_signup_off(self) -> None:
        image = "mattermost/mattermost-team-edition:12.0.1"
        job = f"services:\n  mattermost-init:\n    image: {image}@sha256:{'0' * 64}\n    restart: \"no\"\n"
        self.run_template()
        self.rewrite_compose("image: demo/demo:1.2.3", f"image: {image}")
        self.rewrite_compose("services:\n", job)
        self.assertError(self.recheck(), "MM_EMAILSETTINGS_ENABLESIGNUPWITHEMAIL")
        self.assertError(self.recheck(), "MM_PLUGINSETTINGS_ENABLEUPLOADS")
        self.assertError(self.recheck(), "MM_PLUGINSETTINGS_REQUIREPLUGINSIGNATURE")
        self.assertError(self.recheck(), "MM_FILESETTINGS_DRIVERNAME")
        self.assertError(self.recheck(), "MM_FILESETTINGS_DIRECTORY")
        self.assertError(self.recheck(), "MM_PLUGINSETTINGS_DIRECTORY")
        self.assertError(self.recheck(), "MM_PLUGINSETTINGS_CLIENTDIRECTORY")
        self.run_template(env='      MM_EMAILSETTINGS_ENABLESIGNUPWITHEMAIL: "false"\n      MM_PLUGINSETTINGS_ENABLEUPLOADS: "false"\n'
                              '      MM_PLUGINSETTINGS_REQUIREPLUGINSIGNATURE: "true"\n      MM_FILESETTINGS_DRIVERNAME: local\n'
                              '      MM_FILESETTINGS_DIRECTORY: /mattermost/data\n      MM_PLUGINSETTINGS_DIRECTORY: /mattermost/plugins\n'
                              '      MM_PLUGINSETTINGS_CLIENTDIRECTORY: /mattermost/client/plugins\n')
        self.rewrite_compose("image: demo/demo:1.2.3", f"image: {image}")
        self.rewrite_compose("services:\n", job.replace('restart: "no"\n', 'restart: "no"\n    environment:\n'
                                                         '      MM_EMAILSETTINGS_ENABLESIGNUPWITHEMAIL: "false"\n'
                                                         '      MM_PLUGINSETTINGS_ENABLEUPLOADS: "false"\n'
                                                         '      MM_PLUGINSETTINGS_REQUIREPLUGINSIGNATURE: "true"\n'
                                                         '      MM_FILESETTINGS_DRIVERNAME: local\n'
                                                         '      MM_FILESETTINGS_DIRECTORY: /mattermost/data/\n'
                                                         '      MM_PLUGINSETTINGS_DIRECTORY: /mattermost/plugins\n'
                                                         '      MM_PLUGINSETTINGS_CLIENTDIRECTORY: /mattermost/client/plugins\n'))
        self.assertFalse([e for e in self.recheck() if "MM_" in e])
        self.rewrite_compose("MM_FILESETTINGS_DIRECTORY: /mattermost/data/", "MM_FILESETTINGS_DIRECTORY: /srv/elsewhere")
        self.assertError(self.recheck(), "MM_FILESETTINGS_DIRECTORY")

    def test_home_assistant_needs_keycloak_access_role(self) -> None:
        image = "ghcr.io/home-assistant/home-assistant:2026.10.4"
        self.run_template()
        self.rewrite_compose("image: demo/demo:1.2.3", f"image: {image}")
        self.assertError(self.recheck(), "keycloak_access_role")
        self.rewrite_manifest("auth:\n", "auth:\n  keycloak_access_role: true\n")
        self.assertFalse([e for e in self.recheck() if "keycloak_access_role: true (auth_oidc" in e])

    def test_auth_oidc_never_links_users(self) -> None:
        errors, _ = self.run_template(extra_files=(("configuration.yaml", "auth_oidc:\n  features:\n    automatic_user_linking: true\n"),))
        self.assertError(errors, "automatic_user_linking")
        errors, _ = self.run_template(extra_files=(("configuration.yaml", "auth_oidc:\n  features:\n    automatic_user_linking: false\n"),))
        self.assertClean(errors)

    def test_synapse_never_attaches_existing_users(self) -> None:
        errors, _ = self.run_template(extra_files=(("start.py", '"allow_existing_users": True,\n'),))
        self.assertError(errors, "Synapse would attach SSO logins")
        errors, _ = self.run_template(extra_files=(("start.py", '"localpart_template": "{{ user.email }}",\n'),))
        self.assertError(errors, "Synapse keys users on email")
        errors, _ = self.run_template(extra_files=(("start.py", '"allow_existing_users": False,\n'
                                                                '"localpart_template": "{{ user.preferred_username }}",\n'),))
        self.assertClean(errors)

    def test_required_init_jobs(self) -> None:
        for image, job in (("ghcr.io/paperless-ngx/paperless-ngx:3.4.1", "paperless-init"),
                           ("ghcr.io/mealie-recipes/mealie:v3.30.0", "mealie-init"),
                           ("ghcr.io/immich-app/immich-server:v2.0.0", "immich-lock-local-users"),
                           ("diocrafts/oxicloud:0.10.0", "oxicloud-init"),
                           ("ghcr.io/home-assistant/home-assistant:2026.10.4", "homeassistant-init"),
                           ("mattermost/mattermost-team-edition:12.0.1", "mattermost-init")):
            with self.subTest(job=job):
                self.run_template()
                self.rewrite_compose("image: demo/demo:1.2.3", f"image: {image}")
                self.assertError(self.recheck(), job)
                self.rewrite_compose("services:\n", f"services:\n  {job}:\n"
                                     f"    image: {image}@sha256:{'0' * 64}\n    restart: \"no\"\n")
                # (the job service has the app image, so image rules apply to it too: not this check)
                self.assertFalse([e for e in self.recheck() if job in e and " must set " not in e])

    def test_vikunja_oidc_only_and_no_linking(self) -> None:
        ok = ('      VIKUNJA_AUTH_OPENID_ENABLED: "true"\n      VIKUNJA_AUTH_LOCAL_ENABLED: "false"\n'
              '      VIKUNJA_OUTGOINGREQUESTS_ALLOWNONROUTABLEIPS: "false"\n')
        errors, _ = self.run_template(env=ok)
        self.assertClean(errors)
        for line, needle in (('      VIKUNJA_AUTH_LOCAL_ENABLED: "false"\n', "VIKUNJA_AUTH_LOCAL_ENABLED"),
                             ('      VIKUNJA_OUTGOINGREQUESTS_ALLOWNONROUTABLEIPS: "false"\n',
                              "VIKUNJA_OUTGOINGREQUESTS_ALLOWNONROUTABLEIPS")):
            with self.subTest(dropped=needle):
                errors, _ = self.run_template(env=ok.replace(line, ""))
                self.assertError(errors, needle)
        for key in ("EMAILFALLBACK", "USERNAMEFALLBACK"):
            for val in ("true", "TRUE", "1", "t", "T"):
                with self.subTest(key=key, val=val):
                    errors, _ = self.run_template(env=ok + f'      VIKUNJA_AUTH_OPENID_PROVIDERS_MY_IDP_{key}: "{val}"\n')
                    self.assertError(errors, "Vikunja links OIDC logins")

    def test_librechat_openid_only_and_group(self) -> None:
        ok = ('      OPENID_SESSION_SECRET: x\n      ALLOW_EMAIL_LOGIN: "false"\n      ALLOW_REGISTRATION: "false"\n'
              '      ALLOW_SHARED_LINKS_PUBLIC: "false"\n'
              '      OPENID_REQUIRED_ROLE: ${PORTCULLIS_ACCESS_GROUP:-users_demo}\n')
        errors, _ = self.run_template(env=ok)
        self.assertClean(errors)
        for line, needle in (('      ALLOW_EMAIL_LOGIN: "false"\n', "ALLOW_EMAIL_LOGIN"),
                             ('      ALLOW_REGISTRATION: "false"\n', "ALLOW_REGISTRATION"),
                             ('      ALLOW_SHARED_LINKS_PUBLIC: "false"\n', "ALLOW_SHARED_LINKS_PUBLIC"),
                             ('      OPENID_REQUIRED_ROLE: ${PORTCULLIS_ACCESS_GROUP:-users_demo}\n', "OPENID_REQUIRED_ROLE")):
            with self.subTest(dropped=needle):
                errors, _ = self.run_template(env=ok.replace(line, ""))
                self.assertError(errors, needle)
        errors, _ = self.run_template(env=ok.replace("${PORTCULLIS_ACCESS_GROUP:-users_demo}", "users_demo"))
        self.assertError(errors, "OPENID_REQUIRED_ROLE")

    def test_librechat_waits_for_its_config(self) -> None:
        image = "ghcr.io/librechat-ai/librechat:v0.8.8"
        self.run_template()
        self.rewrite_compose("image: demo/demo:1.2.3", f"image: {image}")
        self.assertError(self.recheck(), "rendered by the config one-shot")
        self.rewrite_compose("services:\n", f"services:\n  config:\n    image: {image}@sha256:{'0' * 64}\n"
                             "    restart: \"no\"\n")
        self.assertFalse([e for e in self.recheck() if "config one-shot" in e])
        self.assertError(self.recheck(), "only after config rendered")
        self.rewrite_compose("    networks:\n      - default\n      - portcullis-proxy\n",
                             "    depends_on:\n      config:\n        condition: service_completed_successfully\n"
                             "    networks:\n      - default\n      - portcullis-proxy\n")
        self.assertFalse([e for e in self.recheck() if "config" in e and "LibreChat" in e])

    def test_firefox_sync_routed_service_waits_for_the_allowlist(self) -> None:
        image = "ghcr.io/porelli/firefox-sync:syncstorage-rs-postgres-0.24.0"
        init = (f"  firefox-sync-init:\n    image: postgres:17.11-alpine@sha256:{'0' * 64}\n    restart: \"no\"\n")
        self.run_template()
        self.rewrite_compose("image: demo/demo:1.2.3", f"image: {image}")
        self.assertError(self.recheck(), "only the firefox-sync-init allowlist trigger")
        self.rewrite_compose("services:\n", "services:\n" + init)
        self.assertFalse([e for e in self.recheck() if "allowlist trigger" in e])
        self.assertError(self.recheck(), "only after firefox-sync-init")
        self.rewrite_compose("    networks:\n      - default\n      - portcullis-proxy\n",
                             "    depends_on:\n      firefox-sync-init:\n        condition: service_started\n"
                             "    networks:\n      - default\n      - portcullis-proxy\n")
        self.assertError(self.recheck(), "only after firefox-sync-init")
        self.rewrite_compose("condition: service_started", "condition: service_completed_successfully")
        self.assertFalse([e for e in self.recheck() if "firefox-sync-init" in e])


class TestGatedClientRouters(unittest.TestCase):
    HOST = "Host(`${PORTCULLIS_HOST_ELEMENT:-element.portcullis.local}`)"

    def check(self, app_id: str, gated: bool) -> List[str]:
        mws = ("client-headers@file,portcullis-auth@docker,portcullis-groups@docker,security-headers@file"
               if gated else "client-headers@file,security-headers@file")
        routers = {"element": {"rule": self.HOST, "entrypoints": "websecure",
                               "tls.options": "authaware@file", "middlewares": mws}}
        t = v.Template(app_id)
        t.manifest = {"instances": "multi", "auth": {"method": "native-oidc", "group_access": True}}
        r = v.Report()
        v.check_routers(t, routers, r)
        return r.errors

    def test_other_native_oidc_app_cannot_gate_its_host(self) -> None:
        errors = self.check("demo", gated=True)
        self.assertTrue(any("must not use" in e for e in errors), errors)

    def test_listed_static_client_may_and_must_be_gated(self) -> None:
        self.assertFalse([e for e in self.check("matrix", gated=True) if "element" in e])
        errors = self.check("matrix", gated=False)
        self.assertTrue(any("router element must be a host router" in e for e in errors), errors)


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

    def test_device_patterns_refuse_dot_segments(self) -> None:
        # Docker maps every node under a directory source: /dev/. or a ..
        # segment would hand the app every host device.
        import yaml
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        good = ["/dev/sda", "/dev/nvme0", "/dev/video0", "/dev/ttyUSB0",
                "/dev/serial/by-id/usb-Silicon_Labs_CP2102-if00-port0",
                "/dev/serial/by-id/usb-ITead_Sonoff_Zigbee_3.0_USB_Dongle_Plus-if00-port0"]
        bad = ["/dev/.", "/dev/..", "/dev/../sda", "/dev/serial/..", "/dev/serial/./x",
               "/dev/.hidden", "/dev/", "/dev//sda", "/dev/sda/", "/dev/sda:rw", "/etc/passwd"]
        for app, key in (("esphome", "serial_device"), ("zigbee2mqtt", "serial_device"),
                         ("motioneye", None), ("scrutiny", None)):
            with open(os.path.join(root, app, "manifest.yaml"), encoding="utf-8") as f:
                m = yaml.safe_load(f)
            pats = []
            for o in m["settings"]["options"]:
                p = (o.get("items") or {}).get("pattern") if o.get("type") == "list" else o.get("pattern")
                if p and p.startswith("^/dev/") and (key is None or o["key"] == key):
                    pats.append(p)
            self.assertTrue(pats, app)
            for p in pats:
                rx = v._compile_pattern(p)
                for s in good:
                    self.assertTrue(rx.fullmatch(s), f"{app}: {s}")
                for s in bad:
                    self.assertFalse(rx.fullmatch(s), f"{app}: {s}")


class SigninTest(Case):
    """tests.signin (sign-in e2e) rules."""

    def test_fixture_is_clean(self) -> None:
        errors, warnings = self.run_template()
        self.assertEqual(errors, [])
        self.assertEqual(warnings, [])

    def test_missing_block(self) -> None:
        self.run_template()
        self.rewrite_manifest("tests:\n  signin:\n    path: /\n", "x_tests:\n  signin:\n    path: /\n")
        errs = self.recheck()
        self.assertTrue(any("no tests.signin block" in e for e in errs), errs)

    def test_signin_requires_path_and_signed_in(self) -> None:
        self.run_template()
        self.rewrite_manifest("    signed_in:\n      text: \"{username}\"\n", "")
        errs = self.recheck()
        self.assertTrue(any("tests.signin" in e and "signed_in" in e for e in errs), errs)

    def test_skip_only_for_public_custom_mtls(self) -> None:
        self.run_template()
        self.rewrite_manifest("    path: /\n    signed_in:\n      text: \"{username}\"\n    admin:\n      reach: /admin\n",
                              "    skip: \"cannot be signed into in CI\"\n")
        errs = self.recheck()
        self.assertTrue(any("tests.signin.skip is only for" in e for e in errs), errs)

    def test_group_admin_needs_admin_check(self) -> None:
        self.run_template()
        self.rewrite_manifest("    admin:\n      reach: /admin\n", "")
        errs = self.recheck()
        self.assertTrue(any("no admin check" in e for e in errs), errs)

    def test_gated_app_cannot_expect_outsider_failure(self) -> None:
        self.run_template()
        self.rewrite_manifest("    admin:\n", "    expected_fail:\n      outsider: {reason: \"some long enough reason\", match: \"signed in\"}\n    admin:\n")
        errs = self.recheck()
        self.assertTrue(any("expected_fail.outsider on a header-auth app" in e for e in errs), errs)

    def test_open_native_oidc_may_expect_outsider_failure(self) -> None:
        self.run_template()
        self.rewrite_manifest("  method: header-auth\n", "  method: native-oidc\n")
        self.rewrite_manifest("  group_access: true\n", "  group_access: false\n")
        self.rewrite_manifest("    admin:\n", "    expected_fail:\n      outsider: {reason: \"no OIDC group restriction yet\", match: \"signed in\"}\n    admin:\n")
        errs = self.recheck()
        self.assertFalse(any("expected_fail" in e for e in errs), errs)

    def test_expected_fail_needs_valid_match(self) -> None:
        self.run_template()
        self.rewrite_manifest("  method: header-auth\n", "  method: native-oidc\n")
        self.rewrite_manifest("    admin:\n", "    expected_fail:\n      member: \"just a string reason\"\n    admin:\n")
        errs = self.recheck()
        self.assertTrue(any("expected_fail.member" in e for e in errs), errs)
        self.rewrite_manifest("      member: \"just a string reason\"\n", "      member: {reason: \"a long enough reason\", match: \"(unclosed\"}\n")
        errs = self.recheck()
        self.assertTrue(any("not a valid regex" in e for e in errs), errs)

    def test_host_must_be_a_host_router(self) -> None:
        self.run_template()
        self.rewrite_manifest("    path: /\n", "    host: \"{{HOST_OTHER}}\"\n    path: /\n")
        errs = self.recheck()
        self.assertTrue(any("tests.signin.host {{HOST_OTHER}}" in e for e in errs), errs)

    def test_signed_in_without_username_warns(self) -> None:
        self.run_template()
        self.rewrite_manifest("      text: \"{username}\"\n", "      text: \"Dashboard\"\n")
        t = v.Template("demo")
        r = v.Report()
        v.check_manifest_schema(t, self.validator, r)
        v.check_manifest_rules(t, r)
        v.check_links(t, r)
        v.check_compose(t, r)
        self.assertTrue(any("does not check the username" in w for w in r.warnings), r.warnings)



LINKS = "links:\n  website: https://demo.example.org/\n  source: https://github.com/example/demo\n"


class TestLinks(Case):
    def links(self, block: str) -> Tuple[List[str], List[str]]:
        self.run_template()
        self.rewrite_manifest(LINKS, block)
        t = v.Template("demo")
        r = v.Report()
        v.check_manifest_schema(t, self.validator, r)
        v.check_links(t, r)
        return r.errors, r.warnings

    def test_links_are_required(self) -> None:
        errors, _ = self.links("")
        self.assertError(errors, "'links' is a required property")

    def test_website_and_source_are_required(self) -> None:
        errors, _ = self.links("links:\n  website: https://demo.example.org/\n")
        self.assertError(errors, "'source' is a required property")
        errors, _ = self.links("links:\n  source: https://github.com/example/demo\n")
        self.assertError(errors, "'website' is a required property")

    def test_https_only(self) -> None:
        for url in ("http://demo.example.org/", "ftp://demo.example.org/", "https://localhost/",
                    "https://{{HOST_DEMO}}/", "https://user@demo.example.org/", "https://demo.example.org/a b", ""):
            with self.subTest(url=url):
                errors, _ = self.links(f"links:\n  website: \"{url}\"\n  source: https://github.com/example/demo\n")
                self.assertError(errors, "links.website")
                errors, _ = self.links(f"links:\n  website: https://demo.example.org/\n  source: \"{url}\"\n")
                self.assertError(errors, "links.source")

    def test_closed_source_needs_a_note(self) -> None:
        errors, _ = self.links("links:\n  website: https://demo.example.org/\n  source: null\n")
        self.assertError(errors, "'source_note' is a required property")
        errors, _ = self.links("links:\n  website: https://demo.example.org/\n  source: null\n"
                               "  source_note: Demo Server is proprietary\n")
        self.assertClean(errors)

    def test_note_only_without_source(self) -> None:
        errors, _ = self.links(LINKS + "  source_note: Demo Server is proprietary\n")
        self.assertError(errors, "links")

    def test_unknown_key(self) -> None:
        errors, _ = self.links(LINKS + "  docs: https://demo.example.org/docs\n")
        self.assertError(errors, "Additional properties are not allowed")

    def test_source_must_be_the_repository_root(self) -> None:
        for url in ("https://github.com/example", "https://github.com/example/demo/tree/main",
                    "https://github.com/example/demo.git", "https://github.com/example/demo/",
                    "https://github.com/example/demo?tab=readme", "https://gitlab.com/example/demo/-/tree/main",
                    "https://git.sr.ht/example/demo"):
            with self.subTest(url=url):
                errors, _ = self.links(f"links:\n  website: https://demo.example.org/\n  source: {url}\n")
                self.assertError(errors, "is not a repository URL")

    def test_known_forges_are_accepted(self) -> None:
        for url in ("https://gitlab.com/example/group/demo", "https://codeberg.org/example/demo",
                    "https://gitea.com/example/demo", "https://git.sr.ht/~example/demo"):
            with self.subTest(url=url):
                errors, warnings = self.links(f"links:\n  website: https://demo.example.org/\n  source: {url}\n")
                self.assertClean(errors)
                self.assertEqual(warnings, [])

    def test_self_hosted_forge_warns(self) -> None:
        errors, warnings = self.links("links:\n  website: https://demo.example.org/\n"
                                      "  source: https://git.example.org/demo/demo\n")
        self.assertClean(errors)
        self.assertTrue(any("not on a known code host" in w for w in warnings), warnings)

    def test_registry_pages_are_refused(self) -> None:
        for url in ("https://hub.docker.com/r/example/demo", "https://ghcr.io/example/demo",
                    "https://github.com/example/demo/pkgs/container/demo"):
            with self.subTest(url=url):
                errors, _ = self.links(f"links:\n  website: {url}\n  source: https://github.com/example/demo\n")
                self.assertError(errors, "registry or package page")

    def test_craft_source_matches_the_downloaded_repo(self) -> None:
        self.run_template(env="      CRAFT_REPO: storytold/democraft\n")
        t = v.Template("demo")
        r = v.Report()
        v.check_manifest_schema(t, self.validator, r)
        v.check_links(t, r)
        self.assertError(r.errors, "links.source must be https://github.com/storytold/democraft")
        self.rewrite_manifest("https://github.com/example/demo", "https://github.com/storytold/democraft")
        t = v.Template("demo")
        r = v.Report()
        v.check_manifest_schema(t, self.validator, r)
        v.check_links(t, r)
        self.assertClean(r.errors)


class TestImmutableHosts(Case):
    def test_immutable_host_router_is_accepted(self) -> None:
        self.run_template()
        self.rewrite_manifest("urls:", "hosts:\n  immutable: [demo]\nurls:")
        self.assertClean(self.recheck())

    def test_immutable_must_name_a_host_router(self) -> None:
        self.run_template()
        self.rewrite_manifest("urls:", "hosts:\n  immutable: [other]\nurls:")
        self.assertError(self.recheck(), "hosts.immutable: other is not a host router")

    def test_immutable_list_is_schema_checked(self) -> None:
        self.run_template()
        self.rewrite_manifest("urls:", "hosts:\n  immutable: []\nurls:")
        self.assertError(self.recheck(), "hosts")

    def test_required_immutable_host(self) -> None:
        with mock.patch.dict(v.IMMUTABLE_HOSTS, {"demo": {"demo": "baked into the data"}}):
            errors, _ = self.run_template()
        self.assertError(errors, "hosts.immutable must list demo")



class TestCoreNamesComplete(unittest.TestCase):
    """CORE_SERVICES / CORE_VOLUMES / CORE_NETWORKS / CORE_ALIASES /
    CORE_TRAEFIK_NAMES list every name of core's docker-compose.yml (the
    Hub's TestCoreNamesComplete / TestCoreTraefikNamesComplete; a sibling
    core checkout or PORTCULLIS_CORE_DIR, skipped without one)."""

    def test_core_names(self) -> None:
        core = os.environ.get("PORTCULLIS_CORE_DIR") or os.path.join(os.path.dirname(v.ROOT), "portcullis")
        path = os.path.join(core, "docker-compose.yml")
        if not os.path.isfile(path):
            self.skipTest(f"no core checkout at {core}")
        with open(path, encoding="utf-8") as f:
            doc = v.yaml.safe_load(f)
        for name, svc in (doc.get("services") or {}).items():
            self.assertIn(name, v.CORE_SERVICES)
            labels = v.labels_of(svc or {})
            for k in labels:
                m = v.re.match(r"^traefik\.http\.(routers|middlewares|services)\.([^.]+)\.", k)
                if m:
                    self.assertIn(m.group(2), v.CORE_TRAEFIK_NAMES[m.group(1)], f"core {name}: {k}")
            nets = (svc or {}).get("networks")
            for cfg in (nets.values() if isinstance(nets, dict) else []):
                for a in ((cfg or {}).get("aliases") or []):
                    self.assertTrue(v.reserved_dns_name(a), f"core {name}: alias {a}")
        for k in doc.get("volumes") or {}:
            self.assertIn(k, v.CORE_VOLUMES)
        for k in doc.get("networks") or {}:
            if k != "portcullis-proxy":
                self.assertIn(k, v.CORE_NETWORKS)
        # The @file middlewares a template may name: exactly core's.
        mw = os.path.join(core, "traefik", "dynamic", "middlewares.yml")
        if os.path.isfile(mw):
            with open(mw, encoding="utf-8") as f:
                self.assertEqual(set(v.yaml.safe_load(f)["http"]["middlewares"]), v.FILE_MIDDLEWARES)

    def test_strip_client_forwarded_file_middleware(self) -> None:
        self.assertIn("strip-client-forwarded", v.FILE_MIDDLEWARES)


class TestHubRules(Case):
    def test_strip_client_forwarded_allowed(self) -> None:
        """Core's strip-client-forwarded@file may be named like the other
        core @file middlewares; an unknown @file one stays refused."""
        errors, _ = self.run_template()
        self.assertClean(errors)
        self.rewrite_compose("security-headers@file", "strip-client-forwarded@file,security-headers@file")
        self.assertClean(self.recheck())
        self.rewrite_compose("strip-client-forwarded@file", "strip-client-forwarded-x@file")
        self.assertError(self.recheck(), "strip-client-forwarded-x@file")

    """The Hub's discovery refusals (templates/coreref.go), mirrored statically."""

    LABELS = '      traefik.http.services.demo.loadbalancer.server.port: "80"\n'

    def label_case(self, extra: str) -> List[str]:
        self.run_template()
        self.rewrite_compose(self.LABELS, self.LABELS + extra)
        return self.recheck()

    def test_clean_template_passes(self) -> None:
        errors, _ = self.run_template()
        self.assertClean(errors)

    def test_refusals(self) -> None:
        cases = {
            "traefik.tcp.routers.x.rule: HostSNI(`*`)\n": "no TCP/UDP",
            "traefik.http.middlewares.fa.forwardauth.address: http://hub:8888\n": "middleware type 'forwardauth'",
            "traefik.http.services.demo.loadbalancer.server.url: http://hub:8888\n": "unsupported service attribute",
            "traefik.http.routers.demo.tls.certresolver: le\n": "unsupported router attribute",
            "traefik.http.routers.x.service: hub@docker\n": "router service 'hub@docker'",
            "traefik.http.routers.x.middlewares: hub-proxy-secret@docker\n": "middleware 'hub-proxy-secret@docker'",
            "traefik.http.routers.x.middlewares: my@file\n": "middleware 'my@file'",
            "traefik.http.routers.Demo2.rule: Host(`x`)\n": "must be lowercase",
            "traefik.http.routers.x.service: Demo\n": "must be lowercase",
            "traefik.http.routerſ.x.rule: Host(`x`)\n": "non-ASCII",
            "traefik.http.routers.hub.entrypoints: websecure\n": "router 'hub' is core's",
            "traefik.http.middlewares.h.headers.customrequestheaders.X: forward-auth-ext\n": "rendered by the Hub only",
            "traefik.http.middlewares.h.headers.customrequestheaders.X: ${DEMO_SECRET:-x}\n": "must be a literal",
            "traefik.http.routers.x].rule: Host(`x`)\n": "segment",
        }
        for extra, needle in cases.items():
            with self.subTest(extra=extra):
                self.assertError(self.label_case("      " + extra), needle)

    def test_reserved_names_and_keys(self) -> None:
        for old, new, needle in (
            ("services:\n  demo:", "services:\n  keycloak:", "DNS name 'keycloak' is core's"),
            ("services:\n  demo:", "services:\n  grafana:", "DNS name 'grafana' is core's"),
            ("    networks:\n      - default", "    hostname: lldap.local\n    networks:\n      - default", "hostname: the DNS name"),
            ("    networks:\n      - default", "    label_file: ./l\n    networks:\n      - default", "compose key 'label_file'"),
            ("    networks:\n      - default", "    pid: container:x\n    networks:\n      - default", "joins another container"),
            ("volumes:\n  demo-data:", "include: [x.yml]\nvolumes:\n  demo-data:", "top-level key 'include'"),
            ("volumes:\n  demo-data: {}", "volumes:\n  demo-data: {}\n  hub_data: {}", "volumes.hub_data is core's"),
        ):
            with self.subTest(new=new):
                self.run_template()
                self.rewrite_compose(old, new)
                self.assertError(self.recheck(), needle)

    def test_single_document_and_tags(self) -> None:
        self.run_template()
        self.rewrite_compose("    labels:\n", "    labels: !override\n")
        self.assertError(self.recheck(), "could not determine a constructor")
        self.run_template()
        path = os.path.join(self.tmp.name, "demo", "compose.yml")
        with open(path, "a", encoding="utf-8") as f:
            f.write("---\n")
        self.assertError(self.recheck(), "expected a single document")

    def test_allowed_references(self) -> None:
        errors = self.label_case(
            "      traefik.http.middlewares.c.chain.middlewares: h,rate-limit@file\n"
            "      traefik.http.middlewares.h.headers.customrequestheaders.X-App: demo\n"
            "      traefik.http.routers.demo-api.rule: Host(`${PORTCULLIS_HOST_DEMO:-demo.portcullis.local}`) && PathPrefix(`/api`)\n"
            "      traefik.http.routers.demo-api.service: demo\n"
            "      traefik.http.routers.demo-api.middlewares: portcullis-auth@docker,portcullis-groups@docker,c@docker\n"
            "      traefik.http.middlewares.r.redirectregex.replacement: https://${PORTCULLIS_HOST_DEMO:-demo.portcullis.local}/\n"
            "      traefik.http.middlewares.r.redirectregex.regex: ^/$$\n")
        self.assertEqual([e for e in errors if "Hub refuses" in e], [], "\n".join(errors))



class TestGatedHomeTemplates(unittest.TestCase):
    """The real esphome / zigbee2mqtt / motioneye / mattermost templates,
    each guard removed in turn: every removal must fail validation."""

    APPS = ("esphome", "zigbee2mqtt", "motioneye", "mattermost")
    REPO = v.ROOT   # the real repo (setUp runs again per subTest)

    def setUp(self) -> None:
        import shutil
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = self.REPO
        for app in self.APPS:
            shutil.copytree(os.path.join(self.repo, app), os.path.join(self.tmp.name, app))
        v.ROOT = self.tmp.name
        self.addCleanup(setattr, v, "ROOT", self.REPO)
        with open(v.SCHEMA_PATH, encoding="utf-8") as f:
            self.validator = v.Draft202012Validator(json.load(f))

    def edit(self, app: str, name: str, old: str, new: str = "", count: int = 1) -> None:
        path = os.path.join(self.tmp.name, app, name)
        with open(path, encoding="utf-8") as f:
            text = f.read()
        self.assertEqual(text.count(old), count, f"{app}/{name}: {old!r}")
        with open(path, "w", encoding="utf-8") as f:
            f.write(text.replace(old, new))

    def errors(self) -> List[str]:
        r = v.Report()
        templates = []
        for app in self.APPS:
            t = v.Template(app)
            v.check_manifest_schema(t, self.validator, r)
            v.check_manifest_rules(t, r)
            v.check_compose(t, r)
            templates.append(t)
        v.check_cross(templates, r)
        return r.errors

    def assertFails(self, needle: str) -> None:
        errors = self.errors()
        self.assertTrue(any(needle in e for e in errors), f"no error containing {needle!r} in:\n" + "\n".join(errors))

    def test_real_templates_are_clean(self) -> None:
        self.assertEqual(self.errors(), [])

    def test_gate_sh_lines(self) -> None:
        for line, needle in (
                ("  allow ${ip};\n", "allow ${ip};"),
                ("  deny all;\n", "deny all;"),
                ('    proxy_set_header Authorization "";\n', "proxy_set_header Authorization"),
                ('    proxy_set_header X-Forwarded-Access-Token "";\n', "X-Forwarded-Access-Token"),
                ("    proxy_set_header Cookie \\$pc_cookie;\n", "proxy_set_header Cookie"),
                ("  if (\\$pc_cookie_left) { return 400; }\n", "the 400"),
        ):
            with self.subTest(line=line.strip()):
                self.setUp()
                for app in self.APPS:   # identical copies: the per-template rule must catch it
                    self.edit(app, "gate.sh", line)
                self.assertFails(needle)

    def test_gate_sh_realip_refused(self) -> None:
        for app in self.APPS:
            self.edit(app, "gate.sh", "  deny all;\n", "  deny all;\n  set_real_ip_from 0.0.0.0/0;\n")
        self.assertFails("realip")

    def test_gate_sh_copies_identical(self) -> None:
        self.edit("motioneye", "gate.sh", "  server_tokens off;\n", "  server_tokens off;\n  # local change\n")
        self.assertFails("differs from")

    def test_gate_service_lines(self) -> None:
        for app, line, needle in (
                ("esphome", "      - ./templates/esphome/gate.sh:/portcullis/gate.sh:ro\n", "must be the gate"),
                ("zigbee2mqtt", '    entrypoint: ["/bin/sh", "/portcullis/gate.sh"]\n', "must run /portcullis/gate.sh"),
                ("motioneye", "    cap_drop: [ALL]\n", "drop all capabilities"),
        ):
            with self.subTest(app=app, line=line.strip()):
                self.setUp()
                self.edit(app, "compose.yml", line)
                self.assertFails(needle)
        self.setUp()
        # Only the gate's PORTCULLIS_TRAEFIK_IP is in the compose file.
        self.edit("esphome", "compose.yml", "      PORTCULLIS_TRAEFIK_IP: ${PORTCULLIS_TRAEFIK_IP:-172.31.250.2}\n")
        self.assertFails("PORTCULLIS_TRAEFIK_IP")

    def test_backend_isolation(self) -> None:
        self.edit("esphome", "compose.yml", "        aliases: [esphome-internal]\n",
                  "        aliases: [esphome-internal]\n      portcullis-proxy: {}\n")
        self.assertFails("default network only")
        self.setUp()
        self.edit("zigbee2mqtt", "compose.yml", "        aliases: [zigbee2mqtt-internal]\n    restart: unless-stopped\n",
                  "        aliases: [zigbee2mqtt-internal]\n    labels:\n      traefik.docker.network: x\n    restart: unless-stopped\n")
        self.assertFails("no traefik labels")

    def test_zigbee2mqtt_lines(self) -> None:
        self.edit("zigbee2mqtt", "compose.yml", '      Z2M_ONBOARD_NO_SERVER: "1"\n')
        self.assertFails("Z2M_ONBOARD_NO_SERVER")
        self.setUp()
        self.edit("zigbee2mqtt", "compose.yml", '      Z2M_ONBOARD_NO_SERVER: "1"\n',
                  '      Z2M_ONBOARD_NO_SERVER: "1"\n      ZIGBEE2MQTT_CONFIG_FRONTEND_HOST: 0.0.0.0\n')
        self.assertFails("ZIGBEE2MQTT_CONFIG_FRONTEND_HOST")

    def test_mosquitto_lines(self) -> None:
        for name, line, needle in (
                ("compose.yml", "      mosquitto-init:\n        condition: service_completed_successfully\n", "mosquitto-init"),
                ("compose.yml", "      - ./templates/zigbee2mqtt/mosquitto.conf:/mosquitto/config/mosquitto.conf:ro\n",
                 "mount the template's mosquitto.conf"),
                ("mosquitto.conf", "allow_anonymous false\n", "allow_anonymous false"),
                ("mosquitto.conf", "plugin_opt_password_file /mosquitto/auth/passwd\n", "password file"),
        ):
            with self.subTest(name=name, line=line.strip()):
                self.setUp()
                self.edit("zigbee2mqtt", name, line)
                self.assertFails(needle)
        self.setUp()
        self.edit("zigbee2mqtt", "mosquitto.conf", "allow_anonymous false\n", "allow_anonymous false\nallow_anonymous true\n")
        self.assertFails("allow_anonymous false")

    def test_motioneye_lines(self) -> None:
        for line, needle in (
                ("        condition: service_healthy\n", "service_healthy"),
                ('      test: ["CMD", "sh", "/portcullis/healthcheck.sh"]\n', "needs its healthcheck"),
                ("      motioneye-init:\n        condition: service_completed_successfully\n", "motioneye-init"),
                ("    healthcheck:\n      test:\n        - CMD-SHELL\n", "the gate needs its healthcheck"),
        ):
            with self.subTest(line=line.strip()):
                self.setUp()
                self.edit("motioneye", "compose.yml", line,
                          "    x-removed:\n      test:\n        - CMD-SHELL\n" if "CMD-SHELL" in line else "")
                self.assertFails(needle)
        self.setUp()
        self.edit("motioneye", "compose.yml", "motioneye-init", "motioneye-setup", count=3)
        self.assertFails("motioneye-init")

    def test_mattermost_is_gated(self) -> None:
        # Mattermost trusts X-Real-Ip: back on portcullis-proxy (any
        # neighbour could skip forward-auth and forge its client address),
        # routed itself, or without the gate's mount, it must fail.
        mm = "        aliases: [mattermost-internal]\n"
        for new, needle in (
                (mm + "      portcullis-proxy: {}\n", "default network only"),
                (mm + "    labels:\n      traefik.enable: \"false\"\n", "no traefik labels"),
        ):
            with self.subTest(needle=needle):
                self.setUp()
                self.edit("mattermost", "compose.yml", mm, new)
                self.assertFails(needle)
        for line, needle in (
                ("      - ./templates/mattermost/gate.sh:/portcullis/gate.sh:ro\n", "must be the gate"),
                ("    cap_drop: [ALL]\n    cap_add: [CHOWN, SETGID, SETUID]\n", "drop all capabilities"),
                ("      PORTCULLIS_TRAEFIK_IP: ${PORTCULLIS_TRAEFIK_IP:-172.31.250.2}\n", "PORTCULLIS_TRAEFIK_IP"),
        ):
            with self.subTest(line=line.strip()):
                self.setUp()
                self.edit("mattermost", "compose.yml", line)
                self.assertFails(needle)
        self.setUp()
        # Sharing the gate's network namespace would put it on portcullis-proxy.
        self.edit("mattermost", "compose.yml", "    # The image's HEALTHCHECK (/api/v4/system/ping) applies.\n",
                  "    network_mode: service:mattermost-gate\n")
        self.assertFails("must not set network_mode")
        self.setUp()
        os.remove(os.path.join(self.tmp.name, "mattermost", "gate.sh"))
        self.assertFails("mattermost/gate.sh is missing")
        for image in ("mattermost/mattermost-team-edition:12.0.1", "docker.io/mattermost/mattermost-enterprise-edition:12.0.1",
                      "mirror.example.org/hub/mattermost/mattermost-team-edition:12.0.1"):
            self.assertTrue(any(v.repo_is(image, repo) for repo in v.GATED_BACKENDS), image)

    def test_gate_upstream_names(self) -> None:
        # Another template's container answering to a gate's upstream name on
        # portcullis-proxy would receive that gate's traffic (Docker DNS).
        z2m_gate = "    networks:\n      - default\n      - portcullis-proxy\n    labels:\n"
        self.edit("zigbee2mqtt", "compose.yml", z2m_gate,
                  "    networks:\n      default: {}\n      portcullis-proxy:\n        aliases: [mattermost-internal]\n    labels:\n")
        self.assertFails("ends in -internal but is on network 'portcullis-proxy'")
        self.assertFails("is mattermost's gate upstream (here on network 'portcullis-proxy')")
        for key in ("hostname", "container_name"):
            with self.subTest(key=key):
                self.setUp()
                self.edit("zigbee2mqtt", "compose.yml", z2m_gate, f"    {key}: esphome-internal\n" + z2m_gate)
                self.assertFails("is esphome's gate upstream")
        self.setUp()
        self.edit("zigbee2mqtt", "compose.yml", z2m_gate,
                  "    networks:\n      default: {}\n      portcullis-proxy:\n        aliases: [anything-internal]\n    labels:\n")
        self.assertFails("'anything-internal' ends in -internal")
        for old, new, needle in (
                ("GATE_UPSTREAM: http://mattermost-internal:8065", "GATE_UPSTREAM: http://mattermost:8065",
                 "must name a <app>-internal alias"),
                ("GATE_UPSTREAM: http://mattermost-internal:8065", "GATE_UPSTREAM: http://other-internal:8065",
                 "must be a default-network alias of the gated backend"),
                ("    shm_size: 128mb\n", "    shm_size: 128mb\n    networks:\n      default:\n        aliases: [mattermost-internal]\n",
                 "is also services.mattermost-db on 'default'"),
        ):
            with self.subTest(needle=needle):
                self.setUp()
                self.edit("mattermost", "compose.yml", old, new)
                self.assertFails(needle)

    def test_shared_default_network_is_not_private(self) -> None:
        # networks.default renamed / external = a shared network: refused, and
        # its -internal names count as being on a shared network.
        for spec in ("    name: portcullis-proxy\n    external: true\n", "    name: portcullis_esphome_default\n",
                     "    external: true\n"):
            with self.subTest(spec=spec.strip()):
                self.setUp()
                self.edit("mattermost", "compose.yml", "networks:\n  portcullis-proxy:\n",
                          "networks:\n  default:\n" + spec + "  portcullis-proxy:\n")
                self.assertFails("networks.default must stay the project's own network")
                self.assertFails("needs the project's own default network")
                self.assertFails("'mattermost-internal' ends in -internal but is on network 'default'")
                self.assertFails("must be a default-network alias of the gated backend")

    def test_network_mode_names_a_network(self) -> None:
        # network_mode <network> joins that network: refused, and its names
        # are checked like any other network's.
        self.edit("zigbee2mqtt", "compose.yml", "services:\n",
                  "services:\n  sneaky:\n    image: nginx:1.31.8-alpine@sha256:" + "0" * 64 + "\n"
                  "    hostname: esphome-internal\n    network_mode: portcullis-proxy\n    restart: unless-stopped\n")
        self.assertFails("network_mode 'portcullis-proxy': only none, host or service:")
        self.assertFails("'esphome-internal' ends in -internal but is on network 'portcullis-proxy'")
        self.assertFails("is esphome's gate upstream (here on network 'portcullis-proxy')")
        self.setUp()
        self.edit("zigbee2mqtt", "compose.yml", "services:\n",
                  "services:\n  quiet:\n    image: nginx:1.31.8-alpine@sha256:" + "0" * 64 + "\n"
                  "    hostname: esphome-internal\n    network_mode: none\n    restart: unless-stopped\n")
        self.assertFalse([e for e in self.errors() if "-internal" in e or "network_mode" in e])

    def test_homeassistant_acl_is_an_allowlist(self) -> None:
        for extra, needle in (("topic deny zigbee2mqtt/bridge/request/options\n", "not deny lines"),
                              ("topic readwrite zigbee2mqtt/#\n", "not in the reviewed"),
                              ("topic zigbee2mqtt/#\n", "not in the reviewed"),
                              ("topic write homeassistant/#\n", "not in the reviewed"),
                              ("topic read zigbee2mqtt/+/+/+\n", "not in the reviewed"),
                              ("topic write zigbee2mqtt/bridge/request/options\n", "only to request/permit_join"),
                              ("topic write zigbee2mqtt/bridge/request/Permit_Join\n", "only to request/permit_join"),
                              ("topic readwrite zigbee2mqtt/bridge/request/permit_join/x\n", "only to request/permit_join"),
                              ("topic read zigbee2mqtt/bridge/+\n", "no wildcard at or after the bridge level"),
                              ("topic read zigbee2mqtt/bridge/response/#\n", "no wildcard at or after the bridge level")):
            with self.subTest(extra=extra.strip()):
                self.setUp()
                self.edit("zigbee2mqtt", "acl", "user homeassistant\n", "user homeassistant\n" + extra)
                self.assertFails(needle)
        self.setUp()
        self.edit("zigbee2mqtt", "acl", "user homeassistant\n", "pattern readwrite %u/#\nuser homeassistant\n")
        self.assertFails("pattern lines")
        self.setUp()
        self.edit("zigbee2mqtt", "acl", "user zigbee2mqtt\n", "topic readwrite #\nuser zigbee2mqtt\n")
        self.assertFails("before any user")
        self.setUp()
        for x in v.HA_ACL_BRIDGE_DENY:
            with self.subTest(deny=x):
                self.setUp()
                self.edit("zigbee2mqtt", "acl", f"topic deny zigbee2mqtt/bridge/{x}\n", "")
                self.assertFails(f"needs topic deny zigbee2mqtt/bridge/{x}")

    def test_gate_caps_are_a_subset(self) -> None:
        self.edit("esphome", "compose.yml", "    cap_add: [CHOWN, SETGID, SETUID]\n", "    cap_add: [CHOWN, SETGID, SETUID, DAC_OVERRIDE]\n")
        self.assertFails("add back only CHOWN, SETGID, SETUID")

    def test_backends_matched_behind_a_mirror(self) -> None:
        self.assertEqual(v.image_repo("ghcr.io/esphome/esphome:2026.10.1@sha256:" + "0" * 64), "esphome/esphome")
        self.assertTrue(v.repo_is("mirror.example.org:5000/proxy/koenkk/zigbee2mqtt:2.14.3", "koenkk/zigbee2mqtt"))
        self.assertTrue(v.repo_is("docker.io/library/eclipse-mosquitto:2.1.2-alpine", "eclipse-mosquitto"))
        self.assertFalse(v.repo_is("ghcr.io/esphome/esphome-other:1", "esphome/esphome"))
        self.edit("esphome", "compose.yml", "image: ghcr.io/esphome/esphome:", "image: mirror.example.org/ghcr/esphome/esphome:", count=1)
        self.edit("esphome", "compose.yml", "        aliases: [esphome-internal]\n",
                  "        aliases: [esphome-internal]\n      portcullis-proxy: {}\n")
        self.assertFails("default network only")


# ── Template contract v3 settings (contract §13) ────────────────────
#
# TestSettingsV3 mirrors the Hub's ValidateSettingsSpec tests
# (portcullis-hub internal/templates/settings_test.go) case for case, plus
# the Hub's type checks (internal/settings) and the stricter routing rules
# of ParseRoutes. The fixtures are the repo's clean header-auth / native-oidc
# templates with the Hub fixture's settings appended: "" = the whole
# template validates clean, "!" = no error names the setting (the fixture's
# other repo rules may complain), otherwise an error contains the text (and
# names "setting <key>" when key is set).

S_DIGEST = "0" * 64
S_HDR = MANIFEST.format(instances="multi", url="https://{{HOST_DEMO}}", notes="")
S_OIDC = S_HDR.replace("  method: header-auth\n", "  method: native-oidc\n").replace(
    "env:\n", "keycloak_clients:\n  - {client_id: demo, name: Demo, secret_env: DEMO_SECRET, "
              "redirect_uri: \"https://{{HOST_DEMO}}/cb\"}\nenv:\n", 1)
S_FIREFOX = ("name: Firefox Sync\ndescription: Sync\nicon: \"x\"\ncategory: productivity\ntags: [sync]\ninstances: multi\n"
             "auth:\n  method: custom\n  sso: false\n  group_access: false\n  group_admin: false\n"
             "  access_group: users_demo\n  notes: Mozilla accounts.\nai:\n  unsupported: test fixture\n")
S_FIREFOX_SETTINGS = """\
settings:
  sections: [Accounts]
  options:
    - key: mozilla_uid
      label: Mozilla account ID
      description: >
        The uid of the Mozilla account you sign in to Firefox with
        (32 lowercase hexadecimal characters). Only accounts listed here
        can sync with this server.
      type: string
      pattern: '^[0-9a-f]{32}$'
      min_len: 32
      max_len: 32
      scope: person_entered
      unique: true
      admin_override: true
      section: Accounts
      applies: restart
      delivery: [{file: {name: allowlist}}]
    - key: extra_accounts
      label: Other allowed accounts
      type: list
      items: {type: string, pattern: '^[0-9a-f]{32}$'}
      unique: true
      scope: instance
      section: Accounts
      applies: restart
      delivery: [{file: {name: allowlist}}]
files:
  - name: allowlist
    service: init
    mount: /portcullis
    on_membership_change: restart
"""
S_FF = S_FIREFOX + S_FIREFOX_SETTINGS

S_HOST = "Host(`${PORTCULLIS_HOST_DEMO:-demo.portcullis.local}`)"
S_INIT = f"  init:\n    image: demo/init:1.0.0@sha256:{S_DIGEST}\n"


def s_env(*names: str) -> str:
    """Compose environment lines interpolating each name."""
    return "".join(f"      {n}: ${{{n}:-}}\n" for n in names)


S_HDR_ENV = s_env("TRASH_DAYS", "THEME") + "      HARD: literal\n" + s_env("DISK_1", "DISK_2")


def s_compose(env: str = "", routers: str = "", demo: str = "", services: str = S_INIT,
              labels: str = "      traefik.enable: \"true\"\n", nets: str = "    networks:\n      - default\n      - portcullis-proxy\n",
              oidc: bool = False) -> str:
    """The clean demo compose file: env lines, routers (default: the gated
    host router; ungated for native-oidc) and extra services."""
    if not routers:
        routers = router("demo", S_HOST, gated=not oidc)
    return (f"services:\n  demo:\n    image: demo/demo:1.2.3@sha256:{S_DIGEST}\n    environment:\n"
            "      DEMO_URL: https://${PORTCULLIS_HOST_DEMO:-demo.portcullis.local}\n"
            "      TRUSTED_PROXY: ${PORTCULLIS_TRAEFIK_IP:-172.31.250.2}\n"
            "      DEMO_SECRET: ${DEMO_SECRET:?DEMO_SECRET must be set}\n"
            f"{env}    volumes:\n      - demo-data:/data\n{nets}{demo}    labels:\n{labels}{routers}"
            "      traefik.http.services.demo.loadbalancer.server.port: \"80\"\n"
            f"{services}\nvolumes:\n  demo-data: {{}}\n\nnetworks:\n  portcullis-proxy:\n    external: true\n")


def s_opts(*lines: str) -> str:
    return "settings:\n  options:\n    - " + "\n    - ".join(lines) + "\n"


S_PERSON_CLAIM = "delivery: [{claim: {client: demo, name: demo_quota, json_type: int}}]"
S_PERSON_HEADER = "{key: quota, label: Q, type: int, scope: person, resolve: priority, default: 1, delivery: [{header: {name: X-Forwarded-Attr-Quota}}]}"
HOOK_APPLY = "hooks:\n  - {name: apply, service: demo, command: [x], when: [start]}\n"
S_FILES = """\
files:
  - {name: people, service: init, mount: /portcullis, on_membership_change: restart}
hooks:
  - {name: apply, service: demo, command: [php, /portcullis/apply.php], when: [start, settings_change], timeout: 60s}
"""
S_ROLE = ("{key: role, label: Role, type: enum, options: [{value: user, label: User}, {value: admin, label: Administrator}], "
          "scope: person, privileged: true, resolve: max, delivery: [{claim: {client: demo, name: demo_role, json_type: string}}], ")


class TestSettingsV3(Case):

    def test_final_review_rules(self) -> None:
        """Hub templates.TestFinalReviewValidatorRules (H1-H6): the validator
        refuses what the runtime could never deliver."""
        h, o = s_compose(S_HDR_ENV), s_compose(oidc=True)

        def hdr(line: str) -> str:
            return S_HDR + s_opts(line)

        def oidc(line: str) -> str:
            return S_OIDC + s_opts(line)
        ff = S_FIREFOX + S_FIREFOX_SETTINGS.replace(
            "delivery: [{file: {name: allowlist}}]\n    - key: extra",
            "delivery: [{file: {name: allowlist, render: {format: yaml}}}]\n    - key: extra", 1)
        people = "files:\n  - {name: people, service: init, mount: /portcullis}\n"
        self.cases([
            # H1: scope person needs resolve.
            ("person without resolve", oidc("{key: quota, label: Q, type: int, scope: person, default: 1, " + S_PERSON_CLAIM + "}"), o, "quota", "scope person needs resolve"),
            # H2: a secret is instance scope only.
            ("group secret", hdr("{key: theme, label: T, type: secret, scope: group, delivery: [{env: THEME, render: {format: json}}]}"), h, "theme", "a secret option needs scope instance"),
            ("person secret", oidc("{key: quota, label: Q, type: secret, scope: person, resolve: priority, " + S_PERSON_CLAIM + "}"), o, "quota", "a secret option needs scope instance"),
            # H3: the default and group_values render through every delivery.
            ("env default with a quote", hdr("{key: theme, label: T, type: string, default: \"it's\"}"), h, "theme", "default"),
            ("env default with a backslash", hdr("{key: theme, label: T, type: string, default: 'a\\b', delivery: [{env: THEME}]}"), h, "theme", "single quote, a backslash"),
            ("size default not whole", hdr("{key: theme, label: T, type: size, default: 1536, delivery: [{env: THEME, render: {unit: KiB, integer: true}}]}"), h, "theme", "whole number"),
            ("list default item with the separator", hdr("{key: theme, label: T, type: list, items: {type: string}, default: ['a,b']}"), h, "theme", "separator"),
            ("group_values not renderable", oidc("{key: quota, label: Q, type: size, scope: person, default: 1GiB, resolve: max, group_values: {'{{ADMIN_GROUP}}': 1536}, delivery: [{claim: {client: demo, name: demo_quota, json_type: int, render: {unit: KiB, integer: true}}}]}"), o, "quota", "group_values"),
            ("env render true with a quote", hdr("{key: theme, label: T, type: bool, default: false, delivery: [{env: THEME, render: {true: \"it's\"}}]}"), h, "theme", "an env value is single-quoted"),
            ("env render join with a backslash", hdr("{key: theme, label: T, type: list, items: {type: string}, delivery: [{env: THEME, render: {join: '\\'}}]}"), h, "theme", "an env value is single-quoted"),
            ("header render true with a quote", hdr("{key: quota, label: Q, type: bool, scope: person, default: false, resolve: any, applies: next_request, delivery: [{header: {name: X-Forwarded-Attr-Quota, render: {true: \"it's\"}}}]}"), s_compose(), "", ""),
            ("env yaml", hdr("{key: theme, label: T, type: list, items: {type: string}, delivery: [{env: THEME, render: {format: yaml}}]}"), h, "theme", "format yaml is multi-line"),
            ("env csv table", hdr("{key: theme, label: T, type: table, columns: [{name: a, label: A, type: string}], delivery: [{env: THEME, render: {format: csv}}]}"), h, "theme", "format csv is multi-line"),
            ("header yaml", hdr("{key: quota, label: Q, type: list, items: {type: string}, scope: person, default: [], resolve: union, applies: next_request, delivery: [{header: {name: X-Forwarded-Attr-Quota, render: {format: yaml}}}]}"), h, "quota", "format yaml is multi-line"),
            ("file yaml list", hdr("{key: quota, label: Q, type: list, items: {type: string}, scope: person, default: [], resolve: union, delivery: [{file: {name: people, render: {format: yaml}}}]}") + people, s_compose(), "", ""),
            ("person_entered scalar file yaml", ff, s_compose(routers=router("demo", S_HOST, gated=False)), "mozilla_uid", "format yaml"),
            # H4: JSON renders don't escape & < >.
            ("json env with an ampersand", hdr("{key: theme, label: T, type: list, items: {type: string}, default: ['https://x/?a=1&b=2'], delivery: [{env: THEME, render: {format: json}}]}"), s_compose(s_env("THEME")), "", ""),
            ("json env with a double quote", hdr("{key: theme, label: T, type: list, items: {type: string}, default: ['say \"hi\"'], delivery: [{env: THEME, render: {format: json}}]}"), h, "theme", "JSON escapes"),
            # H5: unlimited's sentinel out of the values' reach.
            ("unlimited sentinel reachable", oidc("{key: quota, label: Q, type: size, allow_unlimited: true, scope: person, default: 1GiB, resolve: min, delivery: [{claim: {client: demo, name: demo_quota, json_type: int, render: {unit: GiB, unlimited: '0'}}}]}"), o, "quota", "allow_unlimited: claim demo_quota renders unlimited as 0"),
            ("unlimited sentinel above max", oidc("{key: quota, label: Q, type: size, allow_unlimited: true, max: 10GiB, scope: person, default: 1GiB, resolve: min, delivery: [{claim: {client: demo, name: demo_quota, json_type: int, render: {unit: GiB, unlimited: '100'}}}]}"), o, "", ""),
            ("unlimited sentinel below min", oidc("{key: quota, label: Q, type: size, allow_unlimited: true, min: 1GiB, scope: person, default: 1GiB, resolve: min, delivery: [{claim: {client: demo, name: demo_quota, json_type: int, render: {unit: GiB, unlimited: '0'}}}]}"), o, "", ""),
            ("unlimited sentinel not a number", oidc("{key: quota, label: Q, type: size, allow_unlimited: true, scope: person, default: 1GiB, resolve: min, delivery: [{claim: {client: demo, name: demo_quota, json_type: string, render: {unit: GiB, unlimited: none}}}]}"), o, "", ""),
            # H6.
            ("required person empty default", oidc("{key: quota, label: Q, type: string, scope: person, required: true, default: '', resolve: priority, delivery: [{claim: {client: demo, name: demo_quota, json_type: string}}]}"), o, "quota", "required on scope person needs a non-empty default"),
            ("required person default", oidc("{key: quota, label: Q, type: string, scope: person, required: true, default: a, resolve: priority, delivery: [{claim: {client: demo, name: demo_quota, json_type: string}}]}"), o, "", ""),
            ("required person bool false", oidc("{key: quota, label: Q, type: bool, scope: person, required: true, default: false, resolve: any, delivery: [{claim: {client: demo, name: demo_quota, json_type: bool}}]}"), o, "", ""),
            ("required group", hdr("{key: theme, label: T, type: string, scope: group, required: true, delivery: [{env: THEME, render: {format: json}}]}"), h, "theme", "required is not for scope group"),
            ("generate above max_len", hdr("{key: theme, label: T, type: secret, max_len: 32, generate: {length: 64, charset: hex}}"), h, "theme", "generate.length 64 is above max_len 32"),
            ("generate below min_len", hdr("{key: theme, label: T, type: secret, min_len: 40, generate: {length: 32, charset: hex}}"), h, "theme", "generate.length 32 is below min_len 40"),
            ("label of 64 runes", hdr("{key: theme, label: " + "é" * 64 + ", type: string}"), s_compose(s_env("THEME")), "", ""),
            ("label of 65 runes", hdr("{key: theme, label: " + "é" * 65 + ", type: string}"), h, "theme", "at most 64 characters"),
            ("choice label of 65 runes", hdr("{key: theme, label: T, type: enum, options: [{value: a, label: " + "é" * 65 + "}], default: a}"), h, "theme", "at most 64 characters"),
            ("indexed item with a quote", hdr("{key: theme, label: T, type: list, items: {type: string}, max_items: 2, default: [\"it's\"], delivery: [{env: 'DISK_{n}'}]}"), h, "theme", "item 1: the value contains a single quote"),
        ])

    def test_render_matches_go(self) -> None:
        """settings.TestJSONRenderNoHTMLEscape: JSON text as the Hub's JSONText writes it."""
        o = {"type": "list", "items": {"type": "string"}}
        self.assertEqual(v.render_value(o, ["https://x/?a=1&b=<2>"], {"format": "json"}).text, '["https://x/?a=1&b=<2>"]')
        self.assertEqual(v.render_value({"type": "string"}, "R&D", {"format": "json"}).text, '"R&D"')
        tb = {"type": "table", "columns": [{"name": "a", "label": "A", "type": "string"}]}
        self.assertEqual(v.render_value(tb, [{"a": "x&y"}], {}).text, '[{"a":"x&y"}]')
        self.assertIn("JSON escapes", v.env_text_problem('["a\\"b"]', True))

    """tests/validate.py check_settings mirrors the Hub's discover-time
    settings refusals (ValidateSettingsSpec + settings.Registry.CheckOption)."""

    def run_raw(self, manifest: str, compose: str, app_id: str = "demo") -> Tuple[List[str], List[str]]:
        d = os.path.join(self.tmp.name, app_id)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "manifest.yaml"), "w", encoding="utf-8") as f:
            f.write(manifest)
        with open(os.path.join(d, "compose.yml"), "w", encoding="utf-8") as f:
            f.write(compose)
        os.makedirs(os.path.join(self.tmp.name, "tests", "apps"), exist_ok=True)
        open(os.path.join(self.tmp.name, "tests", "apps", app_id + ".sh"), "w").close()
        t = v.Template(app_id)
        r = v.Report()
        if v.check_layout(t, r):
            v.check_manifest_schema(t, self.validator, r)
            if t.manifest is not None:
                v.check_manifest_rules(t, r)
                v.check_compose(t, r)
        return r.errors, r.warnings

    def cases(self, cases: List[Tuple[str, str, str, str, str]]) -> None:
        for name, manifest, compose, key, want in cases:
            with self.subTest(name):
                errors, _ = self.run_raw(manifest, compose)
                if want == "":
                    self.assertClean(errors)
                elif want == "!":
                    self.assertFalse([e for e in errors if f"setting {key}:" in e], "\n".join(errors))
                else:
                    hit = [e for e in errors if want in e and (not key or f"setting {key}:" in e)]
                    self.assertTrue(hit, f"no error containing {want!r}" + (f" naming setting {key}" if key else "")
                                    + " in:\n" + "\n".join(errors))

    # ── Hub TestOptionKeyRule … TestPersonEnteredRules, case for case ──

    def test_option_key_rule(self) -> None:
        c = s_compose(S_HDR_ENV)
        self.cases([
            ("upper", S_HDR + s_opts("{key: IMMICH_X, label: X, type: string}"), c, "IMMICH_X", "must match"),
            ("digit", S_HDR + s_opts("{key: 1a, label: X, type: string}"), c, "1a", "must match"),
            ("long", S_HDR + s_opts("{key: " + "a" * 41 + ", label: X, type: string}"), c, "", "must match"),
            ("duplicate", S_HDR + s_opts("{key: trash_days, label: X, type: int}", "{key: trash_days, label: Y, type: int, delivery: [{env: THEME}]}"), c, "trash_days", "declared twice"),
            ("no label", S_HDR + s_opts("{key: trash_days, type: int}"), c, "trash_days", "label"),
            ("unknown field", S_HDR + s_opts("{key: trash_days, label: X, type: int, priviledged: true}"), c, "", "priviledged"),
            ("unknown section", S_HDR + s_opts("{key: trash_days, label: X, type: int, section: Nope}"), c, "trash_days", "section"),
            ("unknown settings key", S_HDR + "settings:\n  option: []\n", c, "", "option"),
            ("ok", S_HDR + s_opts("{key: trash_days, label: Keep deleted items for, type: int, unit: days, min: 0, max: 3650, default: 30}"),
             s_compose(s_env("TRASH_DAYS")), "", ""),
        ])

    def test_old_types_refused(self) -> None:
        c = s_compose(S_HDR_ENV)
        cases = [(old, S_HDR + s_opts(f"{{key: theme, label: X, type: {old}}}"), c, "theme", "use " + repl)
                 for old, repl in {"text": "string", "boolean": "bool", "select": "enum", "paths": "path"}.items()]
        cases += [
            ("v2 list", S_HDR + "settings:\n  - key: THEME\n    type: text\n", c, "", "contract v3"),
            ("unknown type", S_HDR + s_opts("{key: theme, label: X, type: colour}"), c, "theme", "unknown type"),
        ]
        self.cases(cases)

    def test_reserved_types_refused(self) -> None:
        c = s_compose(S_HDR_ENV)
        self.cases([
            ("folder", S_HDR + s_opts("{key: media, label: X, type: folder}"), c, "media",
             "type folder is reserved: a shared folder is a type: path option with a folder block (§13.15)"),
            # File sharing landed: person_secret / person_id are typed
            # (TestFileSharing); on a routed template they are refused.
            ("person_secret", S_HDR + s_opts("{key: smb, label: X, type: person_secret}"), c, "smb", "router-less"),
            ("person_id", S_HDR + s_opts("{key: uid, label: X, type: person_id}"), c, "uid", "router-less"),
            ("folder block", S_HDR + s_opts("{key: media, label: X, type: path, target: {service: demo, mount: /media}, folder: {access: read, runs_as: {uid: 0, gid: 0}}}"), c, "media", "!"),
            ("checks", S_HDR + s_opts("{key: media, label: X, type: path, target: {service: demo, mount: /media}, folder: {access: write, runs_as: {uid: 0, gid: 0}}, checks: [{kind: exclusive, reason: one writer}]}"), c, "media", "!"),
            ("uid_from", S_HDR + s_opts("{key: media, label: X, type: path, target: {service: demo, mount: /media}, folder: {access: write, runs_as: {uid_from: person_uid, gid: 0}}}"), c, "media", "uid_from person_uid is not a person_id option"),
            ("hash", S_HDR + s_opts("{key: theme, label: X, type: string, hash: nt}"), c, "theme", "hash is for person_secret options"),
            ("length", S_HDR + s_opts("{key: theme, label: X, type: string, length: 8}"), c, "theme", "length is for person_secret options"),
            ("revoke_on_leave", S_HDR + s_opts("{key: theme, label: X, type: string, revoke_on_leave: true}"), c, "theme", "revoke_on_leave is for person_secret options"),
            ("mount", S_HDR + s_opts("{key: theme, label: X, type: string, mount: {service: demo, path: /x}}"), c, "theme", "mount is for person_secret options"),
            ("bare delivery", S_HDR + s_opts("{key: theme, label: X, type: string, delivery: file}"), c, "theme", "delivery: file is for person_secret options"),
        ])

    def test_person_scope_needs_default_and_person_delivery(self) -> None:
        o, h = s_compose(oidc=True), s_compose(S_HDR_ENV)
        self.cases([
            ("no default", S_OIDC + s_opts("{key: quota, label: Q, type: int, scope: person, resolve: max, " + S_PERSON_CLAIM + "}"), o, "quota", "default"),
            ("env only", S_HDR + s_opts("{key: quota, label: Q, type: int, scope: person, resolve: priority, default: 1, delivery: [{env: TRASH_DAYS}]}"), h, "quota", "per-person env is not allowed"),
            ("no delivery", S_HDR + s_opts("{key: quota, label: Q, type: int, scope: person, resolve: priority, default: 1}"), h, "quota", "per-person delivery"),
            ("claim", S_OIDC + s_opts("{key: quota, label: Q, type: int, scope: person, default: 10, resolve: max, " + S_PERSON_CLAIM + "}"), o, "", ""),
            ("bad scope", S_HDR + s_opts("{key: quota, label: Q, type: int, scope: everyone}"), h, "quota", "scope"),
            ("group default", S_HDR + s_opts("{key: quota, label: Q, type: int, scope: group, default: 1, delivery: [{env: THEME, render: {format: json}}]}"), h, "quota", "default"),
            ("group env not json", S_HDR + s_opts("{key: quota, label: Q, type: int, scope: group, delivery: [{env: THEME}]}"), h, "quota", "format: json"),
            ("group env json", S_HDR + s_opts("{key: quota, label: Q, type: int, scope: group, delivery: [{env: THEME, render: {format: json}}]}"), s_compose(s_env("THEME")), "", ""),
            ("group claim", S_OIDC + s_opts("{key: quota, label: Q, type: int, scope: group, " + S_PERSON_CLAIM + "}"), o, "quota", "claim"),
            ("instance header", S_HDR + s_opts("{key: quota, label: Q, type: int, delivery: [{header: {name: X-Forwarded-Attr-Quota}}]}"), h, "quota", "header"),
            ("instance resolve", S_HDR + s_opts("{key: trash_days, label: Q, type: int, resolve: max}"), h, "trash_days", "resolve"),
            ("instance privileged", S_HDR + s_opts("{key: trash_days, label: Q, type: bool, privileged: true}"), h, "trash_days", "privileged"),
            ("instance self_visible", S_HDR + s_opts("{key: trash_days, label: Q, type: int, self_visible: false}"), h, "trash_days", "self_visible"),
            ("two kinds in one delivery", S_OIDC + s_opts("{key: quota, label: Q, type: int, scope: person, resolve: priority, default: 1, delivery: [{env: TRASH_DAYS, hook: x}]}"), s_compose(s_env("TRASH_DAYS"), oidc=True), "quota", "exactly one"),
        ])

    def test_resolve_fits_type(self) -> None:
        o = s_compose(oidc=True)
        self.cases([
            ("max on string", S_OIDC + s_opts("{key: quota, label: Q, type: string, scope: person, default: a, resolve: max, " + S_PERSON_CLAIM + "}"), o, "quota", "resolve max"),
            ("union on list", S_OIDC + s_opts("{key: langs, label: L, type: list, items: {type: string}, scope: person, default: [en], resolve: union, delivery: [{claim: {client: demo, name: demo_langs, json_type: json, render: {format: json}}}]}"), o, "", ""),
            ("any on bool", S_OIDC + s_opts("{key: beta, label: B, type: bool, scope: person, default: false, resolve: any, delivery: [{claim: {client: demo, name: demo_beta, json_type: bool}}]}"), o, "", ""),
            ("priority on string", S_OIDC + s_opts("{key: quota, label: Q, type: string, scope: person, default: a, resolve: priority, delivery: [{claim: {client: demo, name: demo_quota, json_type: string}}]}"), o, "", ""),
            ("unknown rule", S_OIDC + s_opts("{key: quota, label: Q, type: int, scope: person, default: 1, resolve: avg, " + S_PERSON_CLAIM + "}"), o, "quota", "resolve avg"),
            ("choice does not fit", S_OIDC + s_opts("{key: quota, label: Q, type: int, scope: person, default: 1, resolve: max, resolve_choices: [max, min, union], " + S_PERSON_CLAIM + "}"), o, "quota", "resolve_choices: union"),
            ("choices fit", S_OIDC + s_opts("{key: quota, label: Q, type: size, step: 1GiB, allow_unlimited: true, scope: person, default: 100GiB, resolve: max, resolve_choices: [max, min, priority], delivery: [{claim: {client: demo, name: demo_quota, json_type: int, render: {unit: GiB, unlimited: '-1'}}}]}"), o, "", ""),
        ])

    def test_env_names(self) -> None:
        h = s_compose(S_HDR_ENV)
        list_form = s_compose(services=S_INIT + "  side:\n    image: demo/side:1.0.0@sha256:" + S_DIGEST +
                              "\n    environment:\n      - THEME=dark\n      - X=${THEME}\n")
        self.cases([
            ("default env", S_HDR + s_opts("{key: trash_days, label: X, type: int}"), s_compose(s_env("TRASH_DAYS")), "", ""),
            ("reserved prefix", S_HDR + s_opts("{key: x, label: X, type: string, delivery: [{env: PORTCULLIS_X}]}"), h, "x", "reserved"),
            ("instance variable", S_HDR + s_opts("{key: x, label: X, type: string, delivery: [{env: PORTCULLIS_INSTANCE}]}"), h, "", "PORTCULLIS_INSTANCE"),
            ("bad name", S_HDR + s_opts("{key: x, label: X, type: string, delivery: [{env: A-B}]}"), h, "x", "env name"),
            ("two options", S_HDR + s_opts("{key: a, label: A, type: string, delivery: [{env: THEME}]}", "{key: b, label: B, type: string, delivery: [{env: THEME}]}"), h, "b", "THEME"),
            ("with env[]", S_HDR.replace("env:\n", "env:\n  - {key: THEME, description: t}\n", 1) + s_opts("{key: theme, label: T, type: string}"), h, "theme", "THEME"),
            ("with ports[]", S_HDR + "ports:\n  - {key: THEME, label: T, protocol: tcp, container: 80, default: 8080, service: demo}\n" + s_opts("{key: theme, label: T, type: string}"), h, "theme", "THEME"),
            ("with port bind", S_HDR + "ports:\n  - {key: TRASH, label: T, protocol: tcp, container: 80, default: 8080, service: demo}\n" + s_opts("{key: x, label: T, type: string, delivery: [{env: TRASH_BIND}]}"), h, "x", "TRASH_BIND"),
            ("with client secret_env", S_OIDC + s_opts("{key: x, label: T, type: string, delivery: [{env: DEMO_SECRET}]}"), s_compose(oidc=True), "x", "DEMO_SECRET"),
            ("not referenced", S_HDR + s_opts("{key: missing, label: M, type: string}"), h, "missing", "not referenced"),
            ("only in a comment", S_HDR + s_opts("{key: missing, label: M, type: string}"), "# uses ${MISSING}\n" + h, "missing", "not referenced"),
            ("only as a key", S_HDR + s_opts("{key: missing, label: M, type: string}"), s_compose(S_HDR_ENV + "      ${MISSING}: x\n"), "missing", "not referenced"),
            ("hard-coded", S_HDR + s_opts("{key: hard, label: H, type: string}"), h, "hard", "hard-codes"),
            ("indexed", S_HDR + s_opts("{key: disks, label: D, type: list, items: {type: string, pattern: '^/dev/.+$'}, max_items: 2, delivery: [{env: 'DISK_{n}'}]}"), s_compose(s_env("DISK_1", "DISK_2")), "", ""),
            ("indexed no max_items", S_HDR + s_opts("{key: disks, label: D, type: list, items: {type: string}, delivery: [{env: 'DISK_{n}'}]}"), h, "disks", "max_items"),
            ("indexed max_items over 64", S_HDR + s_opts("{key: disks, label: D, type: list, items: {type: string}, max_items: 65, delivery: [{env: 'DISK_{n}'}]}"), h, "disks", "max_items (1-64)"),
            ("indexed unreferenced", S_HDR + s_opts("{key: disks, label: D, type: list, items: {type: string}, max_items: 3, delivery: [{env: 'DISK_{n}'}]}"), h, "disks", "DISK_3"),
            ("indexed beyond max_items", S_HDR + s_opts("{key: disks, label: D, type: list, items: {type: string}, max_items: 1, delivery: [{env: 'DISK_{n}'}]}"), h, "disks", "DISK_2"),
            ("indexed on string", S_HDR + s_opts("{key: disks, label: D, type: string, max_items: 2, delivery: [{env: 'DISK_{n}'}]}"), h, "disks", "list"),
            ("other braces", S_HDR + s_opts("{key: disks, label: D, type: list, items: {type: string}, max_items: 2, delivery: [{env: 'DISK_{i}'}]}"), h, "disks", "NAME_{n}"),
            ("indexed dup", S_HDR + s_opts("{key: disks, label: D, type: list, items: {type: string}, max_items: 2, delivery: [{env: 'DISK_{n}'}]}", "{key: d1, label: D, type: string, delivery: [{env: DISK_1}]}"), h, "d1", "DISK_1"),
            ("list hard-coded", S_HDR + s_opts("{key: theme, label: T, type: string}"), list_form, "theme", "hard-codes"),
        ])

    def test_claim_delivery_needs_native_oidc_client(self) -> None:
        o = s_compose(oidc=True)
        cases = [
            ("forward-auth", S_HDR + s_opts("{key: quota, label: Q, type: int, scope: person, resolve: priority, default: 1, " + S_PERSON_CLAIM + "}"), s_compose(), "quota", "native-oidc"),
            ("unknown client", S_OIDC + s_opts("{key: quota, label: Q, type: int, scope: person, resolve: priority, default: 1, delivery: [{claim: {client: other, name: demo_quota, json_type: int}}]}"), o, "quota", "client other"),
            ("bad json_type", S_OIDC + s_opts("{key: quota, label: Q, type: int, scope: person, resolve: priority, default: 1, delivery: [{claim: {client: demo, name: demo_quota, json_type: float}}]}"), o, "quota", "json_type"),
            ("bad name", S_OIDC + s_opts("{key: quota, label: Q, type: int, scope: person, resolve: priority, default: 1, delivery: [{claim: {client: demo, name: Quota, json_type: int}}]}"), o, "quota", "must match"),
            ("duplicate claim", S_OIDC + s_opts("{key: quota, label: Q, type: int, scope: person, resolve: priority, default: 1, " + S_PERSON_CLAIM + "}", "{key: q2, label: Q, type: int, scope: person, resolve: priority, default: 1, " + S_PERSON_CLAIM + "}"), o, "q2", "demo_quota"),
        ]
        for n in ("sub", "email", "groups", "acr", "amr", "preferred_username", "attr_x", "portcullis_x"):
            cases.append(("claim " + n, S_OIDC + s_opts("{key: quota, label: Q, type: int, scope: person, resolve: priority, default: 1, delivery: [{claim: {client: demo, name: " + n + ", json_type: int}}]}"), o, "quota", "claim " + n))
        self.cases(cases)

    def test_header_delivery_rules(self) -> None:
        h = s_compose()
        no_groups = h.replace("portcullis-auth@docker,portcullis-groups@docker", "portcullis-auth@docker", 1)
        public = s_compose(routers=router("demo", S_HOST) + router("share", S_HOST + " && PathPrefix(`/share`)", gated=False))
        native = ("name: App\nauth:\n  method: custom\n  sso: false\n  native_login: {supported: true, allow_without_gateway: true}\n")
        side = s_compose(services=S_INIT.rstrip("\n") + "\n    labels:\n      traefik.enable: \"true\"\n" +
                         router("side", S_HOST + " && PathPrefix(`/side`)", gated=False) +
                         "      traefik.http.routers.side.service: demo\n")
        pub = router("pub", S_HOST + " && PathPrefix(`/pub`)", gated=False) + "      traefik.http.routers.pub.service: demo\n"
        elsewhere = ("services:\n  demo:\n    image: x\n    labels:\n      traefik.http.services.demo.loadbalancer.server.port: \"80\"\n" + pub +
                     "  init:\n    image: x\n    labels:\n" + router("demo", S_HOST) + "      traefik.http.routers.demo.service: demo@docker\n")
        public_access = ("  identity_headers: [X-WEBAUTH-USER]\n  public_access:\n    description: Shared dashboards\n"
                         "    paths:\n      - {prefix: /public-dashboards, description: Shared dashboards}\n")
        hdr_pa = S_HDR.replace("  notes: Demo.\n", "  notes: Demo.\n" + public_access, 1)
        q2 = S_PERSON_HEADER.replace("key: quota", "key: q2", 1)
        self.cases([
            ("ok", S_HDR + s_opts(S_PERSON_HEADER), h, "", ""),
            ("bad name", S_HDR + s_opts("{key: quota, label: Q, type: int, scope: person, resolve: priority, default: 1, delivery: [{header: {name: X-Quota}}]}"), h, "quota", "X-Forwarded-Attr-"),
            ("trailing dash", S_HDR + s_opts("{key: quota, label: Q, type: int, scope: person, resolve: priority, default: 1, delivery: [{header: {name: X-Forwarded-Attr-Quota-}}]}"), h, "quota", "X-Forwarded-Attr-"),
            ("double dash", S_HDR + s_opts("{key: quota, label: Q, type: int, scope: person, resolve: priority, default: 1, delivery: [{header: {name: X-Forwarded-Attr-A--B}}]}"), h, "quota", "X-Forwarded-Attr-"),
            ("bare prefix", S_HDR + s_opts("{key: quota, label: Q, type: int, scope: person, resolve: priority, default: 1, delivery: [{header: {name: X-Forwarded-Attr-}}]}"), h, "quota", "X-Forwarded-Attr-"),
            ("trailing newline", S_HDR + s_opts("{key: quota, label: Q, type: int, scope: person, resolve: priority, default: 1, delivery: [{header: {name: \"X-Forwarded-Attr-Quota\\n\"}}]}"), h, "quota", "X-Forwarded-Attr-"),
            ("multi-part name", S_HDR + s_opts("{key: quota, label: Q, type: int, scope: person, resolve: priority, default: 1, delivery: [{header: {name: X-Forwarded-Attr-Grafana-Role}}]}"), h, "", ""),
            ("no group-gate", S_HDR + s_opts(S_PERSON_HEADER), no_groups, "quota", "portcullis-groups"),
            ("public router", S_HDR + s_opts(S_PERSON_HEADER), public, "quota", "router share"),
            ("sign_in native", native + s_opts(S_PERSON_HEADER), h, "quota", "own login"),
            ("method public", "name: App\nauth:\n  method: public\n" + s_opts(S_PERSON_HEADER), h, "quota", "no Portcullis identity"),
            ("custom without native_login", "name: App\nauth:\n  method: custom\n  sso: false\n" + s_opts(S_PERSON_HEADER), h, "quota", "no Portcullis identity"),
            ("router elsewhere reaches the backend", S_HDR + s_opts(S_PERSON_HEADER), side, "quota", "router side reaches service demo"),
            ("gated router elsewhere, public on the backend", S_HDR + s_opts(S_PERSON_HEADER), elsewhere, "quota", "router pub reaches service demo"),
            ("gated router elsewhere, backend clean", S_HDR + s_opts(S_PERSON_HEADER), elsewhere.replace(pub, "", 1), "quota", "!"),
            ("public_access on the delivering service", hdr_pa + s_opts(S_PERSON_HEADER), h, "quota", "!"),
            ("duplicate", S_HDR + s_opts(S_PERSON_HEADER, q2), h, "q2", "X-Forwarded-Attr-Quota"),
            ("duplicate case-insensitive", S_HDR + s_opts(S_PERSON_HEADER, q2.replace("Attr-Quota", "Attr-QUOTA", 1)), h, "q2", "QUOTA"),
        ])

    def test_file_and_hook_refs(self) -> None:
        h = s_compose(S_HDR_ENV)

        def pf(o: str) -> str:
            return S_HDR + s_opts(o) + S_FILES
        self.cases([
            ("ok", pf("{key: quota, label: Q, type: int, scope: person, resolve: priority, default: 1, delivery: [{file: {name: people, field: quota}}, {hook: apply}]}"), s_compose(), "", ""),
            ("undeclared file", pf("{key: quota, label: Q, type: int, scope: person, resolve: priority, default: 1, delivery: [{file: {name: nope}}]}"), h, "quota", "file nope"),
            ("undeclared hook", pf("{key: quota, label: Q, type: int, scope: person, resolve: priority, default: 1, delivery: [{hook: nope}]}"), h, "quota", "hook nope"),
            ("field on instance", pf("{key: trash_days, label: Q, type: int, delivery: [{file: {name: people, field: x}}]}"), h, "trash_days", "field"),
            ("bad field", pf("{key: quota, label: Q, type: int, scope: person, resolve: priority, default: 1, delivery: [{file: {name: people, field: Quota}}]}"), h, "quota", "field \"Quota\""),
            ("duplicate field", S_HDR + s_opts("{key: quota, label: Q, type: int, scope: person, resolve: priority, default: 1, delivery: [{file: {name: people, field: q}}]}",
                                               "{key: q2, label: Q, type: int, scope: person, resolve: priority, default: 1, delivery: [{file: {name: people, field: q}}]}") + S_FILES, h, "q2", "already written by setting quota"),
            ("file service", S_HDR + "files:\n  - {name: people, service: nope, mount: /portcullis}\n", h, "", "files[people]: service nope"),
            ("file name", S_HDR + "files:\n  - {name: People, service: init, mount: /portcullis}\n", h, "", "People"),
            ("file mount relative", S_HDR + "files:\n  - {name: people, service: init, mount: portcullis}\n", h, "", "absolute"),
            ("file twice", S_HDR + "files:\n  - {name: people, service: init, mount: /a}\n  - {name: people, service: init, mount: /b}\n", h, "", "twice"),
            ("two files one mount", S_HDR + "files:\n  - {name: a, service: init, mount: /p}\n  - {name: b, service: init, mount: /p}\n", h, "", "/p"),
            ("nested files", S_HDR + "files:\n  - {name: a, service: init, mount: /p}\n  - {name: b, service: init, mount: /p/q}\n", h, "", "collides with files[a]"),
            ("file on_membership_change", S_HDR + "files:\n  - {name: people, service: init, mount: /p, on_membership_change: sometimes}\n", h, "", "on_membership_change"),
            ("membership hook needs a hook", S_HDR + "files:\n  - {name: people, service: init, mount: /p, on_membership_change: hook}\n", h, "", "membership_change"),
            ("mount collides with path", S_HDR + s_opts("{key: media, label: M, type: path, target: {service: init, mount: /portcullis}}") + "files:\n  - {name: people, service: init, mount: /portcullis}\n", h, "", "media"),
            ("mount inside a path", S_HDR + s_opts("{key: media, label: M, type: path, target: {service: init, mount: /data}}") + "files:\n  - {name: people, service: init, mount: /data/portcullis}\n", h, "", "media"),
            ("path on another service", S_HDR + s_opts("{key: media, label: M, type: path, target: {service: demo, mount: /portcullis}}") + "files:\n  - {name: people, service: init, mount: /portcullis}\n", s_compose(), "", ""),
            ("hook empty command", S_HDR + "hooks:\n  - {name: apply, service: demo, command: [], when: [start]}\n", h, "", "hooks[apply]: command"),
            ("hook empty arg", S_HDR + "hooks:\n  - {name: apply, service: demo, command: [php, ''], when: [start]}\n", h, "", "hooks[apply]: command"),
            ("hook control char", S_HDR + "hooks:\n  - {name: apply, service: demo, command: [\"php\\n\"], when: [start]}\n", h, "", "hooks[apply]: command"),
            ("hook name", S_HDR + "hooks:\n  - {name: Apply, service: demo, command: [x], when: [start]}\n", h, "", "hooks[Apply]: name"),
            ("hook twice", S_HDR + "hooks:\n  - {name: a, service: demo, command: [x], when: [start]}\n  - {name: a, service: demo, command: [x], when: [start]}\n", h, "", "hooks[a]: declared twice"),
            ("hook when", S_HDR + "hooks:\n  - {name: apply, service: demo, command: [x], when: [start, boot]}\n", h, "", "boot"),
            ("hook no when", S_HDR + "hooks:\n  - {name: apply, service: demo, command: [x]}\n", h, "", "when"),
            ("hook service", S_HDR + "hooks:\n  - {name: apply, service: nope, command: [x], when: [start]}\n", h, "", "service nope"),
            ("hook timeout", S_HDR + "hooks:\n  - {name: apply, service: demo, command: [x], when: [start], timeout: 11m}\n", h, "", "timeout"),
            ("hook timeout negative", S_HDR + "hooks:\n  - {name: apply, service: demo, command: [x], when: [start], timeout: -1s}\n", h, "", "timeout"),
            ("hook timeout unparsable", S_HDR + "hooks:\n  - {name: apply, service: demo, command: [x], when: [start], timeout: soon}\n", h, "", "soon"),
            ("hook timeout ok", S_HDR + "hooks:\n  - {name: apply, service: demo, command: [x], when: [start], timeout: 1m30s}\n", s_compose(), "", ""),
            ("path delivery", S_HDR + s_opts("{key: media, label: M, type: path, target: {service: demo, mount: /media}, delivery: [{env: THEME}]}"), h, "media", "target"),
            ("path no target", S_HDR + s_opts("{key: media, label: M, type: path}"), h, "media", "target"),
            ("path target service", S_HDR + s_opts("{key: media, label: M, type: path, target: {service: nope, mount: /media}}"), h, "media", "nope"),
            ("path person", S_HDR + s_opts("{key: media, label: M, type: path, scope: person, resolve: priority, default: /x, target: {service: demo, mount: /media}}"), h, "media", "instance"),
        ])

    def test_reload_rules(self) -> None:
        h = s_compose(S_HDR_ENV)
        o = s_opts("{key: theme, label: T, type: string, applies: reload}")
        ok = s_compose(s_env("THEME"))
        self.cases([
            ("applies reload", S_HDR + o, h, "theme", "reload"),
            ("on_membership_change reload", S_HDR + "files:\n  - {name: people, service: init, mount: /p, on_membership_change: reload}\n", h, "", "files[people]: on_membership_change: reload"),
            ("signal", S_HDR + o + "reload: {service: demo, signal: KILL}\n", h, "", "KILL"),
            ("signal service", S_HDR + o + "reload: {service: nope, signal: HUP}\n", h, "", "nope"),
            ("hook", S_HDR + o + "reload: {hook: nope}\n", h, "", "reload: hook nope"),
            ("both forms", S_HDR + o + S_FILES + "reload: {service: demo, signal: HUP, hook: apply}\n", h, "", "reload"),
            ("unknown key", S_HDR + o + "reload: {service: demo, signal: HUP, grace: 5s}\n", h, "", "grace"),
            ("ok signal", S_HDR + o + "reload: {service: demo, signal: HUP}\n", ok, "", ""),
            ("ok hook", S_HDR + o + S_FILES + "reload: {hook: apply}\n", ok, "", ""),
            ("applies unknown", S_HDR + s_opts("{key: theme, label: T, type: string, applies: soon}"), h, "theme", "applies"),
            ("live without hook", S_HDR + s_opts("{key: theme, label: T, type: string, applies: live}"), h, "theme", "live"),
        ])

    def test_group_values_placeholders_only(self) -> None:
        o = s_compose(oidc=True)
        self.cases([
            ("literal", S_OIDC + s_opts(S_ROLE + "default: user, group_values: {admins: admin}}"), o, "role", "admins"),
            ("admin placeholder", S_OIDC + s_opts(S_ROLE + 'default: user, group_values: {"{{ADMIN_GROUP}}": admin}}'), o, "", ""),
            ("access placeholder on a privileged option", S_OIDC + s_opts(S_ROLE + 'default: user, group_values: {"{{ACCESS_GROUP}}": admin}}'), o, "role", "privileged"),
            ("access placeholder", S_OIDC + s_opts(S_ROLE.replace("privileged: true, ", "", 1) + 'default: user, group_values: {"{{ACCESS_GROUP}}": admin}}'), o, "", ""),
            ("no admin group", S_OIDC.replace("  admin_group: admin_demo\n", "", 1) + s_opts(S_ROLE + 'default: user, group_values: {"{{ADMIN_GROUP}}": admin}}'), o, "role", "admin_group"),
            ("no access group", S_OIDC.replace("  access_group: users_demo\n", "", 1) + s_opts(S_ROLE.replace("privileged: true, ", "", 1) + 'default: user, group_values: {"{{ACCESS_GROUP}}": admin}}'), o, "role", "access_group"),
            ("value not a choice", S_OIDC + s_opts(S_ROLE + 'default: user, group_values: {"{{ADMIN_GROUP}}": owner}}'), o, "role", "group_values[{{ADMIN_GROUP}}]"),
            ("instance scope", S_HDR + s_opts('{key: theme, label: T, type: string, group_values: {"{{ADMIN_GROUP}}": x}}'), s_compose(S_HDR_ENV), "theme", "group_values"),
        ])

    def test_privileged_default_lowest(self) -> None:
        o = s_compose(oidc=True)
        self.cases([
            ("admin default", S_OIDC + s_opts(S_ROLE + "default: admin}"), o, "role", "lowest"),
            ("user default", S_OIDC + s_opts(S_ROLE + "default: user}"), o, "", ""),
            ("bool true", S_OIDC + s_opts("{key: admin, label: A, type: bool, scope: person, privileged: true, default: true, resolve: any, delivery: [{claim: {client: demo, name: demo_admin, json_type: bool}}]}"), o, "admin", "lowest"),
            ("bool false", S_OIDC + s_opts("{key: admin, label: A, type: bool, scope: person, privileged: true, default: false, resolve: any, delivery: [{claim: {client: demo, name: demo_admin, json_type: bool}}]}"), o, "", ""),
            ("privileged int", S_OIDC + s_opts("{key: quota, label: Q, type: int, scope: person, privileged: true, default: 1, resolve: max, " + S_PERSON_CLAIM + "}"), o, "quota", "privileged"),
        ])

    def test_requires(self) -> None:
        h = s_compose(S_HDR_ENV)
        self.cases([
            ("unknown", S_HDR + s_opts("{key: theme, label: T, type: string, requires: [nope]}"), h, "theme", "nope"),
            ("self", S_HDR + s_opts("{key: theme, label: T, type: string, requires: [theme]}"), h, "theme", "itself"),
            ("person target", S_HDR + s_opts("{key: theme, label: T, type: string, requires: [quota]}", S_PERSON_HEADER), h, "theme", "quota"),
            ("on a person option", S_HDR + s_opts("{key: theme, label: T, type: string}", S_PERSON_HEADER.replace("default: 1,", "default: 1, requires: [theme],")), h, "quota", "instance options"),
            ("ok", S_HDR + s_opts("{key: theme, label: T, type: string, requires: [trash_days]}", "{key: trash_days, label: D, type: int}"), s_compose(s_env("TRASH_DAYS", "THEME")), "", ""),
        ])

    def test_writes_as(self) -> None:
        path = "{key: media, label: M, type: path, target: {service: demo, mount: /media}, mode: ro, needs: read, writes_as: "
        ids = "{key: puid, label: U, type: int, delivery: [{env: TRASH_DAYS}]}"
        h = s_compose(S_HDR_ENV)
        self.cases([
            ("numbers", S_HDR + s_opts(path + "{uid: 0, gid: 0}}"), s_compose(), "", ""),
            ("keys", S_HDR + s_opts(path + "{uid: puid, gid: 100}}", ids), s_compose(s_env("TRASH_DAYS")), "", ""),
            ("string key", S_HDR + s_opts(path + "{uid: theme, gid: 0}}", "{key: theme, label: T, type: string}"), s_compose(s_env("THEME")), "", ""),
            ("unknown key", S_HDR + s_opts(path + "{uid: nope, gid: 0}}"), h, "media", "nope"),
            ("bool key", S_HDR + s_opts(path + "{uid: theme, gid: 0}}", "{key: theme, label: T, type: bool}"), h, "media", "theme"),
            ("person key", S_HDR + s_opts(path + "{uid: quota, gid: 0}}", S_PERSON_HEADER), h, "media", "quota"),
            ("negative", S_HDR + s_opts(path + "{uid: -1, gid: 0}}"), h, "media", "uid"),
            ("missing gid", S_HDR + s_opts(path + "{uid: 0}}"), h, "media", "writes_as.gid"),
            ("not a path", S_HDR + s_opts("{key: theme, label: T, type: string, writes_as: {uid: 0, gid: 0}}"), h, "theme", "writes_as"),
        ])

    def test_generate_none_refused(self) -> None:
        h = s_compose(S_HDR_ENV)

        def env_entry(e: str) -> str:
            return S_HDR.replace("env:\n", "env:\n  - " + e + "\n", 1)
        self.cases([
            ("none", env_entry("{key: THEME, description: t, generate: none}"), h, "", "declare a setting"),
            ("other", env_entry("{key: THEME, description: t, generate: always}"), h, "", "generate"),
            ("random", env_entry("{key: THEME, description: t, generate: random}"), s_compose(s_env("THEME")), "", ""),
            ("secret generate", S_HDR + s_opts("{key: theme, label: T, type: secret, generate: {length: 32, charset: alphanumeric}}"), s_compose(s_env("THEME")), "", ""),
            ("secret generate short", S_HDR + s_opts("{key: theme, label: T, type: secret, generate: {length: 4, charset: hex}}"), h, "theme", "length"),
            ("secret generate long", S_HDR + s_opts("{key: theme, label: T, type: secret, generate: {length: 129, charset: hex}}"), h, "theme", "length"),
            ("secret generate charset", S_HDR + s_opts("{key: theme, label: T, type: secret, generate: {length: 32, charset: emoji}}"), h, "theme", "charset"),
            ("generate on string", S_HDR + s_opts("{key: theme, label: T, type: string, generate: {length: 32, charset: hex}}"), h, "theme", "generate"),
        ])

    def test_person_entered_rules(self) -> None:
        ff = S_FF
        ffc = s_compose(routers=router("demo", S_HOST, gated=False))

        def uid(old: str, repl: str) -> str:
            self.assertIn(old, ff)
            return ff.replace(old, repl, 1)

        def add(field: str) -> str:
            return uid("      applies: restart\n      delivery: [{file: {name: allowlist}}]\n    - key: extra",
                       field + "\n      applies: restart\n      delivery: [{file: {name: allowlist}}]\n    - key: extra")

        def pe(o: str) -> str:
            return "{key: mozilla_uid, label: U, type: string, max_len: 32, scope: person_entered, " + o + "}"
        allow = "files:\n  - {name: allowlist, service: init, mount: /p, on_membership_change: restart}\n"
        h, hook = s_compose(S_HDR_ENV), "hooks:\n  - {name: h, service: demo, command: [x], when: [membership_change]}\n"
        self.cases([
            ("firefox sync", ff, ffc, "mozilla_uid", "!"),
            ("firefox sync, extra_accounts", ff, ffc, "extra_accounts", "!"),
            ("secret", uid("type: string\n      pattern", "type: secret\n      pattern"), ffc, "mozilla_uid", "a per-person credential is person_secret (project 3)"),
            ("list", uid("type: string\n      pattern", "type: list\n      pattern"), ffc, "mozilla_uid", "person_entered"),
            ("default", add("      default: x"), ffc, "mozilla_uid", "default"),
            ("required", add("      required: true"), ffc, "mozilla_uid", "required"),
            ("resolve", add("      resolve: priority"), ffc, "mozilla_uid", "resolve"),
            ("resolve_choices", add("      resolve_choices: [priority]"), ffc, "mozilla_uid", "resolve_choices"),
            ("group_values", add('      group_values: {"{{ACCESS_GROUP}}": x}'), ffc, "mozilla_uid", "group_values"),
            ("privileged", add("      privileged: true"), ffc, "mozilla_uid", "privileged"),
            ("requires on it", add("      requires: [extra_accounts]"), ffc, "mozilla_uid", "requires"),
            ("requires naming it", uid("      scope: instance\n", "      scope: instance\n      requires: [mozilla_uid]\n"), ffc, "extra_accounts", "mozilla_uid"),
            ("self_visible false", add("      self_visible: false"), ffc, "mozilla_uid", "self_visible"),
            ("self_visible true", add("      self_visible: true"), ffc, "mozilla_uid", "!"),
            ("account_creation", uid("      applies: restart\n      delivery: [{file: {name: allowlist}}]\n    - key: extra", "      applies: account_creation\n      delivery: [{file: {name: allowlist}}]\n    - key: extra"), ffc, "mozilla_uid", "account_creation"),
            ("unbounded string", uid("      pattern: '^[0-9a-f]{32}$'\n      min_len: 32\n      max_len: 32\n", ""), ffc, "mozilla_uid", "max_len"),
            ("max_len too big", uid("      max_len: 32\n", "      max_len: 300\n"), ffc, "mozilla_uid", "256"),
            ("format bounds", uid("      pattern: '^[0-9a-f]{32}$'\n      min_len: 32\n      max_len: 32\n", "      format: email\n"), ffc, "mozilla_uid", "!"),
            ("unique bool", S_FIREFOX + s_opts("{key: opt_in, label: O, type: bool, scope: person_entered, unique: true, applies: restart, delivery: [{file: {name: allowlist}}]}") + allow, ffc, "opt_in", "unique"),
            ("unique enum", S_FIREFOX + s_opts("{key: tier, label: O, type: enum, options: [{value: a, label: A}], scope: person_entered, unique: true, applies: restart, delivery: [{file: {name: allowlist}}]}") + allow, ffc, "tier", "unique"),
            ("unique int", S_FIREFOX + s_opts("{key: tier, label: O, type: int, scope: person_entered, unique: true, applies: restart, delivery: [{file: {name: allowlist}}]}") + allow, ffc, "tier", "!"),
            ("admin_override elsewhere", uid("      scope: instance\n", "      scope: instance\n      admin_override: true\n"), ffc, "extra_accounts", "admin_override"),
            ("no delivery", S_FIREFOX + s_opts(pe("applies: restart")), ffc, "mozilla_uid", "needs a delivery"),
            ("env without join", S_HDR + s_opts(pe("applies: restart, delivery: [{env: THEME}]")), h, "mozilla_uid", "render.join"),
            ("env joined", S_HDR + s_opts(pe("applies: restart, delivery: [{env: THEME, render: {join: ' '}}]")), s_compose(s_env("THEME")), "", ""),
            ("env json", S_HDR + s_opts(pe("applies: restart, delivery: [{env: THEME, render: {format: json}}]")), s_compose(s_env("THEME")), "", ""),
            ("env not restart", S_HDR + s_opts(pe("applies: next_request, delivery: [{env: THEME, render: {join: ' '}}]")), h, "mozilla_uid", "restart"),
            ("file applies live", uid("      applies: restart\n      delivery: [{file: {name: allowlist}}]\n    - key: extra", "      applies: live\n      delivery: [{file: {name: allowlist}}]\n    - key: extra"), ffc, "mozilla_uid", "on_membership_change"),
            ("file without on_membership_change", uid("    on_membership_change: restart\n", ""), ffc, "mozilla_uid", "no on_membership_change"),
            ("hook not live", S_HDR + s_opts(pe("applies: restart, delivery: [{hook: h}]")) + hook, h, "mozilla_uid", "live"),
            ("hook without membership_change", S_HDR + s_opts(pe("applies: live, delivery: [{hook: h}]")) + "hooks:\n  - {name: h, service: demo, command: [x], when: [start]}\n", h, "mozilla_uid", "membership_change"),
            ("file via hook live", S_HDR + s_opts(pe("applies: live, delivery: [{file: {name: people}}]")) + "files:\n  - {name: people, service: init, mount: /p, on_membership_change: hook}\n" + hook, s_compose(), "", ""),
            ("hook ok", S_HDR + s_opts(pe("applies: live, delivery: [{hook: h}]")) + hook, s_compose(), "", ""),
            ("claim not next_sign_in", S_OIDC + s_opts(pe("applies: restart, delivery: [{claim: {client: demo, name: demo_uid}}]")), s_compose(oidc=True), "mozilla_uid", "next_sign_in"),
            ("claim ok", S_OIDC + s_opts(pe("delivery: [{claim: {client: demo, name: demo_uid}}]")), s_compose(oidc=True), "", ""),
            ("header not next_request", S_HDR + s_opts(pe("applies: restart, delivery: [{header: {name: X-Forwarded-Attr-Uid}}]")), h, "mozilla_uid", "next_request"),
            ("header ok", S_HDR + s_opts(pe("applies: next_request, delivery: [{header: {name: X-Forwarded-Attr-Uid}}]")), s_compose(), "", ""),
            ("custom without access_group", ff.replace("  access_group: users_demo\n", "", 1), ffc, "mozilla_uid", "access_group"),
            ("public without access_group", "name: App\nauth:\n  method: public\n" + S_FIREFOX_SETTINGS, ffc, "mozilla_uid", "access_group"),
            ("own login only without access_group", "name: App\nauth:\n  method: custom\n  sso: false\n  native_login: {supported: true, allow_without_gateway: true}\n" + S_FIREFOX_SETTINGS, ffc, "mozilla_uid", "access_group"),
            ("header-auth needs no access_group", S_HDR.replace("  access_group: users_demo\n", "", 1) + s_opts(pe("applies: next_request, delivery: [{header: {name: X-Forwarded-Attr-Uid}}]")), s_compose(), "mozilla_uid", "!"),
            ("person_entered admin_override ok", S_FF, ffc, "mozilla_uid", "!"),
        ])

    # ── carries: Hub rules from Tasks 3–15A ──────────────────────────

    def test_size_default_canonical(self) -> None:
        o = "{key: quota, label: Q, type: size, step: 1GiB, default: %s}"
        self.cases([
            ("500GiB", S_HDR + s_opts(o % "500GiB"), s_compose(s_env("QUOTA")), "", ""),
            ("500 GiB", S_HDR + s_opts(o % "500 GiB"), s_compose(s_env("QUOTA")), "", ""),
            ("bytes", S_HDR + s_opts(o % "1073741824"), s_compose(s_env("QUOTA")), "", ""),
            ("500 gigs", S_HDR + s_opts(o % "500 gigs"), s_compose(s_env("QUOTA")), "quota", "default"),
            ("500GB", S_HDR + s_opts(o % "500GB"), s_compose(s_env("QUOTA")), "quota", "not a size"),
            ("500G", S_HDR + s_opts(o % "500G"), s_compose(s_env("QUOTA")), "quota", "binary units"),
            ("off the step", S_HDR + s_opts(o % "1.5GiB"), s_compose(s_env("QUOTA")), "quota", "multiple of 1 GiB"),
            ("step in GB", S_HDR + s_opts("{key: quota, label: Q, type: size, step: 1GB}"), s_compose(s_env("QUOTA")), "quota", "step"),
        ])

    def test_size_parse_table(self) -> None:
        """The Go examples of settings.TestSizeParse / TestScalarCheckOption."""
        gib = 1 << 30
        o = {"key": "k", "label": "K", "type": "size", "step": "1GiB", "allow_unlimited": True}
        for raw in ("10GiB", 10 * gib, float(10 * gib), "10 GiB", "10gib", "10240MiB", "10485760 KiB"):
            with self.subTest(raw=raw):
                self.assertEqual(v.setting_value(o, raw), 10 * gib)
        self.assertIs(v.setting_value(o, "unlimited"), v.UNLIMITED)
        for raw, part in (("1.5GiB", "must be a multiple of 1 GiB"),):
            with self.subTest(raw=raw):
                with self.assertRaises(v.SettingError) as cm:
                    v.setting_value(o, raw)
                self.assertIn(part, str(cm.exception))
        plain = {"key": "k", "label": "K", "type": "size"}
        with self.assertRaises(v.SettingError) as cm:
            v.setting_value(plain, "unlimited")
        self.assertIn("unlimited", str(cm.exception))
        for bad in ("500 gigs", "10GB", "10G", "-1", -1, "1e3", "", True, "0.5B", 1.5, "10Ki", "10 KiB ", "1.2.3GiB",
                    "10\u212aiB", "10GiB\n", "99999999999999999999GiB", 2 ** 64, None, [1]):
            with self.subTest(bad=bad):
                with self.assertRaises(v.SettingError):
                    v.setting_value(plain, bad)
        for good, want in (("0", 0), ("1.5KiB", 1536), ("0.5KiB", 512), ("512", 512), ("1B", 1), ("1PiB", 1 << 50),
                           ("7.5", None), ("1 b", 1)):
            with self.subTest(good=good):
                if want is None:
                    with self.assertRaises(v.SettingError):
                        v.setting_value(plain, good)
                else:
                    self.assertEqual(v.setting_value(plain, good), want)
        # TestScalarCheckOption: whole options (the default as canonical value).
        for line in ("{key: q, label: Q, type: size, step: 1GiB, min: 0, max: 1TiB, default: 500GiB, allow_unlimited: true, delivery: [{env: Q, render: {unlimited: \"-1\"}}]}",):
            self.cases([("ok " + line, S_HDR + s_opts(line), s_compose(s_env("Q")), "", "")])
        bad_opts = {
            "{key: q, label: Q, type: size, step: 1GB}": "step",
            "{key: q, label: Q, type: size, step: 0}": "step",
            "{key: q, label: Q, type: size, step: 1GiB, default: 1.5GiB}": "default",
            "{key: q, label: Q, type: size, default: 500 gigs}": "default",
            "{key: q, label: Q, type: size, default: unlimited}": "default",
            "{key: q, label: Q, type: size, unit: GiB}": "unit",
            "{key: q, label: Q, type: size, min: 2GiB, max: 1GiB}": "min",
        }
        self.cases([(line, S_HDR + s_opts(line), s_compose(s_env("Q")), "q", part) for line, part in bad_opts.items()])

    def test_scalar_kinds(self) -> None:
        """settings.TestScalarCheckOption / TestIntParse / TestDurationParse /
        TestEnumRankAndCompare / TestBoolParse, as manifest options."""
        good = [
            "{key: q, label: Q, type: int, min: 0, max: 10, step: 2, unit: days, default: 4}",
            "{key: q, label: Q, type: int, min: 1, step: 2, default: 3}",
            "{key: q, label: Q, type: int, default: \"3650\"}",
            "{key: q, label: Q, type: duration, min: 1h, max: 30d, default: 7d}",
            "{key: q, label: Q, type: duration, default: 90m}",
            "{key: q, label: Q, type: duration, default: 1w2d}",
            "{key: q, label: Q, type: duration, default: 60}",
            "{key: q, label: Q, type: bool, default: false}",
            "{key: q, label: Q, type: string, default: abc, max_len: 5}",
            "{key: q, label: Q, type: enum, options: [{value: viewer, label: Viewer}, {value: admin, label: Admin}], default: admin}",
            "{key: q, label: Q, type: multi_enum, options: [{value: a, label: A}, {value: b, label: B}], default: [b, a, b], max_items: 2}",
            "{key: q, label: Q, type: list, items: {type: int, min: 1}, default: [1, 2]}",
            "{key: q, label: Q, type: table, key_column: name, columns: [{name: name, label: N, type: string, required: true}, {name: port, label: P, type: int}], default: [{name: a, port: 80}, {name: b}]}",
            "{key: q, label: Q, type: groups, default: [admins, users_demo]}",
            "{key: q, label: Q, type: users, default: [Alice, bob]}",
            "{key: q, label: Q, type: user, default: alice.b}",
            "{key: q, label: Q, type: path, target: {service: demo, mount: /media}, default: /srv//media/}",
        ]
        self.cases([(g, S_HDR + s_opts(g), s_compose("" if "type: path" in g else s_env("Q")), "", "") for g in good])
        bad = {
            "{key: q, label: Q, type: int, min: 5, max: 1}": "min is above max",
            "{key: q, label: Q, type: int, step: 0}": "step",
            "{key: q, label: Q, type: int, step: -2}": "step",
            "{key: q, label: Q, type: int, min: x}": "min",
            "{key: q, label: Q, type: int, max: 10, default: 11}": "at most 10",
            "{key: q, label: Q, type: int, min: 0, step: 5, default: 31}": "multiple of 5",
            "{key: q, label: Q, type: int, min: 1, step: 2, default: 4}": "multiple of 2",
            "{key: q, label: Q, type: int, default: 1.5}": "default",
            "{key: q, label: Q, type: int, allow_unlimited: true}": "allow_unlimited",
            "{key: q, label: Q, type: int, unit: \"a\\nb\"}": "unit",
            "{key: q, label: Q, type: duration, min: 2d, max: 1d}": "min",
            "{key: q, label: Q, type: duration, step: 1d}": "step",
            "{key: q, label: Q, type: duration, default: 1500ms}": "whole seconds",
            "{key: q, label: Q, type: duration, default: -5m}": "negative",
            "{key: q, label: Q, type: duration, default: soon}": "not a duration",
            "{key: q, label: Q, type: duration, min: 1h, default: 59m}": "at least 1h",
            "{key: q, label: Q, type: bool, default: yes}": "default",
            "{key: q, label: Q, type: bool, default: 1}": "default",
            "{key: q, label: Q, type: enum}": "options",
            "{key: q, label: Q, type: enum, options: [{value: a, label: A}, {value: a, label: B}]}": "listed twice",
            "{key: q, label: Q, type: enum, options: [{value: '', label: A}]}": "value",
            "{key: q, label: Q, type: enum, options: [{value: a, label: ''}]}": "label",
            "{key: q, label: Q, type: enum, options: [{value: \"a\\nb\", label: A}]}": "control",
            "{key: q, label: Q, type: enum, options: [{value: a, label: A}], min: 1}": "min is not a constraint of type enum",
            "{key: q, label: Q, type: enum, options: [{value: a, label: A}], default: owner}": "not one of",
            "{key: q, label: Q, type: multi_enum, options: [{value: a, label: A}], default: [a], min_items: 2}": "at least 2 items",
            "{key: q, label: Q, type: multi_enum, options: [{value: a, label: A}], min_items: 3, max_items: 2}": "min_items is above max_items",
            "{key: q, label: Q, type: list}": "items",
            "{key: q, label: Q, type: list, items: {type: size}}": "items: type",
            "{key: q, label: Q, type: list, items: {type: string, min: 1}}": "items: min is not a constraint",
            "{key: q, label: Q, type: list, items: {type: int}, max_items: 1001}": "max_items must be 0-1000",
            "{key: q, label: Q, type: list, items: {type: int}, unique: true, default: [1, 1]}": "duplicate",
            "{key: q, label: Q, type: table}": "column",
            "{key: q, label: Q, type: table, columns: [{name: Name, label: N, type: string}]}": "columns: name",
            "{key: q, label: Q, type: table, columns: [{name: a, label: A, type: string}, {name: a, label: B, type: int}]}": "listed twice",
            "{key: q, label: Q, type: table, columns: [{name: a, label: A, type: size}]}": "columns: a: type",
            "{key: q, label: Q, type: table, columns: [{name: a, label: A, type: string}], key_column: b}": "key_column b",
            "{key: q, label: Q, type: table, key_column: a, columns: [{name: a, label: A, type: string}], default: [{a: x}, {a: x}]}": "duplicate a",
            "{key: q, label: Q, type: table, columns: [{name: a, label: A, type: string, required: true}], default: [{a: ''}]}": "a is required",
            "{key: q, label: Q, type: table, columns: [{name: a, label: A, type: string}], default: [{b: x}]}": "b is not a column",
            "{key: q, label: Q, type: groups, default: [\"bad group\"]}": "not a valid group name",
            "{key: q, label: Q, type: user, default: alice@example.com}": "not an email",
            "{key: q, label: Q, type: user, default: \"\\u212aelvin\"}": "ASCII",
            "{key: q, label: Q, type: user, min_items: 1}": "min_items is not a constraint",
            "{key: q, label: Q, type: string, pattern: '[a-z]+'}": "anchored",
            "{key: q, label: Q, type: string, pattern: '^[a-z+$'}": "pattern",
            "{key: q, label: Q, type: string, pattern: '^(?=a)a$'}": "pattern",
            "{key: q, label: Q, type: string, pattern: '^(?x) a $'}": "error parsing regexp",
            "{key: q, label: Q, type: string, pattern: '^(a)\\1$'}": "error parsing regexp",
            "{key: q, label: Q, type: string, min_len: 5, max_len: 2}": "min_len",
            "{key: q, label: Q, type: string, max_len: 70000}": "max_len",
            "{key: q, label: Q, type: string, max_len: 2, default: abc}": "default",
            "{key: q, label: Q, type: string, format: hex, default: xyz}": "default",
            "{key: q, label: Q, type: string, format: phone}": "format",
            "{key: q, label: Q, type: string, pattern: '^a|b$', default: axx}": "pattern",
            "{key: q, label: Q, type: string, default: 5}": "want a string",
            "{key: q, label: Q, type: string, default: \"a\\tb\"}": "control",
            "{key: q, label: Q, type: string, default: \"a\\u202eb\"}": "control",
            "{key: q, label: Q, type: string, pattern: '" + "a" * 501 + "'}": "pattern",
            "{key: q, label: Q, type: path, target: {service: demo, mount: /media}, mode: rw2}": "mode",
            "{key: q, label: Q, type: path, target: {service: demo, mount: /media}, needs: exec}": "needs",
            "{key: q, label: Q, type: path, target: {service: demo, mount: /media}, mode: ro, needs: write}": "needs: write with mode: ro",
            "{key: q, label: Q, type: path, target: {service: demo, mount: /media}, default: relative}": "absolute",
            "{key: q, label: Q, type: path, target: {service: demo, mount: /media}, default: /}": "/",
            "{key: q, label: Q, type: path, target: {service: demo, mount: /media}, default: \"folder:x\"}": "shared folder",
            "{key: q, label: Q, type: path, target: {service: demo, mount: \"/a:b\"}}": "no ':'",
            "{key: q, label: Q, type: path, target: {service: demo, mount: /a/../b}}": "clean",
            "{key: q, label: Q, type: secret, default: x}": "takes no default",
            "{key: q, label: Q, type: secret, format: hex}": "format is not a constraint of type secret",
            "{key: q, label: Q, type: bool, pattern: '^x$'}": "pattern is not a constraint of type bool",
        }
        self.cases([(line, S_HDR + s_opts(line), s_compose(s_env("Q")), "q", part) for line, part in bad.items()])

    def test_patterns_are_re2(self) -> None:
        """Patterns compile and match as Go's regexp (RE2) does; each row was
        checked with regexp.Compile("^(?:" + pattern + ")$") under Go."""
        rows = [   # (pattern, default, Go accepts the pattern, Go matches the default)
            ("^a++$", "a", False, False),               # invalid nested repetition operator
            ("^a{2}{3}$", "aaaaaa", False, False),
            ("^.{1,4096}$", "a", False, False),         # invalid repeat count (> 1000)
            ("^.{1,1000}$", "a", True, True),
            ("^a{,3}$", "a{,3}", True, True),           # literal text in RE2, {0,3} in Python
            ("^a{,3}$", "aaa", True, False),
            ("^[[:alpha:]]$", "a]", True, False),       # a POSIX class in RE2
            ("^[[:alpha:]]$", "a", True, True),
            ("^\\pL+$", "\u00e9t\u00e9", True, True),
            ("^(?U)a+$", "aa", True, True),
            ("^\\C$", "a", False, False),               # Go refuses \C (C++ RE2 has it)
            ("^\\\\C$", "\\C", True, True),             # an escaped backslash, then C
            ("^(?<n>a)$", "a", True, True),
            ("^(?P<n>a)$", "a", True, True),
            ("^\\Qa.b\\E$", "a.b", True, True),
            ("^\\Qa.b\\E$", "axb", True, False),
            ("^[\\d]$", "\u0663", True, False),             # \d is ASCII
            ("^(?i)k$", "K", True, True),
            ("^(?=a)a$", "a", False, False),
            ("^(a)\\1$", "aa", False, False),
            ("^(?>a)$", "a", False, False),
            ("^a$", "a\n", True, False),                # control characters are refused first anyway
        ]
        cases = []
        for pat, default, compiles, matches in rows:
            # A hook delivery: the implicit env would refuse the backslash of \\C.
            line = "{key: q, label: Q, type: string, pattern: %s, default: %s, delivery: [{hook: apply}]}" % (json.dumps(pat), json.dumps(default))
            want = "" if compiles and matches else ("pattern" if not compiles else "default")
            cases.append((f"{pat} / {default!r}", S_HDR + s_opts(line) + HOOK_APPLY, s_compose(), "q" if want else "", want))
        self.cases(cases)
        # Linear time: a pattern Python's re would backtrack on for ages.
        import time
        start = time.monotonic()
        with self.assertRaises(v.SettingError):
            v.setting_value({"key": "q", "type": "string", "pattern": "^(a+)+$"}, "a" * 5000 + "b")
        self.assertLess(time.monotonic() - start, 1.0)

    def test_yaml_scalars_as_the_hub_reads_them(self) -> None:
        h = s_compose(s_env("Q"))
        self.cases([
            ("base-60 int is a string", S_HDR + s_opts("{key: q, label: Q, type: int, default: 1:30}"), h, "q", "default"),
            ("base-60 duration is a string", S_HDR + s_opts("{key: q, label: Q, type: duration, default: 1:30}"), h, "q", "default"),
            ("yes is a string", S_HDR + s_opts("{key: q, label: Q, type: bool, default: yes}"), h, "q", "want true or false"),
            ("true key", S_HDR + s_opts("{key: q, label: Q, type: bool, delivery: [{env: Q, render: {true: on, false: off}}]}"), h, "", ""),
            ("TRUE key matches no field", S_HDR + s_opts("{key: q, label: Q, type: bool, delivery: [{env: Q, render: {TRUE: on}}]}"), h, "", "delivery"),
            ("True key matches no field", S_HDR + s_opts("{key: q, label: Q, type: bool, delivery: [{env: Q, render: {True: on}}]}"), h, "", "delivery"),
        ])

    def test_read_only_as_compose_reads_it(self) -> None:
        bind = "      - {type: bind, source: ./templates/demo/app.conf, target: /app.conf, read_only: %s}\n"
        ca = "      - {type: bind, source: ./certs/ca-bundle.crt, target: /ca.crt, read_only: %s}\n"
        for mount, what in ((bind, "shared by every instance"), (ca, "must be read-only")):
            for val, ok in (("true", True), ("yes", True), ("ON", True), ("y", True), ("\"True\"", True),
                            ("false", False), ("no", False), ("off", False), ("n", False), ("\"No\"", False)):
                with self.subTest(mount=what, val=val):
                    c = s_compose().replace("      - demo-data:/data\n", "      - demo-data:/data\n" + mount % val)
                    self.run_raw(S_HDR, c)
                    with open(os.path.join(self.tmp.name, "demo", "app.conf"), "w") as f:
                        f.write("x\n")
                    errors, _ = self.run_raw(S_HDR, c)
                    if ok:
                        self.assertClean(errors)
                    else:
                        self.assertError(errors, what)
            for val in ("maybe", "1", "\" yes\""):
                with self.subTest(mount=what, val=val):
                    errors, _ = self.run_raw(S_HDR, s_compose().replace("      - demo-data:/data\n", "      - demo-data:/data\n" + mount % val))
                    self.assertError(errors, "is not a boolean compose reads")

    def test_network_mode_exact(self) -> None:
        for mode, ok in (("host", True), ("none", True), ("service:demo", True),
                         (" host", False), ("Host", False), ("NONE", False), ("host ", False), ("service:side", False),
                         ("service:nope", False), ("Service:demo", False), ("portcullis-proxy", False)):
            with self.subTest(mode=mode):
                c = s_compose(services=S_INIT + f"  side:\n    image: demo/side:1.0.0@sha256:{S_DIGEST}\n    network_mode: \"{mode}\"\n")
                errors, _ = self.run_raw(S_HDR, c)
                bad = [e for e in errors if "services.side: network_mode" in e]
                self.assertEqual(not bad, ok, errors)

    def test_string_formats(self) -> None:
        """settings.TestStringFormats / TestFormatsStrict, as defaults."""
        cases = {
            "hostname": (["a.example.com", "x1.y"], ["-a", "A.example.com", "localhost", "a..b"]),
            "ip": (["10.0.0.1", "::1", "fd00::1"], ["10.0.0.300", "fe80::1%eth0", "010.0.0.1", ""]),
            "cidr": (["10.0.0.0/8", "192.168.1.0/24", "fd00::/8", "10.0.0.1/32"], ["10.0.0.0/33", "10.0.0.1/8", "fd00::1/8", "10.0.0.0", "10.0.0.0/08"]),
            "url": (["https://x", "http://app.example.com:8080/a/b?c=d", "https://x:1", "https://x:65535/", "https://x/a%20b", "https://x/?q=\"a\"&b=%zz"],
                    ["x", "https://x/a b", "https://x:99999", "https://x:0", "https://x:abc", "javascript://x", "mqtt://broker",
                     "ftp://x", "https://x/\u202e", "https://x/\u00e9", "https://", "//x", "HTTPS://x", "https://x/a%zz", "https://x/a\"b",
                     "https://x:080/"]),
            "email": (["alice@example.com", "a.b+c@sub.example.org"], ["alice", "a@b", "Alice <a@example.com>", "a b@example.com", "a@@example.com"]),
            "iana_tz": (["Europe/Rome", "UTC", "America/Argentina/Buenos_Aires"], ["Mars/Base", "Local", "../etc/passwd", "Europe/Rome/", "/Europe/Rome", "europe/rome"]),
            "locale": (["it-IT", "en", "zh-Hant-TW", "de-CH-1996"], ["it-!!", "it_IT", "IT-it", "it-it", ""]),
            "cron": (["*/5 * * * *", "@hourly", "0 3 * * 1-5", "0 0 1 JAN,jul MON-FRI", "15,45 */2 1-15/3 * ?"],
                     ["61 * * * *", "*/5  * * * *", " */5 * * * *", "*/5 * * * * ", "*/5\t* * * *", "@every 5m", "CRON_TZ=UTC 0 * * * *",
                      "* * * *", "* * * * * *", "0 24 * * *", "0 0 0 * *", "0 0 * 13 *", "0 0 * * 7", "*/0 * * * *", "5-1 * * * *"]),
            "semver": (["1.2.3", "1.2.3-rc.1", "1.2.3+build.5", "0.0.0"], ["1.2", "v1.2.3", "01.2.3", "1.2.3-01", "1.2.3.4"]),
            "hex": (["deadBEEF", "0"], ["xyz", "", "0x1f"]),
        }
        rows = []
        for fmt, (good, bad) in cases.items():
            for g in good:
                rows.append((f"{fmt} {g!r}", S_HDR + s_opts("{key: q, label: Q, type: string, format: %s, default: %s}" % (fmt, json.dumps(g))), s_compose(s_env("Q")), "q", "!"))
            for b in bad:
                rows.append((f"{fmt} {b!r} refused", S_HDR + s_opts("{key: q, label: Q, type: string, format: %s, default: %s}" % (fmt, json.dumps(b))), s_compose(s_env("Q")), "q", "default"))
        self.cases(rows)

    def test_render_checks(self) -> None:
        """settings.TestCheckOptionRenders: each delivery's render fits the type."""
        bad = {
            "{key: q, label: Q, type: size, delivery: [{env: Q, render: {unit: days}}]}": "unit",
            "{key: q, label: Q, type: size, delivery: [{env: Q, render: {unit: G}}]}": "unit",
            "{key: q, label: Q, type: size, allow_unlimited: true, delivery: [{env: Q, render: {unit: GiB}}]}": "unlimited",
            "{key: q, label: Q, type: size, allow_unlimited: true}": "allow_unlimited needs deliveries",
            "{key: q, label: Q, type: size, delivery: [{env: Q, render: {unlimited: \"-1\"}}]}": "unlimited",
            "{key: q, label: Q, type: int, unit: days, delivery: [{env: Q, render: {unit: GiB}}]}": "the option's unit",
            "{key: q, label: Q, type: int, delivery: [{env: Q, render: {unit: days}}]}": "the option's unit",
            "{key: q, label: Q, type: string, delivery: [{env: Q, render: {true: \"y\"}}]}": "true",
            "{key: q, label: Q, type: string, delivery: [{env: Q, render: {join: \"+\"}}]}": "join",
            "{key: q, label: Q, type: string, delivery: [{env: Q, render: {format: xml}}]}": "format",
            "{key: q, label: Q, type: string, delivery: [{hook: apply, render: {format: yaml}}]}": "format yaml is for list",
            "{key: q, label: Q, type: int, delivery: [{hook: apply, render: {format: csv}}]}": "format csv is for list",
            "{key: q, label: Q, type: string, delivery: [{env: Q, render: {format: yaml}}]}": "format yaml is multi-line",
            "{key: q, label: Q, type: list, items: {type: string}, delivery: [{env: Q, render: {format: csv}}]}": "format csv is multi-line",
            "{key: q, label: Q, type: table, columns: [{name: a, label: A, type: string}], delivery: [{env: Q, render: {format: yaml}}]}": "format yaml is multi-line",
            "{key: q, label: Q, type: duration, delivery: [{env: Q, render: {unit: GiB}}]}": "unit",
            "{key: q, label: Q, type: bool, delivery: [{env: Q, render: {integer: true}}]}": "integer",
            "{key: q, label: Q, type: list, items: {type: string}, delivery: [{env: Q, render: {join: \"\"}}]}": "join",
            "{key: q, label: Q, type: list, items: {type: string}, delivery: [{env: Q, render: {join: \",\", format: json}}]}": "exclude each other",
            "{key: q, label: Q, type: string, delivery: [{env: Q, render: {unit: GiB}}]}": "unit is for size",
        }
        hooks = HOOK_APPLY
        self.cases([(line, S_HDR + s_opts(line) + hooks, s_compose(s_env("Q")), "q", part) for line, part in bad.items()])
        ok = [
            "{key: q, label: Q, type: size, delivery: [{hook: apply, render: {unit: GB, integer: true}}]}",
            "{key: q, label: Q, type: size, delivery: [{env: Q, render: {unit: TB}}]}",
            "{key: q, label: Q, type: list, items: {type: string}, delivery: [{env: Q, render: {join: \" \"}}]}",
            "{key: q, label: Q, type: list, items: {type: string}, delivery: [{hook: apply, render: {format: csv}}]}",
            "{key: q, label: Q, type: table, columns: [{name: a, label: A, type: string}], delivery: [{hook: apply, render: {format: yaml}}]}",
            "{key: q, label: Q, type: bool, delivery: [{env: Q, render: {true: \"on\", false: \"off\"}}]}",
            "{key: q, label: Q, type: int, unit: days, delivery: [{env: Q, render: {unit: days}}]}",
            "{key: q, label: Q, type: duration, delivery: [{env: Q, render: {unit: d, integer: true}}]}",
        ]
        self.cases([(line, S_HDR + s_opts(line) + hooks, s_compose("" if "{hook:" in line else s_env("Q")), "", "") for line in ok])

    def test_claim_json_type_fits_render(self) -> None:
        o = s_compose(oidc=True)

        def c(typ: str, extra: str, claim: str) -> str:
            return S_OIDC + s_opts("{key: v, label: V, type: " + typ + ", scope: person, resolve: priority, " + extra + ", delivery: [{claim: {client: demo, name: demo_v, " + claim + "}}]}")
        self.cases([
            ("int ok", c("int", "default: 1", "json_type: int"), o, "", ""),
            ("size in GiB ok", c("size", "default: 1GiB, step: 1GiB", "json_type: int, render: {unit: GiB, integer: true}"), o, "", ""),
            ("duration ok", c("duration", "default: 1h", "json_type: int"), o, "", ""),
            ("size in bytes", c("size", "default: 1GiB", "json_type: int"), o, "v", "json_type int"),
            ("size in B", c("size", "default: 1GiB", "json_type: int, render: {unit: B}"), o, "v", "json_type int"),
            ("unlimited not a number", c("size", "default: 1GiB, allow_unlimited: true", "json_type: int, render: {unit: GiB, unlimited: none}"), o, "v", "unlimited"),
            ("unlimited over 32 bits", c("size", "default: 1GiB, allow_unlimited: true", "json_type: int, render: {unit: GiB, unlimited: '4294967296'}"), o, "v", "32-bit"),
            ("unlimited missing", c("size", "default: 1GiB, allow_unlimited: true", "json_type: int, render: {unit: GiB}"), o, "v", "unlimited"),
            ("int from string", c("string", "default: x", "json_type: int"), o, "v", "json_type int"),
            ("bool ok", c("bool", "default: false", "json_type: bool"), o, "", ""),
            ("bool rendered 1/0", c("bool", "default: false", 'json_type: bool, render: {"true": "1", "false": "0"}'), o, "v", "json_type bool"),
            ("bool from enum", c("enum", "default: a, options: [{value: a, label: A}]", "json_type: bool"), o, "v", "json_type bool"),
            ("json list ok", c("list", "default: [a], items: {type: string}", "json_type: json, render: {format: json}"), o, "", ""),
            ("json list joined", c("list", "default: [a], items: {type: string}", "json_type: json"), o, "v", "json_type json"),
            ("json string", c("string", "default: x", "json_type: json"), o, "v", "json_type json"),
            ("json int ok", c("int", "default: 1", "json_type: json"), o, "", ""),
            ("json size in bytes ok", c("size", "default: 1GiB", "json_type: json"), o, "", ""),
            ("json unlimited null ok", c("size", "default: 1GiB, allow_unlimited: true", "json_type: json, render: {unlimited: 'null'}"), o, "", ""),
            ("json unlimited text", c("size", "default: 1GiB, allow_unlimited: true", "json_type: json, render: {unlimited: none}"), o, "v", "unlimited"),
            ("json unlimited NaN", c("size", "default: 1GiB, allow_unlimited: true", "json_type: json, render: {unlimited: NaN}"), o, "v", "unlimited"),
            ("json table ok", c("table", "default: [], columns: [{name: a, label: A, type: string}]", "json_type: json"), o, "", ""),
            ("string anything", c("enum", "default: a, options: [{value: a, label: A}]", "json_type: string"), o, "", ""),
        ])

    def test_header_delivery_public_router_refused(self) -> None:
        """P14: a router the template labels public (no forward-auth, e.g.
        tls.options public@file) reaching the delivering backend."""
        pub_tls = router("share", S_HOST + " && PathPrefix(`/share`)", gated=False).replace("authaware@file", "public@file")
        self.cases([
            ("ungated router", S_HDR + s_opts(S_PERSON_HEADER),
             s_compose(routers=router("demo", S_HOST) + router("share", S_HOST + " && PathPrefix(`/share`)", gated=False)), "quota", "router share reaches service demo"),
            ("public@file router", S_HDR + s_opts(S_PERSON_HEADER), s_compose(routers=router("demo", S_HOST) + pub_tls), "quota", "without Portcullis forward-auth"),
            ("auth only still strips", S_HDR + s_opts(S_PERSON_HEADER),
             s_compose(routers=router("demo", S_HOST) + router("api", S_HOST + " && PathPrefix(`/api`)").replace(",portcullis-groups@docker", "")), "quota", "!"),
            ("other backend may be public", S_HDR + s_opts(S_PERSON_HEADER),
             s_compose(services=S_INIT.rstrip("\n") + "\n    labels:\n      traefik.enable: \"true\"\n" + router("side", S_HOST + " && PathPrefix(`/side`)", gated=False)), "quota", "!"),
        ])

    def test_env_delivery_hard_coded_refused(self) -> None:
        self.cases([
            ("map form", S_HDR + s_opts("{key: hard, label: H, type: string}"), s_compose("      HARD: literal\n"), "hard", "compose.yml hard-codes HARD in service demo"),
            ("named delivery", S_HDR + s_opts("{key: x, label: H, type: string, delivery: [{env: HARD}]}"), s_compose("      HARD: literal\n"), "x", "hard-codes HARD"),
            ("escaped only", S_HDR + s_opts("{key: theme, label: T, type: string}"), s_compose("      THEME: $${THEME}\n"), "theme", "hard-codes"),
            ("number", S_HDR + s_opts("{key: theme, label: T, type: int}"), s_compose("      THEME: 5\n"), "theme", "hard-codes"),
            ("interpolated", S_HDR + s_opts("{key: theme, label: T, type: string}"), s_compose("      THEME: ${THEME:-dark}\n"), "", ""),
            ("passed through", S_HDR + s_opts("{key: theme, label: T, type: string}"), s_compose("      THEME:\n      X: ${THEME}\n"), "theme", "!"),
        ])

    def test_env_live_reload_warns(self) -> None:
        hooks = "hooks:\n  - {name: apply, service: demo, command: [x], when: [settings_change]}\n"
        for applies, extra in (("live", hooks), ("reload", "reload: {service: demo, signal: HUP}\n")):
            with self.subTest(applies=applies):
                m = S_HDR + s_opts("{key: theme, label: T, type: string, applies: %s, delivery: [{env: THEME}, {hook: apply}]}" % applies) + hooks + \
                    ("reload: {service: demo, signal: HUP}\n" if applies == "reload" else "")
                errors, warnings = self.run_raw(m, s_compose(s_env("THEME")))
                self.assertClean(errors)
                self.assertTrue(any("setting theme" in w and "restart" in w for w in warnings), warnings)
        errors, warnings = self.run_raw(S_HDR + s_opts("{key: theme, label: T, type: string, applies: live, delivery: [{hook: apply}]}") + hooks, s_compose())
        self.assertClean(errors)
        self.assertFalse([w for w in warnings if "setting theme" in w], warnings)

    def test_integer_render_refuses_default(self) -> None:
        m = S_HDR + s_opts("{key: q, label: Q, type: size, default: 1536MiB, delivery: [{env: Q, render: {unit: GiB, integer: true}}]}")
        errors, _ = self.run_raw(m, s_compose(s_env("Q")))
        self.assertError(errors, "setting q: default 1536MiB: env Q: 1.5 GiB is not a whole number of GiB")
        errors, warnings = self.run_raw(m.replace("1536MiB", "2GiB"), s_compose(s_env("Q")))
        self.assertClean(errors)
        self.assertFalse([w for w in warnings if "setting q" in w], warnings)

    def test_files_name_and_mount(self) -> None:
        h = s_compose()
        rows = []
        for name in ("people", "a", "a-b_c", "x" * 32):
            rows.append((f"name {name}", S_HDR + "files:\n  - {name: %s, service: init, mount: /portcullis}\n" % name, h, "", ""))
        for name in ("People", "1a", "-a", "a.b", "x" * 33, "a b"):
            rows.append((f"name {name}", S_HDR + "files:\n  - {name: \"%s\", service: init, mount: /portcullis}\n" % name, h, "", "name must match"))
        for mount in ("portcullis", "/", "/a/", "/a//b", "/a/./b", "/a/../b", "/a:b", "/a\\tb", "./a"):
            rows.append((f"mount {mount}", S_HDR + "files:\n  - {name: people, service: init, mount: \"%s\"}\n" % mount, h, "", "absolute, clean"))
        rows.append(("unknown key", S_HDR + "files:\n  - {name: people, service: init, mount: /p, mode: \"0600\"}\n", h, "", "mode"))
        self.cases(rows)

    def test_secrets_file_user_warns(self) -> None:
        m = S_HDR + s_opts("{key: token, label: T, type: secret, delivery: [{file: {name: cfg}}]}") + \
            "files:\n  - {name: cfg, service: init, mount: /portcullis}\n"
        for user, warn in (("", False), ("0", False), ("root", False), ("10001", False), ("10001:10001", False), ("1000", True), ("app", True)):
            with self.subTest(user=user):
                svc = S_INIT + (f"    user: \"{user}\"\n" if user else "")
                errors, warnings = self.run_raw(m, s_compose(services=svc))
                self.assertClean(errors)
                self.assertEqual(any("cfg.secrets.json" in w for w in warnings), warn, warnings)

    def test_spec_examples(self) -> None:
        immich = S_OIDC + """\
settings:
  sections: [Storage, Accounts, Library]
  options:
    - key: trash_days
      label: Keep deleted items for
      type: int
      unit: days
      min: 0
      max: 3650
      default: 30
      scope: instance
      section: Library
      applies: restart
      delivery: [{env: IMMICH_TRASH_DAYS}]
    - key: storage_quota
      label: Storage quota
      type: size
      step: 1GiB
      allow_unlimited: true
      scope: person
      default: 100GiB
      resolve: max
      resolve_choices: [max, min, priority]
      section: Storage
      applies: next_sign_in
      delivery:
        - claim: {client: demo, name: immich_quota, json_type: int,
                  render: {unit: GiB, unlimited: "-1"}}
    - key: role
      label: Role
      type: enum
      options: [{value: user, label: User}, {value: admin, label: Administrator}]
      scope: person
      privileged: true
      default: user
      group_values: {"{{ADMIN_GROUP}}": admin}
      resolve: max
      section: Accounts
      applies: next_sign_in
      delivery: [{claim: {client: demo, name: immich_role, json_type: string}}]
    - key: external_library
      label: External photo library
      type: path
      mode: ro
      needs: read
      writes_as: {uid: 0, gid: 0}
      target: {service: demo, mount: /usr/src/app/external}
      scope: instance
      applies: restart
"""
        nextcloud = S_HDR + """\
hooks:
  - name: apply-settings
    service: demo
    command: [php, /portcullis/apply-settings.php]
    when: [start, settings_change]
    timeout: 60s
settings:
  options:
    - key: default_quota
      label: Default storage quota
      type: size
      step: 1GiB
      allow_unlimited: true
      scope: instance
      default: 10GiB
      applies: live
      delivery: [{hook: apply-settings, render: {unit: GiB, integer: true, unlimited: none}}]
"""
        self.cases([
            ("immich", immich, s_compose(s_env("IMMICH_TRASH_DAYS"), oidc=True), "", ""),
            ("nextcloud", nextcloud, s_compose(), "", ""),
        ])

    def test_settings_shape(self) -> None:
        h = s_compose(S_HDR_ENV)
        self.cases([
            ("section name", S_HDR + "settings:\n  sections: [\"Bad/Section\"]\n  options: []\n", h, "", "settings.sections"),
            ("section twice", S_HDR + "settings:\n  sections: [A, A]\n  options: []\n", h, "", "listed twice"),
            ("description control", S_HDR + s_opts("{key: theme, label: T, type: string, description: \"a\\u0007b\"}"), h, "theme", "description"),
            ("description newline ok", S_HDR + s_opts("{key: theme, label: T, type: string, description: \"a\\nb\"}"), s_compose(s_env("THEME")), "", ""),
            ("description too long", S_HDR + s_opts("{key: theme, label: T, type: string, description: " + "x" * 501 + "}"), h, "theme", "description"),
            ("label too long", S_HDR + s_opts("{key: theme, label: " + "x" * 65 + ", type: string}"), h, "theme", "label"),
            ("label of 64 runes", S_HDR + s_opts("{key: theme, label: " + "\u00e9" * 64 + ", type: string}"), s_compose(s_env("THEME")), "", ""),
            ("label of 65 runes", S_HDR + s_opts("{key: theme, label: " + "\u00e9" * 65 + ", type: string}"), h, "theme", "at most 64 characters"),
            ("unique on string", S_HDR + s_opts("{key: theme, label: T, type: string, unique: true}"), h, "theme", "unique"),
            ("admin_override on instance", S_HDR + s_opts("{key: theme, label: T, type: string, admin_override: true}"), h, "theme", "admin_override"),
            ("wrong shape", S_HDR + s_opts("{key: theme, label: T, type: string, required: \"yes\"}"), h, "", "required"),
            ("render outside", S_HDR + s_opts("{key: quota, label: Q, type: int, scope: person, resolve: priority, default: 1, delivery: [{header: {name: X-Forwarded-Attr-Quota}, render: {format: json}}]}"), h, "quota", "render goes inside"),
            ("empty delivery", S_HDR + s_opts("{key: theme, label: T, type: string, delivery: [{}]}"), h, "theme", "exactly one"),
        ])

    # ── ParseRoutes' stricter rules (every template) ──────────────────

    def test_duplicate_traefik_service_refused(self) -> None:
        init = (S_INIT.rstrip("\n") + "\n    networks:\n      - default\n      - portcullis-proxy\n    labels:\n      traefik.enable: \"true\"\n" +
                router("side", S_HOST + " && PathPrefix(`/side`)") +
                "      traefik.http.services.demo.loadbalancer.server.port: \"80\"\n")
        for name, svc in (("explicit", init + "      traefik.http.routers.side.service: demo\n"), ("implicit", init)):
            with self.subTest(name):
                errors, _ = self.run_raw(S_HDR, s_compose(services=svc))
                self.assertError(errors, "Traefik service demo is defined on services demo and init (Traefik would merge them into one load balancer)")
        errors, _ = self.run_raw(S_HDR, s_compose(services=init.replace("services.demo.", "services.side.")))
        self.assertFalse([e for e in errors if "defined on services" in e], errors)

    def test_auto_service_name_refused(self) -> None:
        rule = ".rule: " + S_HOST + "\n"
        for label in ("traefik.http.services.demo-portcullis-app.loadbalancer.server.port: \"80\"\n",
                      "traefik.http.services.x-PORTCULLIS.loadbalancer.server.port: \"80\"\n",
                      "traefik.http.routers.a-portcullis-b" + rule,
                      "TRAEFIK.HTTP.SERVICES.db-portcullis-x.loadbalancer.server.port: \"80\"\n",
                      "traefik.http.services.web-portculli\u017f-app.loadbalancer.server.port: \"80\"\n"):
            with self.subTest(label=label):
                errors, _ = self.run_raw(S_HDR, s_compose(routers=router("demo", S_HOST) + "      " + label))
                self.assertError(errors, "looks like an automatic service name")
        for ok in ("portcullis-auth", "portcullisapp", "my-portcullisx", "app"):
            with self.subTest(ok=ok):
                errors, _ = self.run_raw(S_HDR, s_compose(routers=router("demo", S_HOST) + f"      traefik.http.services.{ok}.loadbalancer.server.port: \"80\"\n"))
                self.assertFalse([e for e in errors if "automatic service name" in e], errors)

    def test_auto_name_collision_refused(self) -> None:
        def collide(a: str, b: str, enable_b: str) -> str:
            return (f"services:\n  {a}:\n    image: x\n    labels:\n      traefik.enable: \"true\"\n" + router("demo", S_HOST) +
                    f"  {b}:\n    image: x\n    labels:\n      traefik.enable: {enable_b}\n" + router("side", S_HOST + " && PathPrefix(`/side`)", gated=False))
        for a, b in (("my-web", "my_web"), ("my-web", "my.web"), ("my_web", "my.web"), ("my-web", "my--web"), ("my-web", "my-_.web"),
                     ("web", "web-"), ("web", "web_"), ("web", "Web"), ("my-web", "My_Web")):
            with self.subTest(a=a, b=b):
                errors, _ = self.run_raw(S_HDR, collide(a, b, '"true"'))
                self.assertError(errors, "would get the same automatic Traefik service name")
        for a, b, en in (("myweb", "my-web", '"true"'), ("web", "web2", '"true"'), ("web-a", "web-b", '"true"'),
                         ("my-web", "my_web", '"false"'), ("my-web", "my_web", "false")):
            with self.subTest(a=a, b=b, en=en):
                errors, _ = self.run_raw(S_HDR, collide(a, b, en))
                self.assertFalse([e for e in errors if "automatic Traefik service name" in e], errors)

    def test_traefik_enable_strict(self) -> None:
        def side(val: str) -> str:
            return s_compose(services=S_INIT + "  side:\n    image: x\n    labels:\n      traefik.enable: " + val + "\n")
        for val in ('"1"', '"t"', '"T"', '"TRUE"', '"True"', '"true "', '" true"', '"yes"', '"on"', '"0"', '"F"', '"FALSE"', '""', "1", "0", "yes", "on"):
            with self.subTest(val=val):
                errors, _ = self.run_raw(S_HDR, side(val))
                self.assertError(errors, "services.side: traefik.enable is")
        for lab in ("      - traefik.enable\n", "      - traefik.enable=1\n"):
            with self.subTest(lab=lab):
                errors, _ = self.run_raw(S_HDR, s_compose(services=S_INIT + "  side:\n    image: x\n    labels:\n" + lab))
                self.assertError(errors, "services.side: traefik.enable is")
        errors, _ = self.run_raw(S_HDR, s_compose(services=S_INIT + "  side:\n    image: x\n    labels:\n      traefik.enable: \"false\"\n      Traefik.Enable: \"true\"\n"))
        self.assertError(errors, "traefik.enable is set twice")
        errors, _ = self.run_raw(S_HDR, s_compose(services=S_INIT + "  side:\n    image: x\n    labels:\n      Traefik.Enable: \"true\"\n"))
        self.assertError(errors, "without an HTTP router rule")
        for val in ('"true"', "true", "True", "TRUE"):
            with self.subTest(ok=val):
                errors, _ = self.run_raw(S_HDR, s_compose(labels="      traefik.enable: " + val + "\n"))
                self.assertClean(errors)
        for val in ('"false"', "false"):
            with self.subTest(ok=val):
                errors, _ = self.run_raw(S_HDR, side(val))
                self.assertFalse([e for e in errors if "traefik.enable" in e], errors)

    def test_check_id_shape(self) -> None:
        for app_id in ("a-portcullis-b", "portcullis", "x-portcullis", "portcullis-x", "a_portcullis_b", "my_app", "my--app", "app-", "app_", "a_b"):
            with self.subTest(app_id=app_id):
                errors, _ = self.run_raw(S_HDR, s_compose(), app_id=app_id)
                self.assertError(errors, "id")
                self.assertTrue(any(app_id + "/" in e and ("portcullis may not be a segment" in e or "single -" in e) for e in errors), errors)
        for app_id in ("my-app", "a-portcullisx", "portcullisx-b", "xportcullis-b", "firefox-sync", "a1-2b"):
            with self.subTest(app_id=app_id):
                self.assertIsNone(v.check_id_shape(app_id))

    def test_duplicate_router_name_refused(self) -> None:
        init = (S_INIT.rstrip("\n") + "\n    networks:\n      - default\n      - portcullis-proxy\n    labels:\n      traefik.enable: \"true\"\n" + router("demo", S_HOST))
        errors, _ = self.run_raw(S_HDR, s_compose(services=init))
        self.assertError(errors, "router demo is defined on services demo and init: give each its own name")
        errors, _ = self.run_raw(S_HDR, s_compose(services=init.replace("routers.demo.", "routers.side.").replace(S_HOST, S_HOST + " && PathPrefix(`/s`)")))
        self.assertFalse([e for e in errors if "defined on services" in e], errors)

    def test_header_network_mode_service(self) -> None:
        def layout(mode: str, extra: str = "", auth: bool = False) -> str:
            side = router("side", S_HOST + " && PathPrefix(`/side`)", gated=False)
            if auth:   # forward-auth without group-gate on side
                side = side.replace("security-headers@file", "portcullis-auth@docker,security-headers@file")
            return ("services:\n  web:\n    image: x\n    labels:\n      traefik.enable: \"true\"\n" + router("demo", S_HOST) +
                    f"  side:\n    image: x\n    network_mode: \"{mode}\"\n    labels:\n      traefik.enable: \"true\"\n" + side + extra)
        m = S_HDR + s_opts(S_PERSON_HEADER)
        for name, c in (("service:web", layout("service:web")),
                        ("chained", layout("service:mid", "  mid:\n    image: x\n    network_mode: \"service:web\"\n")),
                        ("chained twice", layout("service:mid", "  mid:\n    image: x\n    network_mode: \"service:mid2\"\n  mid2:\n    image: x\n    network_mode: \"service:web\"\n"))):
            with self.subTest(name):
                errors, _ = self.run_raw(m, c)
                self.assertError(errors, "router side reaches service web (its network namespace) without Portcullis forward-auth")
        rev = ("services:\n  web:\n    image: x\n    network_mode: \"service:side\"\n    labels:\n      traefik.enable: \"true\"\n" + router("demo", S_HOST) +
               "  side:\n    image: x\n    labels:\n      traefik.enable: \"true\"\n" + router("side", S_HOST + " && PathPrefix(`/side`)", gated=False))
        errors, _ = self.run_raw(m, rev)
        self.assertError(errors, "router side reaches service side")
        errors, _ = self.run_raw(m, layout("service:web", auth=True))
        self.assertFalse([e for e in errors if "setting quota:" in e or "YAML" in e], errors)
        errors, _ = self.run_raw(m, layout("service:mid", "  mid:\n    image: x\n    network_mode: \"service:side\"\n"))
        self.assertError(errors, "a cycle?")

    def test_header_network_mode_host_labelled(self) -> None:
        def layout(mode: str, extra: str = "", auth: bool = False) -> str:
            side = router("side", S_HOST + " && PathPrefix(`/side`)", gated=False)
            if auth:   # forward-auth without group-gate on side
                side = side.replace("security-headers@file", "portcullis-auth@docker,security-headers@file")
            return ("services:\n  web:\n    image: x\n    labels:\n      traefik.enable: \"true\"\n" + router("demo", S_HOST) +
                    f"  side:\n    image: x\n    network_mode: \"{mode}\"\n    labels:\n      traefik.enable: \"true\"\n" + side + extra)
        m = S_HDR + s_opts(S_PERSON_HEADER)
        for name, c in (("host, ungated", layout("host")),
                        ("host, gated", layout("host", auth=True)),
                        ("via service: to host", layout("service:mid", "  mid:\n    image: x\n    network_mode: \"host\"\n"))):
            with self.subTest(name):
                errors, _ = self.run_raw(m, c)
                self.assertError(errors, "service side has Traefik labels and runs in the host's network namespace")
        errors, _ = self.run_raw(S_HDR, layout("host"))
        self.assertFalse([e for e in errors if "host's network namespace" in e], errors)
        errors, _ = self.run_raw(m, s_compose(services=S_INIT + "  agent:\n    image: x\n    network_mode: \"host\"\n"))
        self.assertFalse([e for e in errors if "host's network namespace" in e], errors)

    def test_header_unresolvable_service_refused(self) -> None:
        for svc in ("x@file", "nope", "nope@docker", "weighted@internal"):
            with self.subTest(svc=svc):
                c = s_compose(routers=router("demo", S_HOST) + f"      traefik.http.routers.demo.service: {svc}\n")
                errors, _ = self.run_raw(S_HDR + s_opts(S_PERSON_HEADER), c)
                self.assertError(errors, f"router demo's service {svc}")
        c = s_compose(routers=router("demo", S_HOST) + "      traefik.http.routers.demo.service: Demo@Docker\n")
        errors, _ = self.run_raw(S_HDR + s_opts(S_PERSON_HEADER), c)
        self.assertFalse([e for e in errors if "setting quota:" in e], errors)

    def test_interpolation_escapes(self) -> None:
        for s, want in {"${X}": True, "a${X:-1}": True, "$${X}": False, "$$${X}": True, "$$$${X}": False,
                        "${XY}": False, "$X": False, "${X-a}": True, "${X?err}": True, "${X:+y}": True}.items():
            with self.subTest(s=s):
                self.assertEqual(v.compose_references(s, "X"), want)
        o = "{key: disks, label: D, type: list, items: {type: string}, max_items: 2, delivery: [{env: 'DISK_{n}'}]}"
        base = s_env("DISK_1", "DISK_2")
        self.cases([
            ("escaped beyond", S_HDR + s_opts(o), s_compose(base + "      X: $${DISK_3}\n"), "", ""),
            ("interpolated beyond", S_HDR + s_opts(o), s_compose(base + "      X: $$${DISK_3}\n"), "disks", "DISK_3"),
            ("escaped only", S_HDR + s_opts("{key: theme, label: T, type: string}"), s_compose("      THEME: $${THEME}\n"), "theme", "hard-codes"),
        ])



# ── Shared folders (contract §13.15): Hub templates/folders_test.go, case for case ──

F_IMG = f"demo/x:1.0.0@sha256:{S_DIGEST}"


def f_svc(name: str, body: str = "") -> str:
    return f"  {name}:\n    image: {F_IMG}\n{body}"


# fixed / named: the Hub fixture's services with a numeric and a named compose user:.
F_USERS = f_svc("fixed", '    user: "1000:1000"\n') + f_svc("named", "    user: www-data\n")
F_ENVUSER = f_svc("envuser", '    user: "${PUID:-1000}:${PGID:-1000}"\n')
F_PUID = "{key: puid, label: P, type: int, default: 1000}"
F_PGID = "{key: pgid, label: G, type: int, default: 1000}"
F_RO = ", folder: {access: read, runs_as: {uid: 1000, gid: 1000}}"


def fc(*env: str, extra: str = "", head: str = "") -> str:
    """The demo compose file: env lines interpolating each name on the demo
    service, the fixed / named services and extra services; head goes
    before services: (anchors)."""
    return head + s_compose(s_env(*env), services=S_INIT + F_USERS + extra)


def fp(key: str, svc: str = "demo", extra: str = "") -> str:
    """A path option on service svc (Hub fpath)."""
    return "{key: " + key + ", label: X, type: path, target: {service: " + svc + ", mount: /" + key + "}" + extra + "}"


def fm(*opts: str) -> str:
    return S_HDR + s_opts(*opts)


class TestFolders(Case):
    """tests/validate.py mirrors the Hub's shared-folder validator
    (internal/templates/folders.go): the folder block, checks, lan_only
    ports, the folder gid range and the strict compose id forms."""

    run_raw = TestSettingsV3.run_raw
    cases = TestSettingsV3.cases

    def test_folder_only_on_instance_path(self) -> None:
        self.cases([
            ("string", fm("{key: theme, label: X, type: string, folder: {access: read, runs_as: {uid: 1, gid: 1}}}"), fc("THEME"), "theme", "folder is for path options with scope instance (not type string, scope instance)"),
            ("person path", fm("{key: media, label: X, type: path, scope: person, default: /srv/x, resolve: priority, target: {service: demo, mount: /m}, folder: {access: read, runs_as: {uid: 1, gid: 1}}}"), fc(), "media", "folder is for path options with scope instance (not type path, scope person)"),
            ("ok", fm(fp("media", extra=F_RO)), fc(), "", ""),
        ])

    def test_folder_access_and_runs_as_required(self) -> None:
        self.cases([
            ("no access", fm(fp("media", extra=", folder: {runs_as: {uid: 1000, gid: 1000}}")), fc(), "media", "folder.access is required (read or write)"),
            ("rw", fm(fp("media", extra=", folder: {access: rw, runs_as: {uid: 1000, gid: 1000}}")), fc(), "media", 'folder.access "rw" must be read or write'),
            ("no runs_as", fm(fp("media", extra=", folder: {access: read}")), fc(), "media", "folder.runs_as is required (the uid and gid the app uses on the mount)"),
            ("ok", fm(fp("media", extra=", folder: {access: read, runs_as: {uid: 1000, gid: 1000}}")), fc(), "", ""),
            ("negative", fm(fp("media", extra=", folder: {access: read, runs_as: {uid: -1, gid: 1000}}")), fc(), "media", "folder.runs_as.uid -1 is not a valid id (0-2147483647)"),
            ("too big", fm(fp("media", extra=", folder: {access: read, runs_as: {uid: 1, gid: 2147483648}}")), fc(), "media", "folder.runs_as.gid 2147483648 is not a valid id"),
        ])

    def test_runs_as_one_source_per_id(self) -> None:
        self.cases([
            ("two uid sources", fm(F_PUID, fp("media", extra=", folder: {access: read, runs_as: {uid: 1, uid_env: PUID, gid: 1}}")), fc("PUID"), "media", "folder.runs_as.uid: exactly one of uid, uid_env, uid_from (a number, the env name of an instance int option, or a person_id option)"),
            ("no uid source", fm(fp("media", extra=", folder: {access: read, runs_as: {gid: 1}}")), fc(), "media", "folder.runs_as.uid: exactly one of uid, uid_env"),
            ("no gid source", fm(fp("media", extra=", folder: {access: read, runs_as: {uid: 1}}")), fc(), "media", "folder.runs_as.gid: exactly one of gid, gid_env"),
        ])

    def test_runs_as_env_names_option(self) -> None:
        self.cases([
            ("no option", fm(fp("media", extra=", folder: {access: read, runs_as: {uid_env: PUID, gid: 1}}")), fc(), "media", "folder.runs_as.uid_env PUID is not the env name of an instance int option of this template"),
            ("reserved", fm(fp("media", extra=", folder: {access: read, runs_as: {uid_env: PORTCULLIS_X, gid: 1}}")), fc(), "media", "folder.runs_as.uid_env PORTCULLIS_X is reserved (PORTCULLIS_*: core and the Hub set them)"),
            ("folder variable", fm(fp("media", extra=", folder: {access: read, runs_as: {uid: 1, gid_env: PORTCULLIS_FOLDER_GID_MEDIA}}")), fc(), "media", "folder.runs_as.gid_env PORTCULLIS_FOLDER_GID_MEDIA is reserved"),
            ("string option", fm("{key: puid, label: P, type: string, default: '1000'}", fp("media", extra=", folder: {access: read, runs_as: {uid_env: PUID, gid: 1}}")), fc("PUID"), "media", "not the env name of an instance int option"),
            ("person option", fm("{key: puid, label: P, type: int, scope: person, resolve: max, default: 1, delivery: [{header: {name: X-Forwarded-Attr-Uid}}]}", fp("media", extra=", folder: {access: read, runs_as: {uid_env: PUID, gid: 1}}")), fc(), "media", "not the env name of an instance int option"),
            ("ok", fm(F_PUID, F_PGID, fp("media", extra=", folder: {access: read, runs_as: {uid_env: PUID, gid_env: PGID}}")), fc("PUID", "PGID"), "", ""),
            ("env delivery name", fm("{key: user_id, label: P, type: int, default: 1000, delivery: [{env: PUID}]}", fp("media", extra=", folder: {access: read, runs_as: {uid_env: PUID, gid: 1}}")), fc("PUID"), "", ""),
            ("second env delivery", fm("{key: user_id, label: P, type: int, default: 1000, delivery: [{env: OTHER_UID}, {env: PUID}]}", fp("media", extra=", folder: {access: read, runs_as: {uid_env: PUID, gid: 1}}")), fc("OTHER_UID", "PUID"), "", ""),
        ])

    def test_runs_as_matches_compose_user(self) -> None:
        both = (F_PUID, F_PGID)
        self.cases([
            ("gid differs", fm(fp("media", "fixed", ", folder: {access: read, runs_as: {uid: 1000, gid: 100}}")), fc(), "media", 'folder.runs_as.gid 100 doesn\'t match service fixed\'s compose user: "1000:1000"'),
            ("uid differs", fm(fp("media", "fixed", ", folder: {access: read, runs_as: {uid: 0, gid: 1000}}")), fc(), "media", "folder.runs_as.uid 0 doesn't match"),
            ("numbers match", fm(fp("media", "fixed", ", folder: {access: read, runs_as: {uid: 1000, gid: 1000}}")), fc(), "", ""),
            ("env form", fm(*both, fp("media", "envuser", ", folder: {access: read, runs_as: {uid_env: PUID, gid_env: PGID}}")), fc("PUID", "PGID", extra=F_ENVUSER), "", ""),
            ("env user, numbers", fm(*both, fp("media", "envuser", ", folder: {access: read, runs_as: {uid: 1000, gid: 1000}}")), fc("PUID", "PGID", extra=F_ENVUSER), "media", "folder.runs_as.uid: service envuser's compose user: takes it from ${PUID}: use uid_env: PUID"),
            ("env user, other env", fm(*both, "{key: other, label: O, type: int, default: 1}", fp("media", "envuser", ", folder: {access: read, runs_as: {uid_env: OTHER, gid_env: PGID}}")), fc("PUID", "PGID", "OTHER", extra=F_ENVUSER), "media", 'folder.runs_as.uid_env OTHER doesn\'t match service envuser\'s compose user: "${PUID:-1000}:${PGID:-1000}" (use uid_env: PUID)'),
            ("numeric user, env", fm(*both, fp("media", "fixed", ", folder: {access: read, runs_as: {uid_env: PUID, gid_env: PGID}}")), fc("PUID", "PGID"), "media", 'folder.runs_as.uid_env PUID doesn\'t match service fixed\'s compose user: "1000:1000" (use uid: 1000)'),
            ("named user", fm(fp("media", "named", ", folder: {access: read, runs_as: {uid: 33, gid: 33}}")), fc(), "media", "service named's compose user: \"www-data\" is not numeric next to a folder block: give numbers in compose `user:`"),
            ("named user, no folder", fm(fp("media", "named")), fc(), "", ""),
            ("uid only user", fm(fp("media", "solo", ", folder: {access: read, runs_as: {uid: 1000, gid: 5}}")), fc(extra=f_svc("solo", '    user: "1000"\n')), "", ""),
        ])

    def test_folder_gid_range_refused(self) -> None:
        self.cases([
            ("runs_as.gid", fm(fp("media", extra=", folder: {access: read, runs_as: {uid: 1000, gid: 60000}}")), fc(), "media", "folder.runs_as.gid 60000 is in 60000-60999 (shared folder groups)"),
            ("writes_as.gid", fm(fp("media", extra=", writes_as: {uid: 1000, gid: 60999}")), fc(), "media", "writes_as.gid 60999 is in 60000-60999 (shared folder groups)"),
            ("edge ok", fm(fp("media", extra=", folder: {access: read, runs_as: {uid: 60000, gid: 61000}}")), fc(), "", ""),
            ("edge below ok", fm(fp("media", extra=", folder: {access: read, runs_as: {uid: 1, gid: 59999}}")), fc(), "", ""),
            ("compose user gid", fm(fp("media")), fc(extra=f_svc("high", '    user: "1000:60001"\n')), "", "service high: compose user: gid 60001 is in 60000-60999 (shared folder groups)"),
            ("gid_env default", fm(F_PUID, "{key: pgid, label: G, type: int, default: 60005}", fp("media", extra=", folder: {access: read, runs_as: {uid_env: PUID, gid_env: PGID}}")), fc("PUID", "PGID"), "media", "folder.runs_as.gid_env PGID names setting pgid, whose default 60005 is in 60000-60999 (shared folder groups)"),
        ])

    def test_folder_gid_defaults_read(self) -> None:
        g = ", folder: {access: read, runs_as: {uid_env: PUID, gid_env: PGID}}"
        c = fc("PUID", "PGID")
        self.cases([
            ("string default", fm(F_PUID, "{key: pgid, label: G, type: int, default: '60001'}", fp("media", extra=g)), c, "media", "whose default 60001 is in 60000-60999"),
            ("float default", fm(F_PUID, "{key: pgid, label: G, type: int, default: 60001.0}", fp("media", extra=g)), c, "media", "whose default 60001 is in 60000-60999"),
            ("unreadable default", fm(F_PUID, fp("media", extra=g), "{key: pgid, label: G, type: int, default: lots}"), c, "media", 'folder.runs_as.gid_env PGID names setting pgid, whose default "lots" is not a whole number'),
            ("bool default", fm(F_PUID, fp("media", extra=g), "{key: pgid, label: G, type: int, default: true}"), c, "media", "whose default true is not a whole number"),
            ("string default ok", fm(F_PUID, "{key: pgid, label: G, type: int, default: '1000'}", fp("media", extra=g)), c, "", ""),
            ("writes_as ref in range", fm("{key: pgid, label: G, type: int, default: 60001}", fp("media", extra=", writes_as: {uid: 0, gid: pgid}")), fc("PGID"), "media", "writes_as.gid: setting pgid's default 60001 is in 60000-60999 (shared folder groups)"),
            ("writes_as ref string", fm("{key: pgid, label: G, type: string, default: 'x'}", fp("media", extra=", writes_as: {uid: 0, gid: pgid}")), fc("PGID"), "media", 'writes_as.gid: setting pgid\'s default "x" is not a whole number'),
            ("writes_as uid ref unreadable", fm("{key: puid, label: P, type: string, default: 'x'}", fp("media", extra=", writes_as: {uid: puid, gid: 0}")), fc("PUID"), "media", 'writes_as.uid: setting puid\'s default "x" is not a whole number'),
            ("writes_as ref ok", fm("{key: pgid, label: G, type: string, default: '1000'}", fp("media", extra=", writes_as: {uid: 0, gid: pgid}")), fc("PGID"), "", ""),
        ])

    def test_uid_defaults_not_range_checked(self) -> None:
        self.cases([
            ("uid_env default", fm("{key: puid, label: P, type: int, default: 60001}", F_PGID, fp("media", extra=", folder: {access: read, runs_as: {uid_env: PUID, gid_env: PGID}}")), fc("PUID", "PGID"), "", ""),
            ("writes_as uid key", fm("{key: puid, label: P, type: int, default: 60001}", fp("media", extra=", writes_as: {uid: puid, gid: 0}")), fc("PUID"), "", ""),
        ])

    def test_joins_group(self) -> None:
        self.cases([
            ("gid_env without runs_as.gid_env", fm(fp("media", extra=", folder: {access: read, runs_as: {uid: 1000, gid: 1000}, joins_group: gid_env}")), fc(), "media", "folder.joins_group: gid_env needs runs_as.gid_env (the variable the folder gid is written to)"),
            ("sudo", fm(fp("media", extra=", folder: {access: read, runs_as: {uid: 1000, gid: 1000}, joins_group: sudo}")), fc(), "media", 'folder.joins_group "sudo" must be group_add, gid_env or template'),
            ("gid_env ok", fm(F_PUID, F_PGID, fp("media", extra=", folder: {access: read, runs_as: {uid_env: PUID, gid_env: PGID}, joins_group: gid_env}")), fc("PUID", "PGID"), "", ""),
            ("template ok", fm(fp("media", extra=", folder: {access: read, runs_as: {uid: 1000, gid: 1000}, joins_group: template}")), fc(), "", ""),
            ("group_add ok", fm(fp("media", extra=", folder: {access: read, runs_as: {uid: 1000, gid: 1000}, joins_group: group_add}")), fc(), "", ""),
        ])

    def test_must_own_writers_only(self) -> None:
        self.cases([
            ("read", fm(fp("media", extra=", folder: {access: read, runs_as: {uid: 1000, gid: 1000}, must_own: true}")), fc(), "media", "folder.must_own needs access: write (the Hub makes the app the owner of what it writes)"),
            ("write", fm(fp("media", extra=", folder: {access: write, runs_as: {uid: 1000, gid: 1000}, must_own: true}")), fc(), "", ""),
        ])

    def test_folder_replaces_mode_needs_writes_as(self) -> None:
        self.cases([(f, fm(fp("media", extra=", " + f + F_RO)), fc(), "media",
                     f"{f.split(':')[0]} together with folder: folder.access and folder.runs_as replace them")
                    for f in ("mode: rw", "needs: write", "writes_as: {uid: 1, gid: 1}")])

    def test_same_env_same_runs_as(self) -> None:
        a = fp("movies", extra=", folder: {access: read, runs_as: {uid_env: PUID, gid_env: PGID}, joins_group: gid_env}")
        b = fp("tv", extra=", folder: {access: read, runs_as: {uid_env: PUID, gid_env: PGID}}")
        same = fp("tv", extra=", folder: {access: write, runs_as: {uid_env: PUID, gid_env: PGID}, joins_group: gid_env}")
        other = fp("tv", "fixed", ", folder: {access: read, runs_as: {uid: 1000, gid: 1000}}")
        uid = fp("tv", extra=", folder: {access: read, runs_as: {uid_env: PUID, gid: 5}}")
        uid0 = fp("movies", extra=", folder: {access: read, runs_as: {uid_env: PUID, gid: 6}}")
        c = fc("PUID", "PGID")
        self.cases([
            ("differ", fm(F_PUID, F_PGID, a, b), c, "tv", "folder names gid_env PGID like setting movies on service demo, with another runs_as or joins_group (one primary gid per process: use identical blocks)"),
            ("identical", fm(F_PUID, F_PGID, a, same), c, "", ""),
            ("other service", fm(F_PUID, F_PGID, a, other), c, "", ""),
            ("uid_env differ", fm(F_PUID, uid0, uid), fc("PUID"), "tv", "folder names uid_env PUID like setting movies on service demo"),
        ])

    def test_gid_env_join_owns_service(self) -> None:
        a = fp("movies", extra=", folder: {access: read, runs_as: {uid_env: PUID, gid_env: PGID}, joins_group: gid_env}")
        num = fp("tv", extra=", folder: {access: read, runs_as: {uid: 1000, gid: 1000}}")
        c = fc("PUID", "PGID")
        self.cases([
            ("numeric after gid_env join", fm(F_PUID, F_PGID, a, num), c, "tv", "service demo joins a folder group through gid_env PGID: every folder option on it must use runs_as.gid_env PGID (setting tv doesn't)"),
            ("gid_env join after numeric", fm(F_PUID, F_PGID, num, a), c, "movies", "service demo joins a folder group through gid_env PGID: every folder option on it must use runs_as.gid_env PGID (setting tv doesn't)"),
        ])

    def test_gid_env_join_variable_not_shared(self) -> None:
        join = fp("movies", "envuser", ", folder: {access: read, runs_as: {uid_env: PUID, gid_env: PGID}, joins_group: gid_env}")
        m = fm(F_PUID, F_PGID, join)
        base = ("PUID", "PGID")
        self.cases([
            ("alone", m, fc(*base, extra=F_ENVUSER), "", ""),
            ("sidecar group_add", m, fc(*base, extra=F_ENVUSER + f_svc("side", '    group_add: ["${PGID}"]\n')), "movies",
             "folder.joins_group: gid_env writes the folder gid to PGID, which service side's group_add also reads: only the services the folder options target may use a gid_env variable"),
            ("sidecar user", m, fc(*base, extra=F_ENVUSER + f_svc("side", '    user: "${PUID:-1000}:${PGID:-1000}"\n')), "movies",
             "folder.joins_group: gid_env writes the folder gid to PGID, which service side's compose user: gid also reads: only the services the folder options target may use a gid_env variable"),
            ("group_add join elsewhere ok", fm(F_PUID, F_PGID, fp("movies", "envuser", ", folder: {access: read, runs_as: {uid_env: PUID, gid_env: PGID}}")),
             fc(*base, extra=F_ENVUSER + f_svc("side", '    group_add: ["${PGID}"]\n')), "", ""),
        ])

    def test_uid_from_not_reserved(self) -> None:
        """Hub TestUIDFromNotReserved: uid_from / gid_from are typed (file sharing)."""
        self.cases([
            ("uid_from", fm(fp("media", extra=", folder: {access: write, runs_as: {uid_from: person_uid, gid: 0}}")), fc(), "media", "folder.runs_as.uid_from person_uid is not a person_id option"),
            ("gid_from", fm(fp("media", extra=", folder: {access: write, runs_as: {uid: 0, gid_from: person_gid}}")), fc(), "media", "folder.runs_as.gid_from needs uid_from"),
        ])
        self.assertFalse(hasattr(v, "reserved_use"), "only type folder is still reserved")

    def test_runs_as_non_integer_friendly(self) -> None:
        self.cases([
            ("string uid", fm(fp("media", extra=", folder: {access: read, runs_as: {uid: abc, gid: 1}}")), fc(), "", 'folder.runs_as.uid: want a whole number, not "abc" (a variable goes in uid_env)'),
            ("float gid", fm(fp("media", extra=", folder: {access: read, runs_as: {uid: 1, gid: 1.5}}")), fc(), "", 'folder.runs_as.gid: want a whole number, not "1.5" (a variable goes in gid_env)'),
            ("quoted uid", fm(fp("media", extra=", folder: {access: read, runs_as: {uid: '1000', gid: 1}}")), fc(), "", 'folder.runs_as.uid: want a whole number, not "1000"'),
            ("bool gid", fm(fp("media", extra=", folder: {access: read, runs_as: {uid: 1, gid: true}}")), fc(), "", "folder.runs_as.gid: want a whole number"),
            ("hex ok", fm(fp("media", extra=", folder: {access: read, runs_as: {uid: 0x10, gid: 1}}")), fc(), "", ""),
            ("null gid = no source", fm(fp("media", extra=", folder: {access: read, runs_as: {uid: 1, gid: ~}}")), fc(), "media", "folder.runs_as.gid: exactly one of gid, gid_env"),
        ])

    def test_compose_gid_defaults_refused(self) -> None:
        ints = ("{key: xg, label: XG, type: int}", "{key: g, label: G, type: int}", "{key: u, label: U, type: int}")
        env = ("XG", "G", "U")
        p = fm(*ints, fp("media"))
        with_string = fm(*ints, "{key: name, label: N, type: string}", fp("media"))

        def svc(body: str, *more: str) -> str:
            return fc(*env, *more, extra=f_svc("extra", body))
        self.cases([
            ("uid undeclared", p, svc('    user: "${NOPE}:1000"\n'), "", "service extra: compose user: uid ${NOPE} must name an instance int option of this template (not a string option, an undeclared variable or PORTCULLIS_*)"),
            ("gid undeclared", p, svc('    user: "1000:$NOPE"\n'), "", "service extra: compose user: gid ${NOPE} must name an instance int option of this template"),
            ("gid string option", with_string, svc('    user: "1000:${NAME}"\n', "NAME"), "", "compose user: gid ${NAME} must name an instance int option"),
            ("uid string option", with_string, svc('    user: "${NAME}"\n', "NAME"), "", "compose user: uid ${NAME} must name an instance int option"),
            ("gid portcullis", p, svc('    user: "1000:${PORTCULLIS_INSTANCE}"\n'), "", "compose user: gid ${PORTCULLIS_INSTANCE} must name an instance int option"),
            ("group_add undeclared", p, svc('    group_add: ["${NOPE:-1000}"]\n'), "", "service extra: group_add ${NOPE} must name an instance int option of this template"),
            ("group_add string option", with_string, svc("    group_add: [$NAME]\n", "NAME"), "", "group_add ${NAME} must name an instance int option"),
            ("user :- default", p, svc('    user: "1000:${XG:-60001}"\n'), "", "service extra: compose user: gid 60001 (the default of ${XG}) is in 60000-60999 (shared folder groups)"),
            ("user - default", p, svc('    user: "1000:${XG-60002}"\n'), "", "gid 60002 (the default of ${XG}) is in 60000-60999"),
            ("user option default", fm("{key: pgid, label: G, type: int, default: 60003}", fp("media")), fc("PGID", extra=f_svc("extra", '    user: "1000:${PGID:-1000}"\n')), "", "service extra: compose user: gid ${PGID} is setting pgid, whose default 60003 is in 60000-60999 (shared folder groups)"),
            ("user ok", p, svc('    user: "1000:${XG:-1000}"\n'), "", ""),
            ("group_add literal", p, svc('    group_add: ["60001"]\n'), "", "service extra: group_add gid 60001 is in 60000-60999 (shared folder groups)"),
            ("group_add int", p, svc("    group_add: [10001, 60999]\n"), "", "service extra: group_add gid 60999 is in 60000-60999"),
            ("group_add default", p, svc('    group_add: ["${G:-60500}"]\n'), "", "service extra: group_add gid 60500 (the default of ${G}) is in 60000-60999"),
            ("group_add option default", fm("{key: pgid, label: G, type: int, default: 60004}", fp("media")), fc("PGID", extra=f_svc("extra", '    group_add: ["${PGID}"]\n')), "", "service extra: group_add ${PGID} is setting pgid, whose default 60004 is in 60000-60999"),
            ("group_add names ok", p, svc('    group_add: [video, "10001", "${G-1000}", $G]\n'), "", ""),
            ("group_add plus", p, svc('    group_add: ["${G:+1000}"]\n'), "", 'group_add entry "${G:+1000}" must be'),
            ("group_add plus bare", p, svc('    group_add: ["${G+1000}"]\n'), "", 'group_add entry "${G+1000}" must be'),
            ("group_add escaped", p, svc('    group_add: ["$${G:-60500}"]\n'), "", 'service extra: group_add entry "$${G:-60500}" must be a whole number, a group name or exactly one ${NAME} / $NAME (no mixed forms)'),
            ("group_add mixed", p, svc('    group_add: ["${XG:-6}0001"]\n'), "", 'service extra: group_add entry "${XG:-6}0001" must be a whole number, a group name or exactly one ${NAME} / $NAME (no mixed forms)'),
            ("group_add nested", p, svc('    group_add: ["${XG:-${G:-60001}}"]\n'), "", 'group_add entry "${XG:-${G:-60001}}" must be'),
            ("user mixed", p, svc('    user: "1000:${XG:-6}0001"\n'), "", 'service extra: compose user: gid "${XG:-6}0001" must be a whole number or exactly one ${NAME} / $NAME (no mixed forms)'),
            ("user two refs", p, svc('    user: "1000:${XG}${G}"\n'), "", 'compose user: gid "${XG}${G}" must be'),
            ("group_add text fallback", p, svc('    group_add: ["${G:-abc}"]\n'), "", 'group_add entry "${G:-abc}" must be'),
            ("group_add empty fallback", p, svc('    group_add: ["${G:-}"]\n'), "", 'group_add entry "${G:-}" must be'),
            ("group_add $ fallback", p, svc('    group_add: ["${G:-$U}"]\n'), "", 'group_add entry "${G:-$U}" must be'),
            ("group_add error form", p, svc('    group_add: ["${G:?unset}"]\n'), "", 'group_add entry "${G:?unset}" must be'),
            ("user forms ok", p, svc('    user: "${U}:${XG-1000}"\n'), "", ""),
            ("user plus", p, svc('    user: "1000:${XG:+1000}"\n'), "", 'compose user: gid "${XG:+1000}" must be'),
            ("user plus in range", p, svc('    user: "1000:${XG+60001}"\n'), "", 'compose user: gid "${XG+60001}" must be'),
            ("uid mixed", p, svc('    user: "${XG:-6}0001:1000"\n'), "", 'service extra: compose user: uid "${XG:-6}0001" must be a whole number, a user name or exactly one ${NAME} / $NAME (no mixed forms)'),
            ("uid plus", p, svc('    user: "${XG:+0}"\n'), "", 'compose user: uid "${XG:+0}" must be'),
            ("uid colon fallback", p, svc('    user: "${XG:-1:60001}"\n'), "", 'service extra: compose user: "${XG:-1:60001}": a ${…} fallback may only be a whole number (no \':\', \'$\' or nesting)'),
            ("uid dollar fallback", p, svc('    user: "${XG:-$G}:1000"\n'), "", "a ${…} fallback may only be a whole number"),
            ("unterminated", p, svc('    user: "${XG:-1"\n'), "", "a ${…} fallback may only be a whole number"),
            ("uid name ok", p, svc("    user: www-data\n"), "", ""),
            ("uid forms ok", p, svc('    user: "${U-1000}:${G:-1000}"\n'), "", ""),
            ("uid bare ok", p, svc('    user: "$U:1000"\n'), "", ""),
            ("user text fallback", p, svc('    user: "1000:${XG:-x}"\n'), "", 'compose user: "1000:${XG:-x}": a ${…} fallback may only be a whole number'),
            ("user gid name", p, svc('    user: "1000:staff"\n'), "", 'compose user: gid "staff" must be'),
            ("group_add not a list", p, svc('    group_add: "60001"\n'), "", "service extra: group_add must be a list"),
            ("group_add mapping entry", p, svc("    group_add: [{a: 1}]\n"), "", "service extra: group_add entries must be numbers or names"),
            ("no settings at all", S_HDR, fc(extra=f_svc("extra", '    group_add: ["60001"]\n')), "", "service extra: group_add gid 60001 is in 60000-60999"),
        ])

    def test_folder_service_references_resolve(self) -> None:
        m = fm(F_PUID, F_PGID, fp("media", "extra", F_RO))
        c = ("PUID", "PGID")
        self.cases([
            ("unknown ref", m, fc(*c, extra=f_svc("extra", '    group_add: ["${NOPE:-1000}"]\n')), "", "service extra: group_add ${NOPE} must name an instance int option of this template"),
            ("named group", m, fc(*c, extra=f_svc("extra", "    group_add: [video]\n")), "media", 'service extra\'s group_add entry "video" next to a folder block must be a number or ${NAME} of an instance int option'),
            ("mixed", m, fc(*c, extra=f_svc("extra", '    group_add: ["1${PGID}"]\n')), "", 'group_add entry "1${PGID}" must be a whole number, a group name or exactly one'),
            ("option ref ok", m, fc(*c, extra=f_svc("extra", '    group_add: ["${PGID:-1000}", "10001", 44]\n')), "", ""),
            ("named group without folder", fm(F_PUID, F_PGID, fp("media", "extra")), fc(*c, extra=f_svc("extra", "    group_add: [video]\n")), "", ""),
        ])

    def test_group_add_resolves_strict_forms(self) -> None:
        opts = [{"key": "pgid", "type": "int"}]
        for e, ok in {"${PGID}": True, "$PGID": True, "${PGID:-1000}": True, "${PGID-1000}": True, "1000": True,
                      "${PGID:+1000}": False, "${PGID+1000}": False, "${PGID:-abc}": False, "${PGID:-$X}": False,
                      "${PGID:-${X}}": False, "${PGID?e}": False, "${NOPE}": False, "video": False, "x${PGID}": False}.items():
            with self.subTest(e=e):
                f = v.FolderCheck(opts, {}, {"s": [e]})
                self.assertEqual(f.group_add_resolves("s") is None, ok, f.group_add_resolves("s"))

    def test_compose_ids_forms(self) -> None:
        two = lambda d="": fm("{key: g2, label: G, type: int" + d + ", delivery: [{env: FIRST}, {env: SECOND}]}", fp("media"))  # noqa: E731
        anchors = 'x-u: &u "1000:60001"\nx-g: &g "60002"\n'

        def svc(body: str, head: str = "") -> str:
            return fc("FIRST", "SECOND", extra=f_svc("extra", body), head=head)
        self.cases([
            ("aliased user", two(), svc("    user: *u\n", anchors), "", "service extra: compose user: gid 60001 is in 60000-60999"),
            ("aliased group_add entry", two(), svc("    group_add: [*g]\n", anchors), "", "service extra: group_add gid 60002 is in 60000-60999"),
            ("aliased group_add list", two(), svc("    group_add: *l\n", "x-l: &l [\"60003\"]\n"), "", "service extra: group_add gid 60003 is in 60000-60999"),
            # validate.py's loader refuses << merge keys outright (compose_ids follows them: below).
            ("merged service", two(), fc("FIRST", "SECOND", extra="  extra:\n    <<: *base\n    image: " + F_IMG + "\n", head="x-base: &base\n  group_add: [\"60004\"]\n"), "", "YAML does not parse"),
            ("octal group_add", two(), svc("    group_add: [0165141]\n"), "", "service extra: group_add gid 60001 is in 60000-60999"),
            ("yaml 1.2 octal group_add", two(), svc("    group_add: [0o165141]\n"), "", "service extra: group_add"),
            ("hex group_add", two(), svc("    group_add: [0xEA61]\n"), "", "service extra: group_add gid 60001 is in 60000-60999"),
            ("underscore group_add", two(), svc("    group_add: [60_001]\n"), "", "service extra: group_add gid 60001 is in 60000-60999"),
            ("08 is a float", two(), svc("    group_add: [08]\n"), "", "service extra: group_add entries must be numbers or names"),
            ("float group_add", two(), svc("    group_add: [60001.0]\n"), "", "service extra: group_add entries must be numbers or names"),
            ("explicit int", two(), svc('    group_add: [!!int "0165141"]\n'), "", "service extra: group_add gid 60001 is in 60000-60999"),
            ("explicit int base 60", two(), svc('    group_add: [!!int "1:0"]\n'), "", "service extra: group_add entries must be numbers or names"),
            ("explicit float user", two(), svc("    user: !!float 1000\n"), "", "service extra: user: want a string or a whole number, not !!float"),
            ("null entry", two(), svc("    group_add: [~]\n"), "", "service extra: group_add entries must be numbers or names"),
            ("str user ok", two(), svc("    user: !!str 1000\n"), "", ""),
            ("octal user", two(), svc("    user: 0165141\n"), "", ""),
            ("timestamp user", two(), svc("    user: 2001-12-14\n"), "", "service extra:"),
            ("second env delivery ok", two(), svc('    user: "1000:${SECOND}"\n    group_add: [$SECOND]\n'), "", ""),
            ("second env delivery default", two(", default: 60003"), svc('    group_add: ["${SECOND}"]\n'), "", "service extra: group_add ${SECOND} is setting g2, whose default 60003 is in 60000-60999"),
        ])

    def test_v3_scalar_resolution(self) -> None:
        """yaml.v3's resolve() for plain scalars, as idScalar sees them."""
        for val, want in {"0165141": ("int", 60001), "0o165141": ("int", 60001), "0xEA61": ("int", 60001), "60_001": ("int", 60001),
                          "+60001": ("int", 60001), "-1": ("int", -1), "08": ("float", None), "1.5": ("float", None),
                          ".5": ("float", None), "~": ("null", None), "": ("null", None), "null": ("null", None),
                          "true": ("bool", None), "yes": ("str", None), "www-data": ("str", None), "0b11": ("int", 3),
                          "18446744073709551615": ("int", 18446744073709551615), "2001-12-14": ("timestamp", None)}.items():
            with self.subTest(val=val):
                tag, n = v.v3_plain_resolve(val)
                self.assertEqual(tag, want[0])
                if want[1] is not None:
                    self.assertEqual(n, want[1])

    def test_binary_tag_refused(self) -> None:
        p = fm(fp("media"))
        self.cases([
            ("group_add", p, fc(extra=f_svc("extra", "    group_add: [!!binary MDYwMDAx]\n")), "", "YAML tag !!binary is not allowed (a binary scalar decodes to text no check sees)"),
            ("user", p, fc(extra=f_svc("extra", "    user: !!binary MTAwMDowNjAwMDE=\n")), "", "YAML tag !!binary is not allowed"),
            ("manifest", S_HDR.replace("description: Demo app\n", "description: !!binary aGk=\n") + s_opts(fp("media")), fc(), "", "YAML tag !!binary is not allowed"),
        ])

    def test_compose_ids_merge_keys(self) -> None:
        """yaml.v3 merges << into a service: explicit keys win, then the
        merged maps, the first of a list first."""
        base = 'x-a: &a {user: "1:2", group_add: ["3"]}\nx-b: &b {group_add: ["4"]}\n'
        self.assertEqual(v.compose_ids(base + "services:\n  s:\n    <<: *a\n    user: '5:6'\n"), ({"s": "5:6"}, {"s": ["3"]}, ""))
        self.assertEqual(v.compose_ids(base + "services:\n  s:\n    <<: [*b, *a]\n")[1], {"s": ["4"]})
        self.assertEqual(v.compose_ids(base + "services:\n  s:\n    '<<': *a\n"), ({}, {}, ""))
        self.assertTrue(v.compose_ids("services:\n  s:\n    <<: 1\n")[2])

    def test_compose_ids_decode_error(self) -> None:
        users, ga, err = v.compose_ids("services:\n  a: [1, 2]\n")
        self.assertTrue(err, (users, ga))
        users, ga, err = v.compose_ids("services:\n  s:\n    user: !!str 1000\n    group_add: [!!int 10001]\n")
        self.assertEqual((users, ga, err), ({"s": "1000"}, {"s": ["10001"]}, ""))

    def test_checks_catalog(self) -> None:
        reason = ", reason: macOS clients store metadata in extended attributes"

        def ck(c: str) -> str:
            return ", checks: [{" + c + "}]"
        wr = ", folder: {access: write, runs_as: {uid: 1, gid: 1}}"
        person = lambda extra: ("{key: quota, label: Q, type: int, scope: person, default: 1, resolve: max, "  # noqa: E731
                                "delivery: [{header: {name: X-Forwarded-Attr-Quota}}]" + extra + "}")
        c = fc()
        self.cases([
            ("unknown kind", fm(fp("media", extra=F_RO + ck("kind: quota" + reason))), c, "media", 'checks[0]: unknown kind "quota" (the catalog: exclusive, filesystem, free_space, requires_group_value)'),
            ("lan_only", fm(fp("media", extra=F_RO + ck("kind: lan_only" + reason))), c, "media", "checks[0]: kind lan_only is not an option check: set lan_only: true on the port"),
            ("empty reason", fm(fp("media", extra=F_RO + ck("kind: filesystem, needs: [acl], reason: ' '"))), c, "media", "checks[0] (filesystem): reason must be one line of 1-200 characters, without control characters"),
            ("no reason", fm(fp("media", extra=F_RO + ck("kind: filesystem, needs: [acl]"))), c, "", "reason"),
            ("long reason", fm(fp("media", extra=F_RO + ck("kind: filesystem, needs: [acl], reason: " + "a" * 201))), c, "media", "reason must be one line of 1-200 characters"),
            ("newline reason", fm(fp("media", extra=F_RO + ck('kind: filesystem, needs: [acl], reason: "a\\nb"'))), c, "media", "reason must be one line"),
            ("200 ok", fm(fp("media", extra=F_RO + ck("kind: filesystem, needs: [acl], reason: " + "é" * 200))), c, "", ""),
            ("filesystem ok", fm(fp("media", extra=F_RO + ck("kind: filesystem, needs: [acl, xattr], not: [nfs]" + reason))), c, "", ""),
            ("needs posix", fm(fp("media", extra=F_RO + ck("kind: filesystem, needs: [posix]" + reason))), c, "media", 'checks[0] (filesystem): needs "posix" must be xattr or acl'),
            ("not ext4", fm(fp("media", extra=F_RO + ck("kind: filesystem, not: [ext4]" + reason))), c, "media", 'not "ext4" must be nfs, cifs or fuse'),
            ("needs twice", fm(fp("media", extra=F_RO + ck("kind: filesystem, needs: [acl, acl]" + reason))), c, "media", 'needs "acl" listed twice'),
            ("filesystem empty", fm(fp("media", extra=F_RO + ck("kind: filesystem" + reason))), c, "media", "checks[0] (filesystem): filesystem needs needs or not (what to check)"),
            ("filesystem no folder", fm(fp("media", extra=ck("kind: filesystem, needs: [acl]" + reason))), c, "media", "checks[0] (filesystem): needs a path option with a folder block"),
            ("exclusive read", fm(fp("media", extra=F_RO + ck("kind: exclusive" + reason))), c, "media", "checks[0] (exclusive): needs a path option with folder.access: write"),
            ("exclusive write", fm(fp("media", extra=wr + ck("kind: exclusive" + reason))), c, "", ""),
            ("exclusive param", fm(fp("media", extra=wr + ck("kind: exclusive, min: 1GiB" + reason))), c, "media", "checks[0] (exclusive): exclusive takes no min"),
            ("exclusive empty needs", fm(fp("media", extra=wr + ck("kind: exclusive, needs: []" + reason))), c, "media", "checks[0] (exclusive): exclusive takes no needs"),
            ("free_space not", fm(fp("media", extra=wr + ck("kind: free_space, min: 1GiB, not: [nfs]" + reason))), c, "media", "checks[0] (free_space): free_space takes no not"),
            ("free_space ok", fm(fp("media", extra=F_RO + ck("kind: free_space, min: 500GiB" + reason))), c, "", ""),
            ("free_space no folder ok", fm(fp("media", extra=ck("kind: free_space, min: 500GiB" + reason))), c, "", ""),
            ("free_space lots", fm(fp("media", extra=F_RO + ck("kind: free_space, min: lots" + reason))), c, "media", 'checks[0] (free_space): min "lots": "lots" is not a size'),
            ("free_space GB", fm(fp("media", extra=F_RO + ck("kind: free_space, min: 500GB" + reason))), c, "media", 'min "500GB"'),
            ("free_space zero", fm(fp("media", extra=F_RO + ck("kind: free_space, min: 0GiB" + reason))), c, "media", "checks[0] (free_space): min must be more than 0"),
            ("free_space bytes ok", fm(fp("media", extra=F_RO + ck("kind: free_space, min: 1048576" + reason))), c, "", ""),
            ("free_space no min", fm(fp("media", extra=F_RO + ck("kind: free_space" + reason))), c, "media", "checks[0] (free_space): free_space needs min (a size such as 500GiB)"),
            ("free_space on string", fm("{key: theme, label: T, type: string" + ck("kind: free_space, min: 1GiB" + reason) + "}"), fc("THEME"), "theme", "checks[0] (free_space): needs a path option"),
            ("requires_group_value instance", fm("{key: theme, label: T, type: string" + ck("kind: requires_group_value" + reason) + "}"), fc("THEME"), "theme", "checks[0] (requires_group_value): needs scope: person"),
            ("requires_group_value person", fm(person(ck("kind: requires_group_value" + reason))), c, "", ""),
            ("kind twice", fm(fp("media", extra=F_RO + ", checks: [{kind: free_space, min: 1GiB" + reason + "}, {kind: free_space, min: 2GiB" + reason + "}]")), c, "media", "checks[1] (free_space): listed twice"),
            ("unknown field", fm(fp("media", extra=F_RO + ck("kind: free_space, min: 1GiB, max: 2GiB" + reason))), c, "", "max"),
        ])
        self.assertEqual(sorted(v.CHECK_KINDS), ["exclusive", "filesystem", "free_space", "requires_group_value"])

    def test_group_names_unshadowed(self) -> None:
        """The folder id-name pattern (Go groupNameRe) never replaces the
        group option's lldap.ValidGroupName (review I1)."""
        self.cases([
            ("leading underscore", fm("{key: grp, label: G, type: group, default: _staff}"), fc("GRP"), "grp", 'default _staff: "_staff" is not a valid group name'),
            ("leading digit", fm("{key: grp, label: G, type: group, default: 1staff}"), fc("GRP"), "", ""),
        ])
        self.assertIsNot(v.GROUP_NAME_RE, v.ID_NAME_RE)

    def test_folder_ref_values(self) -> None:
        """A folder: value is the Hub's (settings.ParseFolderRef): a path
        option's default can't name one."""
        self.cases([
            ("default", fm(fp("media", extra=', default: "folder:media"')), fc(), "media", 'default folder:media: "folder:media": a shared folder value is resolved by the Hub'),
        ])

    def test_lan_only_port(self) -> None:
        ports = ("ports:\n  - {key: SMB, label: SMB, container: 445, default: 445, protocol: tcp, service: demo, lan_only: true}\n"
                 "  - {key: WEB, label: W, container: 80, default: 8080, protocol: tcp, service: demo}\n")
        self.cases([
            ("lan_only", S_HDR + ports, fc(), "", ""),
            ("not a bool", S_HDR + ports.replace("lan_only: true", "lan_only: yes"), fc(), "", "lan_only"),
        ])

    def test_folder_schema(self) -> None:
        """The schema takes the folder block, checks and lan_only (and
        refuses unknown fields in them)."""
        self.cases([
            ("unknown folder field", fm(fp("media", extra=", folder: {access: read, runs_as: {uid: 1, gid: 1}, owner: 1}")), fc(), "", "owner"),
            ("unknown runs_as field", fm(fp("media", extra=", folder: {access: read, runs_as: {uid: 1, gid: 1, user: 1}}")), fc(), "", "user"),
            ("must_own not a bool", fm(fp("media", extra=", folder: {access: write, runs_as: {uid: 1, gid: 1}, must_own: yes}")), fc(), "", "must_own"),
        ])

    def test_real_templates_declare_folders(self) -> None:
        """Every path option of the real templates has a folder block
        (preflight D17 / ruling 13), with the conversions of Task 15."""
        import yaml
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        want = {
            ("immich", "external_library"): {"access": "read", "runs_as": {"uid": 0, "gid": 0}},
            ("jellyfin", "movies_path"): {"access": "read", "runs_as": {"uid": 0, "gid": 0}, "joins_group": "group_add"},
            ("jellyfin", "tv_path"): {"access": "read", "runs_as": {"uid": 0, "gid": 0}, "joins_group": "group_add"},
            ("jellyfin", "music_path"): {"access": "read", "runs_as": {"uid": 0, "gid": 0}, "joins_group": "group_add"},
            ("plex", "movies_path"): {"access": "read", "runs_as": {"uid_env": "PLEX_UID", "gid_env": "PLEX_GID"}, "joins_group": "gid_env"},
            ("plex", "tv_path"): {"access": "read", "runs_as": {"uid_env": "PLEX_UID", "gid_env": "PLEX_GID"}, "joins_group": "gid_env"},
            ("plex", "music_path"): {"access": "read", "runs_as": {"uid_env": "PLEX_UID", "gid_env": "PLEX_GID"}, "joins_group": "gid_env"},
            ("motioneye", "media_path"): {"access": "write", "runs_as": {"uid": 0, "gid": 0}},
            ("timemachine", "storage"): {"access": "write", "runs_as": {"uid_from": "uid", "gid_from": "uid"}, "joins_group": "template"},
            ("timemachine", "avahi_services_dir"): {"access": "write", "runs_as": {"uid": 0, "gid": 0}},
            ("samba", "homes"): {"access": "write", "runs_as": {"uid_from": "uid", "gid_from": "uid"}, "joins_group": "template"},
            ("samba", "avahi_services_dir"): {"access": "write", "runs_as": {"uid": 0, "gid": 0}},
            **{("samba", f"share{n}_folder"): {"access": "write", "runs_as": {"uid_from": "uid"}, "joins_group": "template"}
               for n in range(1, 9)},
        }
        seen = set()
        for app in sorted(os.listdir(root)):
            path = os.path.join(root, app, "manifest.yaml")
            if not os.path.isfile(path):
                continue
            with open(path, encoding="utf-8") as f:
                m = yaml.safe_load(f)
            for o in ((m.get("settings") or {}).get("options") or []):
                if o.get("type") != "path":
                    continue
                seen.add((app, o["key"]))
                self.assertIn((app, o["key"]), want, f"{app} {o['key']}: a path option without a declared folder block")
                self.assertEqual(o.get("folder"), want[(app, o["key"])], f"{app} {o['key']}")
                for f in ("mode", "needs", "writes_as"):
                    self.assertNotIn(f, o, f"{app} {o['key']}")
        self.assertEqual(seen, set(want))



# ── File sharing (contract §3 router-less, §13.2, §13.7, §13.8, §13.15–13.17) ──
#
# TestFileSharing mirrors the Hub's internal/templates/filesharing_test.go,
# filesharing_vars_test.go and routerless_test.go row for row (the refusal
# texts are the Hub's), plus the Hub's secrets-volume (F15) and shared
# namespace (Task 6) refusals and the templates repo's own rules (shared
# portcullis-sync, lan_only ports).

FS_HEAD = """\
name: Files
description: File sharing
icon: "x"
category: storage
tags: [files]
links:
  website: https://demo.example.org/
  source: https://github.com/example/demo
instances: multi
auth:
  method: custom
  sso: false
  group_access: true
  group_admin: false
  access_group: users_demo
  notes: No web page.
tests:
  signin:
    skip: router-less file sharing, no web page
ports:
  - {key: SMB, label: SMB, container: 445, default: 445, protocol: tcp, service: smb, lan_only: true}
files:
  - {name: people, service: smb, mount: /portcullis/data, format: tsv}
hooks:
  - {name: sync, service: smb, command: [/portcullis/portcullis-sync], when: [start, settings_change, membership_change, credential_change], timeout: 60s}
ai:
  unsupported: test fixture
"""
FS_IMG = f"demo/smb:1.0.0@sha256:{S_DIGEST}"


def fs_compose(smb: str = "", other: str = "", extra: str = "") -> str:
    """Router-less: services smb and other, no Traefik router; smb / other
    take extra lines (indented 4)."""
    return f"services:\n  smb:\n    image: {FS_IMG}\n{smb}  other:\n    image: {FS_IMG}\n{other}{extra}"


FS_COMPOSE = fs_compose()
# FS_ROUTED adds a service with an HTTP router.
FS_ROUTED = fs_compose(extra=(
    f"  web:\n    image: {FS_IMG}\n    networks: [default, portcullis-proxy]\n    labels:\n"
    "      traefik.enable: \"true\"\n"
    "      traefik.http.routers.files.rule: Host(`${PORTCULLIS_HOST_FILES:-files.portcullis.local}`)\n"
    "      traefik.http.routers.files.entrypoints: websecure\n"
    "      traefik.http.routers.files.tls.options: authaware@file\n"
    "      traefik.http.routers.files.middlewares: security-headers@file\n"
    "      traefik.http.services.files.loadbalancer.server.port: \"80\"\n"
    "networks:\n  portcullis-proxy:\n    external: true\n"))

FS_PS = ("{key: share_password, label: File-share password, type: person_secret, hash: nt, length: 24, delivery: file, "
         "mount: {service: smb, path: /portcullis/secrets}, revoke_on_leave: true, on_restore: void, applies: live, "
         "username: {pattern: '^[a-z_][a-z0-9_.-]{0,31}$', reserved: [root, nobody], reason: \"isn't a valid Samba and Unix name\"}, "
         "info: [{label: Address, value: 'smb://{value:connect_address}{port_suffix:SMB:445}/Home'}, {label: Username, value: '{user}'}, "
         "{label: Port, value: '{port:SMB}'}]}")
FS_UID = "{key: uid, label: File owner id, type: person_id, pool: posix_uid, self_visible: false, delivery: [{file: {name: people, field: uid}}]}"
FS_CONNECT = ("{key: connect_address, label: Address people connect to, type: string, format: hostname, required: true, "
              "self_visible: true, delivery: [{file: {name: people}}]}")
FS_PATTERN = "'^[a-z_][a-z0-9_.-]{0,31}$'"
FS_SLOT = ("{key: share1_folder, label: Share 1 folder, type: path, target: {service: smb, mount: /shares/1}, "
           "folder: {access: write, runs_as: {uid_from: uid}, joins_group: template}}")


def fs_edit(o: str, *pairs: str) -> str:
    """The Hub test's edit: replace each old / new pair once; an old of "}"
    appends new as extra fields of the flow mapping."""
    for old, new in zip(pairs[::2], pairs[1::2]):
        if old == "}":
            o = o[:-1] + ", " + new + "}"
            continue
        assert old in o, f"no {old} in {o}"
        o = o.replace(old, new, 1)
    return o


def fs_ps(*pairs: str) -> str:
    return fs_edit(FS_PS, *pairs)


def fs_uid(*pairs: str) -> str:
    return fs_edit(FS_UID, *pairs)


def fs_smb(*lines: str) -> str:
    """FS_HEAD with connect_address, uid and the given options."""
    return FS_HEAD + s_opts(FS_CONNECT, FS_UID, *lines)


def fs_env(svc: str, val: str) -> str:
    """A compose file whose service svc has environment KEY: val."""
    line = f"    environment:\n      KEY: {val}\n"
    return fs_compose(smb=line) if svc == "smb" else fs_compose(other=line)


class TestFileSharing(Case):
    run_raw = TestSettingsV3.run_raw
    cases = TestSettingsV3.cases

    def test_person_secret_rules(self) -> None:
        """Hub TestPersonSecretRules."""
        no_access = FS_HEAD.replace("  access_group: users_demo\n", "", 1)
        no_group_access = FS_HEAD.replace("group_access: true", "group_access: false", 1)
        no_cred_hook = FS_HEAD.replace(", credential_change]", "]", 1)
        other_hook = FS_HEAD.replace("{name: sync, service: smb,", "{name: sync, service: other,", 1)
        header_auth = FS_HEAD.replace("method: custom", "method: header-auth", 1)
        json_file = FS_HEAD.replace("hooks:\n", "  - {name: json, service: other, mount: /json}\nhooks:\n", 1)
        path_opt = "{key: data, label: Data, type: path, target: {service: smb, mount: /portcullis/secrets/x}}"
        secret_opt = "{key: api, label: API, type: secret, delivery: [{file: {name: json}}]}"
        plain_opt = "{key: motd, label: Motd, type: string, delivery: [{file: {name: people}}]}"
        list_opt = "{key: names, label: Names, type: list, items: {type: string}, self_visible: true, delivery: [{file: {name: people}}]}"
        c = FS_COMPOSE

        def pat_env(val: str) -> str:
            return fs_compose(smb=f"    environment:\n      PORTCULLIS_USERNAME_PATTERN: '{val}'\n")

        def pat(p: str) -> str:
            return fs_ps(FS_PATTERN, p)
        S, PW = fs_smb, "share_password"
        self.cases([
            ("ok", S(fs_ps()), c, "", ""),
            ("hash", S(fs_ps("hash: nt", "hash: md5")), c, PW, "hash must be nt"),
            ("no hash", S(fs_ps("hash: nt, ", "")), c, PW, "hash must be nt"),
            ("short", S(fs_ps("length: 24", "length: 20")), c, PW, "length 20 must be at least 24"),
            ("not groups of 4", S(fs_ps("length: 24", "length: 26")), c, PW, "multiple of 4"),
            ("long ok", S(fs_ps("length: 24", "length: 32")), c, "", ""),
            ("delivery list", S(fs_ps("delivery: file", "delivery: [{file: {name: people}}]")), c, PW, "delivery: file"),
            ("delivery hook", S(fs_ps("delivery: file", "delivery: hook")), c, PW, "delivery: file"),
            ("delivery env", S(fs_ps("delivery: file", "delivery: [{env: X}]")), c, PW, "delivery: file"),
            ("no delivery", S(fs_ps("delivery: file, ", "")), c, PW, "delivery: file"),
            ("no mount", S(fs_ps("mount: {service: smb, path: /portcullis/secrets}, ", "")), c, PW, "needs mount"),
            ("mount service", S(fs_ps("service: smb, path", "service: nope, path")), c, PW, "mount.service nope is not in compose.yml"),
            ("mount relative", S(fs_ps("path: /portcullis/secrets", "path: portcullis/secrets")), c, PW, "mount.path"),
            ("mount colon", S(fs_ps("path: /portcullis/secrets", "path: '/a:b'")), c, PW, "mount.path"),
            ("mount unclean", S(fs_ps("path: /portcullis/secrets", "path: /portcullis//secrets")), c, PW, "mount.path"),
            ("mount on the data file", S(fs_ps("path: /portcullis/secrets", "path: /portcullis")), c, PW, "collides with files[people]"),
            ("mount on a path option", S(path_opt, fs_ps()), c, PW, "collides with setting data"),
            ("two on one mount", S(fs_ps(), fs_ps("key: share_password", "key: other_password")), c, "other_password", "collides with setting share_password"),
            ("mount elsewhere, hook not there", S(fs_ps("service: smb, path: /portcullis/secrets", "service: other, path: /portcullis/data")), c, PW, "credential_change"),
            ("revoke_on_leave false", S(fs_ps("revoke_on_leave: true", "revoke_on_leave: false")), c, PW, "revoke_on_leave must be true"),
            ("revoke_on_leave missing", S(fs_ps("revoke_on_leave: true, ", "")), c, PW, "revoke_on_leave must be true"),
            ("on_restore", S(fs_ps("on_restore: void", "on_restore: keep")), c, PW, "on_restore must be void"),
            ("on_restore missing", S(fs_ps("on_restore: void, ", "")), c, PW, "on_restore must be void"),
            ("applies", S(fs_ps("applies: live", "applies: restart")), c, PW, "applies"),
            ("applies omitted", S(fs_ps("applies: live, ", "")), c, "", ""),
            ("scope", S(fs_ps("}", "scope: person")), c, PW, "takes no scope"),
            ("default", S(fs_ps("}", "default: x")), c, PW, "takes no default"),
            ("required", S(fs_ps("}", "required: true")), c, PW, "takes no required"),
            ("resolve", S(fs_ps("}", "resolve: priority")), c, PW, "takes no resolve"),
            ("resolve_choices", S(fs_ps("}", "resolve_choices: [priority]")), c, PW, "takes no resolve_choices"),
            ("group_values", S(fs_ps("}", "group_values: {'{{ACCESS_GROUP}}': x}")), c, PW, "takes no group_values"),
            ("privileged", S(fs_ps("}", "privileged: true")), c, PW, "takes no privileged"),
            ("requires", S(fs_ps("}", "requires: [connect_address]")), c, PW, "takes no requires"),
            ("requires_any", S(fs_ps("}", "requires_any: [connect_address]")), c, PW, "takes no requires_any"),
            ("self_visible", S(fs_ps("}", "self_visible: false")), c, PW, "takes no self_visible"),
            ("checks", S(fs_ps("}", "checks: [{kind: requires_group_value, reason: x}]")), c, PW, "takes no checks"),
            # Stricter than the contract text (task-3-report §4): both types refuse these too.
            ("admin_override", S(fs_ps("}", "admin_override: true")), c, PW, "takes no admin_override"),
            ("unique", S(fs_ps("}", "unique: true")), c, PW, "takes no unique"),
            ("generate", S(fs_ps("}", "generate: {length: 24, charset: hex}")), c, PW, "takes no generate"),
            ("writes_as", S(fs_ps("}", "writes_as: {uid: 1}")), c, PW, "takes no writes_as"),
            ("pool", S(fs_ps("}", "pool: posix_uid")), c, PW, "pool is for person_id"),
            ("constraint", S(fs_ps("}", "max_len: 3")), c, PW, "max_len is not a constraint of type person_secret"),
            ("no access group", no_access + s_opts(FS_CONNECT, fs_ps()), c, PW, "router-less"),
            ("no group access", no_group_access + s_opts(FS_CONNECT, fs_ps()), c, PW, "router-less"),
            ("with a router", FS_HEAD + s_opts(FS_CONNECT, fs_ps()), FS_ROUTED, PW, "router-less"),
            ("header-auth", header_auth + s_opts(FS_CONNECT, fs_ps()), FS_ROUTED, PW, "router-less"),
            ("no credential hook", no_cred_hook + s_opts(FS_CONNECT, fs_ps()), c, PW, "credential_change"),
            ("hook on another service", other_hook + s_opts(FS_CONNECT, fs_ps()), c, PW, "credential_change"),
            # The username pattern (Task 3 fix round 1): only what RE2 and busybox ERE read alike.
            ("bad pattern", S(pat("'^[a-z$'")), c, PW, "username.pattern"),
            ("unanchored pattern", S(pat("'[a-z]{1,8}'")), c, PW, "username.pattern"),
            ("perl class", S(pat("'^\\w{1,8}$'")), c, PW, "username.pattern"),
            ("escape", S(pat("'^a\\.b$'")), c, PW, "username.pattern"),
            ("dot", S(pat("'^a.b$'")), c, PW, "username.pattern"),
            ("alternation", S(pat("'^(a|b)$'")), c, PW, "username.pattern"),
            ("star", S(pat("'^a*$'")), c, PW, "username.pattern"),
            ("plus", S(pat("'^a+$'")), c, PW, "username.pattern"),
            ("question", S(pat("'^a?$'")), c, PW, "username.pattern"),
            ("flags", S(pat("'(?i)^a$'")), c, PW, "username.pattern"),
            ("literals and repeats", S(pat("'^u-[a-z]{2}[0-9]{1,3}$'")), c, "", ""),
            ("collating element", S(pat("'^[[.a.]]$'")), c, PW, "username.pattern"),
            ("equivalence class", S(pat("'^[[=a=]]$'")), c, PW, "username.pattern"),
            ("interval without m", S(pat("'^a{,3}$'")), c, PW, "username.pattern"),
            ("interval not digits", S(pat("'^a{x}$'")), c, PW, "username.pattern"),
            ("open interval", S(pat("'^a{1,}$'")), c, PW, "username.pattern"),
            ("interval m > n", S(pat("'^a{3,2}$'")), c, PW, "username.pattern"),
            ("interval over 1000", S(pat("'^a{1,1001}$'")), c, PW, "username.pattern"),
            ("interval 1000", S(pat("'^a{1,1000}$'")), c, "", ""),
            ("literal brace", S(pat("'^a}$'")), c, PW, "username.pattern"),
            ("lone open brace", S(pat("'^{$'")), c, PW, "username.pattern"),
            ("literal close bracket", S(pat("'^a]$'")), c, PW, "username.pattern"),
            ("bracket in class", S(pat("'^[a[b]$'")), c, PW, "username.pattern"),
            ("word class", S(pat("'^[[:word:]]{1,3}$'")), c, PW, "username.pattern"),
            ("space class", S(pat("'^[[:space:]]{1,3}$'")), c, PW, "username.pattern"),
            ("non-ASCII", S(pat("'^[é]{1,2}$'")), c, PW, "username.pattern"),
            ("non-ASCII literal", S(pat("'^é$'")), c, PW, "username.pattern"),
            ("empty class", S(pat("'^[]$'")), c, PW, "username.pattern"),
            ("repeated interval", S(pat("'^a{1,2}{1,2}$'")), c, PW, "username.pattern"),
            ("interval on the anchor", S(pat("'^{1,2}a$'")), c, PW, "username.pattern"),
            ("space", S(pat("'^a b$'")), c, PW, "username.pattern"),
            ("tab", S(pat('"^a\\tb$"')), c, PW, "username.pattern"),
            ("too long", S(pat("'^" + "a" * 499 + "$'")), c, PW, "username.pattern"),
            ("samba rule", S(pat("'^[a-z][a-z0-9._-]{0,31}$'")), c, "", ""),
            ("posix lower", S(pat("'^[[:lower:]]{1,8}$'")), c, "", ""),
            ("posix classes", S(pat("'^[[:alpha:]_][[:alnum:][:digit:][:upper:][:xdigit:].-]{0,31}$'")), c, "", ""),
            ("negated class", S(pat("'^[^A-Z]{1,8}$'")), c, "", ""),
            ("exact interval", S(pat("'^x[0-9]{4}$'")), c, "", ""),
            ("reversed range", S(pat("'^[z-a]$'")), c, PW, "username.pattern"),
            ("reserved upper", S(fs_ps("reserved: [root, nobody]", "reserved: [Root]")), c, PW, "username.reserved"),
            ("reserved empty name", S(fs_ps("reserved: [root, nobody]", "reserved: ['']")), c, PW, "username.reserved"),
            ("reserved with a space", S(fs_ps("reserved: [root, nobody]", "reserved: ['a b']")), c, PW, "username.reserved"),
            ("reserved of 65", S(fs_ps("reserved: [root, nobody]", "reserved: [" + "a" * 65 + "]")), c, PW, "username.reserved"),
            ("reserved of 64", S(fs_ps("reserved: [root, nobody]", "reserved: [" + "a" * 64 + "]")), c, "", ""),
            ("reason too long", S(fs_ps('"isn\'t a valid Samba and Unix name"', "x" * 201)), c, PW, "username.reason"),
            ("reason 200", S(fs_ps('"isn\'t a valid Samba and Unix name"', "x" * 200)), c, "", ""),
            ("reason missing", S(fs_ps(', reason: "isn\'t a valid Samba and Unix name"', "")), c, PW, "username.reason"),
            ("reason blank", S(fs_ps('"isn\'t a valid Samba and Unix name"', "'  '")), c, PW, "username.reason"),
            ("username unknown key", S(fs_ps("reserved: [root, nobody]", "reserved: [root], max: 3")), c, "", "max"),
            ("info unknown option", S(fs_ps("{value:connect_address}", "{value:nope}")), c, PW, "info[0]"),
            ("info unknown port", S(fs_ps("{port:SMB}", "{port:NOPE}")), c, PW, "info[2]"),
            ("info unknown suffix port", S(fs_ps("{port_suffix:SMB:445}", "{port_suffix:NOPE:445}")), c, PW, "info[0]"),
            ("info bad default", S(fs_ps("{port_suffix:SMB:445}", "{port_suffix:SMB:70000}")), c, PW, "info[0]"),
            ("info non-canonical default", S(fs_ps("{port_suffix:SMB:445}", "{port_suffix:SMB:0445}")), c, PW, "info[0]"),
            ("info rows", S(fs_ps("{port:SMB}", "{rows:shares}")), c, PW, "info[2]"),
            ("info stray brace", S(fs_ps("/Home", "/{Home")), c, PW, "info[0]"),
            ("info stray close", S(fs_ps("/Home", "/Home}")), c, PW, "info[0]"),
            ("info secret", json_file + s_opts(FS_CONNECT, FS_UID, secret_opt, fs_ps("{value:connect_address}", "{value:api}")), c, PW, "info[0]"),
            ("info path option", S("{key: data, label: Data, type: path, self_visible: true, target: {service: other, mount: /data}}",
                                   fs_ps("{value:connect_address}", "{value:data}")), c, PW, "info[0]"),
            ("info not self_visible", S(plain_opt, fs_ps("{value:connect_address}", "{value:motd}")), c, PW, "self_visible: true"),
            ("info list", S(list_opt, fs_ps("{value:connect_address}", "{value:names}")), c, PW, "info[0]"),
            ("info person option", S(fs_ps("{value:connect_address}", "{value:uid}")), c, PW, "info[0]"),
            ("info empty label", S(fs_ps("{label: Username,", "{label: '',")), c, PW, "info[1]"),
            ("info empty value", S(fs_ps("value: '{user}'", "value: ''")), c, PW, "info[1]"),
            ("info value of 501", S(fs_ps("value: '{user}'", "value: '" + "x" * 501 + "'")), c, PW, "info[1]"),
            ("info value of 500", S(fs_ps("value: '{user}'", "value: '" + "x" * 500 + "'")), c, "", ""),
            ("info label of 65", S(fs_ps("{label: Username,", "{label: " + "x" * 65 + ",")), c, PW, "info[1]"),
            ("info unknown key", S(fs_ps("{label: Username,", "{label: Username, hint: x,")), c, "", "hint"),
            ("pattern env matches", S(fs_ps()), pat_env("^[a-z_][a-z0-9_.-]{0,31}$$"), "", ""),
            ("pattern env differs", S(fs_ps()), pat_env("^[a-z]{0,31}$$"), "", "PORTCULLIS_USERNAME_PATTERN"),
            ("pattern env not escaped", S(fs_ps()), pat_env("^[a-z_][a-z0-9_.-]{0,31}$"), "", "PORTCULLIS_USERNAME_PATTERN"),
            ("pattern env without a rule",
             S(fs_ps("username: {pattern: '^[a-z_][a-z0-9_.-]{0,31}$', reserved: [root, nobody], reason: \"isn't a valid Samba and Unix name\"}, ", "")),
             pat_env("^a$$"), "", "PORTCULLIS_USERNAME_PATTERN"),
            # Fields of the two types on other types.
            ("hash on string", FS_HEAD + s_opts(fs_edit(FS_CONNECT, "}", "hash: nt")), c, "connect_address", "hash is for person_secret"),
            ("mount on string", FS_HEAD + s_opts(fs_edit(FS_CONNECT, "}", "mount: {service: smb, path: /x}")), c, "connect_address", "mount is for person_secret"),
            ("info on string", FS_HEAD + s_opts(fs_edit(FS_CONNECT, "}", "info: [{label: a, value: b}]")), c, "connect_address", "info is for person_secret"),
            ("username on string", FS_HEAD + s_opts(fs_edit(FS_CONNECT, "}", "username: {reason: x}")), c, "connect_address", "username is for person_secret"),
            ("on_restore on string", FS_HEAD + s_opts(fs_edit(FS_CONNECT, "}", "on_restore: void")), c, "connect_address", "on_restore is for person_secret"),
            ("bare delivery on string", FS_HEAD + s_opts(fs_edit(FS_CONNECT, "delivery: [{file: {name: people}}]", "delivery: file")), c,
             "connect_address", "delivery: file is for person_secret"),
            ("pool on string", FS_HEAD + s_opts(fs_edit(FS_CONNECT, "}", "pool: posix_uid")), c, "connect_address", "pool is for person_id"),
        ])

    def test_username_pattern_grammar(self) -> None:
        """The Hub's usernamePattern, called directly."""
        for p in ("^a$", "^[a-z_][a-z0-9_.-]{0,31}$", "^[[:lower:]]{1,8}$", "^[^A-Z]{1,8}$", "^x[0-9]{4}$", "^$"):
            self.assertEqual(v.username_pattern_problem(p), "", p)
        for p in ("a", "^a", "a$", "^a{,3}$", "^[[.a.]]$", "^a|b$", "^[a\\]]$", "^a{1000,1001}$", "^a{00001}$"):
            self.assertNotEqual(v.username_pattern_problem(p), "", p)

    def test_time_machine_block(self) -> None:
        """Hub TestTimeMachineBlock: the spec's Time Machine declaration (as
        the contract and the rulings amend it) passes."""
        m = FS_HEAD.split("ports:\n")[0] + """\
ports:
  - {key: TM_SMB, label: SMB, container: 445, default: 445, protocol: tcp, service: timemachine, lan_only: true}
files:
  - {name: people, service: timemachine, mount: /portcullis/data, format: tsv, on_membership_change: hook}
hooks:
  - name: sync
    service: timemachine
    command: [/portcullis/portcullis-sync]
    when: [start, settings_change, membership_change, credential_change]
    timeout: 60s
ai:
  unsupported: test fixture
settings:
  sections: [Access, Backups, Network]
  options:
    - key: share_password
      label: File-share password
      type: person_secret
      hash: nt
      length: 24
      delivery: file
      mount: {service: timemachine, path: /portcullis/secrets}
      revoke_on_leave: true
      on_restore: void
      username: {pattern: "^[a-z_][a-z0-9_.-]{0,31}$",
                 reserved: [root, nobody, timemachine],
                 reason: "isn't a valid Samba and Unix name"}
      info:
        - {label: Server, value: "smb://{value:connect_address}{port_suffix:TM_SMB:445}/{value:share_prefix}-{user}"}
        - {label: Username, value: "{user}"}
      applies: live
      section: Access
    - key: uid
      label: File owner id
      type: person_id
      pool: posix_uid
      self_visible: false
      delivery: [{file: {name: people, field: uid}}]
    - key: size_limit
      label: Backup size limit
      type: size
      step: 1GiB
      allow_unlimited: true
      scope: person
      default: 500GiB
      resolve: max
      section: Backups
      applies: live
      delivery: [{file: {name: people, field: size_limit, render: {unit: MiB, integer: true, unlimited: none}}}]
      checks: [{kind: requires_group_value, reason: "Most people should get a deliberate limit"}]
    - key: storage
      label: Backup storage
      type: path
      target: {service: timemachine, mount: /opt}
      folder:
        access: write
        runs_as: {uid_from: uid, gid_from: uid}
        joins_group: template
      checks:
        - {kind: filesystem, needs: [xattr], not: [nfs, cifs, fuse], reason: "Time Machine stores metadata in extended attributes"}
        - {kind: exclusive, reason: "Backup bundles must not be written by other apps"}
    - key: share_prefix
      label: Share name prefix
      type: string
      pattern: "^[A-Za-z0-9][A-Za-z0-9 _-]{0,31}$"
      default: TimeMachine
      applies: live
      self_visible: true
      delivery: [{file: {name: people}}]
    - key: connect_address
      label: Address people connect to
      type: string
      format: hostname
      required: true
      section: Network
      self_visible: true
      delivery: [{file: {name: people}}]
    - key: avahi_services_dir
      label: Host Avahi services directory (Bonjour advertising)
      description: "Empty = off. Advertising shows every share name, which contains usernames, to everyone on the local network."
      type: path
      target: {service: timemachine, mount: /portcullis/avahi}
      section: Network
      applies: restart
    - key: model
      label: Shown in Finder as
      type: enum
      options: [{value: "TimeCapsule8,119", label: Time Capsule}, {value: "MacPro7,1", label: Mac Pro}]
      default: "TimeCapsule8,119"
      delivery: [{env: MIMIC_MODEL}]
      applies: restart
      section: Network
"""
        c = (f"services:\n  timemachine:\n    image: {FS_IMG}\n    environment:\n      MIMIC_MODEL: ${{MIMIC_MODEL}}\n"
             "      PORTCULLIS_USERNAME_PATTERN: '^[a-z_][a-z0-9_.-]{0,31}$$'\n")
        self.cases([("time machine", m, c, "", "")])
        o = [x for x in v.setting_options(self._load(m)) if x.get("key") in ("share_password", "uid")]
        for x in o:
            self.assertEqual(v.scope_of(x), "person", x["key"])
            self.assertEqual(v.option_env_names(x), [], x["key"])

    def _load(self, text: str) -> dict:
        import yaml
        return yaml.safe_load(text)

    def test_person_id_rules(self) -> None:
        """Hub TestPersonIDRules."""
        no_access = FS_HEAD.replace("  access_group: users_demo\n", "", 1)
        hook_file = FS_HEAD.replace("format: tsv}", "format: tsv, on_membership_change: hook}", 1)
        json_head = hook_file.replace("hooks:\n", "  - {name: json, service: other, mount: /json}\nhooks:\n", 1)

        def one(o: str) -> str:
            return hook_file + s_opts(FS_CONNECT, FS_PS, o)
        two = one(FS_UID)[:-1] + "\n    - " + fs_uid("key: uid", "key: gid", "field: uid", "field: gid") + "\n"
        twice = one(FS_UID)[:-1] + "\n    - " + fs_uid("key: uid", "key: gid") + "\n"
        c, U = FS_COMPOSE, "uid"
        self.cases([
            ("ok", one(FS_UID), c, "", ""),
            ("two ok", two, c, "", ""),
            ("unknown pool", one(fs_uid("pool: posix_uid", "pool: posix_gid")), c, U, "pool must be posix_uid"),
            ("no pool", one(fs_uid("pool: posix_uid, ", "")), c, U, "pool must be posix_uid"),
            ("self_visible missing", one(fs_uid("self_visible: false, ", "")), c, U, "self_visible: false"),
            ("self_visible true", one(fs_uid("self_visible: false", "self_visible: true")), c, U, "self_visible: false"),
            ("hook delivery", one(fs_uid("delivery: [{file: {name: people, field: uid}}]", "delivery: [{hook: sync}]")), c, U, "only file deliveries"),
            ("env delivery", one(fs_uid("delivery: [{file: {name: people, field: uid}}]", "delivery: [{env: UID}]")), c, U, "only file deliveries"),
            ("file and hook", one(fs_uid("{file: {name: people, field: uid}}", "{file: {name: people, field: uid}}, {hook: sync}")), c, U, "only file deliveries"),
            ("bare file", one(fs_uid("delivery: [{file: {name: people, field: uid}}]", "delivery: file")), c, U, "only file deliveries"),
            ("delivery render", one(fs_uid("{file: {name: people, field: uid}}", "{file: {name: people, field: uid}, render: {unit: x}}")), c, U, "only file deliveries"),
            ("no delivery", one(fs_uid(", delivery: [{file: {name: people, field: uid}}]", "")), c, U, "file delivery"),
            ("default", one(fs_uid("}", "default: 20000")), c, U, "takes no default"),
            ("scope", one(fs_uid("}", "scope: person")), c, U, "takes no scope"),
            ("required", one(fs_uid("}", "required: true")), c, U, "takes no required"),
            ("resolve", one(fs_uid("}", "resolve: max")), c, U, "takes no resolve"),
            ("requires", one(fs_uid("}", "requires: [connect_address]")), c, U, "takes no requires"),
            ("requires_any", one(fs_uid("}", "requires_any: [connect_address]")), c, U, "takes no requires_any"),
            ("admin_override", one(fs_uid("}", "admin_override: true")), c, U, "takes no admin_override"),
            ("unique", one(fs_uid("}", "unique: true")), c, U, "takes no unique"),
            ("generate", one(fs_uid("}", "generate: {length: 24, charset: hex}")), c, U, "takes no generate"),
            ("writes_as", one(fs_uid("}", "writes_as: {uid: 1}")), c, U, "takes no writes_as"),
            ("hash", one(fs_uid("}", "hash: nt")), c, U, "hash is for person_secret"),
            ("constraint", one(fs_uid("}", "min: 1")), c, U, "min is not a constraint of type person_id"),
            ("applies live, hook file", one(fs_uid("}", "applies: live")), c, "", ""),
            ("applies live, second file not hook",
             json_head + s_opts(FS_CONNECT, FS_PS, fs_uid("{file: {name: people, field: uid}}", "{file: {name: people, field: uid}}, {file: {name: json}}", "}", "applies: live")),
             c, U, "applies: live"),
            ("applies live, first file not hook",
             json_head + s_opts(FS_CONNECT, FS_PS, fs_uid("{file: {name: people, field: uid}}", "{file: {name: json}}, {file: {name: people, field: uid}}", "}", "applies: live")),
             c, U, "applies: live"),
            ("field twice", twice, c, "gid", "field uid is already written by setting uid"),
            ("no access group", no_access + s_opts(FS_CONNECT, FS_UID), c, U, "router-less"),
            ("with a router", FS_HEAD + s_opts(FS_CONNECT, FS_UID), FS_ROUTED, U, "router-less"),
        ])

    def test_credential_change_trigger(self) -> None:
        """Hub TestCredentialChangeTrigger."""
        when = "when: [start, settings_change, membership_change, credential_change]"
        only = FS_HEAD.replace(when, "when: [credential_change]", 1)
        bad = FS_HEAD.replace(when, "when: [credential]", 1)
        self.assertIn("credential_change", v.HOOK_TRIGGERS)
        self.cases([
            ("credential_change only", only + s_opts(FS_CONNECT, FS_UID, FS_PS), FS_COMPOSE, "", ""),
            ("unknown trigger", bad + s_opts(FS_CONNECT), FS_COMPOSE, "", 'when "credential" must be start, settings_change, membership_change, credential_change, ai or vpn'),
        ])

    def test_data_file_format(self) -> None:
        """Hub TestDataFileFormat: format json | tsv; tsv refuses tables and secrets."""
        def fmt(f: str) -> str:
            return FS_HEAD.replace(", format: tsv}", f + "}", 1)
        secret_opt = "{key: api, label: API, type: secret, delivery: [{file: {name: people}}]}"
        table_opt = "{key: shares, label: Shares, type: table, columns: [{name: name, label: Name, type: string}], delivery: [{file: {name: people}}]}"
        c = FS_COMPOSE
        self.cases([
            ("tsv", fmt(", format: tsv") + s_opts(FS_CONNECT), c, "", ""),
            ("json", fmt(", format: json") + s_opts(FS_CONNECT), c, "", ""),
            ("default json", fmt("") + s_opts(FS_CONNECT), c, "", ""),
            ("xml", fmt(", format: xml") + s_opts(FS_CONNECT), c, "", 'files[people]: format "xml" must be json or tsv'),
            ("secret into tsv", FS_HEAD + s_opts(FS_CONNECT, secret_opt), c, "api", "tsv"),
            ("secret into json", fmt(", format: json") + s_opts(FS_CONNECT, secret_opt), c, "", ""),
            ("table into tsv", FS_HEAD + s_opts(FS_CONNECT, table_opt), c, "shares", "tsv"),
            ("table into json", fmt("") + s_opts(FS_CONNECT, table_opt), c, "", ""),
        ])

    def test_tsv_refuses_render_format(self) -> None:
        """Hub H10 mirror: a tsv delivery is the default scalar / list text; any render.format is refused."""
        def lst(f: str) -> str:
            return "{key: tags, label: T, type: list, items: {type: string}, delivery: [{file: {name: people" + f + "}}]}"
        c = FS_COMPOSE
        self.cases([
            ("list as text", FS_HEAD + s_opts(FS_CONNECT, lst("")), c, "", ""),
            ("list join", FS_HEAD + s_opts(FS_CONNECT, lst(", render: {join: ','}")), c, "", ""),
            ("json", FS_HEAD + s_opts(FS_CONNECT, lst(", render: {format: json}")), c, "tags", "file people is tsv: render.format json"),
            ("yaml", FS_HEAD + s_opts(FS_CONNECT, lst(", render: {format: yaml}")), c, "tags", "file people is tsv: render.format yaml"),
            ("csv", FS_HEAD + s_opts(FS_CONNECT, lst(", render: {format: csv}")), c, "tags", "file people is tsv: render.format csv"),
            ("json into a json file", FS_HEAD.replace(", format: tsv}", "}", 1) + s_opts(FS_CONNECT, lst(", render: {format: json}")), c, "", ""),
        ])

    def test_requires_any(self) -> None:
        """Hub TestRequiresAny: the generic option-level requires_any (F2's share slots)."""
        r = "{key: readers, label: R, type: groups, delivery: [{file: {name: people}}]}"
        w = "{key: writers, label: W, type: groups, delivery: [{file: {name: people}}]}"

        def folder(extra: str) -> str:
            return "{key: share1_folder, label: Folder, type: path, target: {service: smb, mount: /shares/1}" + extra + "}"
        person = "{key: quota, label: Q, type: int, scope: person, default: 1, resolve: max, delivery: [{file: {name: people}}]}"
        c = FS_COMPOSE
        self.cases([
            ("ok", FS_HEAD + s_opts(r, w, folder(", requires_any: [readers, writers]")), c, "", ""),
            ("unknown", FS_HEAD + s_opts(r, folder(", requires_any: [readers, writers]")), c, "share1_folder", "requires_any writers: no such option"),
            ("self", FS_HEAD + s_opts(r, folder(", requires_any: [share1_folder]")), c, "share1_folder", "requires_any names itself"),
            ("person listed", FS_HEAD + s_opts(r, person, folder(", requires_any: [readers, quota]")), c, "share1_folder", "requires_any quota: not an instance option"),
            ("on a person option", FS_HEAD + s_opts(r, fs_edit(person, "}", "requires_any: [readers]")), c, "quota", "requires_any is for instance options"),
            ("empty", FS_HEAD + s_opts(r, folder(", requires_any: []")), c, "", ""),
        ])

    def test_runs_as_from(self) -> None:
        """Hub TestRunsAsFrom: uid_from / gid_from name a person_id option."""
        def fo(ra: str, join: str) -> str:
            return "{key: storage, label: S, type: path, target: {service: smb, mount: /opt}, folder: {access: write, runs_as: " + ra + join + "}}"
        tmpl = ", joins_group: template"
        not_id = "{key: num, label: N, type: int, default: 1000, delivery: [{file: {name: people}}]}"
        c, S = FS_COMPOSE, fs_smb
        self.cases([
            ("per-person tree", S(FS_PS, fo("{uid_from: uid, gid_from: uid}", tmpl)), c, "", ""),
            ("shared folder slot", S(FS_PS, fo("{uid_from: uid}", tmpl)), c, "", ""),
            ("uid_from with a gid", S(FS_PS, fo("{uid_from: uid, gid: 1000}", "")), c, "", ""),
            ("uid_from, group_add, no gid", S(FS_PS, fo("{uid_from: uid}", "")), c, "storage", "folder.runs_as.gid"),
            ("uid_from not a person_id", S(FS_PS, not_id, fo("{uid_from: num}", tmpl)), c, "storage", "uid_from num is not a person_id option"),
            ("uid_from unknown", S(FS_PS, fo("{uid_from: nope}", tmpl)), c, "storage", "uid_from nope is not a person_id option"),
            ("gid_from not a person_id", S(FS_PS, not_id, fo("{uid_from: uid, gid_from: num}", tmpl)), c, "storage", "gid_from num is not a person_id option"),
            ("gid_from without uid_from", S(FS_PS, fo("{uid: 0, gid_from: uid}", tmpl)), c, "storage", "gid_from needs uid_from"),
            ("gid_from with group_add", S(FS_PS, fo("{uid_from: uid, gid_from: uid}", "")), c, "storage", "gid_from needs joins_group: template"),
            ("gid_from with gid_env", S(FS_PS, fo("{uid_from: uid, gid_from: uid}", ", joins_group: gid_env")), c, "storage", "joins_group"),
            ("uid and uid_from", S(FS_PS, fo("{uid: 0, uid_from: uid}", tmpl)), c, "storage", "folder.runs_as.uid: exactly one of"),
            ("uid_env and uid_from", S(FS_PS, not_id, fo("{uid_env: NUM, uid_from: uid}", tmpl)), c, "storage", "folder.runs_as.uid: exactly one of"),
            ("gid and gid_from", S(FS_PS, fo("{uid_from: uid, gid: 0, gid_from: uid}", tmpl)), c, "storage", "folder.runs_as.gid: exactly one of"),
            # Stricter than the contract text (task-3-report §4): uid_from next to a compose user:.
            ("uid_from with compose user", S(FS_PS, fo("{uid_from: uid}", tmpl)), fs_compose(smb='    user: "1000:1000"\n'), "storage",
             "folder.runs_as.uid_from: service smb's compose user"),
        ])

    def test_routerless_custom_group_access(self) -> None:
        """Contract §3 / F1: a router-less custom template may set
        group_access with an access group and no native_login; a routed
        custom template still needs native_login for group_access."""
        self.cases([
            ("router-less", FS_HEAD, FS_COMPOSE, "", ""),
            ("router-less with the types", fs_smb(FS_PS), FS_COMPOSE, "", ""),
        ])
        errors, _ = self.run_raw(FS_HEAD, FS_ROUTED)
        self.assertError(errors, "auth.method custom with group_access: true needs auth.native_login.supported: true")

    def test_routerless_group_access_without_person_type_warns(self) -> None:
        """Task 15 Low: a router-less template's access group only decides
        who gets a person_secret / person_id; without one, group_access
        gates nothing (a warning)."""
        _, warnings = self.run_raw(FS_HEAD, FS_COMPOSE)
        self.assertTrue([w for w in warnings if "gates nothing" in w], "\n".join(warnings))
        _, warnings = self.run_raw(fs_smb(FS_PS), FS_COMPOSE)
        self.assertFalse([w for w in warnings if "gates nothing" in w], "\n".join(warnings))
        _, warnings = self.run_raw(FS_HEAD.replace("group_access: true", "group_access: false", 1), FS_COMPOSE)
        self.assertFalse([w for w in warnings if "gates nothing" in w], "\n".join(warnings))

    def test_username_reserved_env(self) -> None:
        """A compose PORTCULLIS_USERNAME_RESERVED is the person_secret's
        username.reserved, space-separated (the script refuses the same
        names as the Hub)."""
        def env(val: str) -> str:
            return fs_compose(smb=f"    environment:\n      PORTCULLIS_USERNAME_RESERVED: '{val}'\n")
        m = fs_smb(FS_PS)
        self.cases([
            ("equal", m, env("root nobody"), "", ""),
            ("unset", m, FS_COMPOSE, "", ""),
            ("missing a name", m, env("root"), "", "PORTCULLIS_USERNAME_RESERVED"),
            ("another order", m, env("nobody root"), "", "PORTCULLIS_USERNAME_RESERVED"),
            ("extra space", m, env("root  nobody"), "", "PORTCULLIS_USERNAME_RESERVED"),
            ("without a person_secret", fs_smb(), env("root nobody"), "", "PORTCULLIS_USERNAME_RESERVED"),
        ])

    def test_zero_routers_need_custom(self) -> None:
        """Hub TestZeroRoutersNeedCustom (F48)."""
        for method in ("forward-auth", "header-auth", "native-oidc", "mtls", "public"):
            with self.subTest(method):
                errors, _ = self.run_raw(FS_HEAD.replace("method: custom", "method: " + method, 1), FS_COMPOSE)
                self.assertError(errors, f"auth.method {method} needs at least one HTTP router")

    def test_local_networks_var_forms(self) -> None:
        """Hub TestLocalNetworksVarForms (F36): only exactly ${PORTCULLIS_LOCAL_NETWORKS}."""
        m = fs_smb(fs_ps())
        lan = "PORTCULLIS_LOCAL_NETWORKS"
        exact = "only as exactly ${PORTCULLIS_LOCAL_NETWORKS}"
        self.cases([
            ("exact", m, fs_env("smb", "${" + lan + "}"), "", ""),
            ("exact in text", m, fs_env("smb", "'allow ${" + lan + "} end'"), "", ""),
            ("list form", m, fs_compose(smb="    environment:\n      - NETS=${" + lan + "}\n"), "", ""),
            ("in a command", m, fs_compose(smb="    command: [run, '${" + lan + "}']\n"), "", ""),
            ("default", m, fs_env("smb", "${" + lan + ":-0.0.0.0/0}"), "", exact),
            ("dash default", m, fs_env("smb", "${" + lan + "-0.0.0.0/0}"), "", exact),
            ("alternate", m, fs_env("smb", "${" + lan + ":+x}"), "", "only as exactly"),
            ("plus", m, fs_env("smb", "${" + lan + "+x}"), "", "only as exactly"),
            ("error form", m, fs_env("smb", "${" + lan + "?unset}"), "", "only as exactly"),
            ("colon error form", m, fs_env("smb", "${" + lan + ":?unset}"), "", "only as exactly"),
            ("bare", m, fs_env("smb", "$" + lan), "", "only as exactly"),
            ("escaped is text", m, fs_env("smb", "$${" + lan + ":-x}"), "", ""),
            ("declared in env", FS_HEAD + "env:\n  - {key: " + lan + ", description: x, generate: random}\n" + s_opts(FS_CONNECT, FS_UID, fs_ps()),
             FS_COMPOSE, "", lan),
        ])
        self.assertTrue(v.reserved_var(lan))

    def test_folder_gid_var_forms(self) -> None:
        """Hub TestFolderGIDVarForms (F36, the plan 2 carry)."""
        m = fs_smb(fs_ps(), FS_SLOT)
        var = "PORTCULLIS_FOLDER_GID_SHARE1_FOLDER"
        plain = "{key: data, label: Data, type: path, target: {service: smb, mount: /data}}"
        self.cases([
            ("on the folder's service", m, fs_env("smb", "${" + var + "}"), "", ""),
            ("list form", m, fs_compose(smb="    environment:\n      - SHARE1_GID=${" + var + "}\n"), "", ""),
            ("another service", m, fs_env("other", "${" + var + "}"), "", var),
            ("default", m, fs_env("smb", "${" + var + ":-60001}"), "", var),
            ("bare", m, fs_env("smb", "$" + var), "", var),
            ("inside text", m, fs_env("smb", "'g${" + var + "}'"), "", var),
            ("uid var", m, fs_env("smb", "${PORTCULLIS_FOLDER_UID_SHARE1_FOLDER}"), "", "PORTCULLIS_FOLDER_UID_SHARE1_FOLDER"),
            ("unknown key", m, fs_env("smb", "${PORTCULLIS_FOLDER_GID_NOPE}"), "", "PORTCULLIS_FOLDER_GID_NOPE"),
            ("no folder block", fs_smb(fs_ps(), plain), fs_env("smb", "${PORTCULLIS_FOLDER_GID_DATA}"), "", "PORTCULLIS_FOLDER_GID_DATA"),
            ("in a command", m, fs_compose(smb="    command: ['${" + var + "}']\n"), "", var),
            ("in a label too", m, fs_compose(smb="    environment:\n      G: ${" + var + "}\n    labels:\n      x: ${" + var + "}\n"), "", var),
            ("another folder prefix", m, fs_env("smb", "${PORTCULLIS_FOLDER_X}"), "", "PORTCULLIS_FOLDER_X"),
            ("no settings at all", FS_HEAD, fs_env("smb", "${PORTCULLIS_FOLDER_GID_X}"), "", "PORTCULLIS_FOLDER_GID_X"),
        ])

    def test_expand_members_rule(self) -> None:
        """Hub TestExpandMembersRule (§13.5)."""
        def readers(d: str) -> str:
            return "{key: share1_readers, label: Readers, type: groups, delivery: [" + d + "]}"
        S = fs_smb
        self.cases([
            ("file", S(fs_ps(), readers("{file: {name: people, render: {expand_members: true}}}")), FS_COMPOSE, "", ""),
            ("group", S(fs_ps(), "{key: g, label: G, type: group, delivery: [{file: {name: people, render: {expand_members: true}}}]}"), FS_COMPOSE, "", ""),
            ("env", S(fs_ps(), "{key: share1_readers, label: Readers, type: groups, delivery: [{env: R, render: {expand_members: true}}]}"),
             fs_env("smb", "${R}"), "share1_readers", "expand_members is for file deliveries"),
            ("hook", S(fs_ps(), readers("{hook: sync, render: {expand_members: true}}")), FS_COMPOSE, "share1_readers", "expand_members is for file deliveries"),
            ("string", S(fs_ps(), "{key: s, label: S, type: string, delivery: [{file: {name: people, render: {expand_members: true}}}]}"),
             FS_COMPOSE, "s", "expand_members is for group and groups options"),
            ("join", S(fs_ps(), readers("{file: {name: people, render: {expand_members: true, join: ','}}}")), FS_COMPOSE,
             "share1_readers", "expand_members renders the member list: no join or format"),
        ])

    def test_secrets_volume_reserved(self) -> None:
        """Hub TestDiscoverRefusesBypasses sec-* rows (F15): the Hub's
        secrets volume key and core's hub_secrets are never a template's."""
        key = "names the Hub's secrets volume"
        self.cases([
            ("key", FS_HEAD, fs_compose(extra="volumes:\n  portcullis-hub-secrets: {}\n"), "", "portcullis-hub-secrets is the Hub's secrets volume"),
            ("key case", FS_HEAD, fs_compose(extra="volumes:\n  Portcullis-Hub-Secrets: {}\n"), "", "the Hub's secrets volume"),
            ("short", FS_HEAD, fs_compose(smb="    volumes: [\"portcullis-hub-secrets:/x:ro\"]\n"), "", key),
            ("long", FS_HEAD, fs_compose(smb="    volumes:\n      - {type: volume, source: portcullis-hub-secrets, target: /x}\n"), "", key),
            ("interpolated", FS_HEAD, fs_compose(smb="    volumes: [\"${S:-portcullis-hub-secrets}:/x\"]\n"), "", key),
            ("volumes_from", FS_HEAD, fs_compose(smb="    volumes_from: [portcullis-hub-secrets]\n"), "", key),
            ("core hub_secrets", FS_HEAD, fs_compose(smb="    volumes: [hub_secrets:/x]\n", extra="volumes:\n  hub_secrets: {}\n"), "", "volumes.hub_secrets is core's"),
        ])

    def test_shared_namespaces_with_person_secret(self) -> None:
        """Hub secretsmount (Task 6 fix round 1b): with a person_secret
        mount, every service's pid / ipc stays private and no service takes
        the mounter's volumes."""
        m = fs_smb(fs_ps())
        ns = "shares the"
        self.cases([
            ("private", m, fs_compose(other="    pid: private\n    ipc: private\n"), "", ""),
            ("ipc shareable", m, fs_compose(smb="    ipc: shareable\n"), "", ""),
            ("ipc none", m, fs_compose(other="    ipc: none\n"), "", ""),
            ("pid host", m, fs_compose(other="    pid: host\n"), "", ns),
            ("ipc host", m, fs_compose(smb="    ipc: host\n"), "", ns),
            ("pid service", m, fs_compose(other="    pid: \"service:smb\"\n"), "", ns),
            ("ipc service", m, fs_compose(smb="    ipc: \"service:other\"\n"), "", ns),
            ("volumes_from the mounter", m, fs_compose(other="    volumes_from: [smb]\n"), "", "takes the volumes of smb"),
            ("volumes_from service form", m, fs_compose(other="    volumes_from: [\"service:smb:ro\"]\n"), "", "takes the volumes of"),
            ("no person_secret", FS_HEAD, fs_compose(other="    pid: host\n"), "", ""),
        ])

    def test_lan_only_required_for_person_secret_ports(self) -> None:
        """Contract §13.17 (a templates-repo rule; the Hub doesn't enforce it):
        a template with a person_secret publishes only lan_only ports."""
        m = fs_smb(fs_ps())
        self.cases([
            ("lan_only", m, FS_COMPOSE, "", ""),
            ("not lan_only", m.replace(", lan_only: true}", "}", 1), FS_COMPOSE, "", "port SMB: a template with a person_secret option"),
            ("false", m.replace("lan_only: true", "lan_only: false", 1), FS_COMPOSE, "", "lan_only: true"),
            ("no person_secret", FS_HEAD.replace(", lan_only: true}", "}", 1), FS_COMPOSE, "", ""),
        ])

    def test_no_proxy_network_when_routerless(self) -> None:
        """Contract §3: a router-less template has no frontend, so no service
        joins portcullis-proxy (the internal-service rule)."""
        errors, _ = self.run_raw(fs_smb(fs_ps()), fs_compose(
            smb="    networks: [default, portcullis-proxy]\n", extra="networks:\n  portcullis-proxy:\n    external: true\n"))
        self.assertError(errors, "internal service is on portcullis-proxy")

    def test_sync_copies_identical(self) -> None:
        """check_sync_copies: every template shipping bin/portcullis-sync has
        the same bytes, and those templates are exactly SYNC_TEMPLATES."""
        self.assertEqual(v.SYNC_TEMPLATES, {"samba", "timemachine"})

        def make(files: dict) -> List[str]:
            for app in ("samba", "timemachine", "demo"):
                d = os.path.join(self.tmp.name, app, "bin")
                os.makedirs(d, exist_ok=True)
                p = os.path.join(d, "portcullis-sync")
                if os.path.exists(p):
                    os.remove(p)
                if app in files:
                    with open(p, "wb") as f:
                        f.write(files[app])
            r = v.Report()
            v.check_sync_copies([v.Template(a) for a in ("samba", "timemachine", "demo")], r)
            return r.errors
        same = b"#!/bin/sh\necho sync\n"
        self.assertClean(make({"samba": same, "timemachine": same}))
        errors = make({"samba": same, "timemachine": same[:-1] + b"!"})
        # Filed under both templates (Task 15 Low): each one's error list shows it.
        self.assertTrue([e for e in errors if e.startswith("samba/bin/portcullis-sync:")], "\n".join(errors))
        self.assertTrue([e for e in errors if e.startswith("timemachine/bin/portcullis-sync:")], "\n".join(errors))
        self.assertError(make({"samba": same, "timemachine": same, "demo": same}), "demo/bin/portcullis-sync")
        self.assertError(make({"samba": same}), "timemachine")
        self.assertError(make({"timemachine": same}), "samba/")
        # Both templates exist (Task 17): a member missing from the repo is an
        # error too, and the shippers must be exactly SYNC_TEMPLATES.
        r = v.Report()
        v.check_sync_copies([v.Template("demo")], r)
        self.assertTrue([e for e in r.errors if e.startswith("samba/")], "\n".join(r.errors))
        self.assertTrue([e for e in r.errors if e.startswith("timemachine/")], "\n".join(r.errors))
        r = v.Report()
        v.check_sync_copies([v.Template(a) for a in ("demo", "timemachine")], r)
        self.assertTrue([e for e in r.errors if e.startswith("samba/") and "not in the repo" in e], "\n".join(r.errors))

    def test_real_templates_ship_sync(self) -> None:
        """The repo's shippers of bin/portcullis-sync are exactly samba and timemachine."""
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        shippers = {d for d in os.listdir(root) if os.path.isfile(os.path.join(root, d, "bin", "portcullis-sync"))}
        self.assertEqual(shippers, {"samba", "timemachine"})
        with open(os.path.join(root, "samba", "bin", "portcullis-sync"), "rb") as a, \
                open(os.path.join(root, "timemachine", "bin", "portcullis-sync"), "rb") as b:
            self.assertEqual(a.read(), b.read(), "portcullis-sync differs between samba and timemachine")



# ── AI support: the ai: block (contract §3.2, Hub ValidateAI) ──

AI_UNSUP = "ai:\n  unsupported: test fixture\n"
AI_HOOKS = ("hooks:\n"
            "  - {name: mcp-mint, service: demo, command: [/mint], when: [ai]}\n"
            "  - {name: mcp-revoke, service: demo, command: [/revoke], when: [ai]}\n"
            "  - {name: apply, service: demo, command: [/apply], when: [start, settings_change]}\n")
AI_MOTD = s_opts("{key: motd, label: Message of the day, type: string, max_len: 200, applies: live, delivery: [{hook: apply}]}")
AI_MCP = """\
ai:
  mcp:
    - name: demo
      label: Demo
      kind: companion
      service: demo-mcp
      port: 8080
      router: demo
      upstream: official
      source: https://example.org/demo-mcp
      protocol: ["2026-07-28", "2025-11-25"]
      modes: [read_only, read_write]
      default_mode: read_write
      identity:
        mode: app_token
        format: "token {credential}"
        mint: mcp-mint
        revoke: mcp-revoke
        scopes:
          read_only: [read:repository]
          read_write: [write:repository]
      tools:
        writes: ["create_*", "delete_*"]
        confirm: ["delete_*", "repo_write:delete"]
        never: []
"""
AI_COMPANION_SVC = (f"  demo-mcp:\n    image: demo/mcp:1.0.0@sha256:{S_DIGEST}\n    environment:\n"
                    "      READONLY: ${PORTCULLIS_AI_READONLY_DEMO:-true}\n    networks: [default]\n")
AI_HEADERS = """\
ai:
  mcp:
    - name: wiki
      label: Wiki
      kind: builtin
      service: demo
      port: 80
      path: /api/mcp
      router: demo
      public_path: /mcp
      upstream: official
      source: https://example.org/wiki
      protocol: ["2025-06-18"]
      modes: [read_only]
      aggregate: false
      identity:
        mode: identity_headers
        caller_secret: {env: DEMO_SECRET, header: X-Mcp-Secret, format: "{secret}"}
"""
AI_TRUST = AI_HEADERS.replace("kind: builtin\n      service: demo\n      port: 80\n      path: /api/mcp\n",
                              "kind: companion\n      service: demo-mcp\n      port: 8000\n").replace(
    "      aggregate: false\n", "").replace("caller_secret: {env: DEMO_SECRET,", "caller_secret: {env: DEMO_MCP_TOKEN,")
AI_TRUST_NETS = "    networks:\n      portcullis-proxy: {}\n      mcp-trust:\n        aliases: [demo-internal]\n"
AI_TRUST_SVC = (f"  demo-mcp:\n    image: demo/mcp:1.0.0@sha256:{S_DIGEST}\n    environment:\n"
                "      TOKEN: ${DEMO_MCP_TOKEN:?DEMO_MCP_TOKEN must be set}\n    networks: [mcp-trust]\n")
AI_OAUTH = """\
hooks:
  - {name: revoke-all, service: demo, command: [/revoke], when: [ai]}
  - {name: toggle, service: demo, command: [/toggle], when: [ai]}
ai:
  on_change: toggle
  mcp:
    - name: oauth
      label: OAuth App
      kind: builtin
      service: demo
      path: /mcp
      router: demo
      upstream: official
      source: https://example.org/oauth
      protocol: ["2025-11-25"]
      modes: [read_write]
      identity: {mode: app_oauth, revoke: revoke-all}
"""
AI_CHAT = """\
ai:
  unsupported: "An AI page: the AI acts in other apps, not in this one"
  chat:
    provider_kinds: {openai_compatible: many, anthropic: one}
    file: {service: demo, mount: /portcullis/ai}
    env: {service: demo}
"""
AI_ALT = ('ai:\n  unsupported: "No official MCP server; community servers are small and not vetted by Portcullis"\n'
          '  alternative: {name: plain-mcp, source: "https://example.org/plain-mcp", note: "community, 12 stars, API token per person"}\n')


def ai_fixtures() -> dict:
    """fixture -> (manifest, compose), each clean."""
    oidc_clients = ('  - {client_id: demo, name: Demo, secret_env: DEMO_SECRET, redirect_uri: "https://{{HOST_DEMO}}/cb"}\n')
    chat_m = S_OIDC.replace(oidc_clients, oidc_clients +
                            '  - {client_id: demo-mcp, name: Demo MCP, secret_env: DEMO_MCP_SECRET, '
                            'redirect_uri: "https://{{HOST_DEMO}}/api/mcp/callback", ai_client: true}\n', 1)
    chat_m = chat_m.replace("env:\n", "env:\n  - key: DEMO_MCP_SECRET\n    description: secret\n    generate: random\n", 1)
    chat_c = s_compose("      MCP_SECRET: ${DEMO_MCP_SECRET:?DEMO_MCP_SECRET must be set}\n", oidc=True)
    return {
        "unsupported": (S_HDR, s_compose()),
        "alternative": (S_HDR.replace(AI_UNSUP, AI_ALT), s_compose()),
        "companion": (S_HDR.replace(AI_UNSUP, AI_HOOKS + AI_MOTD + AI_MCP),
                      s_compose("      DEMO_AI: ${PORTCULLIS_AI_ENABLED:-false}\n", services=S_INIT + AI_COMPANION_SVC)),
        "headers": (S_HDR.replace(AI_UNSUP, AI_HEADERS).replace(
            "env:\n", "env:\n  - key: PLAIN\n    description: plain\n", 1), s_compose("      PLAIN: ${PLAIN:-}\n")),
        "oauth": (S_OIDC.replace(AI_UNSUP, AI_OAUTH), s_compose(oidc=True)),
        "chat": (chat_m.replace(AI_UNSUP, AI_CHAT), chat_c),
        "trust": (S_HDR.replace(AI_UNSUP, AI_TRUST).replace(
            "env:\n", "env:\n  - key: DEMO_MCP_TOKEN\n    description: caller secret\n    generate: random\n", 1),
                  s_compose(nets=AI_TRUST_NETS, services=S_INIT + AI_TRUST_SVC) + "  mcp-trust:\n    internal: true\n"),
    }


class AITests(Case):
    """Hub internal/templates/ai_test.go (TestAI*, TestCompanionRules,
    TestChatRules, TestAIClientFlag, TestHookAITrigger,
    TestReservedMCPNames), row for row: every refusal the Hub makes at
    discover is an error here naming the field."""
    run_raw = TestSettingsV3.run_raw

    def edit(self, text: str, pairs: List[str]) -> str:
        for old, new in zip(pairs[::2], pairs[1::2]):
            self.assertIn(old, text)
            text = text.replace(old, new, 1)
        return text

    def rows(self, rows: List[Tuple[str, str, List[str], List[str], str]], app_id: str = "demo") -> None:
        fx = ai_fixtures()
        for name, fixture, medits, cedits, want in rows:
            with self.subTest(name):
                m, c = fx[fixture]
                errors, _ = self.run_raw(self.edit(m, medits), self.edit(c, cedits), app_id)
                if want == "":
                    self.assertClean(errors)
                else:
                    self.assertError(errors, want)

    def test_fixtures_are_clean(self) -> None:
        self.rows([(f, f, [], [], "") for f in ai_fixtures()])

    def test_trust_network(self) -> None:
        """Hub TestTrustNetwork."""
        comp = "    networks: [mcp-trust]\n"
        self.rows([
            ("companion on default", "trust", [], [comp, "    networks: [default]\n"], "exactly one network"),
            ("companion on two networks", "trust", [], [comp, "    networks: [mcp-trust, default]\n"], "exactly one network"),
            ("trust network not internal", "trust", [], ["  mcp-trust:\n    internal: true\n", "  mcp-trust: {}\n"], "exactly {internal: true}"),
            ("trust network internal false", "trust", [], ["    internal: true\n", "    internal: false\n"], "exactly {internal: true}"),
            ("trust network with ipam", "trust", [], ["  mcp-trust:\n    internal: true\n", "  mcp-trust:\n    internal: true\n    ipam: {config: [{subnet: 10.0.0.0/8}]}\n"], "exactly {internal: true}"),
            ("trust network with driver", "trust", [], ["  mcp-trust:\n    internal: true\n", "  mcp-trust:\n    internal: true\n    driver: macvlan\n"], "exactly {internal: true}"),
            ("trust network with driver_opts", "trust", [], ["  mcp-trust:\n    internal: true\n", "  mcp-trust:\n    internal: true\n    driver_opts: {com.docker.network.bridge.inhibit_ipv4: \"true\"}\n"], "exactly {internal: true}"),
            ("trust network with enable_ipv6", "trust", [], ["  mcp-trust:\n    internal: true\n", "  mcp-trust:\n    internal: true\n    enable_ipv6: true\n"], "exactly {internal: true}"),
            ("trust network with attachable", "trust", [], ["  mcp-trust:\n    internal: true\n", "  mcp-trust:\n    internal: true\n    attachable: true\n"], "exactly {internal: true}"),
            ("trust network with labels", "trust", [], ["  mcp-trust:\n    internal: true\n", "  mcp-trust:\n    internal: true\n    labels: {a: b}\n"], "exactly {internal: true}"),
            ("trust network with name", "trust", [], ["  mcp-trust:\n    internal: true\n", "  mcp-trust:\n    internal: true\n    name: mcp-trust\n"], "exactly {internal: true}"),
            ("trust network with external", "trust", [], ["  mcp-trust:\n    internal: true\n", "  mcp-trust:\n    internal: true\n    external: false\n"], "exactly {internal: true}"),
            ("a third member", "trust", [], [comp, comp + "  other:\n    image: x/y:1.0.0@sha256:" + S_DIGEST + "\n    networks: [mcp-trust]\n"],
             "service other joins the trust network"),
            ("app not on it", "trust", [], ["      mcp-trust:\n        aliases: [demo-internal]\n", ""], "must join the trust network"),
            ("sharing the app's namespace", "trust", [], [comp, comp + "  side:\n    image: x/y:1.0.0@sha256:" + S_DIGEST + "\n    network_mode: service:demo\n"],
             "share an address on the trust network"),
            ("pid of the app", "trust", [], [comp, comp + "  side:\n    image: x/y:1.0.0@sha256:" + S_DIGEST + "\n    pid: service:demo\n"], "uses pid service:demo"),
            ("pid of the companion", "trust", [], [comp, comp + "  side:\n    image: x/y:1.0.0@sha256:" + S_DIGEST + "\n    pid: service:demo-mcp\n"], "uses pid service:demo-mcp"),
            ("pid host", "trust", [], [comp, comp + "  side:\n    image: x/y:1.0.0@sha256:" + S_DIGEST + "\n    pid: host\n"], "uses pid host"),
            ("caller secret in another service", "trust", [], [comp, comp + "  side:\n    image: x/y:1.0.0@sha256:" + S_DIGEST + "\n    environment:\n      X: ${DEMO_MCP_TOKEN:-}\n"], "reads the caller secret DEMO_MCP_TOKEN"),
            ("caller secret bare in another service", "trust", [], [comp, comp + "  side:\n    image: x/y:1.0.0@sha256:" + S_DIGEST + "\n    command: [sh, -c, \"echo $DEMO_MCP_TOKEN\"]\n"], "reads the caller secret DEMO_MCP_TOKEN"),
            ("caller secret nested in another service", "trust", [], [comp, comp + "  side:\n    image: x/y:1.0.0@sha256:" + S_DIGEST + "\n    environment:\n      X: ${OTHER:-${DEMO_MCP_TOKEN}}\n"], "reads the caller secret DEMO_MCP_TOKEN"),
            ("a host-network service", "trust", [], [comp, comp + "  side:\n    image: x/y:1.0.0@sha256:" + S_DIGEST + "\n    network_mode: host\n"],
             "uses network_mode host: not allowed next to an identity_headers companion"),
            ("a host-network service next to a builtin identity_headers companion", "headers", [],
             ["  init:\n", "  side:\n    image: x/y:1.0.0@sha256:" + S_DIGEST + "\n    network_mode: host\n  init:\n"], "uses network_mode host"),
            ("-internal alias on an internal network with ipam", "trust", [], ["  mcp-trust:\n    internal: true\n",
             "  mcp-trust:\n    internal: true\n    ipam: {config: [{subnet: 10.9.0.0/24}]}\n"], "ends in -internal"),
            ("-internal alias on a plain network", "trust", [], ["  mcp-trust:\n    internal: true\n", "  mcp-trust: {}\n"], "ends in -internal"),
        ])

    def test_ai_required(self) -> None:
        long = "x" * 201
        self.rows([
            ("no block", "unsupported", [AI_UNSUP, ""], [], "'ai' is a required property"),
            ("neither", "unsupported", [AI_UNSUP, "ai: {}\n"], [], "ai: required (ai.mcp or ai.unsupported)"),
            ("both", "companion", ["ai:\n", "ai:\n  unsupported: no\n"], [], "ai: either ai.mcp or ai.unsupported, not both"),
            ("empty unsupported", "unsupported", ["unsupported: test fixture", 'unsupported: ""'], [], "ai.unsupported must be one line"),
            ("201 chars", "unsupported", ["unsupported: test fixture", "unsupported: " + long], [], "ai.unsupported must be one line of 1–200"),
            ("two lines", "unsupported", ["unsupported: test fixture", 'unsupported: "a\\nb"'], [], "ai.unsupported"),
            ("control char", "unsupported", ["unsupported: test fixture", 'unsupported: "No MCP\\a server"'], [], "ai.unsupported"),
            ("line separator", "unsupported", ["unsupported: test fixture", 'unsupported: "No MCP\\u2028server"'], [], "ai.unsupported"),
            ("empty mcp list", "unsupported", [AI_UNSUP, "ai:\n  mcp: []\n"], [], "ai.mcp: list at least one companion"),
            ("unknown key", "unsupported", ["ai:\n", "ai:\n  bogus: 1\n"], [], "bogus"),
            ("200 runes ok", "unsupported", ["unsupported: test fixture", "unsupported: " + "é" * 200], [], ""),
        ])

    def test_alternative_rules(self) -> None:
        self.rows([
            ("alternative with mcp", "companion", ["ai:\n", 'ai:\n  alternative: {name: x, source: "https://example.org", note: y}\n'], [],
             "ai.alternative is only allowed with ai.unsupported"),
            ("alternative without source", "alternative", ['source: "https://example.org/plain-mcp", ', ""], [], "source"),
            ("alternative http source", "alternative", ['"https://example.org/plain-mcp"', '"http://example.org/plain-mcp"'], [], "ai.alternative.source"),
            ("alternative bad escape", "alternative", ['"https://example.org/plain-mcp"', '"https://x/%zz"'], [], "ai.alternative.source must be an https:// URL"),
            ("alternative trailing %", "alternative", ['"https://example.org/plain-mcp"', '"https://x/%"'], [], "ai.alternative.source must be an https:// URL"),
            ("alternative escape in host", "alternative", ['"https://example.org/plain-mcp"', '"https://ex%41mple.com/"'], [], "ai.alternative.source must be an https:// URL"),
            ("alternative non-numeric port", "alternative", ['"https://example.org/plain-mcp"', '"https://example.com:abc/x"'], [], "ai.alternative.source must be an https:// URL"),
            ("alternative doubled port", "alternative", ['"https://example.org/plain-mcp"', '"https://x:80:80/"'], [], "ai.alternative.source must be an https:// URL"),
            ("alternative userinfo", "alternative", ['"https://example.org/plain-mcp"', '"https://u:p@example.org/"'], [], "ai.alternative.source must be an https:// URL"),
            ("alternative empty host", "alternative", ['"https://example.org/plain-mcp"', '"https:///x"'], [], "ai.alternative.source must be an https:// URL"),
            ("alternative port, query, escape, IPv6 ok", "alternative", ['"https://example.org/plain-mcp"', '"https://[::1]:8443/a%2Fb?q=1#f"'], [], ""),
        ] + [
            (f"alternative host with {ch}", "alternative", ['"https://example.org/plain-mcp"', f'"https://exa{ch}mple.org/"'], [], "ai.alternative.source must be an https:// URL")
            for ch in ("|", "{", "^", "`")
        ] + [
            ("companion source bad escape", "companion", ["https://example.org/demo-mcp", "https://x/%zz"], [], "ai.mcp[demo]: source must be an https:// URL"),
            ("alternative long name", "alternative", ["name: plain-mcp", "name: " + "n" * 65], [], "ai.alternative.name"),
            ("alternative long note", "alternative", ['note: "community, 12 stars, API token per person"', "note: " + "n" * 201], [], "ai.alternative.note"),
            ("on_change with unsupported", "unsupported", ["ai:\n", "ai:\n  on_change: x\n"], [], "ai.on_change is only allowed with ai.mcp"),
            ("chat with mcp", "companion", ["ai:\n", "ai:\n  chat: {provider_kinds: {openai: one}, file: {service: demo, mount: /x}, env: {service: demo}}\n"], [],
             "ai.chat is only allowed with ai.unsupported"),
        ])

    def test_companion_rules(self) -> None:
        comp = "companion"
        other_builtin = ('  mcp:\n    - {name: other, label: O, kind: builtin, service: demo, port: 80, router: demo, public_path: /mcp/other, '
                         'upstream: official, source: "https://example.org", protocol: ["2025-06-18"], modes: [read_write], '
                         'identity: {mode: app_token, format: "Bearer {credential}", mint: mcp-mint, revoke: mcp-revoke}}\n')
        self.rows([
            ("source missing", comp, ["      source: https://example.org/demo-mcp\n", ""], [], "'source' is a required property"),
            ("source http", comp, ["https://example.org/demo-mcp", "http://example.org/demo-mcp"], [], "ai.mcp[demo]: source must be an https:// URL"),
            ("name Gitea", comp, ["- name: demo\n", "- name: Gitea\n"], [], "ai.mcp[0]: name"),
            ("name --", comp, ["- name: demo\n", "- name: a--b\n"], [], "ai.mcp[0]: name"),
            ("name 32 chars", comp, ["- name: demo\n", "- name: " + "a" * 32 + "\n"], [], "ai.mcp[0]: name"),
            ("duplicate name", "headers", ["  mcp:\n", '  mcp:\n    - {name: wiki, label: W, kind: builtin, service: demo, port: 1, router: demo, public_path: /other, upstream: official, source: "https://example.org", protocol: ["2025-06-18"], modes: [read_only], aggregate: false, identity: {mode: identity_headers, caller_secret: {env: DEMO_SECRET}}}\n'], [],
             "ai.mcp[wiki]: name declared twice"),
            ("label empty", comp, ["      label: Demo\n", '      label: ""\n'], [], "ai.mcp[demo]: label"),
            ("bad kind", comp, ["kind: companion", "kind: sidecar"], [], "ai.mcp.0.kind: 'sidecar' is not one of ['companion', 'builtin']"),
            ("service not in compose", comp, ["service: demo-mcp", "service: nope"], [], "ai.mcp[demo]: service nope is not in compose.yml"),
            ("service shape", comp, ["service: demo-mcp", "service: demo_mcp"], ["  demo-mcp:\n", "  demo_mcp:\n"], "ai.mcp[demo]: service demo_mcp must match"),
            ("companion service twice", comp, ["  mcp:\n", '  mcp:\n    - {name: other, label: O, kind: companion, service: demo-mcp, port: 8080, router: demo, public_path: /other, upstream: official, source: "https://example.org", protocol: ["2025-06-18"], modes: [read_write], identity: {mode: app_token, format: "Bearer {credential}", mint: mcp-mint, revoke: mcp-revoke}}\n'], [],
             "companion service demo-mcp already backs companion other"),
            ("companion with traefik label", comp, [], ["    networks: [default]\n", "    networks: [default]\n    labels:\n      traefik.enable: \"false\"\n"],
             "ai.mcp[demo]: companion service demo-mcp may have no traefik.* label"),
            ("companion on portcullis-proxy", comp, [], ["    networks: [default]\n", "    networks: [default, portcullis-proxy]\n"],
             "ai.mcp[demo]: companion service demo-mcp may not join portcullis-proxy"),
            ("companion with container_name", comp, [], ["    networks: [default]\n", "    networks: [default]\n    container_name: mcpbox\n"],
             "ai.mcp[demo]: companion service demo-mcp may not set container_name"),
            ("companion with hostname", comp, [], ["    networks: [default]\n", "    networks: [default]\n    hostname: mcpbox\n"],
             "ai.mcp[demo]: companion service demo-mcp may not set hostname"),
            ("companion with network_mode", comp, [], ["    networks: [default]\n", "    network_mode: none\n"],
             "ai.mcp[demo]: companion service demo-mcp may not set network_mode"),
            ("service in the companion's namespace", comp, [], [S_INIT, S_INIT + "    network_mode: service:demo-mcp\n"],
             "ai.mcp[demo]: service init uses network_mode service:demo-mcp"),
            ("builtin namespace ok", "headers", [], ["  init:\n    image: demo/init:1.0.0@sha256:" + S_DIGEST + "\n",
                                                     "  init:\n    image: demo/init:1.0.0@sha256:" + S_DIGEST + "\n    network_mode: service:demo\n"], ""),
            ("companion publishes ports", comp, [], ["    networks: [default]\n", "    networks: [default]\n    ports: [\"8080:8080\"]\n"],
             "ai.mcp[demo]: companion service demo-mcp may not publish ports"),
            ("companion image unpinned", comp, [], [f"demo/mcp:1.0.0@sha256:{S_DIGEST}", "demo/mcp:1.0.0"], "sha256"),
            ("port 0", comp, ["port: 8080", "port: 0"], [], "ai.mcp[demo]: port 0 must be 1–65535"),
            ("port missing", comp, ["      port: 8080\n", ""], [], "ai.mcp[demo]: port 0 must be 1–65535"),
            ("path relative", comp, ["      router: demo\n", "      router: demo\n      path: mcp\n"], [], "ai.mcp[demo]: path"),
            ("path query", comp, ["      router: demo\n", "      router: demo\n      path: /mcp?x\n"], [], "ai.mcp[demo]: path"),
            ("router not a host router", comp, ["router: demo", "router: nope"], [], "ai.mcp[demo]: router \"nope\" is not a host router"),
            ("router a path router", comp, ["router: demo", "router: demo-api"],
             ["      traefik.http.services.demo", "      traefik.http.routers.demo-api.rule: Host(`${PORTCULLIS_HOST_DEMO:-demo.portcullis.local}`) && PathPrefix(`/api`)\n"
              "      traefik.http.routers.demo-api.entrypoints: websecure\n      traefik.http.routers.demo-api.tls.options: authaware@file\n"
              "      traefik.http.routers.demo-api.middlewares: portcullis-auth@docker,portcullis-groups@docker,security-headers@file\n"
              "      traefik.http.services.demo"],
             "ai.mcp[demo]: router \"demo-api\" is not a host router"),
            ("public_path /", comp, ["      router: demo\n", "      router: demo\n      public_path: /\n"], [], "ai.mcp[demo]: public_path \"/\""),
            ("public_path well-known", comp, ["      router: demo\n", "      router: demo\n      public_path: /.well-known/x\n"], [],
             "ai.mcp[demo]: public_path /.well-known/x may not be at or under /.well-known/"),
            ("public_path oauth2", comp, ["      router: demo\n", "      router: demo\n      public_path: /oauth2/x\n"], [],
             "ai.mcp[demo]: public_path /oauth2/x may not be at or under /oauth2/"),
            ("public_path unclean", comp, ["      router: demo\n", "      router: demo\n      public_path: /a/../mcp\n"], [], "ai.mcp[demo]: public_path"),
            ("public_path under public access", comp, [
                "  admin_group: admin_demo\n", "  admin_group: admin_demo\n  public_access:\n    default_mode: links\n    enabled_by_default: false\n"
                "    paths:\n      - {prefix: \"/s/{token}\", description: Shares}\n    token_pattern: '^[A-Za-z0-9]{16}$'\n",
                "      router: demo\n", "      router: demo\n      public_path: /s/mcp\n"], [],
             "ai.mcp[demo]: public_path /s/mcp overlaps the auth.public_access path /s"),
            ("nested public_path", comp, ["  mcp:\n", other_builtin], [], "overlaps companion"),
            ("same public_path twice", comp, ["  mcp:\n", other_builtin.replace("public_path: /mcp/other, ", "")], [],
             "ai.mcp[demo]: endpoint path (public_path, or path for app_oauth) /mcp on router demo overlaps companion other's /mcp"),
            ("app_oauth path vs public_path", "oauth", ["  mcp:\n", '  mcp:\n    - {name: tok, label: T, kind: builtin, service: demo, port: 8080, router: demo, public_path: /mcp, upstream: official, source: "https://example.org", protocol: ["2025-06-18"], modes: [read_write], identity: {mode: app_token, format: "Bearer {credential}", mint: revoke-all, revoke: toggle}}\n', "  on_change: toggle\n", ""], [],
             "overlaps companion"),
            ("on_change hook not ai", "oauth", ["{name: toggle, service: demo, command: [/toggle], when: [ai]}", "{name: toggle, service: demo, command: [/toggle], when: [settings_change]}"], [],
             "ai.on_change: hook toggle must have exactly when: [ai]"),
            ("on_change hook missing", "oauth", ["  on_change: toggle\n", "  on_change: nope\n"], [], "ai.on_change: hook nope is not declared in hooks"),
            ("mint hook missing", comp, ["mint: mcp-mint", "mint: nope"], [], "ai.mcp[demo]: identity.mint: hook nope is not declared in hooks"),
            ("mint hook not ai", comp, ["mint: mcp-mint", "mint: apply"], [], "ai.mcp[demo]: identity.mint: hook apply must have exactly when: [ai]"),
            ("hook ai plus another", comp, ["command: [/mint], when: [ai]", "command: [/mint], when: [ai, start]"], [], "hooks[mcp-mint]: when: ai can't be combined"),
            ("ai hook nobody names", comp, ["  - {name: apply,", "  - {name: stray, service: demo, command: [/s], when: [ai]}\n  - {name: apply,"], [],
             "hooks[stray]: when: [ai] but no ai: field names it"),
            ("ai hook in an unsupported template", "unsupported", [AI_UNSUP, AI_UNSUP + "hooks:\n  - {name: stray, service: demo, command: [/s], when: [ai]}\n"], [],
             "hooks[stray]: when: [ai] but no ai: field names it"),
            ("app_oauth companion kind", "oauth", ["kind: builtin", "kind: companion"], [], "ai.mcp[oauth]: app_oauth needs kind builtin"),
            ("app_oauth without revoke", "oauth", ["identity: {mode: app_oauth, revoke: revoke-all}", "identity: {mode: app_oauth}"], [], "identity.revoke"),
            ("app_oauth read_only", "oauth", ["modes: [read_write]", "modes: [read_only, read_write]\n      default_mode: read_write"], [], "ai.mcp[oauth]: an app_oauth companion's modes are exactly [read_write]"),
            ("app_oauth aggregate", "oauth", ["modes: [read_write]", "modes: [read_write]\n      aggregate: true"], [], "ai.mcp[oauth]: aggregate: true is refused"),
            ("app_oauth public_path", "oauth", ["      path: /mcp\n", "      path: /mcp\n      public_path: /x\n"], [], "ai.mcp[oauth]: public_path is refused on an app_oauth companion"),
            ("app_oauth extra key", "oauth", ["identity: {mode: app_oauth, revoke: revoke-all}", 'identity: {mode: app_oauth, revoke: revoke-all, format: "Bearer {credential}"}'], [],
             "ai.mcp[oauth]: identity.format is not a parameter of mode app_oauth"),
            ("identity_headers without caller_secret", "headers", ['        caller_secret: {env: DEMO_SECRET, header: X-Mcp-Secret, format: "{secret}"}\n', ""], [],
             "ai.mcp[wiki]: identity_headers needs identity.caller_secret"),
            ("identity_headers with mint", "headers", ["        mode: identity_headers\n", "        mode: identity_headers\n        mint: x\n"], [],
             "ai.mcp[wiki]: identity.mint is not a parameter of mode identity_headers"),
            ("caller_secret env not random", "headers", ["env: DEMO_SECRET,", "env: PLAIN,"], [], "ai.mcp[wiki]: identity.caller_secret.env \"PLAIN\" must be an env entry with generate: random"),
            ("caller_secret env undeclared", "headers", ["env: DEMO_SECRET,", "env: NOPE,"], [], "generate: random"),
            ("caller_secret format", "headers", ['format: "{secret}"', 'format: "{secret} {secret}"'], [], "ai.mcp[wiki]: identity.caller_secret.format"),
        ] + [
            (f"caller_secret header {h}", "headers", ["header: X-Mcp-Secret", f"header: {h}"], [], "ai.mcp[wiki]: identity.caller_secret.header")
            for h in ("Cookie", "content-length", "Transfer-Encoding", "CONNECTION", "te", "Upgrade", "Keep-Alive", "Trailer",
                      "proxy-connection", "x-forwarded-user", "X-Auth-Request-User", "Remote-User", "X-Portcullis-Secret", "Mcp-Session-Id",
                      "Mcp-Method", "MCP-Protocol-Version", "Host", "Accept", "Content-Type", "Proxy-Authorization", "Bad_Header")
        ] + [
            ("app_token header Upgrade", comp, ['format: "token {credential}"', 'header: Upgrade\n        format: "token {credential}"'], [], "ai.mcp[demo]: identity.header"),
            ("app_token header ok", comp, ['format: "token {credential}"', 'header: X-Api-Key\n        format: "token {credential}"'], [], ""),
            ("app_token without mint", comp, ["        mint: mcp-mint\n", ""], [], "ai.mcp[demo]: identity.mint (a hook) is required for app_token"),
            ("app_token without revoke", comp, ["        revoke: mcp-revoke\n", ""], [], "ai.mcp[demo]: identity.revoke (a hook) is required for app_token"),
            ("app_token bad format", comp, ['format: "token {credential}"', 'format: "{credential}"'], [], "ai.mcp[demo]: identity.format"),
            ("app_token neither format nor basic", comp, ['        format: "token {credential}"\n', ""], [], "ai.mcp[demo]: identity: app_token needs format or basic"),
            ("app_token format and basic", comp, ['format: "token {credential}"', 'format: "token {credential}"\n        basic: {user: "{username}", password: "{credential}"}'], [],
             "ai.mcp[demo]: identity: exactly one of format and basic"),
            ("app_token basic ok", comp, ['format: "token {credential}"', 'basic: {user: "{username}", password: "{credential}"}'], [], ""),
            ("app_token basic password", comp, ['format: "token {credential}"', 'basic: {user: "{username}", password: "x"}'], [], "ai.mcp[demo]: identity.basic.password"),
            ("app_token basic user colon", comp, ['format: "token {credential}"', 'basic: {user: "a:b", password: "{credential}"}'], [], "ai.mcp[demo]: identity.basic.user"),
            ("app_token caller_secret", comp, ["        mint: mcp-mint\n", "        mint: mcp-mint\n        caller_secret: {env: X}\n"], [],
             "ai.mcp[demo]: identity.caller_secret is not a parameter of mode app_token"),
            ("scopes key not a mode", comp, ["modes: [read_only, read_write]\n      default_mode: read_write", "modes: [read_write]"], [], "ai.mcp[demo]: identity.scopes key \"read_only\""),
            ("bad identity mode", comp, ["mode: app_token", "mode: shared_admin"], [], "ai.mcp.0.identity.mode: 'shared_admin' is not one of"),
            ("modes empty", comp, ["modes: [read_only, read_write]\n      default_mode: read_write", "modes: []"], [], "ai.mcp[demo]: modes"),
            ("modes repeat", comp, ["modes: [read_only, read_write]", "modes: [read_write, read_write]"], [], "ai.mcp[demo]: modes"),
            ("modes unknown", comp, ["modes: [read_only, read_write]", "modes: [read_only, admin]"], [], "ai.mcp.0.modes.1: 'admin' is not one of ['read_only', 'read_write']"),
            ("default_mode not in modes", comp, ["modes: [read_only, read_write]\n      default_mode: read_write", "modes: [read_only]\n      default_mode: read_write"], [],
             "ai.mcp[demo]: default_mode \"read_write\" is not one of modes"),
            ("default_mode missing with two", comp, ["      default_mode: read_write\n", ""], [], "ai.mcp[demo]: default_mode is required when modes has two entries"),
            ("community builtin", "headers", ["upstream: official", "upstream: community"], [], "ai.mcp[wiki]: upstream community with kind builtin"),
            ("community companion ok", comp, ["upstream: official", "upstream: community"], [], ""),
            ("upstream missing", comp, ["      upstream: official\n", ""], [], "'upstream' is a required property"),
            ("protocol empty", comp, ['protocol: ["2026-07-28", "2025-11-25"]', "protocol: []"], [], "ai.mcp[demo]: protocol must list at least one"),
            ("protocol unknown", comp, ['protocol: ["2026-07-28", "2025-11-25"]', 'protocol: ["2024-11-05"]'], [], "ai.mcp.0.protocol.0: '2024-11-05' is not one of"),
            ("protocol twice", comp, ['protocol: ["2026-07-28", "2025-11-25"]', 'protocol: ["2025-11-25", "2025-11-25"]'], [], "ai.mcp[demo]: protocol \"2025-11-25\" must be one of"),
            ("tool pattern", comp, ['writes: ["create_*", "delete_*"]', 'writes: ["create *"]'], [], "ai.mcp[demo]: tools.writes pattern"),
            ("too many tool patterns", comp, ['never: []', "never: [" + ", ".join(f"t{i}" for i in range(257)) + "]"], [], "ai.mcp[demo]: tools.never lists more than 256"),
            ("admin_paths", comp, ["  admin_group: admin_demo\n", "  admin_group: admin_demo\n  admin_paths: [/admin]\n"],
             ["      traefik.http.services.demo", "      traefik.http.routers.demo-admin.rule: Host(`${PORTCULLIS_HOST_DEMO:-demo.portcullis.local}`) && PathPrefix(`/admin`)\n"
              "      traefik.http.routers.demo-admin.entrypoints: websecure\n      traefik.http.routers.demo-admin.tls.options: authaware@file\n"
              "      traefik.http.routers.demo-admin.middlewares: portcullis-auth@docker,portcullis-groups@docker,security-headers@file\n"
              "      traefik.http.services.demo"],
             "ai.mcp: not allowed with auth.admin_paths"),
            ("method mtls", "headers", ["method: header-auth", "method: mtls"], [], "ai.mcp: not allowed with auth.method mtls"),
            ("method public", "headers", ["method: header-auth", "method: public"], [], "ai.mcp: not allowed with auth.method public"),
            ("readonly var other form", comp, [], ["${PORTCULLIS_AI_READONLY_DEMO:-true}", "${PORTCULLIS_AI_READONLY_DEMO:-false}"],
             "PORTCULLIS_AI_READONLY_DEMO may appear only as exactly ${PORTCULLIS_AI_READONLY_DEMO:-true}"),
            ("readonly var foreign companion", comp, [], ["${PORTCULLIS_AI_READONLY_DEMO:-true}", "${PORTCULLIS_AI_READONLY_OTHER:-true}"],
             "references PORTCULLIS_AI_READONLY_OTHER"),
            ("enabled var other form", comp, [], ["${PORTCULLIS_AI_ENABLED:-false}", "$PORTCULLIS_AI_ENABLED"], "PORTCULLIS_AI_ENABLED may appear only as exactly"),
            ("enabled var default true", comp, [], ["${PORTCULLIS_AI_ENABLED:-false}", "${PORTCULLIS_AI_ENABLED:-true}"], "PORTCULLIS_AI_ENABLED may appear only as exactly"),
            ("other ai var", comp, [], ["${PORTCULLIS_AI_ENABLED:-false}", "${PORTCULLIS_AI_MODE}"], "references PORTCULLIS_AI_MODE"),
            ("enabled var without mcp", "unsupported", [], ["      DEMO_SECRET: ${DEMO_SECRET:?DEMO_SECRET must be set}\n",
                                                          "      DEMO_SECRET: ${DEMO_SECRET:?DEMO_SECRET must be set}\n      AI: ${PORTCULLIS_AI_ENABLED:-false}\n"],
             "PORTCULLIS_AI_ENABLED may appear only as exactly ${PORTCULLIS_AI_ENABLED:-false}, in a template with ai.mcp"),
        ])

    def test_misshapen_block(self) -> None:
        """A schema error under ai: says what to fix; no follow-on errors
        about the companions' variables or hooks."""
        fx = ai_fixtures()
        m, c = fx["companion"]
        errors, _ = self.run_raw(self.edit(m, ["kind: companion", "kind: sidecar"]), c)
        self.assertError(errors, "ai.mcp.0.kind: 'sidecar' is not one of")
        self.assertFalse([e for e in errors if "only AI variables" in e or "no ai: field names it" in e
                          or "may appear only as exactly" in e], "\n".join(errors))

    def test_mcp_gate_ip_is_a_core_variable(self) -> None:
        fx = ai_fixtures()
        m, c = fx["unsupported"]
        env = "      DEMO_SECRET: ${DEMO_SECRET:?DEMO_SECRET must be set}\n"
        errors, _ = self.run_raw(m, self.edit(c, [env, env + "      GATE: ${PORTCULLIS_MCP_GATE_IP:-172.31.250.3}\n"]))
        self.assertClean(errors)
        errors, _ = self.run_raw(m, self.edit(c, [env, env + "      GATE: ${PORTCULLIS_MCP_GATE_IP}\n"]))
        self.assertError(errors, "${PORTCULLIS_MCP_GATE_IP} must use the default form ${PORTCULLIS_MCP_GATE_IP:-172.31.250.3}")
        self.assertEqual(v.CORE_VARS[v.VAR_MCP_GATE_IP], "172.31.250.3")

    def test_alias_limit(self) -> None:
        fx = ai_fixtures()
        m, c = fx["companion"]
        m31 = self.edit(m, ["- name: demo\n", "- name: " + "a" * 31 + "\n"])
        c31 = self.edit(c, ["PORTCULLIS_AI_READONLY_DEMO", "PORTCULLIS_AI_READONLY_" + "A" * 31])
        for app_id, ok in (("b" * 15, True), ("b" * 16, False)):
            with self.subTest(app_id):
                errors, _ = self.run_raw(m31, c31, app_id=app_id)
                alias = [e for e in errors if "ai.mcp[" + "a" * 31 + "]: the alias" in e]
                if ok:
                    self.assertFalse(alias, "\n".join(alias))
                else:
                    self.assertTrue(alias and "63" in alias[0], "\n".join(errors))

    def test_router_less(self) -> None:
        m = (FS_HEAD.replace(AI_UNSUP, "") + s_opts(FS_CONNECT, FS_UID, fs_ps()) +
             'ai:\n  mcp:\n    - {name: s, label: S, kind: builtin, service: smb, port: 1, router: s, upstream: official, '
             'source: "https://example.org", protocol: ["2025-06-18"], modes: [read_write], '
             'identity: {mode: app_token, format: "Bearer {credential}", mint: sync, revoke: sync}}\n')
        errors, _ = self.run_raw(m, FS_COMPOSE)
        self.assertError(errors, "ai.mcp: not allowed on a router-less template")

    def test_chat_rules(self) -> None:
        chat = "chat"
        self.rows([
            ("no provider kinds", chat, ["provider_kinds: {openai_compatible: many, anthropic: one}", "provider_kinds: {}"], [], "ai.chat.provider_kinds: list at least one"),
            ("unknown provider kind", chat, ["anthropic: one", "mistral: one"], [], "ai.chat.provider_kinds: \"mistral\" must be one of"),
            ("bad cardinality", chat, ["anthropic: one", "anthropic: two"], [], "ai.chat.provider_kinds: anthropic: \"two\" must be one or many"),
            ("file service missing", chat, ["file: {service: demo,", "file: {service: nope,"], [], "ai.chat.file: service \"nope\" is not in compose.yml"),
            ("file mount relative", chat, ["mount: /portcullis/ai", "mount: portcullis"], [], "ai.chat.file: mount \"portcullis\""),
            ("file mount on a data file", chat, ["ai:\n", "files:\n  - {name: people, service: demo, mount: /portcullis}\nai:\n"], [], "ai.chat.file: mount /portcullis/ai collides with files[people]"),
            ("env service missing", chat, ["env: {service: demo}", "env: {service: nope}"], [], "ai.chat.env: service \"nope\" must be a service of compose.yml"),
            ("env missing", chat, ["    env: {service: demo}\n", ""], [], "'env' is a required property"),
            ("chat without ai_client", chat, [", ai_client: true}", "}"], [], "ai.chat: exactly one keycloak_clients entry has ai_client: true (found 0)"),
            ("two ai_clients", chat, ['redirect_uri: "https://{{HOST_DEMO}}/cb"}', 'redirect_uri: "https://{{HOST_DEMO}}/cb", ai_client: true}'], [],
             "ai.chat: exactly one keycloak_clients entry has ai_client: true (found 2)"),
            ("provider var reference", chat, [], ["      MCP_SECRET: ${DEMO_MCP_SECRET:?DEMO_MCP_SECRET must be set}\n",
                                                 "      MCP_SECRET: ${DEMO_MCP_SECRET:?DEMO_MCP_SECRET must be set}\n      KEY: ${PORTCULLIS_AI_PROVIDER_X_KEY}\n"],
             "PORTCULLIS_AI_PROVIDER_* variables are never referenced"),
            ("provider var bare", chat, [], ["      MCP_SECRET: ${DEMO_MCP_SECRET:?DEMO_MCP_SECRET must be set}\n",
                                            "      MCP_SECRET: ${DEMO_MCP_SECRET:?DEMO_MCP_SECRET must be set}\n      KEY: $PORTCULLIS_AI_PROVIDER_X_KEY\n"],
             "PORTCULLIS_AI_PROVIDER_* variables are never referenced"),
            # Fix round 1 (Task 23): a service may not set one either.
            ("provider var map key", chat, [], ["      MCP_SECRET: ${DEMO_MCP_SECRET:?DEMO_MCP_SECRET must be set}\n",
                                               "      MCP_SECRET: ${DEMO_MCP_SECRET:?DEMO_MCP_SECRET must be set}\n      PORTCULLIS_AI_PROVIDER_X_KEY: sk-literal\n"],
             "service demo sets PORTCULLIS_AI_PROVIDER_X_KEY"),
            ("provider var map key lowercase", chat, [], ["      MCP_SECRET: ${DEMO_MCP_SECRET:?DEMO_MCP_SECRET must be set}\n",
                                                         "      MCP_SECRET: ${DEMO_MCP_SECRET:?DEMO_MCP_SECRET must be set}\n      portcullis_ai_provider_x_key: sk-literal\n"],
             "service demo sets portcullis_ai_provider_x_key"),
            ("provider var list bare", chat, [], ["    environment:\n      DEMO_URL: https://${PORTCULLIS_HOST_DEMO:-demo.portcullis.local}\n      TRUSTED_PROXY: ${PORTCULLIS_TRAEFIK_IP:-172.31.250.2}\n      DEMO_SECRET: ${DEMO_SECRET:?DEMO_SECRET must be set}\n      MCP_SECRET: ${DEMO_MCP_SECRET:?DEMO_MCP_SECRET must be set}\n", "    environment:\n      - DEMO_URL=https://${PORTCULLIS_HOST_DEMO:-demo.portcullis.local}\n      - TRUSTED_PROXY=${PORTCULLIS_TRAEFIK_IP:-172.31.250.2}\n      - DEMO_SECRET=${DEMO_SECRET:?DEMO_SECRET must be set}\n      - MCP_SECRET=${DEMO_MCP_SECRET:?DEMO_MCP_SECRET must be set}\n      - PORTCULLIS_AI_PROVIDER_X_KEY\n"],
             "service demo sets PORTCULLIS_AI_PROVIDER_X_KEY"),
            ("provider var list assignment", chat, [], ["    environment:\n      DEMO_URL: https://${PORTCULLIS_HOST_DEMO:-demo.portcullis.local}\n      TRUSTED_PROXY: ${PORTCULLIS_TRAEFIK_IP:-172.31.250.2}\n      DEMO_SECRET: ${DEMO_SECRET:?DEMO_SECRET must be set}\n      MCP_SECRET: ${DEMO_MCP_SECRET:?DEMO_MCP_SECRET must be set}\n", "    environment:\n      - DEMO_URL=https://${PORTCULLIS_HOST_DEMO:-demo.portcullis.local}\n      - TRUSTED_PROXY=${PORTCULLIS_TRAEFIK_IP:-172.31.250.2}\n      - DEMO_SECRET=${DEMO_SECRET:?DEMO_SECRET must be set}\n      - MCP_SECRET=${DEMO_MCP_SECRET:?DEMO_MCP_SECRET must be set}\n      - Portcullis_AI_Provider_X_KEY=sk-literal\n"],
             "service demo sets Portcullis_AI_Provider_X_KEY"),
            # Security review: names built by interpolation, AI names in defaults.
            ("env name interpolated", chat, [], ["      MCP_SECRET: ${DEMO_MCP_SECRET:?DEMO_MCP_SECRET must be set}\n", "      MCP_SECRET: ${DEMO_MCP_SECRET:?DEMO_MCP_SECRET must be set}\n      PORTCULLIS_AI_${X}: sk-literal\n"], "is built by interpolation"),
            ("env list name interpolated", chat, [], ["    environment:\n      DEMO_URL: https://${PORTCULLIS_HOST_DEMO:-demo.portcullis.local}\n      TRUSTED_PROXY: ${PORTCULLIS_TRAEFIK_IP:-172.31.250.2}\n      DEMO_SECRET: ${DEMO_SECRET:?DEMO_SECRET must be set}\n      MCP_SECRET: ${DEMO_MCP_SECRET:?DEMO_MCP_SECRET must be set}\n", "    environment:\n      - DEMO_URL=https://${PORTCULLIS_HOST_DEMO:-demo.portcullis.local}\n      - TRUSTED_PROXY=${PORTCULLIS_TRAEFIK_IP:-172.31.250.2}\n      - DEMO_SECRET=${DEMO_SECRET:?DEMO_SECRET must be set}\n      - MCP_SECRET=${DEMO_MCP_SECRET:?DEMO_MCP_SECRET must be set}\n      - PORTCULLIS_AI_${X}PROVIDER_X_KEY=sk\n"], "is built by interpolation"),
            ("AI name in a default", chat, [], ["      MCP_SECRET: ${DEMO_MCP_SECRET:?DEMO_MCP_SECRET must be set}\n", "      MCP_SECRET: ${DEMO_MCP_SECRET:?DEMO_MCP_SECRET must be set}\n      KEY: ${FOO:-PORTCULLIS_AI_PROVIDER_X_KEY}\n"], "a default or alternate value naming PORTCULLIS_AI_"),
            ("AI name in an alternate", chat, [], ["      MCP_SECRET: ${DEMO_MCP_SECRET:?DEMO_MCP_SECRET must be set}\n", "      MCP_SECRET: ${DEMO_MCP_SECRET:?DEMO_MCP_SECRET must be set}\n      KEY: ${FOO:+portcullis_ai_x}\n"], "a default or alternate value naming PORTCULLIS_AI_"),
            ("env list without provider vars", chat, [], ["    environment:\n      DEMO_URL: https://${PORTCULLIS_HOST_DEMO:-demo.portcullis.local}\n      TRUSTED_PROXY: ${PORTCULLIS_TRAEFIK_IP:-172.31.250.2}\n      DEMO_SECRET: ${DEMO_SECRET:?DEMO_SECRET must be set}\n      MCP_SECRET: ${DEMO_MCP_SECRET:?DEMO_MCP_SECRET must be set}\n", "    environment:\n      - DEMO_URL=https://${PORTCULLIS_HOST_DEMO:-demo.portcullis.local}\n      - TRUSTED_PROXY=${PORTCULLIS_TRAEFIK_IP:-172.31.250.2}\n      - DEMO_SECRET=${DEMO_SECRET:?DEMO_SECRET must be set}\n      - MCP_SECRET=${DEMO_MCP_SECRET:?DEMO_MCP_SECRET must be set}\n"], ""),
            ("ai-providers file", "companion", ["hooks:\n", "files:\n  - {name: ai-providers, service: demo, mount: /data}\nhooks:\n"], [],
             "files[ai-providers]: the data file name ai-providers is reserved"),
        ])

    def test_ai_client_flag(self) -> None:
        self.rows([
            ("ai_client without chat", "oauth", ['redirect_uri: "https://{{HOST_DEMO}}/cb"}', 'redirect_uri: "https://{{HOST_DEMO}}/cb", ai_client: true}'], [],
             "keycloak_clients: client demo has ai_client: true, which is only allowed with ai.chat"),
            ("portcullis-ai- client id", "oauth", ["client_id: demo,", "client_id: portcullis-ai-claude,"], [],
             "keycloak_clients: client_id portcullis-ai-claude: the prefix portcullis-ai- is the Hub's AI clients'"),
            ("portcullis-ai- client id folded", "oauth", ["client_id: demo,", "client_id: Portcullis-AI-x,"], [], "the prefix portcullis-ai-"),
        ])

    def test_hook_ai_trigger(self) -> None:
        self.assertIn("ai", v.HOOK_TRIGGERS)
        self.rows([
            ("unknown trigger names all six", "companion", ["when: [start, settings_change]", "when: [boot]"], [],
             'when "boot" must be start, settings_change, membership_change, credential_change, ai or vpn'),
            ("empty when names all six", "companion", ["when: [start, settings_change]", "when: []"], [],
             "start, settings_change, membership_change, credential_change, ai, vpn"),
            ("option delivers to an ai hook", "companion", ["delivery: [{hook: apply}]", "delivery: [{hook: mcp-mint}]"], [],
             "hook mcp-mint is an ai hook (when: [ai]): no option delivers to it"),
            ("reload names an ai hook", "companion", ["settings:\n", "reload: {hook: mcp-mint}\nsettings:\n"], [],
             "reload: hook mcp-mint is an ai hook (when: [ai])"),
            ("mint hook on the companion service", "companion", ["{name: mcp-mint, service: demo,", "{name: mcp-mint, service: demo-mcp,"], [],
             "hooks[mcp-mint]: an ai hook may not run on service demo-mcp"),
            ("revoke hook on the companion service", "companion", ["{name: mcp-revoke, service: demo,", "{name: mcp-revoke, service: demo-mcp,"], [],
             "hooks[mcp-revoke]: an ai hook may not run on service demo-mcp"),
        ])

    def test_reserved_mcp_names(self) -> None:
        comp, plain = "companion", "unsupported"
        demo_env = "      DEMO_SECRET: ${DEMO_SECRET:?DEMO_SECRET must be set}\n"
        self.rows([
            ("router name", comp, [], ["      traefik.http.services.demo", "      traefik.http.routers.portcullis-mcp-x.rule: Host(`${PORTCULLIS_HOST_DEMO:-demo.portcullis.local}`) && PathPrefix(`/x`)\n      traefik.http.services.demo"], "portcullis-mcp-"),
            ("middleware name", comp, [], ["      traefik.http.services.demo", "      traefik.http.middlewares.Portcullis-MCP-x.headers.customrequestheaders.X: y\n      traefik.http.services.demo"], "portcullis-mcp-"),
            ("service name", comp, ["service: demo-mcp", "service: portcullis-mcp-demo-demo"], ["  demo-mcp:\n", "  portcullis-mcp-demo-demo:\n"], "portcullis-mcp-"),
            ("container_name", plain, [], ["    labels:\n", "    container_name: portcullis-mcp-demo--demo\n    labels:\n"], "portcullis-mcp-"),
            ("hostname", plain, [], ["    labels:\n", "    hostname: portcullis-mcp-x\n    labels:\n"], "portcullis-mcp-"),
            ("network alias", plain, [], ["    networks:\n      - default\n      - portcullis-proxy\n",
                                          "    networks:\n      default:\n        aliases: [portcullis-mcp-demo--x]\n      portcullis-proxy: {}\n"], "portcullis-mcp-"),
            ("split by a variable", plain, [], [demo_env, demo_env + "      X: portcullis-mcp${DEMO_SECRET}-x\n"], "portcullis-mcp-"),
            ("any value", plain, [], [demo_env, demo_env + "      X: http://PORTCULLIS-MCP-demo--demo:8080\n"], "portcullis-mcp-"),
            ("declares PORTCULLIS_AI_ENABLED", plain, ["env:\n", "env:\n  - key: PORTCULLIS_AI_ENABLED\n    description: x\n"], [], "env key PORTCULLIS_AI_ENABLED is reserved"),
            ("declares a provider variable", plain, ["env:\n", "env:\n  - key: PORTCULLIS_AI_PROVIDER_X\n    description: x\n"], [], "env key PORTCULLIS_AI_PROVIDER_X is reserved"),
            ("declares the gate IP", plain, ["env:\n", "ports:\n  - {key: PORTCULLIS_MCP_GATE_IP, label: X, container: 1, default: 1, service: demo}\nenv:\n"], [], "ports key PORTCULLIS_MCP_GATE_IP is reserved"),
            ("mcp default subdomain", plain, ["{{HOST_DEMO}}", "{{HOST_DEMO}}"], ["demo.portcullis.local}`)", "mcp.portcullis.local}`)"], "subdomain 'mcp' belongs to core"),
            ("core service mcp-gate", plain, [], ["  init:\n", "  mcp-gate:\n"], "the DNS name 'mcp-gate' is core's"),
            ("core service dns-tool", plain, [], ["  init:\n", "  dns-tool:\n"], "the DNS name 'dns-tool' is core's"),
            ("core volume mcp_gate_data", plain, [], ["  demo-data: {}\n", "  demo-data: {}\n  mcp_gate_data: {}\n"], "volumes.mcp_gate_data is core's"),
            ("core router mcp", plain, [], ["routers.demo.", "routers.mcp."] * 4, "Traefik label 'traefik.http.routers.mcp.rule': router 'mcp' is core's (reserved)"),
            ("core service mcp-gate label", plain, [], ["traefik.http.services.demo.", "traefik.http.services.mcp-gate."], "service 'mcp-gate' is core's (reserved)"),
        ])
        for k in ("PORTCULLIS_AI_ENABLED", "PORTCULLIS_AI_READONLY_GITEA", "PORTCULLIS_AI_PROVIDER_X", "PORTCULLIS_AI_ANYTHING", "PORTCULLIS_MCP_GATE_IP"):
            self.assertTrue(v.reserved_var(k), k)
            self.assertTrue(v.ai_reserved_var(k), k)
        self.assertIn("mcp", v.CORE_SUBDOMAINS)

    def test_real_templates_all_classified(self) -> None:
        """Every template on main has an ai: block (G63: 50 of them)."""
        import yaml
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        ids = [e for e in sorted(os.listdir(root)) if os.path.isfile(os.path.join(root, e, "manifest.yaml"))]
        self.assertGreaterEqual(len(ids), 50)
        for i in ids:
            with open(os.path.join(root, i, "manifest.yaml"), encoding="utf-8") as f:
                ai = (yaml.safe_load(f) or {}).get("ai")
            self.assertIsInstance(ai, dict, i)
            self.assertTrue(("mcp" in ai) != ("unsupported" in ai), i)


# ── One-off jobs and setup options (contracts §3, §13.18) ───────────
#
# TestSetup mirrors the Hub's internal/templates/setup_test.go
# (TestJobsListed, TestSetupOptionValidation) case for case, with the
# Hub's messages.

def svc(name: str, extra: str = "") -> str:
    return f"  {name}:\n    image: demo/{name}:1.0.0@sha256:{S_DIGEST}\n{extra}"


DB_SERVICES = S_INIT + svc("db-mysql", "    profiles: [db-mysql]\n") + svc("db-postgres", "    profiles: [db-postgres]\n")
DB_CHOICE = ("{key: database, label: Database, type: enum, options: [{value: mysql, label: MySQL}, {value: postgres, label: PostgreSQL}], "
             "default: mysql, setup: true, fixed_after_start: true, %s}")
PROFILES = "profiles: {mysql: [db-mysql], postgres: [db-postgres]}"


def db_opt(extra: str) -> str:
    return DB_CHOICE.replace("%s", extra, 1)


class TestSetup(Case):
    run_raw = TestSettingsV3.run_raw
    cases = TestSettingsV3.cases

    def test_jobs(self) -> None:
        c = s_compose(services=S_INIT + svc("migrate"))
        self.cases([
            ("listed job", S_HDR + "jobs: [migrate]\n", c, "", ""),
            ("init too", S_HDR + "jobs: [migrate, init]\n", c, "", ""),
            ("unknown service", S_HDR + "jobs: [nope]\n", c, "", "jobs: nope is not a compose service"),
            ("twice", S_HDR + "jobs: [migrate, migrate]\n", c, "", "jobs: migrate is listed twice"),
            ("routed", S_HDR + "jobs: [demo]\n", c, "", "jobs: demo has a Traefik router: a one-off job serves nothing"),
            ("not a list", S_HDR + "jobs: migrate\n", c, "", "jobs"),
        ])

    def test_setup_options(self) -> None:
        c = s_compose(s_env("DATABASE"), services=DB_SERVICES)
        plain = s_compose(s_env("THEME"))
        self.cases([
            ("ok", S_HDR + s_opts(db_opt(PROFILES)), c, "", ""),
            ("empty list for a value", S_HDR + s_opts(db_opt("profiles: {mysql: [], postgres: [db-postgres, db-mysql]}")), c, "", ""),
            ("setup string", S_HDR + s_opts("{key: theme, label: T, type: string, default: dark, setup: true}"), plain, "", ""),
            ("setup not fixed", S_HDR + s_opts("{key: theme, label: T, type: string, default: dark, setup: true, fixed_after_start: false}"), plain, "", ""),
            ("profiles on a string", S_HDR + s_opts("{key: theme, label: T, type: string, default: mysql, setup: true, profiles: {mysql: [db-mysql]}}"), c,
             "theme", "profiles is for setup enum options of scope instance"),
            ("profiles without setup", S_HDR + s_opts(db_opt(PROFILES).replace("setup: true, fixed_after_start: true, ", "")), c,
             "database", "profiles is for setup enum options of scope instance"),
            ("profiles without default", S_HDR + s_opts(db_opt(PROFILES).replace("default: mysql, ", "")), c, "database", "profiles needs a default"),
            ("unknown value key", S_HDR + s_opts(db_opt("profiles: {mysql: [db-mysql], postgres: [db-postgres], sqlite: []}")), c,
             "database", "profiles: sqlite is not one of the option's values"),
            ("value without entry", S_HDR + s_opts(db_opt("profiles: {mysql: [db-mysql]}")), c, "database", "profiles: value postgres has no entry"),
            ("unknown profile", S_HDR + s_opts(db_opt("profiles: {mysql: [db-mysql], postgres: [db-pg]}")), c,
             "database", "profiles.postgres: profile db-pg is on no compose service"),
            ("uncovered profiled service", S_HDR + s_opts(db_opt("profiles: {mysql: [db-mysql], postgres: []}")), c,
             "", "service db-postgres: no setup option's profiles start it (its profiles db-postgres)"),
            ("profiled service, no settings", S_HDR, c, "", "service db-mysql: no setup option's profiles start it"),
            ("profiles not a list", S_HDR + s_opts(db_opt(PROFILES)), s_compose(s_env("DATABASE"), services=DB_SERVICES + svc("extra", "    profiles: extra\n")),
             "", "service extra: profiles must be a list of literal profile names"),
            ("profile interpolated", S_HDR + s_opts(db_opt(PROFILES)), s_compose(s_env("DATABASE"), services=DB_SERVICES + svc("extra", "    profiles: [\"${P}\"]\n")),
             "", "service extra: profiles must be a list of literal profile names"),
            ("fixed without setup", S_HDR + s_opts("{key: theme, label: T, type: string, default: dark, fixed_after_start: true}"), plain,
             "theme", "fixed_after_start needs setup: true"),
            ("setup secret", S_HDR + s_opts("{key: theme, label: T, type: secret, setup: true, delivery: [{env: THEME}]}"), plain,
             "theme", "setup needs scope instance and a type other than secret"),
            ("setup person", S_OIDC + s_opts("{key: quota, label: Q, type: int, scope: person, resolve: max, default: 1, setup: true, "
                                              + S_PERSON_CLAIM + "}"), s_compose(oidc=True),
             "quota", "setup needs scope instance and a type other than secret"),
            ("compose profiles reserved", S_HDR.replace("env:\n", "env:\n  - key: COMPOSE_PROFILES\n    description: x\n", 1), plain,
             "", "COMPOSE_PROFILES is an instance variable the Hub sets"),
        ])


    def test_jobs_found_refused_with_router(self) -> None:
        late = svc("late", "    depends_on:\n      demo: {condition: service_completed_successfully}\n")
        ok = svc("late", "    depends_on:\n      init: {condition: service_completed_successfully}\n")
        self.cases([
            ("routed dependency", S_HDR, s_compose(services=S_INIT + late), "", "jobs: demo has a Traefik router: a one-off job serves nothing"),
            ("unrouted dependency", S_HDR, s_compose(services=S_INIT + ok), "", ""),
        ])

    def test_yaml_anchors(self) -> None:
        """Anchors in depends_on and profiles: are followed. validate.py's
        loader refuses << merge keys outright (stricter than the Hub, whose
        TestSetupYAMLAnchors covers them), so a merged depends_on is refused."""
        head = "x-wait: &wait\n  init: {condition: service_completed_successfully}\nx-p: &p [db-mysql]\n"
        services = (S_INIT + svc("late", "    depends_on: *wait\n")
                    + svc("other", "    depends_on: *wait\n") + svc("db-mysql", "    profiles: *p\n")
                    + svc("db-postgres", "    profiles: [db-postgres]\n"))
        c = head + s_compose(s_env("DATABASE"), services=services)
        self.assertEqual(v.job_services({}, v.yaml.safe_load(c)["services"]), {"init"})
        routed = "x-wait: &wait\n  demo: {condition: service_completed_successfully}\n" + s_compose(
            services=S_INIT + svc("late", "    depends_on: *wait\n"))
        merged = head + s_compose(services=S_INIT + svc("late", "    depends_on:\n      <<: *wait\n"))
        self.cases([
            ("anchored profiles", S_HDR + s_opts(db_opt(PROFILES)), c, "", ""),
            ("anchored profiles uncovered", S_HDR + s_opts(db_opt("profiles: {mysql: [], postgres: [db-postgres]}")), c,
             "", "service db-mysql: no setup option's profiles start it"),
            ("anchored dependency on a routed service", S_HDR, routed, "", "jobs: demo has a Traefik router"),
            ("merged depends_on", S_HDR, merged, "", "YAML does not parse"),
        ])

    def test_null_profiles_refused(self) -> None:
        self.cases([
            ("null profiles", S_HDR + s_opts(db_opt("profiles: ~")), s_compose(s_env("DATABASE")), "database", "profiles: value mysql has no entry"),
            ("null profiles on a string", S_HDR + s_opts("{key: theme, label: T, type: string, default: dark, profiles: null}"),
             s_compose(s_env("THEME")), "theme", "profiles is for setup enum options of scope instance"),
        ])

    def test_unprofiled_depends_on_profiled(self) -> None:
        m = S_HDR + s_opts(db_opt(PROFILES))

        def c(extra: str) -> str:
            return s_compose(s_env("DATABASE"), services=DB_SERVICES + extra)
        self.cases([
            ("depends_on list", m, c(svc("app", "    depends_on: [db-mysql]\n")), "", "service app: depends_on names profiled service db-mysql"),
            ("depends_on map", m, c(svc("app", "    depends_on:\n      db-postgres: {condition: service_healthy}\n")),
             "", "service app: depends_on names profiled service db-postgres"),
            ("network_mode", m, c(svc("app", "    network_mode: service:db-mysql\n")), "", "service app: network_mode names profiled service db-mysql"),
            ("volumes_from", m, c(svc("app", "    volumes_from: [\"db-mysql:ro\"]\n")), "", "service app: volumes_from names profiled service db-mysql"),
            ("profiled may depend on profiled", m, c(svc("admin", "    profiles: [db-mysql]\n    depends_on: [db-mysql]\n")), "", ""),
            ("unprofiled dependency ok", m, c(svc("app", "    depends_on: [init]\n")), "", ""),
        ])

    def test_schema_profile_pattern(self) -> None:
        errors, _ = self.run_raw(S_HDR + s_opts(db_opt("profiles: {mysql: [db-mysql], postgres: ['-bad']}")), s_compose(s_env("DATABASE"), services=DB_SERVICES))
        self.assertError(errors, "-bad")


class RootlessTests(unittest.TestCase):
    """Tests for rootless Podman compatibility classification (Task 6)."""

    def test_vectors(self) -> None:
        """Test each vector through rootless_compat equals want."""
        vectors_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rootless_vectors.json")
        with open(vectors_path, encoding="utf-8") as f:
            vectors = json.load(f)

        for vec in vectors:
            with self.subTest(name=vec["name"]):
                # Create a minimal template
                t = v.Template("test")
                # As the Hub's harness: a vector port's port is both its
                # default (the host port) and its container port.
                t.manifest = {"ports": [{"key": p["key"], "default": p["port"], "container": p["port"], "protocol": p["protocol"]}
                                        for p in vec.get("ports", [])]}
                t.compose = v.yaml.safe_load(vec["compose"])

                status, reasons = v.rootless_compat(t, env=vec.get("env", {}), port_start=vec["port_start"])

                want_status = vec["want"]["status"]
                want_reasons = vec["want"]["reasons"]

                self.assertEqual(status, want_status, f"Status mismatch for {vec['name']}")
                self.assertEqual(reasons, want_reasons, f"Reasons mismatch for {vec['name']}")

    def compat(self, compose: str, manifest: Dict[str, Any], env: Optional[Dict[str, str]] = None) -> Tuple[str, List[str]]:
        t = v.Template("test")
        t.manifest = manifest
        t.compose = v.yaml.safe_load(compose)
        return v.rootless_compat(t, env=env, port_start=80)

    def test_rules_vectors_cannot_express(self) -> None:
        """Rules the shared vectors' format can't carry (the Hub's TestRootlessCompatRules)."""
        app = "services:\n  a:\n    image: x\n"
        below = ("host port {0}/tcp is below net.ipv4.ip_unprivileged_port_start (80): "
                 "lower it to {0} on the host to allow it (any local user can then bind ports from {0})")
        ids = "service {} runs as id {}, outside the rootless id range (0–65535)"
        for name, manifest, env, want in [
            ("host port is default, not container", {"ports": [{"key": "P", "container": 53, "default": 8053}]}, None, ("ok", [])),
            ("default below the start", {"ports": [{"key": "P", "container": 8080, "default": 53}]}, None, ("refused", [below.format(53)])),
            ("range start", {"ports": [{"key": "R", "range": "49152-65535", "protocol": "udp"}]}, None,
             ("degraded", ["UDP clients on port 49152 appear with a rewritten source address"])),
            ("range from env", {"ports": [{"key": "R", "range": "49152-65535"}]}, {"R": "40-50"}, ("refused", [below.format(40)])),
            ("folder runs_as uid", {"settings": {"options": [{"key": "media", "type": "folder", "target": {"service": "a"},
                                                               "folder": {"runs_as": {"uid": 70000, "gid": 1000}}}]}}, None,
             ("refused", [ids.format("a", 70000)])),
            ("folder runs_as names the key without a target", {"settings": {"options": [{"key": "media", "folder": {"runs_as": {"gid": -1}}}]}}, None,
             ("refused", [ids.format("media", -1)])),
        ]:
            with self.subTest(name=name):
                self.assertEqual(self.compat(app, manifest, env), want)

    def test_unreadable_compose_refused(self) -> None:
        for name, text in [("bad yaml", "services: [\n"), ("services not a mapping", "services: [a]\n"),
                           ("service not a mapping", "services:\n  a: [x]\n")]:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmpdir:
                os.makedirs(os.path.join(tmpdir, "t"))
                with open(os.path.join(tmpdir, "t", "compose.yml"), "w", encoding="utf-8") as f:
                    f.write(text)
                with mock.patch.object(v, "ROOT", tmpdir):
                    t = v.Template("t")
                    t.manifest = {}
                    status, reasons = v.rootless_compat(t)
                self.assertEqual(status, "refused")
                self.assertEqual(len(reasons), 1)
                self.assertTrue(reasons[0].startswith("compose.yml can't be read: "), reasons)

    def test_committed_classification(self) -> None:
        """Test that validate.py --rootless output matches tests/rootless.txt."""
        rootless_txt_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rootless.txt")
        if not os.path.exists(rootless_txt_path):
            self.skipTest("tests/rootless.txt does not exist yet")

        with open(rootless_txt_path, encoding="utf-8") as f:
            expected = f.read().strip()

        # Run validate.py --rootless
        result = v.main(["--rootless"])
        self.assertEqual(result, 0, "validate.py --rootless should exit 0")

        # We can't easily capture stdout from main(), so we test it separately below

    def test_reserved_port_start(self) -> None:
        """Test that a template referencing PORTCULLIS_UNPRIVILEGED_PORT_START is refused (P15)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            app_dir = os.path.join(tmpdir, "test-app")
            os.makedirs(app_dir)

            manifest = MANIFEST.format(instances="single", notes="test", url="https://{{{{HOST_MAIN}}}}/")
            with open(os.path.join(app_dir, "manifest.yaml"), "w", encoding="utf-8") as f:
                f.write(manifest)

            compose = """services:
  app:
    image: nginx:alpine
    environment:
      - PORT=${PORTCULLIS_UNPRIVILEGED_PORT_START:-80}
networks:
  portcullis-proxy:
    external: true
"""
            with open(os.path.join(app_dir, "compose.yml"), "w", encoding="utf-8") as f:
                f.write(compose)

            with mock.patch.object(v, "ROOT", tmpdir):
                r = v.Report()
                t = v.Template("test-app")
                v.check_layout(t, r)
                v.check_compose(t, r)
                self.assertTrue(any("PORTCULLIS_UNPRIVILEGED_PORT_START" in e for e in r.errors),
                                "Should refuse PORTCULLIS_UNPRIVILEGED_PORT_START")

    def test_expected_refusals(self) -> None:
        """Test that pihole, adguard, scrutiny, esphome, motioneye, zigbee2mqtt, samba, timemachine
        are classified as expected."""
        expected = {
            "pihole": ("refused", "53/tcp"),
            "adguard": ("refused", "53/tcp"),
            "scrutiny": ("refused", "SYS_RAWIO"),
            "esphome": ("degraded", None),
            "motioneye": ("degraded", None),
            "zigbee2mqtt": ("degraded", None),
            "samba": ("ok", None),
            "timemachine": ("ok", None),
        }

        for app_id, (want_status, reason_substr) in expected.items():
            app_path = os.path.join(v.ROOT, app_id)
            if not os.path.isdir(app_path):
                continue

            with self.subTest(app=app_id):
                t = v.Template(app_id)
                r = v.Report()
                if not v.check_layout(t, r):
                    continue

                # Load manifest and compose
                try:
                    with open(t.manifest_path, encoding="utf-8") as f:
                        t.manifest = v.yaml.safe_load(f.read())
                except:
                    continue

                try:
                    with open(t.compose_path, encoding="utf-8") as f:
                        t.compose = v.yaml.safe_load(f.read())
                except:
                    continue

                status, reasons = v.rootless_compat(t, env={}, port_start=80)

                self.assertEqual(status, want_status, f"{app_id} should be {want_status}, got {status}")
                if reason_substr:
                    self.assertTrue(any(reason_substr in r for r in reasons),
                                    f"{app_id} should have reason containing '{reason_substr}', got {reasons}")



VPN_BLOCK = """\
hooks:
  - {name: vpn-devices, service: init, command: [python3, /vpn/glue.py], when: [vpn]}
  - {name: vpn-dns, service: init, command: [python3, /vpn/glue.py], when: [vpn]}
vpn:
  label: Demo tailnet
  ranges: ["100.64.0.0/10"]
  ingress: {service: gateway, proxy_protocol: v2}
  identity: {source: hook, hook: vpn-devices, owner: oidc_sub, refresh: 60s}
  dns: {hook: vpn-dns}
  control_routers: [demo]
"""
VPN_GATEWAY = (f"  gateway:\n    image: docker.io/tailscale/tailscale:v1.90.0@sha256:{S_DIGEST}\n"
               "    command: [\"sh\", \"-c\", \"echo $$PORTCULLIS_VPN_EDGE\"]\n    cap_drop: [ALL]\n")


def load_app_signin(app: str) -> Any:
    """tests/e2e/app_signin.py as a module, for app (it reads the app's
    manifest at import)."""
    import importlib.util
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "e2e", "app_signin.py")
    spec = importlib.util.spec_from_file_location("app_signin_" + app.replace("-", "_"), path)
    mod = importlib.util.module_from_spec(spec)
    with mock.patch.object(sys, "argv", ["app_signin.py", app]):
        spec.loader.exec_module(mod)
    return mod


class VPNTests(Case):
    """The vpn: block (contract §3.3), the vpn hook trigger and the
    reserved portcullis-vpn names, as the Hub's ValidateVPN (shared
    vectors tests/vpn_vectors.json = Hub
    internal/templates/testdata/vpn_vectors.json)."""
    run_raw = TestSettingsV3.run_raw

    def vpn_template(self, medit: Tuple[str, str] = ("", ""), cedit: Tuple[str, str] = ("", "")) -> List[str]:
        # group_admin: true would make the control router an admin UI.
        m = S_OIDC.replace(AI_UNSUP, AI_UNSUP + VPN_BLOCK).replace("  group_admin: true\n", "  group_admin: false\n", 1)
        c = s_compose(oidc=True, services=S_INIT + VPN_GATEWAY)
        if medit[0]:
            self.assertIn(medit[0], m)
            m = m.replace(medit[0], medit[1], 1)
        if cedit[0]:
            self.assertIn(cedit[0], c)
            c = c.replace(cedit[0], cedit[1], 1)
        errors, _ = self.run_raw(m, c)
        return errors

    # The refusals the shared vectors exercise (ValidateVPN, and the VPN
    # rules of the Hub's settings, coreref and reservedvars checks).
    VPN_FAMILY = ("vpn.", "vpn:", "when: [vpn]", "vpn can't be combined", "is a vpn hook", "portcullis-vpn", "PORTCULLIS_VPN_")

    @staticmethod
    def hub_texts(error: str) -> List[str]:
        """A validate.py error as the Hub would word it: '<app>/<file>:
        msg' -> msg, '<file>: msg' and '<file> msg' (the Hub's texts carry
        the file name where theirs need one), hint dropped."""
        head = error.split("\n", 1)[0]
        loc, _, msg = head.partition(": ")
        f = loc.rsplit("/", 1)[-1]
        out = [msg, f"{f}: {msg}", f"{f} {msg}"]
        # check_hub_rules words a service's location services.<s>: where the
        # Hub's coreref texts say service <s>:.
        m = v.re.match(r"services\.([^:]+): (.*)", msg, v.re.S)
        if m:
            out.append(f"service {m.group(1)}: {m.group(2)}")
        return out

    def test_vectors(self) -> None:
        """Each Hub vector (a whole template; the Hub's TestVPNVectors
        builds it as app mesh) gives the Hub's error among validate.py's,
        and, for a ValidateVPN refusal, as vpn_errors' first; an ok
        vector gives no VPN refusal (validate.py's other repo rules may
        still fire on the vectors' minimal templates)."""
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vpn_vectors.json")
        with open(path, encoding="utf-8") as f:
            vectors = json.load(f)
        self.assertGreater(len(vectors), 40)
        for vec in vectors:
            with self.subTest(vec["name"]):
                self.assertEqual(sorted(vec), ["compose", "manifest", "name", "want_error"])
                errors, _ = self.run_raw(vec["manifest"], vec["compose"], "mesh")
                texts = [t for e in errors for t in self.hub_texts(e)]
                family = [e for e in errors if any(k in self.hub_texts(e)[0] for k in self.VPN_FAMILY)]
                want = vec["want_error"]
                if want == "":
                    self.assertEqual(family, [], "\n".join(errors))
                    continue
                # The repo's YAML 1.2 loader has no merge keys: such a file
                # already fails to load (stricter; vpn_errors still says
                # what the Hub says).
                if not ("merge keys" in want and any("tag:yaml.org,2002:merge" in e for e in errors)):
                    self.assertIn(want, texts, "\n".join(errors))
                first = v.vpn_errors(v.yaml.safe_load(vec["manifest"]), v.yaml.safe_load(vec["compose"]), "mesh", vec["compose"])
                if want.startswith(("vpn.", "vpn:")) or "needs a vpn: block" in want:
                    self.assertEqual(first[:1], [want], first)

    def test_template_with_vpn_block_clean(self) -> None:
        self.assertClean(self.vpn_template())

    def test_template_reports_vpn_refusal(self) -> None:
        self.assertError(self.vpn_template(("label: Demo tailnet", 'label: ""')), "vpn.label: a single line of 1–64 characters")
        self.assertError(self.vpn_template(("ingress: {service: gateway,", "ingress: {service: demo,")),
                         "vpn.ingress.service: demo has a Traefik router")

    def test_schema_vpn_strict(self) -> None:
        for name, old, new in [
            ("top level", "  label: Demo tailnet\n", "  label: Demo tailnet\n  bogus: 1\n"),
            ("ingress", "proxy_protocol: v2}", "proxy_protocol: v2, bogus: 1}"),
            ("identity", "refresh: 60s}", "refresh: 60s, bogus: 1}"),
            ("dns", "dns: {hook: vpn-dns}", "dns: {hook: vpn-dns, bogus: 1}"),
        ]:
            with self.subTest(name):
                self.assertError(self.vpn_template((old, new)), "bogus")
        # The source is the validator's (the Hub's text), not a schema enum.
        self.assertError(self.vpn_template(("source: hook", "source: mesh")), "vpn.identity.source: hook or static")

    def test_reserved_vpn_ref(self) -> None:
        for name, old, new in [
            ("allowlist middleware", "middlewares: security-headers@file", "middlewares: portcullis-vpnallow-x@docker,security-headers@file"),
            ("the network", "      - portcullis-proxy\n    labels", "      - portcullis-proxy\n      - portcullis-vpn\n    labels"),
            ("folded", "DEMO_URL:", "X: Portcullis-VPN\n      DEMO_URL:"),
        ]:
            with self.subTest(name):
                errors = self.vpn_template(cedit=(old, new))
                self.assertError(errors, 'references "portcullis-vpn"')
        # The forwarder image name doesn't contain the reserved prefix (V1).
        self.assertClean(self.vpn_template(cedit=("docker.io/tailscale/tailscale:v1.90.0", "ghcr.io/porelli/portcullis-forwarder:1.0.0")))

    def test_reserved_vpn_var(self) -> None:
        for name, old, new in [
            ("braced", "DEMO_URL:", "EDGE: ${PORTCULLIS_VPN_EDGE}\n      DEMO_URL:"),
            ("default form", "DEMO_URL:", "EDGE: ${PORTCULLIS_VPN_EDGE:-172.31.254.3:9001}\n      DEMO_URL:"),
            ("bare", "DEMO_URL:", "EDGE: $PORTCULLIS_VPN_MODE\n      DEMO_URL:"),
        ]:
            with self.subTest(name):
                self.assertError(self.vpn_template(cedit=(old, new)), "PORTCULLIS_VPN_")
        # $$PORTCULLIS_VPN_EDGE (the container's shell reads it) is clean:
        # VPN_GATEWAY's command uses it.
        self.assertIn("$$PORTCULLIS_VPN_EDGE", VPN_GATEWAY)
        self.assertClean(self.vpn_template())
        errors = self.vpn_template(("env:\n", "env:\n  - key: PORTCULLIS_VPN_PORT\n    description: x\n"))
        self.assertError(errors, "PORTCULLIS_VPN_PORT is reserved")

    def test_core_names(self) -> None:
        self.assertIn("wg", v.CORE_SERVICES)
        self.assertIn("wg_data", v.CORE_VOLUMES)
        self.assertIn("vpn_doc", v.CORE_VOLUMES)
        self.assertIn("vpn", v.HOOK_TRIGGERS)
        errors = self.vpn_template(cedit=("  gateway:\n", "  wg:\n"), medit=("service: gateway,", "service: wg,"))
        self.assertError(errors, "wg")
        # Core's wg metrics alias and VPN Traefik names (Hub coreAliases /
        # coreTraefikNames).
        self.assertTrue(v.reserved_dns_name("wg-metrics") and v.reserved_dns_name("WG-Metrics.example."))
        self.assertError(self.vpn_template(cedit=("    networks:\n      - default\n      - portcullis-proxy\n    labels",
                                                   "    networks:\n      default:\n        aliases: [wg-metrics]\n      portcullis-proxy: {}\n    labels")),
                         "network alias 'wg-metrics' is core's DNS name (reserved)")
        self.assertError(self.vpn_template(cedit=("traefik.http.routers.demo.", "traefik.http.routers.people-vpn-enrol.")),
                         "router 'people-vpn-enrol' is core's (reserved)")
        self.assertError(self.vpn_template(cedit=('      traefik.enable: "true"\n',
                                                   '      traefik.enable: "true"\n      traefik.http.middlewares.vpn-required-path.headers.customrequestheaders.X-A: "1"\n')),
                         "middleware 'vpn-required-path' is core's (reserved)")
        # A volume keyed like core's vpn_doc (Docker name portcullis_vpn_doc).
        errors = self.vpn_template(cedit=("volumes:\n  demo-data: {}\n", "volumes:\n  demo-data: {}\n  vpn_doc: {}\n"))
        self.assertError(errors, "vpn_doc")

    def test_vpn_hooks_never_in_the_settings_engine(self) -> None:
        """V10: a vpn hook is never a reload hook nor an option's delivery hook."""
        self.assertError(self.vpn_template(("vpn:\n", "reload: {hook: vpn-dns}\nvpn:\n")),
                         "reload: hook vpn-dns is a vpn hook (when: [vpn]): the settings engine never runs it")
        opt = s_opts("{key: theme, label: Theme, type: string, default: x, applies: live, delivery: [{hook: vpn-dns}]}")
        self.assertError(self.vpn_template(("vpn:\n", opt + "vpn:\n")),
                         "hook vpn-dns is a vpn hook (when: [vpn]): no option delivers to it")

    def test_ingress_namespace(self) -> None:
        """Hub checkVPNIngress: services in the ingress's network namespace
        (chains followed) and host namespaces."""
        fwd = f"ghcr.io/porelli/portcullis-forwarder:1.0.0@sha256:{S_DIGEST}"
        sib = "  {name}:\n    image: {image}\n    network_mode: service:{of}\n    cap_drop: [ALL]\n{extra}"
        def with_services(*svcs: str) -> List[str]:
            return self.vpn_template(cedit=("  gateway:\n", "".join(svcs) + "  gateway:\n"))
        self.assertClean(with_services(sib.format(name="fwd", image=fwd, of="gateway", extra="")))
        self.assertError(with_services(sib.format(name="side", image=f"x/y:1.0.0@sha256:{S_DIGEST}", of="gateway",
                                                  extra="    labels:\n      traefik.enable: \"false\"\n")),
                         "vpn.ingress.service: side shares gateway's network namespace: only the pinned "
                         "ghcr.io/porelli/portcullis-forwarder image may")
        self.assertError(with_services(sib.format(name="fwd", image=fwd, of="gateway", extra="    labels:\n      traefik.enable: \"false\"\n")),
                         "vpn.ingress.service: fwd has a Traefik router")
        self.assertError(with_services(sib.format(name="fwd", image="ghcr.io/porelli/portcullis-forwarder:1.0.0", of="gateway", extra="")),
                         "fwd shares gateway's network namespace")
        # A chain: tail -> fwd -> gateway.
        self.assertError(with_services(sib.format(name="fwd", image=fwd, of="gateway", extra=""),
                                       sib.format(name="tail", image=f"x/y:1.0.0@sha256:{S_DIGEST}", of="fwd", extra="")),
                         "vpn.ingress.service: tail shares gateway's network namespace")
        self.assertEqual(v.vpn_net_ns({"a": {"network_mode": "service:b"}, "b": {"network_mode": "service:a"}}, "a"), None)
        self.assertEqual(v.vpn_net_ns({"a": {"network_mode": "service:b"}, "b": {"network_mode": "service:c"}, "c": {}}, "a"), "c")
        # Host namespaces with a vpn: block: pid: host on no service;
        # network_mode: host never for the ingress, its namespace's members
        # or a routed service, others keep the template rules.
        host = f"  hostly:\n    image: x/y:1.0.0@sha256:{S_DIGEST}\n    {{}}: host\n{{}}"
        label = "    labels:\n      traefik.enable: \"false\"\n"
        self.assertError(with_services(host.format("network_mode", label)), "vpn: service hostly uses network_mode: host")
        self.assertError(with_services(host.format("pid", label)), "vpn: service hostly uses pid: host")
        self.assertFalse([e for e in with_services(host.format("network_mode", "")) if "vpn: service" in e])
        self.assertError(with_services(host.format("pid", "")), "vpn: service hostly uses pid: host")
        self.assertError(self.vpn_template(cedit=("  gateway:\n    image: docker.io/tailscale/tailscale:v1.90.0@sha256:" + S_DIGEST + "\n",
                                                   "  gateway:\n    image: docker.io/tailscale/tailscale:v1.90.0@sha256:" + S_DIGEST + "\n    pid: host\n")),
                         "vpn: service gateway uses pid: host")
        self.assertError(with_services(sib.format(name="fwd", image=fwd, of="gateway", extra="    pid: host\n")), "vpn: service fwd uses pid: host")

    def test_gateway_runs_userspace(self) -> None:
        """Ruling (Task 19, security review): an allowlist for the ingress and
        its namespace: privileged absent or false, cap_drop includes ALL,
        cap_add only NET_BIND_SERVICE, no devices, no device_cgroup_rules."""
        gw = "    cap_drop: [ALL]\n"
        only = "a VPN gateway may add only NET_BIND_SERVICE"
        for name, new, want in [
            ("no cap_drop", "", "vpn.ingress.service: gateway must set cap_drop: [ALL]"),
            ("NET_ADMIN", gw + "    cap_add: [NET_ADMIN]\n", f"gateway adds NET_ADMIN: {only}"),
            ("CAP_NET_RAW", gw + "    cap_add: [CAP_NET_RAW]\n", f"gateway adds CAP_NET_RAW: {only}"),
            ("CHOWN", gw + "    cap_add: [CHOWN]\n", f"gateway adds CHOWN: {only}"),
            ("ALL", gw + "    cap_add: [ALL]\n", f"gateway adds ALL: {only}"),
            ("interpolated", gw + "    cap_add: [\"${GW_CAP:-NET_BIND_SERVICE}\"]\n", "gateway adds ${GW_CAP:-NET_BIND_SERVICE}"),
            ("tun", gw + "    devices: [\"/dev/net/tun:/dev/net/tun\"]\n", "gateway has devices"),
            ("any device", gw + "    devices: []\n", "gateway has devices"),
            ("cgroup rules", gw + "    device_cgroup_rules: [\"c 10:200 rwm\"]\n", "gateway has device_cgroup_rules"),
            ("privileged", gw + "    privileged: true\n", "vpn.ingress.service: gateway is privileged"),
            ("privileged interpolated", gw + "    privileged: ${GW_PRIV:-false}\n", "vpn.ingress.service: gateway is privileged"),
            ("privileged 0", gw + "    privileged: 0\n", "vpn.ingress.service: gateway is privileged"),
        ]:
            with self.subTest(name):
                self.assertError(self.vpn_template(cedit=(gw, new)), want)
        for ok in ("    cap_add: [NET_BIND_SERVICE]\n", "    cap_add: [cap_net_bind_service]\n", "    privileged: false\n"):
            with self.subTest(ok):
                self.assertClean(self.vpn_template(cedit=(gw, gw + ok)))
        # The string "false" passes the VPN rule (the repo's multi-instance
        # rule still refuses any truthy privileged).
        self.assertFalse([e for e in self.vpn_template(cedit=(gw, gw + '    privileged: "false"\n')) if "is privileged" in e])
        fwd = f"ghcr.io/porelli/portcullis-forwarder:1.0.0@sha256:{S_DIGEST}"
        self.assertError(self.vpn_template(cedit=("  gateway:\n", f"  fwd:\n    image: {fwd}\n    network_mode: service:gateway\n"
                                                                    "    cap_drop: [ALL]\n    cap_add: [NET_ADMIN]\n  gateway:\n")),
                         f"vpn.ingress.service: fwd adds NET_ADMIN: {only}")

    def test_pid_ipc_of_the_gateway_namespace(self) -> None:
        """A service sharing the pid or ipc namespace of the ingress (or a
        member of its namespace) reaches the gateway's processes."""
        side = f"  side:\n    image: x/y:1.0.0@sha256:{S_DIGEST}\n    {{}}: service:{{}}\n  gateway:\n"
        self.assertError(self.vpn_template(cedit=("  gateway:\n", side.format("pid", "gateway"))),
                         "vpn.ingress.service: side shares the pid namespace of gateway")
        self.assertError(self.vpn_template(cedit=("  gateway:\n", side.format("ipc", "gateway"))),
                         "vpn.ingress.service: side shares the ipc namespace of gateway")
        self.assertFalse([e for e in self.vpn_template(cedit=("  gateway:\n", side.format("pid", "init"))) if "shares the" in e])
        # Symmetric: the ingress (and its namespace) set neither key.
        gw = "    cap_drop: [ALL]\n"
        for key in ("pid", "ipc"):
            self.assertError(self.vpn_template(cedit=(gw, gw + f"    {key}: private\n")),
                             f"vpn.ingress.service: gateway sets {key}: a VPN gateway keeps its own pid and ipc namespaces")
        # container: targets: refused for every template (check_hub_rules).
        self.assertError(self.vpn_template(cedit=("  gateway:\n", f"  side:\n    image: x/y:1.0.0@sha256:{S_DIGEST}\n"
                                                                    "    ipc: container:portcullis-demo-gateway-1\n  gateway:\n")),
                         "ipc container:portcullis-demo-gateway-1")

    def test_volumes_from_the_gateway_namespace(self) -> None:
        """volumes_from, both ways: nobody mounts the gateway's volumes, the
        gateway mounts nobody's."""
        side = f"  side:\n    image: x/y:1.0.0@sha256:{S_DIGEST}\n    volumes_from: [{{}}]\n  gateway:\n"
        for vf in ("gateway", "\"gateway:ro\"", "\"service:gateway\"", "\"service:gateway:rw\""):
            with self.subTest(vf):
                self.assertError(self.vpn_template(cedit=("  gateway:\n", side.format(vf))),
                                 "vpn.ingress.service: side mounts the volumes of gateway (volumes_from)")
        for vf in ("\"gateway:z\"", "\"gateway:ro:rw\"", "\"init:RO\""):
            with self.subTest(vf):
                self.assertError(self.vpn_template(cedit=("  gateway:\n", side.format(vf))), ": the mode must be ro or rw")
        gw = "    cap_drop: [ALL]\n"
        self.assertError(self.vpn_template(cedit=(gw, gw + "    volumes_from: [init]\n")),
                         "vpn.ingress.service: gateway uses volumes_from: a VPN gateway mounts no other service's volumes")
        self.assertFalse([e for e in self.vpn_template(cedit=("  gateway:\n", side.format("init"))) if "mounts the volumes" in e])

    def test_bind_symlinks_stay_in_the_template(self) -> None:
        """A bind under ./templates/<id>/ resolves (symlinks followed) inside
        the template's own directory."""
        d = os.path.join(self.tmp.name, "demo", "vpn")
        os.makedirs(d, exist_ok=True)
        open(os.path.join(d, "gw.sh"), "w").close()
        os.symlink("/etc", os.path.join(d, "out"))
        os.symlink("gw.sh", os.path.join(d, "in"))
        bind = "  init:\n    image: demo/init:1.0.0@sha256:" + S_DIGEST + "\n"
        for src, want in (("./templates/demo/vpn/out/passwd", "it resolves outside templates/demo/ (a symlink)"),
                          ("./templates/demo/vpn/in", "")):
            with self.subTest(src):
                errors = self.vpn_template(cedit=(bind, bind + f"    volumes: [\"{src}:/x:ro\"]\n"))
                if want:
                    self.assertError(errors, f"vpn.ingress.service: init mounts {src}:/x:ro: {want}")
                else:
                    self.assertFalse([e for e in errors if "resolves outside" in e], "\n".join(errors))

    def test_control_router_shapes(self) -> None:
        """Ruling (Task 19): a control router is Host() alone or Host() &&
        one PathPrefix()."""
        self.assertTrue(v._HOST_ONLY_RULE_RE.fullmatch("Host(`a`) && PathPrefix(`/x/`)"))
        self.assertTrue(v._HOST_ONLY_RULE_RE.fullmatch("Host(`a`)"))
        for bad in ("PathPrefix(`/x`)", "Host(`a`) && Path(`/x`)", "Host(`a`) || PathPrefix(`/x`)",
                    "Host(`a`) && PathPrefix(`/a`) && PathPrefix(`/b`)", "Host(`a`) && !PathPrefix(`/x`)"):
            with self.subTest(bad):
                self.assertFalse(v._HOST_ONLY_RULE_RE.fullmatch(bad))

    def test_policy_doc_v7(self) -> None:
        mod = load_app_signin("headscale")
        v6 = mod.policy_doc(6)
        self.assertEqual(v6["version"], 6)
        self.assertNotIn("vpn", v6)
        v7 = mod.policy_doc(7)
        self.assertEqual(v7["version"], 7)
        self.assertEqual(v7["vpn"], {"hosts": {}, "server_mode": False, "admin_only": False, "public_enrol": True,
                                     "devices_file": "vpn.json"})
        self.assertEqual({k: x for k, x in v7.items() if k not in ("version", "vpn")},
                         {k: x for k, x in v6.items() if k != "version"})


if __name__ == "__main__":
    unittest.main()
