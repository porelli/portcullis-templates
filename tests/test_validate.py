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
from unittest import mock
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
tests:
  signin:
    path: /
    signed_in:
      text: "{{username}}"
    admin:
      reach: /admin
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
        v.check_compose(t, r)
        self.assertTrue(any("does not check the username" in w for w in r.warnings), r.warnings)



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



class TestHubRules(Case):
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

if __name__ == "__main__":
    unittest.main()


class TestGatedHomeTemplates(unittest.TestCase):
    """The real esphome / zigbee2mqtt / motioneye templates, each guard
    removed in turn: every removal must fail validation."""

    APPS = ("esphome", "zigbee2mqtt", "motioneye")
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
