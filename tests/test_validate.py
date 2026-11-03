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
from typing import List, Tuple

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
             "  access_group: users_demo\n  notes: Mozilla accounts.\n")
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
S_PERSON_HEADER = "{key: quota, label: Q, type: int, scope: person, default: 1, delivery: [{header: {name: X-Forwarded-Attr-Quota}}]}"
S_FILES = """\
files:
  - {name: people, service: init, mount: /portcullis, on_membership_change: restart}
hooks:
  - {name: apply, service: demo, command: [php, /portcullis/apply.php], when: [start, settings_change], timeout: 60s}
"""
S_ROLE = ("{key: role, label: Role, type: enum, options: [{value: user, label: User}, {value: admin, label: Administrator}], "
          "scope: person, privileged: true, resolve: max, delivery: [{claim: {client: demo, name: demo_role, json_type: string}}], ")


class TestSettingsV3(Case):
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
            ("folder", S_HDR + s_opts("{key: media, label: X, type: folder}"), c, "media", "type folder needs shared folders (project 2)"),
            ("person_secret", S_HDR + s_opts("{key: smb, label: X, type: person_secret}"), c, "smb", "type person_secret needs file sharing (project 3)"),
            ("person_id", S_HDR + s_opts("{key: uid, label: X, type: person_id}"), c, "uid", "type person_id needs file sharing (project 3)"),
            ("folder block", S_HDR + s_opts("{key: media, label: X, type: path, target: {service: demo, mount: /media}, folder: {access: read}}"), c, "media", "shared folders (project 2)"),
            ("checks", S_HDR + s_opts("{key: media, label: X, type: path, target: {service: demo, mount: /media}, checks: [{kind: exclusive}]}"), c, "media", "shared folders (project 2)"),
            ("hash", S_HDR + s_opts("{key: theme, label: X, type: string, hash: nt}"), c, "theme", "file sharing (project 3)"),
            ("length", S_HDR + s_opts("{key: theme, label: X, type: string, length: 8}"), c, "theme", "length needs file sharing"),
            ("revoke_on_leave", S_HDR + s_opts("{key: theme, label: X, type: string, revoke_on_leave: true}"), c, "theme", "file sharing"),
            ("mount", S_HDR + s_opts("{key: theme, label: X, type: string, mount: {service: demo, path: /x}}"), c, "theme", "mount needs file sharing"),
            ("bare delivery", S_HDR + s_opts("{key: theme, label: X, type: string, delivery: file}"), c, "theme", "file sharing (project 3)"),
        ])

    def test_person_scope_needs_default_and_person_delivery(self) -> None:
        o, h = s_compose(oidc=True), s_compose(S_HDR_ENV)
        self.cases([
            ("no default", S_OIDC + s_opts("{key: quota, label: Q, type: int, scope: person, resolve: max, " + S_PERSON_CLAIM + "}"), o, "quota", "default"),
            ("env only", S_HDR + s_opts("{key: quota, label: Q, type: int, scope: person, default: 1, delivery: [{env: TRASH_DAYS}]}"), h, "quota", "per-person env is not allowed"),
            ("no delivery", S_HDR + s_opts("{key: quota, label: Q, type: int, scope: person, default: 1}"), h, "quota", "per-person delivery"),
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
            ("two kinds in one delivery", S_OIDC + s_opts("{key: quota, label: Q, type: int, scope: person, default: 1, delivery: [{env: TRASH_DAYS, hook: x}]}"), s_compose(s_env("TRASH_DAYS"), oidc=True), "quota", "exactly one"),
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
            ("forward-auth", S_HDR + s_opts("{key: quota, label: Q, type: int, scope: person, default: 1, " + S_PERSON_CLAIM + "}"), s_compose(), "quota", "native-oidc"),
            ("unknown client", S_OIDC + s_opts("{key: quota, label: Q, type: int, scope: person, default: 1, delivery: [{claim: {client: other, name: demo_quota, json_type: int}}]}"), o, "quota", "client other"),
            ("bad json_type", S_OIDC + s_opts("{key: quota, label: Q, type: int, scope: person, default: 1, delivery: [{claim: {client: demo, name: demo_quota, json_type: float}}]}"), o, "quota", "json_type"),
            ("bad name", S_OIDC + s_opts("{key: quota, label: Q, type: int, scope: person, default: 1, delivery: [{claim: {client: demo, name: Quota, json_type: int}}]}"), o, "quota", "must match"),
            ("duplicate claim", S_OIDC + s_opts("{key: quota, label: Q, type: int, scope: person, default: 1, " + S_PERSON_CLAIM + "}", "{key: q2, label: Q, type: int, scope: person, default: 1, " + S_PERSON_CLAIM + "}"), o, "q2", "demo_quota"),
        ]
        for n in ("sub", "email", "groups", "acr", "amr", "preferred_username", "attr_x", "portcullis_x"):
            cases.append(("claim " + n, S_OIDC + s_opts("{key: quota, label: Q, type: int, scope: person, default: 1, delivery: [{claim: {client: demo, name: " + n + ", json_type: int}}]}"), o, "quota", "claim " + n))
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
            ("bad name", S_HDR + s_opts("{key: quota, label: Q, type: int, scope: person, default: 1, delivery: [{header: {name: X-Quota}}]}"), h, "quota", "X-Forwarded-Attr-"),
            ("trailing dash", S_HDR + s_opts("{key: quota, label: Q, type: int, scope: person, default: 1, delivery: [{header: {name: X-Forwarded-Attr-Quota-}}]}"), h, "quota", "X-Forwarded-Attr-"),
            ("double dash", S_HDR + s_opts("{key: quota, label: Q, type: int, scope: person, default: 1, delivery: [{header: {name: X-Forwarded-Attr-A--B}}]}"), h, "quota", "X-Forwarded-Attr-"),
            ("bare prefix", S_HDR + s_opts("{key: quota, label: Q, type: int, scope: person, default: 1, delivery: [{header: {name: X-Forwarded-Attr-}}]}"), h, "quota", "X-Forwarded-Attr-"),
            ("trailing newline", S_HDR + s_opts("{key: quota, label: Q, type: int, scope: person, default: 1, delivery: [{header: {name: \"X-Forwarded-Attr-Quota\\n\"}}]}"), h, "quota", "X-Forwarded-Attr-"),
            ("multi-part name", S_HDR + s_opts("{key: quota, label: Q, type: int, scope: person, default: 1, delivery: [{header: {name: X-Forwarded-Attr-Grafana-Role}}]}"), h, "", ""),
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
            ("ok", pf("{key: quota, label: Q, type: int, scope: person, default: 1, delivery: [{file: {name: people, field: quota}}, {hook: apply}]}"), s_compose(), "", ""),
            ("undeclared file", pf("{key: quota, label: Q, type: int, scope: person, default: 1, delivery: [{file: {name: nope}}]}"), h, "quota", "file nope"),
            ("undeclared hook", pf("{key: quota, label: Q, type: int, scope: person, default: 1, delivery: [{hook: nope}]}"), h, "quota", "hook nope"),
            ("field on instance", pf("{key: trash_days, label: Q, type: int, delivery: [{file: {name: people, field: x}}]}"), h, "trash_days", "field"),
            ("bad field", pf("{key: quota, label: Q, type: int, scope: person, default: 1, delivery: [{file: {name: people, field: Quota}}]}"), h, "quota", "field \"Quota\""),
            ("duplicate field", S_HDR + s_opts("{key: quota, label: Q, type: int, scope: person, default: 1, delivery: [{file: {name: people, field: q}}]}",
                                               "{key: q2, label: Q, type: int, scope: person, default: 1, delivery: [{file: {name: people, field: q}}]}") + S_FILES, h, "q2", "already written by setting quota"),
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
            ("path person", S_HDR + s_opts("{key: media, label: M, type: path, scope: person, default: /x, target: {service: demo, mount: /media}}"), h, "media", "instance"),
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
            line = "{key: q, label: Q, type: string, pattern: %s, default: %s}" % (json.dumps(pat), json.dumps(default))
            want = "" if compiles and matches else ("pattern" if not compiles else "default")
            cases.append((f"{pat} / {default!r}", S_HDR + s_opts(line), s_compose(s_env("Q")), "q" if want else "", want))
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
            "{key: q, label: Q, type: string, delivery: [{env: Q, render: {format: yaml}}]}": "format yaml is for list",
            "{key: q, label: Q, type: int, delivery: [{env: Q, render: {format: csv}}]}": "format csv is for list",
            "{key: q, label: Q, type: duration, delivery: [{env: Q, render: {unit: GiB}}]}": "unit",
            "{key: q, label: Q, type: bool, delivery: [{env: Q, render: {integer: true}}]}": "integer",
            "{key: q, label: Q, type: list, items: {type: string}, delivery: [{env: Q, render: {join: \"\"}}]}": "join",
            "{key: q, label: Q, type: list, items: {type: string}, delivery: [{env: Q, render: {join: \",\", format: json}}]}": "exclude each other",
            "{key: q, label: Q, type: string, delivery: [{env: Q, render: {unit: GiB}}]}": "unit is for size",
        }
        self.cases([(line, S_HDR + s_opts(line), s_compose(s_env("Q")), "q", part) for line, part in bad.items()])
        ok = [
            "{key: q, label: Q, type: size, delivery: [{hook: apply, render: {unit: GB, integer: true}}]}",
            "{key: q, label: Q, type: size, delivery: [{env: Q, render: {unit: TB}}]}",
            "{key: q, label: Q, type: list, items: {type: string}, delivery: [{env: Q, render: {join: \" \"}}]}",
            "{key: q, label: Q, type: list, items: {type: string}, delivery: [{env: Q, render: {format: csv}}]}",
            "{key: q, label: Q, type: table, columns: [{name: a, label: A, type: string}], delivery: [{env: Q, render: {format: yaml}}]}",
            "{key: q, label: Q, type: bool, delivery: [{env: Q, render: {true: \"on\", false: \"off\"}}]}",
            "{key: q, label: Q, type: int, unit: days, delivery: [{env: Q, render: {unit: days}}]}",
            "{key: q, label: Q, type: duration, delivery: [{env: Q, render: {unit: d, integer: true}}]}",
        ]
        hooks = "hooks:\n  - {name: apply, service: demo, command: [x], when: [start]}\n"
        self.cases([(line, S_HDR + s_opts(line) + hooks, s_compose("" if "{hook:" in line else s_env("Q")), "", "") for line in ok])

    def test_claim_json_type_fits_render(self) -> None:
        o = s_compose(oidc=True)

        def c(typ: str, extra: str, claim: str) -> str:
            return S_OIDC + s_opts("{key: v, label: V, type: " + typ + ", scope: person, " + extra + ", delivery: [{claim: {client: demo, name: demo_v, " + claim + "}}]}")
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

    def test_integer_render_warns(self) -> None:
        m = S_HDR + s_opts("{key: q, label: Q, type: size, default: 1536MiB, delivery: [{env: Q, render: {unit: GiB, integer: true}}]}")
        errors, warnings = self.run_raw(m, s_compose(s_env("Q")))
        self.assertClean(errors)
        self.assertTrue(any("setting q" in w and "whole number of GiB" in w for w in warnings), warnings)
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
            ("label multibyte", S_HDR + s_opts("{key: theme, label: " + "\u00e9" * 33 + ", type: string}"), h, "theme", "label"),
            ("unique on string", S_HDR + s_opts("{key: theme, label: T, type: string, unique: true}"), h, "theme", "unique"),
            ("admin_override on instance", S_HDR + s_opts("{key: theme, label: T, type: string, admin_override: true}"), h, "theme", "admin_override"),
            ("wrong shape", S_HDR + s_opts("{key: theme, label: T, type: string, required: \"yes\"}"), h, "", "required"),
            ("render outside", S_HDR + s_opts("{key: quota, label: Q, type: int, scope: person, default: 1, delivery: [{header: {name: X-Forwarded-Attr-Quota}, render: {format: json}}]}"), h, "quota", "render goes inside"),
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


if __name__ == "__main__":
    unittest.main()
