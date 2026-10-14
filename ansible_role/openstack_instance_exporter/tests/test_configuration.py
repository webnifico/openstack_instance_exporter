#!/usr/bin/env python3
"""Behavior-file and feed-direction contracts.

Local tests use Jinja; render_test.py runs the same cases through Ansible's
Templar. These tests never deploy files or restart a service.
"""
from __future__ import annotations

import shlex
import unittest
from pathlib import Path
from typing import Callable

import jinja2
import yaml

ROLE_DIR = Path(__file__).resolve().parents[1]
PREFIX = "openstack_instance_exporter_"


def boolean(value: object) -> bool:
    return value is True or value == 1 or (
        isinstance(value, str) and value.lower() in {"yes", "on", "true", "1"}
    )


def resolve(overrides: dict[str, object]) -> tuple[jinja2.Environment, dict]:
    env = jinja2.Environment(undefined=jinja2.StrictUndefined, keep_trailing_newline=True)
    env.filters["bool"] = boolean
    variables = yaml.safe_load((ROLE_DIR / "defaults/main.yml").read_text())
    variables.update(overrides)
    variables.update(inventory_hostname="localhost", hostvars={
        "localhost": {"ansible_br_monitoring": {"ipv4": {"address": "192.0.2.50"}}}
    })
    for kind in ("ports", "rules"):
        name = PREFIX + "behavior_" + kind + "_config_path"
        value = variables[name]
        if isinstance(value, str) and "{{" in value:
            variables[name] = env.from_string(value).render(variables)
    return env, variables


def render_local(overrides: dict[str, object]) -> str:
    env, variables = resolve(overrides)
    return env.from_string((ROLE_DIR / "templates/openstack_instance_exporter.service.j2").read_text()).render(variables)


def configuration_cases():
    for kind in ("ports", "rules"):
        path = PREFIX + "behavior_" + kind + "_config_path"
        content = PREFIX + "behavior_" + kind + "_config_yaml"
        flag = "-behavior." + kind + "_config="
        valid = "behavior: {ports: {inbound_monitored: {22: ssh}}}" if kind == "ports" else "rules: [{id: ssh, ports: [22], signal: ssh}]"
        yield kind + ": built-in", {}, (), (flag,)
        yield kind + ": inline default path", {content: valid}, (flag + "/opt/openstack_instance_exporter/behavior-" + kind + ".yaml",), ()
        yield kind + ": custom install directory", {content: valid, PREFIX + "install_dir": "/srv/oie"}, (flag + "/srv/oie/behavior-" + kind + ".yaml",), ()
        yield kind + ": inline explicit path", {content: valid, path: "/etc/oie/" + kind + ".yml"}, (flag + "/etc/oie/" + kind + ".yml",), ()
        yield kind + ": externally managed", {path: "/etc/oie/" + kind + ".yml"}, (flag + "/etc/oie/" + kind + ".yml",), ()
        yield kind + ": empty content preserves external file", {path: "/etc/oie/" + kind + ".yml", content: ""}, (flag + "/etc/oie/" + kind + ".yml",), ()
        yield kind + ": empty content returns to built-in", {content: "  \n"}, (), (flag,)
    for feed, flag in (("tor_exit", "tor.exit"), ("tor_relay", "tor.relay"), ("spamhaus", "spamhaus"), ("emergingthreats", "emergingthreats"), ("customlist", "customlist")):
        key = PREFIX + feed + "_direction"
        option = "-" + flag + ".direction="
        base = {PREFIX + "profile": "bidir-max", PREFIX + "contacts_direction": "in"}
        # Custom lists have no profile-supplied direction.
        expected = (option + "any",) if feed != "customlist" else ()
        forbidden = () if feed != "customlist" else (option,)
        yield feed + ": profile", base, expected, forbidden
        yield feed + ": empty inherits global", dict(base, **{key: ""}), (option, "-contacts.direction=in"), (option + "any",)
        yield feed + ": explicit direction", dict(base, **{key: "out"}), (option + "out",), (option + "any",)
    # Ansible's -e key=value syntax supplies strings. A string false must
    # override a profile just as a YAML boolean false does.
    toggles = {
        "inbound_behavior_enable": "inbound.behavior.enable",
        "outbound_behavior_enable": "outbound.behavior.enable",
        "tor_exit_enable": "tor.exit.enable",
        "tor_relay_enable": "tor.relay.enable",
        "spamhaus_enable": "spamhaus.enable",
        "emergingthreats_enable": "emergingthreats.enable",
        "customlist_enable": "customlist.enable",
        "host_threats_enable": "host.threats.enable",
        "host_ips_allow_private": "host.ips.allow-private",
        "log_file_enable": "log.file.enable",
        "volume_retype_enable": "volume.retype.enable",
        "web_debug_log_level_enable": "web.debug-log-level.enable",
        "conntrack_ipv4_enable": "conntrack.ipv4.enable",
        "conntrack_ipv6_enable": "conntrack.ipv6.enable",
    }
    for name, flag in toggles.items():
        for value in ("false", "no", "0", "true", "yes", "1"):
            enabled = boolean(value)
            overrides = {PREFIX + "profile": "bidir-max", PREFIX + name: value}
            if name.startswith("conntrack_"):
                wanted = "-" + flag + "=" + str(enabled).lower()
                unwanted = "-" + flag + "=" + str(not enabled).lower()
                yield name + ": string " + value, overrides, (wanted,), (unwanted,)
            else:
                option = "-" + flag
                required, forbidden = ((option,), ()) if enabled else ((), (option,))
                yield name + ": string " + value, overrides, required, forbidden


def validate_configuration(render: Callable[[dict[str, object]], str]) -> int:
    count = 0
    for name, overrides, required, forbidden in configuration_cases():
        result = render(overrides)
        starts = [line.removeprefix("ExecStart=") for line in result.splitlines() if line.startswith("ExecStart=")]
        if len(starts) != 1:
            raise AssertionError(f"{name}: expected one ExecStart")
        arguments = shlex.split(starts[0])
        for value in required:
            if value not in arguments:
                raise AssertionError(f"{name}: missing argument {value!r}")
        for value in forbidden:
            if any(arg.startswith(value) if value.endswith("=") else arg == value for arg in arguments):
                raise AssertionError(f"{name}: unexpected argument {value!r}")
        count += 1
    return count


class ConfigurationContract(unittest.TestCase):
    def test_service_configuration_matrix(self):
        self.assertEqual(validate_configuration(render_local), 113)

    def test_string_boolean_file_logging_and_accounting(self):
        tasks = yaml.safe_load((ROLE_DIR / "tasks/main.yml").read_text())
        block = next(task["block"] for task in tasks if task.get("name") == "Installation and Configuration")
        accounting = next(task for task in block if task.get("name") == "Enable nf_conntrack_acct")
        for value in ("false", "no", "0", "true", "yes", "1"):
            with self.subTest(value=value):
                env, variables = resolve({PREFIX + "nf_conntrack_acct_enable": value,
                                          PREFIX + "log_file_enable": value})
                enabled = boolean(value)
                self.assertEqual(env.compile_expression(accounting["when"])(variables), enabled)
                service = render_local({PREFIX + "log_file_enable": value})
                self.assertEqual("StandardOutput=null" in service, enabled)
                rotation = env.from_string(variables[PREFIX + "logrotate_content"]).render(variables)
                self.assertEqual("daily" in rotation, enabled)

    def test_inline_content_only_controls_file_writes(self):
        tasks = yaml.safe_load((ROLE_DIR / "tasks/main.yml").read_text())
        block = next(task["block"] for task in tasks if task.get("name") == "Installation and Configuration")
        for kind in ("ports", "rules"):
            task = next(task for task in block if task.get("name") == "Render behavior " + kind + " configuration from inline YAML")
            path = PREFIX + "behavior_" + kind + "_config_path"
            content = PREFIX + "behavior_" + kind + "_config_yaml"
            for overrides, expected in (({}, False), ({path: "/etc/oie/config.yaml"}, False), ({path: "/etc/oie/config.yaml", content: ""}, False), ({content: "rules: []"}, True)):
                with self.subTest(kind=kind, overrides=overrides):
                    env, variables = resolve(overrides)
                    write = all(env.compile_expression(condition)(variables) for condition in task["when"])
                    self.assertEqual(write, expected)
                    if write:
                        destination = env.from_string(task["ansible.builtin.copy"]["dest"]).render(variables)
                        self.assertEqual(destination, "/opt/openstack_instance_exporter/behavior-" + kind + ".yaml")


if __name__ == "__main__":
    unittest.main()
