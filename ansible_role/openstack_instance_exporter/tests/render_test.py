#!/usr/bin/env python3
"""Validate release source selection and render the role's public profiles."""

from __future__ import annotations

from pathlib import Path

from ansible.parsing.dataloader import DataLoader
from ansible.template import Templar

try:
    from ansible.template import trust_as_template
except ImportError:
    def trust_as_template(value: str) -> str:
        return value


ROLE_DIR = Path(__file__).resolve().parents[1]
DEFAULTS_PATH = ROLE_DIR / "defaults" / "main.yml"
TASKS_PATH = ROLE_DIR / "tasks" / "main.yml"
TEMPLATE_PATH = ROLE_DIR / "templates" / "openstack_instance_exporter.service.j2"


def load_defaults(loader: DataLoader) -> dict:
    # Match Ansible's role loader, which trusts templates in role defaults.
    source = trust_as_template(DEFAULTS_PATH.read_text(encoding="utf-8"))
    defaults = loader.load(source, file_name=str(DEFAULTS_PATH))
    if not isinstance(defaults, dict):
        raise AssertionError("role defaults did not load as a mapping")
    return defaults


def render(loader: DataLoader, defaults: dict, **overrides: object) -> str:
    variables = dict(defaults)
    variables.update(overrides)
    variables["inventory_hostname"] = "localhost"
    variables["hostvars"] = {
        "localhost": {
            "ansible_br_monitoring": {"ipv4": {"address": "192.0.2.50"}},
        }
    }
    source = trust_as_template(TEMPLATE_PATH.read_text(encoding="utf-8"))
    result = Templar(loader=loader, variables=variables).template(source)
    if not isinstance(result, str):
        raise AssertionError(f"template result has unexpected type {type(result)!r}")
    return result


def require(rendered: str, *fragments: str) -> None:
    for fragment in fragments:
        if fragment not in rendered:
            raise AssertionError(f"rendered service is missing {fragment!r}")


def forbid(rendered: str, *fragments: str) -> None:
    for fragment in fragments:
        if fragment in rendered:
            raise AssertionError(f"rendered service unexpectedly contains {fragment!r}")


def validate_extraction_idempotency(loader: DataLoader) -> None:
    tasks = loader.load_from_file(str(TASKS_PATH))
    extraction_when = None
    for outer_task in tasks:
        if outer_task.get("name") != "Installation and Configuration":
            continue
        for task in outer_task.get("block", []):
            if task.get("name") == "Extract openstack_instance_exporter tarball":
                extraction_when = task.get("when")
                break
    if not isinstance(extraction_when, str):
        raise AssertionError("archive extraction has no idempotency condition")

    def should_extract(
        local_changed: bool,
        download_changed: bool,
        regular: bool | None,
        executable: bool | None,
        size: int | None,
    ) -> bool:
        binary_stat = {}
        if regular is not None:
            binary_stat["isreg"] = regular
        if executable is not None:
            binary_stat["executable"] = executable
        if size is not None:
            binary_stat["size"] = size
        variables = {
            "oie_tar_local_result": {"changed": local_changed},
            "oie_tar_download_result": {"changed": download_changed},
            "oie_installed_binary": {"stat": binary_stat},
        }
        result = Templar(loader=loader, variables=variables).template(
            trust_as_template("{{ " + extraction_when + " }}")
        )
        if not isinstance(result, bool):
            raise AssertionError("archive extraction condition did not return bool")
        return result

    cases = (
        (True, False, True, True, 1, True),
        (False, True, True, True, 1, True),
        (False, False, False, False, 1, True),
        (False, False, None, None, None, True),
        (False, False, True, False, 1, True),
        (False, False, True, True, 0, True),
        (False, False, True, True, 1, False),
    )
    for case in cases:
        if should_extract(*case[:5]) is not case[5]:
            raise AssertionError(f"archive extraction condition failed case {case}")


def validate_profiles(loader: DataLoader, defaults: dict) -> None:
    disabled = render(loader, defaults, openstack_instance_exporter_profile="disabled")
    require(
        disabled,
        "ExecStart=/opt/openstack_instance_exporter/openstack_instance_exporter",
        "-web.listen-address=192.0.2.50:9120",
    )
    forbid(
        disabled,
        "-outbound.behavior.enable",
        "-inbound.behavior.enable",
        "-spamhaus.enable",
        "-tor.exit.enable",
        "-volume.retype.enable",
    )

    expected = {
        "resource-only": (
            "-severity.weight.resource=1.0",
            "-severity.weight.behavior=0.0",
            "-severity.weight.threat_list=0.0",
        ),
        "outbound-standard": (
            "-outbound.behavior.enable",
            "-behavior.sensitivity=1.0",
            "-spamhaus.enable",
            "-emergingthreats.enable",
        ),
        "outbound-observant": (
            "-outbound.behavior.enable",
            "-behavior.sensitivity=1.25",
            "-tor.exit.enable",
            "-tor.relay.enable",
        ),
        "outbound-max": (
            "-outbound.behavior.enable",
            "-behavior.sensitivity=1.5",
            "-tor.exit.enable",
            "-tor.relay.enable",
        ),
        "bidir-standard": (
            "-outbound.behavior.enable",
            "-inbound.behavior.enable",
            "-behavior.sensitivity=1.0",
        ),
        "bidir-observant": (
            "-outbound.behavior.enable",
            "-inbound.behavior.enable",
            "-behavior.sensitivity=1.25",
            "-tor.exit.enable",
        ),
        "bidir-max": (
            "-outbound.behavior.enable",
            "-inbound.behavior.enable",
            "-behavior.sensitivity=1.5",
            "-tor.exit.enable",
        ),
    }
    configured = set(defaults["openstack_instance_exporter_profile_defaults"])
    if configured != set(expected):
        raise AssertionError(
            f"profile coverage mismatch: configured={sorted(configured)} tested={sorted(expected)}"
        )
    for profile, fragments in expected.items():
        forbid(render(loader, defaults, openstack_instance_exporter_profile=profile), "-volume.retype.enable")
        require(
            render(loader, defaults, openstack_instance_exporter_profile=profile),
            *fragments,
        )


def validate_explicit_overrides(loader: DataLoader, defaults: dict) -> None:
    overrides = {
        "openstack_instance_exporter_profile": "bidir-max",
        "openstack_instance_exporter_behavior_sensitivity": 2.25,
        "openstack_instance_exporter_inbound_behavior_enable": False,
        "openstack_instance_exporter_outbound_behavior_enable": False,
        "openstack_instance_exporter_threat_ewma_tau": "4m",
        "openstack_instance_exporter_behavior_ports_config_path": "/etc/oie/ports.yml",
        "openstack_instance_exporter_behavior_ports_config_yaml": "behavior: {ports: {inbound_monitored: {22: ssh}}}",
        "openstack_instance_exporter_behavior_rules_config_path": "/etc/oie/rules.yml",
        "openstack_instance_exporter_behavior_rules_config_yaml": "rules: [{id: ssh, ports: [22], kind: ssh}]",
        "openstack_instance_exporter_conntrack_ipv6_enable": False,
        "openstack_instance_exporter_web_listen_address": "127.0.0.1:19120",
        "openstack_instance_exporter_collection_interval": "30s",
        "openstack_instance_exporter_host_threats_enable": True,
        "openstack_instance_exporter_host_interfaces": ["bgp-nic", "br-monitoring"],
        "openstack_instance_exporter_log_file_enable": True,
        "openstack_instance_exporter_log_file_path": "/var/log/oie.log",
        "openstack_instance_exporter_log_level": "debug",
    }
    rendered = render(loader, defaults, **overrides)
    require(
        rendered,
        "-behavior.sensitivity=2.25",
        "-threat.ewma_tau=4m",
        "-behavior.ports_config=/etc/oie/ports.yml",
        "-behavior.rules_config=/etc/oie/rules.yml",
        "-conntrack.ipv6.enable=false",
        "-web.listen-address=127.0.0.1:19120",
        "-collection.interval=30s",
        "-host.threats.enable",
        "-host.interfaces=bgp-nic,br-monitoring",
        "-log.file.enable",
        "-log.file.path=/var/log/oie.log",
        "-log.level=debug",
        "StandardOutput=null",
        "StandardError=null",
    )
    forbid(rendered, "-outbound.behavior.enable", "-inbound.behavior.enable")
    if render(loader, defaults, **overrides) != rendered:
        raise AssertionError("repeated service rendering was not deterministic")


def validate_release_sources(loader: DataLoader, defaults: dict) -> None:
    blocks = loader.load_from_file(str(TASKS_PATH))
    install = next(t["block"] for t in blocks if t.get("name") == "Installation and Configuration")
    copy = next(t for t in install if "ansible.builtin.copy" in t)
    download = next(t for t in install if "ansible.builtin.get_url" in t)
    settings = next(t["ansible.builtin.assert"]["that"] for t in install if "ansible.builtin.assert" in t)
    prefix = "openstack_instance_exporter_"
    cases = (
        ({}, ["download"], True),
        ({"archive_src": "/tmp/oie.tar.xz"}, ["local"], True),
        ({"download_url": "https://example.invalid/oie.tar.xz"}, ["download"], True),
        ({"archive_src": "/tmp/oie.tar.xz", "download_url": ""}, ["local"], True),
        ({"download_url": ""}, [], False),
        ({"sha256": ""}, ["download"], False),
        ({"sha256": "not-a-checksum"}, ["download"], False),
    )
    for overrides, expected_sources, valid in cases:
        variables = dict(defaults, ansible_architecture="x86_64")
        variables.update({prefix + key: value for key, value in overrides.items()})
        templar = Templar(loader=loader, variables=variables)

        def evaluate(expression: str) -> object:
            return templar.template(trust_as_template("{{ " + expression + " }}"))

        selected = []
        for name, task in (("local", copy), ("download", download)):
            conditions = task["when"] if isinstance(task["when"], list) else [task["when"]]
            if all(evaluate(condition) for condition in conditions):
                selected.append(name)
        if selected != expected_sources or all(evaluate(s) for s in settings) is not valid:
            raise AssertionError(f"release source selection or preflight failed: {overrides}")
        if "download" in selected:
            expected_url = overrides.get("download_url", "https://github.com/webnifico/openstack_instance_exporter/releases/download/v2.0.0/openstack_instance_exporter-v2.0.0-linux-amd64.tar.xz")
            if evaluate(prefix + "download_url") != expected_url:
                raise AssertionError("release URL did not resolve to the selected archive")


def validate_retype_opt_in(loader: DataLoader, defaults: dict) -> None:
    variable = "openstack_instance_exporter_volume_retype_enable"
    if defaults.get(variable) is not False:
        raise AssertionError("retype monitoring must default to false")
    for value in (False, "false", "no", 0):
        forbid(render(loader, defaults, **{variable: value}), "-volume.retype.enable")
    for profile in ["disabled", *defaults["openstack_instance_exporter_profile_defaults"]]:
        enabled = render(loader, defaults, **{variable: True, "openstack_instance_exporter_profile": profile})
        if enabled.count("-volume.retype.enable") != 1:
            raise AssertionError(f"explicit retype opt-in failed for profile {profile}")
    require(render(loader, defaults, **{variable: "true"}), "-volume.retype.enable")


def main() -> None:
    loader = DataLoader()
    defaults = load_defaults(loader)
    validate_release_sources(loader, defaults)
    validate_extraction_idempotency(loader)
    validate_profiles(loader, defaults)
    validate_explicit_overrides(loader, defaults)
    validate_retype_opt_in(loader, defaults)
    print("Ansible release source selection and service template render matrix passed")


if __name__ == "__main__":
    main()
