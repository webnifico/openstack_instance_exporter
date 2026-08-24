#!/usr/bin/env python3
"""Render the role's systemd template with Ansible and validate its profiles."""

from __future__ import annotations

import re
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
    defaults = loader.load_from_file(str(DEFAULTS_PATH))
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
        download_changed: bool,
        binary_is_regular: bool | None,
        binary_is_executable: bool | None,
        binary_size: int | None,
    ) -> bool:
        binary_stat = {}
        if binary_is_regular is not None:
            binary_stat["isreg"] = binary_is_regular
        if binary_is_executable is not None:
            binary_stat["executable"] = binary_is_executable
        if binary_size is not None:
            binary_stat["size"] = binary_size
        templar = Templar(
            loader=loader,
            variables={
                "oie_tar_download_result": {"changed": download_changed},
                "oie_installed_binary": {"stat": binary_stat},
            },
        )
        result = templar.template(
            trust_as_template("{{ " + extraction_when + " }}")
        )
        if not isinstance(result, bool):
            raise AssertionError(
                f"archive extraction condition returned {type(result)!r}"
            )
        return result

    cases = (
        (True, True, True, 1, True, "upgrade"),
        (False, False, False, 1, True, "repair non-regular binary"),
        (False, None, None, None, True, "repair missing binary"),
        (False, True, False, 1, True, "repair non-executable binary"),
        (False, True, True, 0, True, "repair empty binary"),
        (False, True, True, 1, False, "unchanged idempotent rerun"),
    )
    for download_changed, binary_is_regular, binary_is_executable, binary_size, expected, name in cases:
        if should_extract(download_changed, binary_is_regular, binary_is_executable, binary_size) is not expected:
            raise AssertionError(f"archive extraction failed {name} case")


def validate_mutating_paths(loader: DataLoader) -> None:
    tasks = loader.load_from_file(str(TASKS_PATH))
    defaults = load_defaults(loader)
    expected_assertions = {
        "Installation and Configuration": (
            "Validate safe openstack_instance_exporter installation paths"
        ),
        "OpenStack Instance Exporter Cleanup Tasks": (
            "Validate safe openstack_instance_exporter cleanup paths"
        ),
    }
    condition_sets = []
    for block_name, assertion_name in expected_assertions.items():
        conditions = None
        for outer_task in tasks:
            if outer_task.get("name") != block_name:
                continue
            block = outer_task.get("block", [])
            for index, task in enumerate(block):
                if task.get("name") == assertion_name:
                    if index != 0:
                        raise AssertionError(
                            f"{assertion_name!r} must precede every mutation in its block"
                        )
                    conditions = task["ansible.builtin.assert"]["that"]
                    break
        if conditions is None:
            raise AssertionError(f"{assertion_name!r} is missing")
        condition_sets.append((assertion_name, conditions))

    def accepted(conditions: list[str], values: dict[str, object]) -> bool:
        templar = Templar(loader=loader, variables=values)
        return all(
            templar.template(trust_as_template("{{ " + condition + " }}")) is True
            for condition in conditions
        )

    base = {
        "openstack_instance_exporter_install_dir": "/opt/openstack_instance_exporter",
        "openstack_instance_exporter_profile": defaults[
            "openstack_instance_exporter_profile"
        ],
        "openstack_instance_exporter_profile_defaults": defaults[
            "openstack_instance_exporter_profile_defaults"
        ],
    }
    configurable_paths = (
        "openstack_instance_exporter_install_dir",
        "openstack_instance_exporter_customlist_path",
        "openstack_instance_exporter_behavior_ports_config_path",
        "openstack_instance_exporter_behavior_rules_config_path",
        "openstack_instance_exporter_log_file_path",
    )
    legitimate = dict(base)
    legitimate.update(
        {
            "openstack_instance_exporter_customlist_path": "/etc/oie/custom.txt",
            "openstack_instance_exporter_behavior_ports_config_path": "/etc/oie/ports.yml",
            "openstack_instance_exporter_behavior_rules_config_path": "/etc/oie/rules.yml",
            "openstack_instance_exporter_log_file_path": "/var/log/openstack_instance_exporter.log",
        }
    )
    for assertion_name, conditions in condition_sets:
        for variable in configurable_paths:
            for value in (
                "/",
                "//",
                "/./",
                "/tmp/..",
                " /tmp/oie",
                "/tmp/oie ",
                " / ",
            ):
                values = dict(base)
                values[variable] = value
                if accepted(conditions, values):
                    raise AssertionError(
                        f"{assertion_name!r} accepted unsafe path: {variable}={value!r}"
                    )
        if not accepted(conditions, legitimate):
            raise AssertionError(
                f"{assertion_name!r} rejected legitimate absolute paths"
            )

        if assertion_name == "Validate safe openstack_instance_exporter installation paths":
            invalid_profile = dict(legitimate)
            invalid_profile["openstack_instance_exporter_profile"] = "misspelled"
            if accepted(conditions, invalid_profile):
                raise AssertionError(
                    f"{assertion_name!r} accepted an unknown behavior profile"
                )
            for profile in ("disabled", *defaults["openstack_instance_exporter_profile_defaults"]):
                valid_profile = dict(legitimate)
                valid_profile["openstack_instance_exporter_profile"] = profile
                if not accepted(conditions, valid_profile):
                    raise AssertionError(
                        f"{assertion_name!r} rejected valid profile {profile!r}"
                    )

        for value in (
            "/var/log/*",
            "/var/log/oie?.log",
            "/var/log/[ab].log",
            "/var/*/oie.log",
        ):
            values = dict(legitimate)
            values["openstack_instance_exporter_log_file_path"] = value
            if accepted(conditions, values):
                raise AssertionError(
                    f"{assertion_name!r} accepted unsafe log glob {value!r}"
                )

    expected_directory_assertions = {
        "Installation and Configuration": (
            "Reject directory-valued openstack_instance_exporter installation paths"
        ),
        "OpenStack Instance Exporter Cleanup Tasks": (
            "Reject directory-valued openstack_instance_exporter cleanup paths"
        ),
    }
    for block_name, assertion_name in expected_directory_assertions.items():
        conditions = None
        for outer_task in tasks:
            if outer_task.get("name") != block_name:
                continue
            block = outer_task.get("block", [])
            for index, task in enumerate(block):
                if task.get("name") == assertion_name:
                    if index != 2:
                        raise AssertionError(
                            f"{assertion_name!r} must precede every mutation in its block"
                        )
                    conditions = task["ansible.builtin.assert"]["that"]
                    break
        if conditions is None:
            raise AssertionError(f"{assertion_name!r} is missing")

        def directory_accepted(is_directory: bool | None) -> bool:
            stat = {} if is_directory is None else {"isdir": is_directory}
            templar = Templar(loader=loader, variables={"item": {"stat": stat}})
            return all(
                templar.template(trust_as_template("{{ " + condition + " }}"))
                is True
                for condition in conditions
            )

        if directory_accepted(True):
            raise AssertionError(f"{assertion_name!r} accepted an existing directory")
        if not directory_accepted(False) or not directory_accepted(None):
            raise AssertionError(
                f"{assertion_name!r} rejected a regular or nonexistent file path"
            )

    managed_refusal = None
    for outer_task in tasks:
        if outer_task.get("name") != "OpenStack Instance Exporter Cleanup Tasks":
            continue
        for task in outer_task.get("block", []):
            if task.get("name") == (
                "Refuse removal of an installation directory containing unmanaged content"
            ):
                managed_refusal = task["ansible.builtin.assert"]["that"]
                break
    if managed_refusal is None:
        raise AssertionError("managed installation-directory refusal is missing")

    def managed_directory_accepted(
        entries: list[dict[str, str]],
        skipped_paths: dict[str, str] | None = None,
    ) -> bool:
        templar = Templar(
            loader=loader,
            variables={
                "oie_unmanaged_install_entries": {
                    "files": entries,
                    "skipped_paths": skipped_paths or {},
                }
            },
        )
        return all(
            templar.template(trust_as_template("{{ " + condition + " }}")) is True
            for condition in managed_refusal
        )

    if not managed_directory_accepted([]):
        raise AssertionError("managed cleanup rejected an empty installation directory")
    if managed_directory_accepted([{"path": "/etc/unmanaged"}]):
        raise AssertionError("managed cleanup accepted unmanaged installation content")
    if managed_directory_accepted(
        [], {"/etc/private": "permission denied"}
    ):
        raise AssertionError("managed cleanup accepted an incomplete directory inspection")

    log_find = None
    for outer_task in tasks:
        if outer_task.get("name") != "OpenStack Instance Exporter Cleanup Tasks":
            continue
        for task in outer_task.get("block", []):
            if task.get("name") == "Find standard openstack_instance_exporter log files":
                log_find = task["ansible.builtin.find"]
                break
    if log_find is None:
        raise AssertionError("standard log discovery task is missing")
    if log_find.get("use_regex") is not True:
        raise AssertionError("standard log discovery does not use exact regex matching")
    if log_find.get("hidden") is not True:
        raise AssertionError("standard log discovery excludes dot-prefixed log files")

    for basename in ("oie+(prod).log", ".oie+(prod).log"):
        log_path = "/var/log/" + basename
        pattern = Templar(
            loader=loader,
            variables={"openstack_instance_exporter_log_file_path": log_path},
        ).template(trust_as_template(log_find["patterns"]))
        for filename in (
            basename + ".1",
            basename + ".12",
            basename + ".2.gz",
        ):
            if re.fullmatch(pattern, filename) is None:
                raise AssertionError(
                    f"managed log cleanup pattern {pattern!r} rejected {filename!r}"
                )
        for filename in (
            basename,
            basename + "back",
            basename + ".old",
            basename + ".gz",
            basename + ".1.backup",
            "oieeprod.log.1",
        ):
            if re.fullmatch(pattern, filename) is not None:
                raise AssertionError(
                    f"managed log cleanup pattern {pattern!r} accepted unrelated {filename!r}"
                )


def main() -> None:
    loader = DataLoader()
    defaults = load_defaults(loader)

    validate_extraction_idempotency(loader)
    validate_mutating_paths(loader)

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
    )

    profile_expectations = {
        "resource-only": {
            "required": (
                "-severity.weight.resource=1.0",
                "-severity.weight.behavior=0.0",
                "-severity.weight.threat_list=0.0",
            ),
            "forbidden": ("-outbound.behavior.enable", "-inbound.behavior.enable"),
        },
        "outbound-standard": {
            "required": (
                "-outbound.behavior.enable",
                "-behavior.sensitivity=1.0",
                "-spamhaus.enable",
                "-emergingthreats.enable",
            ),
            "forbidden": ("-inbound.behavior.enable", "-tor.exit.enable"),
        },
        "outbound-observant": {
            "required": (
                "-outbound.behavior.enable",
                "-behavior.sensitivity=1.25",
                "-spamhaus.enable",
                "-emergingthreats.enable",
                "-tor.exit.enable",
                "-tor.relay.enable",
            ),
            "forbidden": ("-inbound.behavior.enable",),
        },
        "outbound-max": {
            "required": (
                "-outbound.behavior.enable",
                "-behavior.sensitivity=1.5",
                "-spamhaus.enable",
                "-emergingthreats.enable",
                "-tor.exit.enable",
                "-tor.relay.enable",
            ),
            "forbidden": ("-inbound.behavior.enable",),
        },
        "bidir-standard": {
            "required": (
                "-outbound.behavior.enable",
                "-inbound.behavior.enable",
                "-behavior.sensitivity=1.0",
                "-spamhaus.direction=any",
                "-emergingthreats.direction=any",
            ),
            "forbidden": (),
        },
        "bidir-observant": {
            "required": (
                "-outbound.behavior.enable",
                "-inbound.behavior.enable",
                "-behavior.sensitivity=1.25",
                "-spamhaus.direction=any",
                "-emergingthreats.direction=any",
                "-tor.exit.enable",
                "-tor.relay.enable",
            ),
            "forbidden": (),
        },
        "bidir-max": {
            "required": (
                "-outbound.behavior.enable",
                "-inbound.behavior.enable",
                "-behavior.sensitivity=1.5",
                "-spamhaus.direction=any",
                "-emergingthreats.direction=any",
                "-tor.exit.enable",
                "-tor.relay.enable",
            ),
            "forbidden": (),
        },
    }
    configured_profiles = set(defaults["openstack_instance_exporter_profile_defaults"])
    if configured_profiles != set(profile_expectations):
        raise AssertionError(
            f"profile coverage mismatch: configured={sorted(configured_profiles)} "
            f"tested={sorted(profile_expectations)}"
        )
    for profile, expectation in profile_expectations.items():
        rendered = render(loader, defaults, openstack_instance_exporter_profile=profile)
        require(rendered, *expectation["required"])
        forbid(rendered, *expectation["forbidden"])

    explicit_vars = {
        "openstack_instance_exporter_profile": "bidir-max",
        "openstack_instance_exporter_behavior_sensitivity": 2.25,
        "openstack_instance_exporter_inbound_behavior_enable": False,
        "openstack_instance_exporter_outbound_behavior_enable": False,
        "openstack_instance_exporter_behavior_ewma_fast_tau": "1m",
        "openstack_instance_exporter_behavior_ewma_slow_tau": "1h",
        "openstack_instance_exporter_behavior_ports_config_path": "/etc/oie/ports.yml",
        "openstack_instance_exporter_behavior_ports_config_yaml": "behavior: {ports: {inbound_monitored: {22: ssh}}}",
        "openstack_instance_exporter_behavior_rules_config_path": "/etc/oie/rules.yml",
        "openstack_instance_exporter_behavior_rules_config_yaml": "rules: [{id: ssh, ports: [22], kind: ssh}]",
        "openstack_instance_exporter_conntrack_raw_rcvbuf_bytes": 67108864,
        "openstack_instance_exporter_conntrack_raw_rcv_timeout": "9s",
        "openstack_instance_exporter_conntrack_ipv4_enable": True,
        "openstack_instance_exporter_conntrack_ipv6_enable": False,
        "openstack_instance_exporter_web_listen_address": "127.0.0.1:19120",
        "openstack_instance_exporter_web_telemetry_path": "/oie-metrics",
        "openstack_instance_exporter_collection_interval": "30s",
        "openstack_instance_exporter_worker_count": 4,
        "openstack_instance_exporter_libvirt_uri": "qemu:///system",
        "openstack_instance_exporter_contacts_direction": "any",
        "openstack_instance_exporter_host_threats_enable": True,
        "openstack_instance_exporter_host_interfaces": ["bgp-nic", "br-monitoring"],
        "openstack_instance_exporter_host_ips_allow_private": True,
        "openstack_instance_exporter_log_file_enable": True,
        "openstack_instance_exporter_log_file_path": "/var/log/oie.log",
        "openstack_instance_exporter_log_level": "debug",
        "openstack_instance_exporter_threat_log_min_interval": "1m",
    }
    explicit = render(loader, defaults, **explicit_vars)
    require(
        explicit,
        "-behavior.sensitivity=2.25",
        "-behavior.ewma_fast_tau=1m",
        "-behavior.ewma_slow_tau=1h",
        "-behavior.ports_config=/etc/oie/ports.yml",
        "-behavior.rules_config=/etc/oie/rules.yml",
        "-conntrack.raw.rcvbuf_bytes=67108864",
        "-conntrack.raw.rcv_timeout=9s",
        "-conntrack.ipv4.enable=true",
        "-conntrack.ipv6.enable=false",
        "-web.listen-address=127.0.0.1:19120",
        "-web.telemetry-path=/oie-metrics",
        "-collection.interval=30s",
        "-worker.count=4",
        "-libvirt.uri=qemu:///system",
        "-contacts.direction=any",
        "-host.threats.enable",
        "-host.interfaces=bgp-nic,br-monitoring",
        "-host.ips.allow-private",
        "-log.file.enable",
        "-log.file.path=/var/log/oie.log",
        "-log.level=debug",
        "-threat.log.min_interval=1m",
        "StandardOutput=null",
        "StandardError=null",
    )
    forbid(explicit, "-outbound.behavior.enable", "-inbound.behavior.enable")
    if render(loader, defaults, **explicit_vars) != explicit:
        raise AssertionError("repeated service rendering was not deterministic")

    print("Ansible service template render matrix passed")


if __name__ == "__main__":
    main()
