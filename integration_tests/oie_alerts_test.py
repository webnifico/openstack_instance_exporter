#!/usr/bin/env python3
"""Test the deployed OIE alert template and current policy with Prometheus.

PROMTOOL=/path/to/promtool python3 oie_alerts_test.py
Requires ansible-core (including Jinja2 and PyYAML). No services are contacted.
"""
import copy
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import jinja2
import yaml
from ansible.plugins.filter.core import FilterModule

HERE = Path(__file__).resolve().parent
COMMON = HERE.parent
SOURCE = COMMON / 'examples/prometheus_alerts_example/openstack_instance_exporter_alerts.yml'
TEMPLATE = HERE / 'alert.rules.j2'
POLICY = yaml.safe_load(SOURCE.read_text())
PROMTOOL = os.environ.get('PROMTOOL', 'promtool')
HOST = {'job': 'openstack-instance-exporter', 'instance': 'compute-a:9120'}
VM = HOST | {'domain': 'instance-a', 'instance_uuid': 'vm-a', 'project_uuid': 'project-a', 'project_name': 'Project A', 'user_uuid': 'user-a', 'server_name': 'Server A'}


def render(optional=False, content=None, **variables):
    env = jinja2.Environment(trim_blocks=True, keep_trailing_newline=True, undefined=jinja2.StrictUndefined)
    # Ansible 2.21 also exports default/d, which require Ansible's own
    # undefined type. Keep Jinja's default for this standalone Jinja renderer.
    ansible_filters = FilterModule().filters()
    env.filters.update({name: ansible_filters[name] for name in ['bool', 'comment', 'regex_replace', 'to_json']})
    data = copy.deepcopy(content or POLICY)
    if optional:
        for group in data['prometheus_alert_rules']:
            for rule in group['group_rules']:
                rule['enabled'] = True
    return env.from_string(TEMPLATE.read_text()).render(
        file_content=data, ansible_managed='Managed by Ansible',
        ansible_fqdn='monitoring.example', inventory_hostname='monitoring.example', **variables)


def series(metric, value, labels=HOST):
    return {'series': metric + '{' + ','.join(k + '=' + json.dumps(v) for k, v in sorted(labels.items())) + '}', 'values': value}


def health(host=HOST, vm=VM):
    data = [series('up', '1x60', host), series('process_start_time_seconds', '-3600x60', host), series('oie_host_collection_interval_seconds', '15x60', host)]
    for metric in ['oie_host_libvirt_ok', 'oie_host_conntrack_raw_ok']:
        data.append(series(metric, '1x60', host))
    for metric in ['oie_host_libvirt_stale_seconds', 'oie_host_conntrack_stale_seconds']:
        data.append(series(metric, '0x60', host))
    for feed in ['TOREXIT', 'TORRELAY', 'spamhaus', 'EMERGING', 'CUSTOMLIST']:
        data.append(series('oie_host_threat_feed_fresh', '1x60', host | {'list': feed}))
    data.append(series('oie_instance_state_code', '1x60', vm))
    for axis in ['cpu', 'mem', 'disk', 'net']:
        for metric in ['fresh', 'available']:
            data.append(series('oie_instance_resource_axis_' + metric, '1x60', vm | {'axis': axis}))
    return data


def replace(data, metric, values):
    for item in data:
        if item['series'].startswith(metric + '{'):
            item['values'] = values


def check(expr, value, at='20m'):
    return {'expr': expr, 'eval_time': at, 'exp_samples': [{'labels': '{}', 'value': value}]}


def alerts(pattern='OpenStack.*', state='firing'):
    return 'count(ALERTS{alertname=~' + json.dumps(pattern) + ',alertstate=' + json.dumps(state) + '}) or vector(0)'


class DeployedPolicy(unittest.TestCase):
    def test_native_ansible_file_loading_matches_policy(self):
        from ansible.parsing.dataloader import DataLoader
        from ansible.template import Templar
        from ansible.plugins import loader as plugin_loader
        try:
            from ansible.template import trust_as_template
        except ImportError:
            def trust_as_template(value):
                return value
        if hasattr(plugin_loader, 'init_plugin_loader'):
            plugin_loader.init_plugin_loader()
        variables = {
            'file_content': trust_as_template("{{ lookup('ansible.builtin.file', " + repr(str(SOURCE)) + ") | from_yaml }}"),
            'ansible_managed': 'Managed by Ansible',
            'ansible_fqdn': 'monitoring.example', 'inventory_hostname': 'monitoring.example',
        }
        native = Templar(loader=DataLoader(), variables=variables).template(trust_as_template(TEMPLATE.read_text()))
        self.assertEqual(yaml.safe_load(native), yaml.safe_load(render()))

    def test_names_defaults_and_links(self):
        groups = POLICY['prometheus_alert_rules']
        definitions = {r['alert']: r for g in groups for r in g['group_rules']}
        baseline = json.loads((HERE / 'fixtures/oie_alert_names_before_operator_update.json').read_text())
        self.assertEqual(set(definitions) - set(baseline), {
            'OpenStackInstanceExporterHostCPUContentionCritical', 'OpenStackInstanceExporterHostMemoryPressureCritical'})
        self.assertTrue(set(baseline) <= set(definitions))
        for optional in [False, True]:
            text = render(optional)
            rules = yaml.safe_load(text)['groups'][0]['rules']
            active = [r for r in rules if 'alert' in r]
            self.assertEqual(len(active), 82 if optional else 33)
            if not optional:
                self.assertEqual(sum(r['labels']['severity'] == 'critical' for r in active), 2)
                self.assertEqual(sum(r['labels']['severity'] == 'info' for r in active), 1)
            for r in active:
                self.assertTrue(r['annotations']['dashboard_url'].startswith('http://monitoring.example:3000/d/'))
                self.assertIn('&from=', r['annotations']['dashboard_url'])
                self.assertIn('&to=', r['annotations']['dashboard_url'])
            with tempfile.TemporaryDirectory() as temp:
                path = Path(temp) / 'rules.yml'
                path.write_text(text)
                result = subprocess.run([PROMTOOL, 'check', 'rules', str(path)], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        custom = render(grafana_server={'root_url': 'https://grafana.example/ops/'})
        self.assertIn('https://grafana.example/ops/d/', custom)
        # The shared role's defaults remain compatible with unrelated rule groups.
        legacy = {'prometheus_alert_rules': [{'group_name': 'legacy', 'group_rules': [{'alert': 'ExistingAlert', 'expr': 'vector(1)', 'labels': {'severity': 'warning'}, 'annotations': {'summary': 'Existing'}}]}]}
        self.assertEqual(yaml.safe_load(render(content=legacy))['groups'][0]['rules'][0]['alert'], 'ExistingAlert')

    def test_current_deployed_rules_with_prometheus(self):
        cases = []
        def case(name, data, checks, optional=False):
            cases.append((optional, {'name': name, 'interval': '1m', 'input_series': copy.deepcopy(data), 'promql_expr_test': checks}))
        hot = health() + [series('oie_instance_resource_cpu_severity', '90x60', VM), series('oie_instance_cpu_vcpu_percent', '90x60', VM)]
        case('high utilization alone is silent by default', hot, [check(alerts(), 0)])
        case('optional severe score does not duplicate its high band', hot, [check(alerts('OpenStackInstanceResourceCPUHigh'), 0), check(alerts('OpenStackInstanceResourceCPUSevere'), 1)], True)
        data = copy.deepcopy(hot); replace(data, 'oie_host_libvirt_ok', '1x3 0x56')
        case('pending retained resource score cannot finish during a Libvirt outage', data, [check(alerts('OpenStackInstanceResourceCPU.*'), 0, '5m')], True)
        for down in ['up', 'oie_host_libvirt_ok', 'oie_host_conntrack_raw_ok']:
            data = health() + [series('oie_instance_mining_suspected', '1x60', VM | {'confidence': 'high_persistent', 'ip': '10.0.0.5', 'family': 'ipv4', 'port': '14444'})]
            replace(data, down, '1x13 0x46')
            case('candidate pending is interrupted by ' + down, data, [check(alerts('OpenStackInstanceMining.*'), 0, '15m')])
        mining = health() + [series('oie_instance_cpu_vcpu_percent', '90x60', VM)]
        for port in ['14444', '24444']:
            mining.append(series('oie_instance_mining_suspected', '1x60', VM | {'confidence': 'high_persistent', 'ip': '10.0.0.5', 'family': 'ipv4', 'port': port}))
        case('corroborated mining ports produce one VM incident', mining, [check(alerts('OpenStackInstanceMiningSuspected'), 1), check(alerts('OpenStackInstanceMiningCandidatePersistent'), 0)])
        data = copy.deepcopy(mining); replace(data, 'oie_instance_cpu_vcpu_percent', '90x13 stale _x45')
        case('missing CPU range tail cannot qualify a mining warning', data, [check(alerts('OpenStackInstanceMiningSuspected'), 0, '15m')])
        data = copy.deepcopy(mining); replace(data, 'oie_instance_state_code', '5x60')
        case('stopped instance cannot qualify a workload alert', data, [check(alerts('OpenStackInstanceMining.*'), 0)])
        data = health() + [series('oie_instance_mining_suspected', '1x60', VM | {'confidence': 'high_persistent'})]
        case('uncorroborated dedicated candidate is informational after its hold', data, [check('count(ALERTS{alertname="OpenStackInstanceMiningCandidatePersistent",alertstate="firing",severity="info"}) or vector(0)', 1)])
        for direction, latency in [('read', 0.3), ('write', 0.3), ('flush', 0.1)]:
            disk = VM | {'volume_uuid': 'volume-a', 'disk_type': 'premium', 'disk_path': 'vda'}
            for ops, expected in [(1, 0), (60, 1)]:
                data = health() + [series('oie_instance_disk_' + direction + '_requests_total', f'0+{ops}x60', disk), series('oie_instance_disk_' + direction + '_seconds_total', f'0+{ops*latency}x60', disk)]
                name = 'OpenStackInstanceDisk' + direction.title() + 'LatencyHigh'
                # Existing names include High before Disk on some historical rules.
                name = next(r['alert'] for g in POLICY['prometheus_alert_rules'] for r in g['group_rules'] if 'LatencyHigh' in r['alert'] and direction.title() in r['alert'])
                case(direction + ' latency operation floor ' + str(ops), data, [check(alerts(name), expected)])
                if ops == 60:
                    replace(data, 'oie_instance_disk_' + direction + '_seconds_total', '0+18x13 stale _x45')
                    case(direction + ' service counter missing at range end', data, [check(alerts(name), 0)])
        for packets, drops, expected in [(2, 1, 0), (1000, 100, 1)]:
            data = health() + [series('oie_instance_net_rx_packets_total', f'0+{packets}x60', VM | {'ifname': 'tap-a'}), series('oie_instance_net_rx_dropped_total', f'0+{drops}x60', VM | {'ifname': 'tap-a'})]
            case('receive drops need meaningful traffic ' + str(packets), data, [check(alerts('.*ReceiveDropRatioHigh'), expected)])
        cpu = health() + [series('oie_host_cpu_usage_percent', '98x60'), series('oie_instance_cpu_vcpu_count', '2x60', VM)]
        case('host utilization alone has no critical', cpu, [check(alerts('.*HostCPUContentionCritical'), 0), check(alerts('.*HostCPUPressureSustained'), 1)])
        data = cpu + [series('oie_instance_cpu_steal_seconds_total', '0+12x60', VM | {'vcpu': '0'})]
        case('sustained host CPU and guest delay corroborate a critical', data, [check(alerts('.*HostCPUContentionCritical'), 1), check(alerts('.*HostCPUPressureSustained'), 0)])
        replace(data, 'oie_instance_cpu_steal_seconds_total', '0+12x13 stale _x45')
        case('removed scheduler counter cannot sustain host critical', data, [check(alerts('.*HostCPUContentionCritical'), 0)])
        mem = health() + [series('oie_host_mem_mb_total', '1000x60'), series('oie_host_mem_available_mb', '10x60')]
        case('host available memory alone has no critical', mem, [check(alerts('.*HostMemoryPressureCritical'), 0), check(alerts('.*HostMemoryPressureSustained'), 1)])
        data = mem + [series('oie_instance_mem_swap_in_bytes_total', '0+125829120x60', VM)]
        case('sustained host shortage and guest paging corroborate a critical', data, [check(alerts('.*HostMemoryPressureCritical'), 1), check(alerts('.*HostMemoryPressureSustained'), 0)])
        # An outage on a different target must neither qualify nor suppress this VM.
        data = copy.deepcopy(mining) + health(HOST | {'instance': 'compute-b:9120'}, VM | {'instance': 'compute-b:9120', 'instance_uuid': 'vm-b'})
        for item in data:
            if 'compute-b:9120' in item['series'] and item['series'].startswith('up{'): item['values'] = '0x60'
        case('one failed host preserves corroborated evidence on a healthy host', data, [check(alerts('OpenStackInstanceMiningSuspected'), 1)])
        data = health() + [series('oie_instance_cpu_vcpu_percent','10x60',VM)]
        for tier in ['high','high_persistent']:
            data.append(series('oie_instance_mining_suspected','1x60',VM|{'confidence':tier,'port':tier}))
        case('stronger evidence on another port suppresses the informational duplicate',data,[check(alerts('OpenStackInstanceMiningSuspected'),1),check(alerts('OpenStackInstanceMiningCandidatePersistent'),0)])
        for status, expected in [(5,0),(6,1)]:
            data=health()+[series('oie_instance_disk_retype_status_code',str(status)+'x60',VM|{'volume_uuid':'volume-a','disk_path':'vda','destination_volume_uuid':'volume-b'})]
            case('ready retype status '+str(status),data,[check(alerts('.*VolumeRetypeReadyStalled'),expected)])
        data=health()+[series('oie_instance_disk_retype_observation_healthy','0x60',VM),series('oie_instance_disk_retype_status_code','1x60',VM)]
        case('persistent per-volume observation failure',data,[check(alerts('.*VolumeRetypeObservationUnhealthy'),1)])
        replace(data,'oie_host_libvirt_ok','0x60')
        case('host-wide Libvirt failure suppresses per-volume warnings',data,[check(alerts('.*VolumeRetype.*'),0)])
        for feed in ['spamhaus', 'EMERGING', 'CUSTOMLIST']:
            data = health()
            listed = HOST | {'list': feed, 'ip': '192.0.2.10', 'family': 'ipv4'}
            data.append(series('oie_host_threat_provider_ip_listed', '1x60', listed))
            case('listed provider IP fires once per host and feed: ' + feed, data, [
                check(alerts('OpenStackInstanceExporterHostThreatListed'), 0, '4m'),
                check('count(ALERTS{alertname="OpenStackInstanceExporterHostThreatListed",alertstate="firing",instance="compute-a:9120"}) or vector(0)', 1, '6m')])
            replace(data, 'up', '0x60')
            case('unreachable listed host is suppressed: ' + feed, data, [check(alerts('OpenStackInstanceExporterHostThreatListed'), 0)])
            data = health() + [series('oie_host_threat_provider_ip_listed', '1x60', listed)]
            for item in data:
                if item['series'].startswith('oie_host_threat_feed_fresh{') and 'list="' + feed + '"' in item['series']:
                    item['values'] = '0x60'
            case('retained listed IP needs its own usable feed: ' + feed, data, [check(alerts('OpenStackInstanceExporterHostThreatListed'), 0)])
        # Another host's fresh feed cannot validate this host's retained hit.
        data += health(HOST | {'instance': 'compute-b:9120'}, VM | {'instance': 'compute-b:9120', 'instance_uuid': 'vm-b'})
        case('provider IP health is target local', data, [check(alerts('OpenStackInstanceExporterHostThreatListed'), 0)])
        for metric, feed, alert_name in [
            ('tor_exit', 'TOREXIT', 'OpenStackInstanceTorExitRepeatedContact'),
            ('tor_relay', 'TORRELAY', 'OpenStackInstanceTorRelayRepeatedContact'),
            ('spamhaus', 'spamhaus', 'OpenStackInstanceSpamhausRepeatedContact'),
            ('emergingthreats', 'EMERGING', 'OpenStackInstanceEmergingThreatsRepeatedContact'),
            ('customlist', 'CUSTOMLIST', 'OpenStackInstanceCustomListRepeatedContact'),
        ]:
            data = health() + [
                series('oie_instance_threat_' + metric + '_contacts_total', '0+10x60', VM | {'direction': 'out', 'ip': '10.0.0.5', 'family': 'ipv4'}),
                series('oie_instance_threat_' + metric + '_active_flows', '1x60', VM | {'direction': 'out', 'ip': '10.0.0.5', 'family': 'ipv4'}),
            ]
            optional = feed in ['TOREXIT', 'TORRELAY']
            unrelated_feed = 'EMERGING' if feed == 'TORRELAY' else 'TORRELAY'
            for item in data:
                if item['series'].startswith('oie_host_threat_feed_fresh{') and 'list="' + unrelated_feed + '"' in item['series']:
                    item['values'] = '0x60'
            case('unrelated feed failure preserves ' + metric + ' evidence', data, [check(alerts(alert_name), 1)], optional)
            for item in data:
                if item['series'].startswith('oie_host_threat_feed_fresh{') and 'list="' + feed + '"' in item['series']:
                    item['values'] = '1x13 stale _x46'
            case('missing current feed cannot qualify ' + metric + ' contacts', data, [check(alerts(alert_name), 0, '15m')], optional)
        for optional in [False, True]:
            with tempfile.TemporaryDirectory(prefix='oie-deployed-alerts-') as temp:
                temp = Path(temp)
                path = temp / 'rules.yml'; path.write_text(render(optional))
                tests = temp / 'tests.yml'
                selected = [case for opt, case in cases if opt == optional]
                tests.write_text(yaml.safe_dump({'rule_files': [str(path)], 'evaluation_interval': '1m', 'tests': selected}, sort_keys=False))
                result = subprocess.run([PROMTOOL, 'test', 'rules', str(tests)], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertNotIn('error executing template', result.stderr.lower())
        print(f'Evaluated {len(cases)} scenarios against the deployed alert template, including opt-in rules.')


if __name__ == '__main__':
    unittest.main()
