#!/usr/bin/env python3
"""Keep real OIE targets visible without turning unavailable VM data into zero.

Native tests evaluate the checked-in queries. Set PROMTOOL to the executable;
without it, the native matrix is explicitly skipped, not reported as validated.
"""
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml
from oie_dashboards_test import DASHBOARDS, get_panel, interpolate, series

HOST_PANELS = {1245, 1305, 1233, 1235, 1212, 1214, 1269, 1270, 1271,
               1250, 1251, 1252, 1253, 1306, 1307, 1267, 1268,
               1248, 1249, 4003, 1247, 4010}
UNDEFINED_WHEN_EMPTY = {1270, 1306}


def host(name, active=0, up=1, ok=1, age=0):
    labels = {'job': 'openstack-instance-exporter', 'instance': name + ':9120'}
    values = {'up': up, 'oie_host_libvirt_ok': ok,
              'oie_host_libvirt_stale_seconds': age,
              'oie_host_collection_interval_seconds': 15,
              'oie_host_libvirt_active_vms': active,
              'oie_host_cpu_active_vcpus': 4 * active,
              'oie_host_cpu_threads': 8, 'oie_host_mem_mib_total': 8192,
              'oie_host_cpu_usage_percent': 35 if active else 25}
    return [series(k, f'{v}+0x8', labels) for k, v in values.items()]


def workload(name='compute-busy'):
    labels = {'job': 'openstack-instance-exporter', 'instance': name + ':9120',
              'domain': 'instance-1', 'instance_uuid': name + '-vm',
              'project_uuid': 'project-1', 'user_uuid': 'user-1'}
    data = [series('oie_instance_inventory_info', '1+0x8', labels | {'libvirt_active': '1'}),
            series('oie_instance_cpu_vcpu_percent', '50+0x8', labels),
            series('oie_instance_cpu_vcpu_count', '4+0x8', labels),
            series('oie_instance_mem_used_mib', '1024+0x8', labels),
            series('oie_instance_mem_allocated_mib', '4096+0x8', labels)]
    data += [series('oie_instance_cpu_steal_seconds_total', '0+0.075x8',
                    labels | {'vcpu': str(vcpu)}) for vcpu in range(4)]
    disk = labels | {'disk_path': 'vda', 'disk_type': 'premium', 'volume_uuid': 'volume-1'}
    for direction, ops, seconds in [('read', 150, 0.15), ('write', 300, 0.6), ('flush', 60, 0.09)]:
        data += [series(f'oie_instance_disk_{direction}_requests_total', f'0+{ops}x8', disk),
                 series(f'oie_instance_disk_{direction}_seconds_total', f'0+{seconds}x8', disk)]
        if direction != 'flush':
            data.append(series(f'oie_instance_disk_{direction}_gib_total', '0+15x8', disk))
    for direction, packets, dropped in [('rx', 150, 15), ('tx', 300, 30)]:
        for suffix, step in [('gib_total', 15), ('packets_total', packets),
                             ('dropped_total', dropped), ('errors_total', 0)]:
            data.append(series(f'oie_instance_net_{direction}_{suffix}', f'0+{step}x8', labels | {'interface': 'tap1'}))
    return data


def expected(expr, value=None, at='2m'):
    return {'expr': expr, 'eval_time': at,
            'exp_samples': [] if value is None else [{'labels': '{}', 'value': value}]}


def matrix():
    records, cases = [], []
    names = {}
    for pid in sorted(HOST_PANELS):
        for target in get_panel('hypervisor', pid)['targets']:
            key = (pid, target['refId'])
            names[key] = f'oie_empty_host_{pid}_{target["refId"]}'
            records.append({'record': names[key], 'expr': interpolate(target['expr'])})
    delta = 'oie_empty_host_raw_delta'
    records.append({'record': delta, 'expr': interpolate(get_panel('hypervisor', 1308)['targets'][0]['expr'])})

    def one(key, hostname):
        return names[key] + '{instance="' + hostname + ':9120"}'

    def absent_or_nan(key, hostname, at='2m'):
        q = one(key, hostname)
        # There must be exactly one host series, explicitly NaN instead of zero.
        return [expected(f'count({q})', 1, at),
                expected(f'count({q} != {q})', 1, at),
                expected(f'count({q} == {q})', None, at)]

    def empty_checks(hostname, at='2m'):
        checks = []
        for key in names:
            if key[0] in UNDEFINED_WHEN_EMPTY:
                checks += absent_or_nan(key, hostname, at)
            else:
                value = 25 if key == (1245, 'B') else 0
                checks += [expected('sum(' + one(key, hostname) + ')', value, at),
                           expected('count(' + one(key, hostname) + ')', 1, at)]
        return checks

    def add(name, data, checks):
        cases.append({'name': name, 'interval': '15s', 'input_series': data, 'promql_expr_test': checks})

    add('empty hypervisor stays visible without VM series', host('compute-empty'),
        empty_checks('compute-empty') + [expected('sum(' + delta + ')', 8192)])
    stopped = {'job': 'openstack-instance-exporter', 'instance': 'compute-empty:9120',
               'instance_uuid': 'stopped-vm', 'libvirt_active': '0'}
    add('inactive-only host is zero for live VM measurements',
        host('compute-empty') + [series('oie_instance_inventory_info', '1+0x8', stopped)],
        empty_checks('compute-empty'))
    for title, data in [('failed scrape', host('compute-empty', up=0)),
                        ('failed Libvirt collection', host('compute-empty', ok=0)),
                        ('expired Libvirt observation', host('compute-empty', age=61)),
                        ('Libvirt never collected', host('compute-empty', ok=0, age=-1))]:
        checks = [check for key in names for check in absent_or_nan(key, 'compute-empty')]
        checks.append(expected(f'count({delta} != {delta})', 1))
        add(title + ' never looks like a healthy empty host', data, checks)
    data = [s for s in host('compute-empty') if not s['series'].startswith((
        'oie_host_libvirt_active_vms{', 'oie_host_cpu_active_vcpus{'))]
    add('missing domain count cannot establish emptiness', data,
        [check for key in names for check in absent_or_nan(key, 'compute-empty')])

    busy_values = {(1245, 'A'): 25, (1245, 'B'): 10, (1305, 'A'): 20,
                   (1233, 'A'): 50, (1235, 'A'): 50, (1212, 'A'): 4,
                   (1214, 'A'): 4096 * 2**20, (1269, 'A'): 12.5,
                   (1270, 'A'): 25, (1271, 'A'): 1024 * 2**20,
                   (1250, 'A'): 2**30, (1251, 'A'): 2**30,
                   (1252, 'A'): 10, (1253, 'A'): 20,
                   (1306, 'A'): .001, (1306, 'B'): .002, (1306, 'C'): .0015,
                   (1307, 'A'): 4, (1307, 'B'): 20,
                   (1267, 'A'): 60 * 2**30, (1268, 'A'): 60 * 2**30,
                   (1248, 'A'): 8 * 2**30, (1249, 'A'): 8 * 2**30,
                   (4003, 'A'): 10, (1247, 'A'): 20}
    # Five-minute rate estimates use the first/last observations in the window.
    # Verify those rates independently; their exact extrapolation is not needed
    # to establish the host roster or empty-host behavior.
    busy = host('compute-busy', active=1) + workload()
    checks = [expected('round(sum(' + one(key, 'compute-busy') + '), 0.000001)', val)
              for key, val in busy_values.items()]
    add('busy and empty hypervisors retain independent values', busy + host('compute-empty'),
        checks + empty_checks('compute-empty') + [expected('sum(' + delta + ')', 12288)])
    no_mem = [entry for entry in busy if not entry['series'].startswith('oie_instance_mem_used_mib{')]
    add('missing guest memory on an active host is not zero', no_mem,
        [check for pid in (1269, 1270, 1271) for check in absent_or_nan((pid, 'A'), 'compute-busy')])
    idle = [dict(entry, values='0+0x8') if entry['series'].startswith('oie_instance_disk_') else entry
            for entry in busy]
    add('active but idle disks do not gain zero latency', idle,
        [check for ref in ('A', 'B', 'C') for check in absent_or_nan((1306, ref), 'compute-busy')] +
        [expected('sum(' + one((1252, 'A'), 'compute-busy') + ')', 0)])
    departure = host('compute-empty') + workload('compute-empty')
    for entry in departure:
        if entry['series'].startswith('oie_host_libvirt_active_vms{'):
            entry['values'] = '1+0x4 0+0x4'
        elif entry['series'].startswith('oie_host_cpu_active_vcpus{'):
            entry['values'] = '4+0x4 0+0x4'
        elif entry['series'].startswith('oie_instance_'):
            entry['values'] = re.sub(r'x8$', 'x4 stale _x3', entry['values'])
    add('departed last VM does not leave phantom rates', departure, empty_checks('compute-empty', '90s'))
    large = busy + [entry for i in range(120) for entry in host(f'compute-empty-{i}')]
    add('all 121 selected targets remain present without Top N truncation', large,
        [expected('count(' + name + ')', 121) for name in names.values()])
    selected = interpolate(get_panel('hypervisor', 1271)['targets'][0]['expr'],
                           {'${gvar_oie_hypervisor}': 'compute-empty'})
    add('host filter does not broaden to a similarly named target',
        host('compute-empty') + host('compute-empty-other'), [expected('count(' + selected + ')', 1)])
    no_capacity = [entry for entry in host('compute-empty') if not entry['series'].startswith('oie_host_mem_mib_total{')]
    add('missing host capacity stays unavailable even on an empty host', no_capacity,
        [check for pid in (1235, 1269) for check in absent_or_nan((pid, 'A'), 'compute-empty')] +
        [expected(f'count({delta} != {delta})', 1)])
    return records, cases


class EmptyHostContract(unittest.TestCase):
    def test_selectors_are_based_on_real_targets_not_instances(self):
        for name, dashboard in DASHBOARDS.items():
            var = next(v for v in dashboard['templating']['list'] if v['name'] == 'gvar_oie_hypervisor')
            self.assertEqual(var['definition'], 'label_values(up{job="openstack-instance-exporter"},instance)', name)
            self.assertEqual(var['definition'], var['query']['query'])
            self.assertTrue(var['multi'])
            self.assertTrue(var['includeAll'])

    def test_all_host_aggregates_have_explicit_roster_and_health(self):
        for pid in HOST_PANELS:
            panel = get_panel('hypervisor', pid)
            for target in panel['targets']:
                query = target['expr']
                for token in ('oie_host_libvirt_active_vms', 'libvirt_active="1"',
                              'oie_host_libvirt_ok', 'oie_host_libvirt_stale_seconds',
                              'oie_host_collection_interval_seconds', '* NaN', 'unless on(instance)'):
                    self.assertIn(token, query, (pid, target['refId']))
                self.assertNotIn('or vector(0)', query)
                self.assertNotIn('topk(', query)
            self.assertFalse(panel['fieldConfig']['defaults']['custom']['spanNulls'])
            self.assertEqual(panel['fieldConfig']['defaults']['noValue'],
                             'N/A' if pid in UNDEFINED_WHEN_EMPTY else 'Unavailable')
            self.assertEqual(panel['fieldConfig']['defaults']['custom']['lineWidth'], 1)

    def test_changed_expressions_have_balanced_delimiters(self):
        records, _ = matrix()
        for record in records:
            stack = []
            quoted = escaped = False
            for char in record['expr']:
                if quoted:
                    if escaped:
                        escaped = False
                    elif char == '\\':
                        escaped = True
                    elif char == '"':
                        quoted = False
                elif char == '"':
                    quoted = True
                elif char in '([{':
                    stack.append(char)
                elif char in ')]}':
                    self.assertTrue(stack, record['record'])
                    self.assertEqual(stack.pop(), {')': '(', ']': '[', '}': '{'}[char], record['record'])
            self.assertFalse(quoted, record['record'])
            self.assertFalse(stack, record['record'])

    def test_fixture_matrix_covers_every_changed_target(self):
        records, cases = matrix()
        self.assertEqual(len(records), 28)
        self.assertGreaterEqual(len(cases), 14)
        self.assertEqual(len({r['record'] for r in records}), len(records))
        self.assertEqual(len({c['name'] for c in cases}), len(cases))
        # Confirm the YAML is serializable and contains no unexpanded variables.
        text = yaml.safe_dump({'records': records, 'tests': cases})
        self.assertNotIn('${gvar_', text)
        self.assertNotIn('$gvar_', text)
        self.assertNotIn('$__', text)
        self.assertEqual(yaml.safe_load(text)['tests'], cases)

    def test_actual_queries_with_promtool(self):
        promtool = shutil.which(os.environ.get('PROMTOOL') or 'promtool')
        if not promtool:
            self.skipTest('promtool unavailable: native empty-host query evaluation not run')
        records, cases = matrix()
        with tempfile.TemporaryDirectory(prefix='oie-empty-hosts-') as temp:
            folder = Path(temp)
            (folder / 'rules.yml').write_text(yaml.safe_dump({
                'groups': [{'name': 'empty_hosts', 'interval': '15s', 'rules': records}]}))
            (folder / 'tests.yml').write_text(yaml.safe_dump({
                'rule_files': ['rules.yml'], 'evaluation_interval': '15s', 'tests': cases}))
            result = subprocess.run([promtool, 'test', 'rules', 'tests.yml'], cwd=folder,
                                    capture_output=True, text=True, timeout=120)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        print(f'Validated {len(cases)} empty-host scenarios against {len(records)} actual dashboard queries.')


if __name__ == '__main__':
    unittest.main()
