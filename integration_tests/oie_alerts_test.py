#!/usr/bin/env python3
"""Validate independent OIE policies through the shared deployment renderer."""
from __future__ import annotations

import copy
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import unittest
from unittest import mock
from pathlib import Path

import jinja2
import yaml

HERE = Path(__file__).resolve().parent
COMMON = HERE.parent
SOURCE = Path(os.environ.get('OIE_ALERT_SOURCE', str(COMMON / 'examples/prometheus_alerts_example/openstack_instance_exporter_alerts.yml')))
TEMPLATE = HERE / 'alert.rules.j2'
PROMTOOL = os.environ.get('PROMTOOL') or shutil.which('promtool')


def series(metric, value, labels=None):
    labels = HOST if labels is None else labels
    return {'series': metric + '{' + ','.join(k + '=' + json.dumps(v) for k, v in sorted(labels.items())) + '}',
            'values': value}


def health(host=None, vm=None, end=60):
    host = HOST if host is None else host
    vm = VM if vm is None else vm
    data = [series('up', f'1x{end}', host),
            series('oie_host_collection_interval_seconds', f'15x{end}', host)]
    for metric in ['oie_host_libvirt_ok', 'oie_host_conntrack_raw_ok']:
        data.append(series(metric, f'1x{end}', host))
    for metric in ['oie_host_libvirt_stale_seconds', 'oie_host_conntrack_stale_seconds']:
        data.append(series(metric, f'0x{end}', host))
    for source in ['libvirt', 'conntrack']:
        data.append(series('oie_host_' + source + '_last_success_timestamp_seconds', f'0+60x{end}', host))
    for feed in ['TOREXIT', 'TORRELAY', 'spamhaus', 'EMERGING', 'CUSTOMLIST']:
        data.append(series('oie_host_threat_feed_fresh', f'1x{end}', host | {'list': feed}))
    data.append(series('oie_instance_state_code', f'1x{end}', vm))
    for axis in ['cpu', 'mem', 'disk', 'net']:
        for kind in ['fresh', 'available']:
            data.append(series('oie_instance_resource_axis_' + kind, f'1x{end}', vm | {'axis': axis}))
    return data


def replace(data, metric, values):
    for item in data:
        if item['series'].startswith(metric + '{'):
            item['values'] = values


def check(expr, value, at='40m'):
    return {'expr': expr, 'eval_time': at, 'exp_samples': [{'labels': '{}', 'value': value}]}


def alerts(pattern='OpenStack.*', state='firing'):
    return 'count(ALERTS{alertname=~' + json.dumps(pattern) + ',alertstate=' + json.dumps(state) + '}) or vector(0)'


HOST = {'job': 'openstack-instance-exporter', 'instance': 'compute-a:9120'}
VM = HOST | {'domain': 'instance-a', 'instance_uuid': 'vm-a', 'project_uuid': 'project-a',
             'project_name': 'Project A', 'user_uuid': 'user-a', 'server_name': 'Server A'}


def load_policy(components=('alerts',), **variables):
    document = yaml.safe_load(SOURCE.read_text())
    if set(components) - {'metrics', 'alerts'}:
        raise ValueError('Only notification measurements and alerts are deployed')
    selected = []
    for group in document['prometheus_alert_rules']:
        group = copy.deepcopy(group)
        for component, key in [('metrics', 'group_recording_rules'), ('alerts', 'group_rules')]:
            if component not in components:
                group.pop(key, None)
        if group.get('group_rules') or group.get('group_recording_rules'):
            selected.append(group)
    return {'prometheus_alert_rules': selected}


def render(content=None, components=('metrics', 'alerts'), **variables):
    env = jinja2.Environment(trim_blocks=True, keep_trailing_newline=True,
                             undefined=jinja2.StrictUndefined)
    env.filters.update(
        bool=lambda v: str(v).lower() in ('true', 'yes', '1'),
        comment=lambda v: '\n'.join('# ' + line for line in str(v).splitlines()),
    )
    env.globals['lookup'] = lambda kind, key, default=False: variables.get(key, default)
    return env.from_string(TEMPLATE.read_text()).render(
        file_content=copy.deepcopy(load_policy(components=components, **variables) if content is None else content),
        ansible_managed='Managed by Ansible', **variables)


class AlertPolicy(unittest.TestCase):
    def test_actual_ansible_file_lookup_preserves_native_annotations(self):
        from ansible.parsing.dataloader import DataLoader
        import ansible.template
        trust = getattr(ansible.template, 'trust_as_template', lambda value: value)
        variables = {'file_content': trust("{{ lookup('file', '" + str(SOURCE) + "') | from_yaml }}"),
                     'ansible_managed': 'Managed by Ansible'}
        actual = ansible.template.Templar(loader=DataLoader(), variables=variables).template(trust(TEMPLATE.read_text()))
        self.assertEqual(yaml.safe_load(actual), yaml.safe_load(render()))

    def test_one_plain_file_and_no_inventory_templating(self):
        self.assertEqual({p.name for p in SOURCE.parent.iterdir()}, {SOURCE.name})
        text = SOURCE.read_text()
        self.assertNotIn('{%', text)
        self.assertNotIn('prometheus_oie_', text)
        self.assertIn('{{ $labels.', text)
    def test_enabled_alert_inventory_and_native_annotations(self):
        group = load_policy()['prometheus_alert_rules'][0]
        self.assertEqual(len(group['group_rules']), 62)
        for alert in group['group_rules']:
            self.assertNotIn('enabled', alert)
            self.assertIn('$value', alert['annotations']['description'])
            self.assertIn('Check ', alert['annotations']['description'])
    def test_shared_renderer_and_helper_uniqueness(self):
        doc = yaml.safe_load(render())
        records = [r['record'] for g in doc['groups'] for r in g['rules'] if 'record' in r]
        self.assertEqual(len(records), 30)
        self.assertEqual(len(records), len(set(records)))
        self.assertEqual(sum('alert' in r for g in doc['groups'] for r in g['rules']), 62)
        self.assertIn('oie:activity:unusual', records)
        self.assertNotIn('oie:disk_iops:review_limit', records)
        self.assertEqual(len(doc['groups']), 1)
        # Dependencies and alerts must see the same evaluation timestamp.
        rules = doc['groups'][0]['rules']
        self.assertTrue(all('record' in r for r in rules[:len(records)]))
        self.assertTrue(all('alert' in r for r in rules[len(records):]))
    def test_direct_yaml_edits_change_notifications(self):
        content = load_policy(components=('metrics','alerts'))
        alert = next(a for g in content['prometheus_alert_rules'] for a in g.get('group_rules', []) if a['alert']=='OpenStackInstanceHighCPUUsage')
        alert['for']='45m'; alert['labels']['severity']='warning'
        modified = yaml.safe_load(render(content=content))
        actual = next(r for g in modified['groups'] for r in g['rules'] if r.get('alert')==alert['alert'])
        self.assertEqual(actual['for'],'45m'); self.assertEqual(actual['labels']['severity'],'warning')
    def test_rule_syntax(self):
        if not PROMTOOL: self.skipTest('PROMTOOL required')
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'rules.yml';path.write_text(render())
            subprocess.run([PROMTOOL,'check','rules',str(path)],check=True,capture_output=True)


class NativeAlertVerificationScheduling(unittest.TestCase):
    def cases(self):
        return [{'name': 'scenario-' + str(i), 'interval': '15s',
                 'input_series': [series('up', '1 1 1', HOST | {'case': str(i)})],
                 'promql_expr_test': [check('count(up)', 1, str(i + 1) + 'm')]}
                for i in range(8)]

    def batch(self, cases, progress=None):
        import oie_alerts_verify as verify
        with tempfile.TemporaryDirectory(prefix='oie-native-scheduling-') as directory:
            root = Path(directory)
            rules = root / 'rules.yml'
            rules.write_text(render())
            return verify.run_native_batch('fake-promtool', root, rules, yaml.safe_load(render()),
                                           cases, '15s', 321, progress)

    def test_complete_fixture_inventory_is_partitioned_losslessly(self):
        import oie_alerts_verify as verify
        from oie_alerts_lifecycle_test import (lifecycle_cases, normal_cases, mitigation_cases,
                                              disk_policy_cases, regression_cases, notification_noise_cases)
        cases = (lifecycle_cases() + normal_cases() + mitigation_cases() + disk_policy_cases() +
                 regression_cases() + notification_noise_cases())
        original = copy.deepcopy(cases)
        self.assertEqual(len(cases), 260)
        self.assertEqual(sum(map(verify.case_assertions, cases)), 647)
        parts = verify.partition_cases(cases)
        verify.validate_parts(cases, parts)
        self.assertEqual([len(part['cases']) for part in parts], [130, 130])
        self.assertEqual(sorted(i for part in parts for i in part['indices']), list(range(260)))
        for part in parts:
            self.assertEqual(part['indices'], sorted(part['indices']))
            for index, case in zip(part['indices'], part['cases']):
                self.assertIs(case, cases[index])
                self.assertEqual(case, original[index])
        self.assertEqual(cases, original)

    def test_partition_rejects_missing_duplicate_and_replaced_scenarios(self):
        import oie_alerts_verify as verify
        cases = self.cases()
        for damage in ('missing', 'duplicate', 'replace'):
            with self.subTest(damage=damage):
                parts = verify.partition_cases(cases)
                if damage == 'missing':
                    parts.pop()
                elif damage == 'duplicate':
                    parts[1]['indices'][0] = parts[0]['indices'][0]
                else:
                    parts[0]['cases'][0] = copy.deepcopy(parts[0]['cases'][0])
                with self.assertRaises(ValueError):
                    verify.validate_parts(cases, parts)
        with self.assertRaises(ValueError):
            verify.partition_cases([])

    def test_two_parts_run_concurrently_with_the_complete_shipped_rules(self):
        import oie_alerts_verify as verify
        cases = self.cases()
        original = copy.deepcopy(cases)
        seen = []
        lock = threading.Lock()
        barrier = threading.Barrier(2)
        active = maximum = 0
        expected_rules = yaml.safe_load(render())
        self.assertEqual(sum(len(group['rules']) for group in expected_rules['groups']), 92)

        def native(args, **kwargs):
            nonlocal active, maximum
            self.assertEqual(args[:3], ['fake-promtool', 'test', 'rules'])
            self.assertEqual(kwargs, {'text': True, 'capture_output': True, 'timeout': 321})
            spec = yaml.safe_load(Path(args[3]).read_text())
            self.assertEqual(spec['evaluation_interval'], '15s')
            self.assertEqual(spec['group_eval_order'], [group['name'] for group in expected_rules['groups']])
            self.assertEqual(len(spec['rule_files']), 1)
            self.assertEqual(yaml.safe_load(Path(spec['rule_files'][0]).read_text()), expected_rules)
            with lock:
                active += 1
                maximum = max(maximum, active)
                seen.extend(spec['tests'])
            try:
                barrier.wait(timeout=10)
                return subprocess.CompletedProcess(args, 0, 'SUCCESS', '')
            finally:
                with lock:
                    active -= 1

        completed = []
        with mock.patch.object(verify.subprocess, 'run', side_effect=native):
            result = self.batch(cases, completed.append)
        self.assertEqual(result['status'], 'PASS')
        self.assertEqual(maximum, 2)
        self.assertEqual(len(completed), 2)
        self.assertEqual([row['part'] for row in result['parts']], [1, 2])
        self.assertEqual(sorted(seen, key=lambda case: case['name']), cases)
        self.assertEqual((result['scenarios'], result['assertions']), (8, 8))
        self.assertEqual(cases, original)

    def test_native_failures_and_partial_timeout_output_cannot_pass(self):
        import oie_alerts_verify as verify
        failures = [subprocess.CompletedProcess([], 1, 'native failure', ''),
                    subprocess.CompletedProcess([], 0, '', 'error executing template'),
                    subprocess.CompletedProcess([], 0, '', '<error expanding'),
                    subprocess.CompletedProcess([], 0, '', '%!s(MISSING)'),
                    subprocess.CompletedProcess([], 0, '', 'panic: native failure'),
                    subprocess.TimeoutExpired('fake-promtool', 321, output=b'partial stdout', stderr=b'partial stderr'),
                    OSError('cannot launch'), RuntimeError('unexpected worker error')]
        for failure in failures:
            with self.subTest(failure=str(failure)):
                with mock.patch.object(verify.subprocess, 'run', side_effect=failure if isinstance(failure, Exception)
                                       else None, return_value=failure):
                    result = self.batch(self.cases())
                self.assertEqual(result['status'], 'FAIL')
                self.assertEqual(len(result['parts']), 2)
                self.assertTrue(all(row['status'] == 'FAIL' for row in result['parts']))
                if isinstance(failure, subprocess.TimeoutExpired):
                    for row in result['parts']:
                        self.assertEqual(row['output'], 'partial stdoutpartial stderr')
        long_output = 'x' * (verify.NATIVE_OUTPUT_LIMIT + 10) + 'diagnostic tail'
        with mock.patch.object(verify.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, long_output, '')):
            result = self.batch(self.cases())
        for row in result['parts']:
            self.assertEqual(len(row['output']), verify.NATIVE_OUTPUT_LIMIT)
            self.assertTrue(row['output'].endswith('diagnostic tail'))

    def test_incomplete_worker_coverage_cannot_pass(self):
        import oie_alerts_verify as verify
        def incomplete(tool, path, number, part, timeout):
            return {'part': number, 'status': 'PASS', 'returncode': 0, 'scenarios': len(part['cases']),
                    'assertions': sum(map(verify.case_assertions, part['cases'])), 'case_indices': []}
        with mock.patch.object(verify, 'run_native_part', side_effect=incomplete):
            self.assertEqual(self.batch(self.cases())['status'], 'FAIL')
        with mock.patch.object(verify, 'run_native_part', side_effect=RuntimeError('worker escaped')):
            completed = []
            result = self.batch(self.cases(), completed.append)
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(len(result['parts']), 2)
        self.assertEqual(len(completed), 2)
        self.assertTrue(all(row['elapsed_seconds'] is None for row in completed))
        self.assertTrue(all('worker escaped' in row['reason'] for row in result['parts']))


if __name__ == '__main__': unittest.main()
