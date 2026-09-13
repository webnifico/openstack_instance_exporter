#!/usr/bin/env python3
"""OIE navigation/table regressions. Run with PROMTOOL=/path/to/promtool python3 this_file.

Requires PyYAML (already an Ansible dependency). PromQL tests evaluate the actual
checked-in dashboard expressions, including missing and retained telemetry.
"""
import json
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

FILES = Path(__file__).resolve().parents[1] / 'examples/grafana_dashboard_example'
DASHBOARDS = {name: json.loads((FILES / f'openstack_instance_exporter_{name}.json').read_text()) for name in ['cluster', 'hypervisor', 'project', 'instance', 'threats']}
REPLACE = {
    '${gvar_oie_hypervisor}': '.*', '$gvar_oie_hypervisor': '.*',
    '$gvar_oie_project_uuid': '.*', '$gvar_oie_project_name': '.*',
    '$gvar_oie_instance_uuid': '.*', '${gvar_oie_volume_uuid}': '.*',
    '$__rate_interval': '1m', '$__interval': '1m', '${__from}': '0', '${__to}': '3600000',
    '${__range_s}': '3600', '${gvar_oie_rank_by:raw}': 'max_over_time',
    '${gvar_oie_rank_instances_by:raw}': 'max_over_time',
    '${gvar_oie_rank_projects_by:raw}': 'max_over_time',
    '${gvar_oie_top_instances}': '10', '${gvar_oie_top_n}': '10',
    '${gvar_oie_top_projects}': '10',
}


def interpolate(expr, replacements=None):
    for old, new in (REPLACE | (replacements or {})).items():
        expr = expr.replace(old, new)
    return expr


def panels(items):
    for panel in items:
        yield panel
        yield from panels(panel.get('panels', []))


def get_panel(name, panel_id):
    return next(p for p in panels(DASHBOARDS[name]['panels']) if p['id'] == panel_id)


class DashboardStructure(unittest.TestCase):
    def test_navigation_identity_and_scope(self):
        uids = {d['uid'] for d in DASHBOARDS.values()}
        for name, d in DASHBOARDS.items():
            with self.subTest(dashboard=name):
                self.assertEqual(d['graphTooltip'], 1)
                self.assertEqual(len(d['links']), 4)
                for link in d['links']:
                    self.assertIn(link['url'].split('/d/')[1].split('?')[0], uids)
                    for token in ['from=${__from}', 'to=${__to}', '${datasource:queryparam}', '${gvar_oie_hypervisor:queryparam}']:
                        self.assertIn(token, link['url'])
                variables = {v['name']: v for v in d['templating']['list']}
                if name != 'hypervisor':
                    v = variables['gvar_oie_instance_uuid']
                    self.assertIn('instance_uuid', v['definition'])
                    self.assertIn('server_name', v['definition'])
                    self.assertIn('(?<value>', v['regex'])
                    self.assertIn('(?<text>', v['regex'])
                    self.assertEqual(v['allValue'], '.*')
                self.assertEqual(d['panels'][0]['id'], 25000)
                self.assertIn('Reset scope', d['panels'][0]['options']['content'])
                if name != 'threats':
                    self.assertEqual(get_panel(name, 25001)['type'], 'table')
                ids = [p['id'] for p in panels(d['panels'])]
                self.assertEqual(len(ids), len(set(ids)))
                for panel in panels(d['panels']):
                    if panel['type'] == 'timeseries':
                        self.assertEqual(panel['options']['tooltip']['mode'], 'multi')
                        self.assertEqual(panel['fieldConfig']['defaults']['custom']['stacking']['mode'], 'none')
                    transforms = [t['id'] for t in panel.get('transformations', [])]
                    if 'labelsToFields' in transforms:
                        self.assertLess(transforms.index('labelsToFields'), transforms.index('merge'))
                        self.assertLess(transforms.index('merge'), transforms.index('organize'))

    def test_volume_filter_is_limited_to_disks(self):
        d = DASHBOARDS['instance']
        self.assertIn('gvar_oie_volume_uuid', [v['name'] for v in d['templating']['list']])
        for panel in panels(d['panels']):
            for target in panel.get('targets', []):
                expr = target.get('expr', '')
                if 'oie_instance_disk_' in expr:
                    self.assertIn('${gvar_oie_volume_uuid}', expr)
                elif panel['id'] != 25001:
                    self.assertNotIn('${gvar_oie_volume_uuid}', expr)
        self.assertEqual(get_panel('instance', 25002)['options']['sortBy'][0]['displayName'], 'Read + write IOPS')

    def test_annotations_have_explicit_time_semantics(self):
        for name, d in DASHBOARDS.items():
            annotations = d['annotations']['list'][1:]
            self.assertEqual(len(annotations), 4)
            for ann in annotations:
                self.assertFalse(ann['enable'])
                self.assertFalse(ann['hide'])
            for ann in annotations[:2]:
                self.assertTrue(ann['useValueForTime'])
                self.assertIn('* 1000', ann['target']['expr'])
                self.assertIn('${__from}', ann['target']['expr'])
                self.assertIn('${__to}', ann['target']['expr'])
            self.assertIn('offset $__interval', annotations[3]['target']['expr'])
            self.assertIn('not an exact recovery timestamp', annotations[3]['textFormat'])


HOST = {'job': 'openstack-instance-exporter', 'instance': 'compute-a:9120'}
VM = HOST | {'domain': 'instance-0001', 'server_name': 'duplicate-name', 'instance_uuid': '11111111-1111-1111-1111-111111111111', 'project_uuid': 'project-a', 'project_name': 'project-name', 'user_uuid': 'user-a'}
DISK = VM | {'volume_uuid': 'volume-b572dff2-3d2e-4bed-b740-6faa8d88d104', 'disk_type': 'volumes', 'disk_path': 'vda'}


def series(metric, values, labels):
    return {'series': metric + '{' + ','.join(k + '=' + json.dumps(v) for k, v in sorted(labels.items())) + '}', 'values': values}


def fixture():
    data = [series('up', '1+0x8', HOST), series('oie_host_libvirt_ok', '1+0x8', HOST), series('oie_host_conntrack_raw_ok', '1+0x8', HOST), series('oie_host_libvirt_stale_seconds', '0+0x8', HOST), series('oie_host_collection_interval_seconds', '15+0x8', HOST), series('oie_instance_info', '1+0x8', VM), series('oie_instance_disk_info', '1+0x8', DISK)]
    data.append(series('oie_instance_inventory_info', '1+0x8', VM))
    for axis, score in [('cpu', 70), ('mem', 40), ('disk', 30), ('net', 20)]:
        data.append(series('oie_instance_resource_' + axis + '_severity', f'{score}+0x8', VM))
        for metric, values in [('fresh', '1+0x8'), ('available', '1+0x8'), ('last_success_timestamp_seconds', '0+15x8')]:
            data.append(series('oie_instance_resource_axis_' + metric, values, VM | {'axis': axis}))
    for direction, requests, seconds, gib in [('read', 150, 1.5, 15 / 1024), ('write', 450, 9, 30 / 1024)]:
        for suffix, step in [('requests_total', requests), ('seconds_total', seconds), ('gbytes_total', gib)]:
            data.append(series(f'oie_instance_disk_{direction}_{suffix}', f'0+{step}x8', DISK))
    return data


def change(data, prefix, values=None, axis=None):
    for entry in data[:]:
        if entry['series'].startswith(prefix + '{') and (axis is None or f'axis="{axis}"' in entry['series']):
            if values is None:
                data.remove(entry)
            else:
                entry['values'] = values


def expect(expr, value=None, at='2m'):
    if re.fullmatch(r'oie_operator_[a-z0-9_]+',expr):
        expr='sum('+expr+')'
    return {'expr': expr, 'eval_time': at, 'exp_samples': [] if value is None else [{'labels': '{}', 'value': value}]}


class PrometheusBehavior(unittest.TestCase):
    def test_native_grafana_variable_interpolation(self):
        promtool = os.environ.get('PROMTOOL', 'promtool')
        fixture_path = Path(__file__).resolve().parent / 'fixtures/grafana_prometheus_interpolation.json'
        interpolation_cases = json.loads(fixture_path.read_text())['cases']
        expressions = []
        for name, dashboard in DASHBOARDS.items():
            for panel in panels(dashboard['panels']):
                expressions.extend((name, target['expr']) for target in panel.get('targets', []) if target.get('expr'))
            expressions.extend((name, ann['target']['expr']) for ann in dashboard['annotations']['list'] if ann.get('target', {}).get('expr'))
            for variable in dashboard['templating']['list']:
                query = variable.get('definition', '')
                if query.startswith('query_result('):
                    expressions.append((name, query[len('query_result('):-1]))
                elif query.startswith('label_values('):
                    # Remove the Grafana-only wrapper and final label argument;
                    # the remaining selector must still be valid PromQL.
                    expressions.append((name, re.sub(r',\s*\w+\s*\)$', '', query[len('label_values('):])))
        records = []
        for case in interpolation_cases:
            for name, expr in expressions:
                self.assertNotIn(':regex}', expr, 'Generic regex formatting bypasses PromQL string escaping')
                records.append({'record': f'oie_interpolation_{len(records)}', 'expr': interpolate(expr, case['replacements'])})
        targets = ['compute-a.lab.example:9120', 'compute-a.lab.example:9100', 'compute-aXlab.example:9120', 'compute-a.lab.example-extra:9120', '172.29.224.5:9120', '172.29.224.5:9100', '172X29X224X5:9120', '172.29.224.50:9120']
        data = [series('up', '1+0x8', HOST | {'instance': target}) for target in targets]
        host_checks = []
        for case in interpolation_cases:
            expr = 'sum(up{job="openstack-instance-exporter", instance=~"^${gvar_oie_hypervisor}(:[0-9]+)?$"})'
            count = 4 if isinstance(case['inputs']['host'], list) else 2
            host_checks.append(expect(interpolate(expr, case['replacements']), count))
        with tempfile.TemporaryDirectory(prefix='oie-interpolation-tests-') as temp:
            temp = Path(temp)
            bad = temp / 'reported-error.yml'
            bad.write_text(yaml.safe_dump({'groups': [{'name': 'reported', 'rules': [{'record': 'reported_error', 'expr': r'up{job="openstack-instance-exporter",instance=~"^(compute-a\.lab\.example|172\.29\.224\.5)(:[0-9]+)?$"}'}]}]}))
            failed = subprocess.run([promtool, 'check', 'rules', str(bad)], capture_output=True, text=True)
            self.assertNotEqual(failed.returncode, 0)
            self.assertIn('unknown escape sequence', failed.stdout + failed.stderr)
            rules = temp / 'valid.yml'
            rules.write_text(yaml.safe_dump({'groups': [{'name': 'native_interpolation', 'rules': records}]}, sort_keys=False))
            checked = subprocess.run([promtool, 'check', 'rules', str(rules)], capture_output=True, text=True)
            self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)
            tests = temp / 'host-matching.yml'
            tests.write_text(yaml.safe_dump({'tests': [{'interval': '15s', 'input_series': data, 'promql_expr_test': host_checks}]}, sort_keys=False))
            evaluated = subprocess.run([promtool, 'test', 'rules', str(tests)], capture_output=True, text=True)
            self.assertEqual(evaluated.returncode, 0, evaluated.stdout + evaluated.stderr)
        print(f'Parsed {len(records)} interpolated expressions across all five dashboards; {len(host_checks)} exact host-matching cases passed.')

    def test_operator_inventory_and_partial_coverage(self):
        promtool = os.environ.get('PROMTOOL', 'promtool')
        cases = []
        records = {}
        def q(name, pid):
            key = f'oie_operator_{name}_{pid}'
            records[key] = {'record':key,'expr':interpolate(get_panel(name,pid)['targets'][0]['expr'])}
            return key
        def base():
            data = fixture()
            data += [series('oie_host_conntrack_stale_seconds', '0+0x8', HOST), series('oie_instance_state_code', '1+0x8', VM), series('oie_instance_outbound_flows', '0+0x8', VM)]
            return data
        def case(name, data, checks):
            cases.append({'name': name, 'interval': '15s', 'input_series': data, 'promql_expr_test': checks})
        count = q('cluster', 22002)
        missing = q('cluster', 22003)
        table = q('cluster', 22001)
        candidate = series('oie_instance_mining_suspected', '1+0x8', VM | {'ip':'10.0.0.5','family':'4','port':'14444','port_name':'pool','confidence':'high_persistent','priority':'100'})
        case('healthy monitoring with no observed candidate', base(), [expect(count, 0), expect(missing, 0)])
        data = base() + [candidate, series('oie_instance_cpu_vcpu_percent', '90+0x8', VM)]
        case('current candidate has CPU context', data, [expect(count, 1), expect('sum(' + table + '{oie_column="cpu"})', 90)])
        data = data + [series('up', '0+0x8', HOST | {'instance':'compute-b:9120'})]
        case('one failed host keeps healthy findings and marks incomplete coverage', data, [expect(count, 1), expect(missing, 1)])
        data = base() + [candidate]
        case('missing CPU is not invented for the evidence table', data, [expect(count, 1), expect('sum(' + table + '{oie_column="cpu"})')])
        data = base() + [candidate | {'values':'1+0x4 stale _x3'}]
        case('disappeared mining evidence returns to zero', data, [expect(count, 0)])
        data = base() + [candidate]
        change(data, 'up', '0+0x8')
        case('whole source outage cannot look clear', data, [expect(count, -1), expect('count(' + table + ')')])
        inv = VM | {'state_desc':'shutoff','libvirt_active':'0','vcpus':'4','mem_mb':'4096'}
        data = base(); change(data, 'oie_instance_inventory_info')
        data.append(series('oie_instance_inventory_info', '1+0x8', inv))
        case('inactive configuration is visible without becoming active', data, [expect(q('cluster',25012),0),expect(q('cluster',25013),1)])
        states = q('cluster',1275)
        data = base(); change(data,'oie_instance_inventory_info')
        data += [series('oie_instance_inventory_info', '1+0x3 stale _x4', VM | {'state_desc':'running','libvirt_active':'1'}), series('oie_instance_inventory_info', '_x4 1+0x4',inv)]
        case('state snapshot drops the former category after a power transition', data, [expect('sum('+states+'{state_desc="running"})'),expect('sum('+states+'{state_desc="shutoff"})',1)])
        threat_count = q('threats', 3001)
        threat_max = q('threats', 3002)
        threat_mean = q('threats', 3003)
        threat_high = q('threats', 3004)
        def threat_data(score='75+0x8'):
            return base() + [series('oie_host_threat_feed_fresh', '1+0x8', HOST | {'list':'spamhaus'}), series('oie_instance_threat_list_severity', score, VM)]
        case('restored threat summaries retain current evidence', threat_data(), [expect(threat_count, 1), expect(threat_max, 75), expect(threat_mean, 75), expect(threat_high, 1)])
        case('restored threat counts clear when scores return to zero', threat_data('75+0x4 0+0x3'), [expect(threat_count, 0), expect(threat_max, 0), expect(threat_mean, 0), expect(threat_high, 0)])
        for metric in ['up', 'oie_host_conntrack_raw_ok', 'oie_host_threat_feed_fresh']:
            data = threat_data(); change(data, metric, '0+0x8')
            case('restored threat summaries reject failed ' + metric, data, [expect(threat_count, -1), expect(threat_max, -1), expect(threat_mean, -1), expect(threat_high, -1)])
        data = threat_data(); change(data, 'oie_instance_threat_list_severity')
        case('missing threat score is not a healthy zero', data, [expect(threat_count, -1), expect(threat_max, -1), expect(threat_mean, -1), expect(threat_high, -1)])
        with tempfile.TemporaryDirectory(prefix='oie-operator-dashboards-') as temp:
            rules=Path(temp)/'rules.yml'; rules.write_text(yaml.safe_dump({'groups':[{'name':'operator','rules':list(records.values())}]},sort_keys=False))
            tests=Path(temp)/'tests.yml'; tests.write_text(yaml.safe_dump({'rule_files':[str(rules)],'evaluation_interval':'15s','tests':cases},sort_keys=False))
            result=subprocess.run([promtool,'test','rules',str(tests)],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        print(f'Validated {len(cases)} inventory, mining coverage, state-transition and threat-summary scenarios.')

    def test_capacity_and_optional_offset_are_separate(self):
        cases = []
        for name, pid in [('cluster', 1274), ('project', 1300)]:
            primary = get_panel(name, pid)
            diagnostic = get_panel(name, 25151)
            self.assertTrue(get_panel(name, 25150)['collapsed'])
            self.assertIn('not space usage', diagnostic['title'])
            self.assertEqual(len(primary['targets']), 1)
            self.assertNotIn('allocation_bytes', primary['targets'][0]['expr'])
            self.assertEqual(primary['fieldConfig']['defaults']['color']['mode'], 'palette-classic')
            capacity = interpolate(primary['targets'][0]['expr'])
            offsets = [interpolate(t['expr']) for t in diagnostic['targets']]
            local = DISK | {'disk_type': 'local', 'disk_path': 'vda'}
            pool = DISK | {'disk_type': 'premium', 'disk_path': 'vdb'}
            data = [series('oie_instance_disk_capacity_bytes', '20+0x8', local), series('oie_instance_disk_capacity_bytes', '60+0x8', pool)]
            for condition in ['missing-offset', 'partial-offset', 'missing-capacity']:
                inputs = list(data) if condition != 'missing-capacity' else []
                if condition != 'missing-offset':
                    inputs.append(series('oie_instance_disk_allocation_bytes', '50+0x8', pool))
                checks = [expect('sum(' + capacity + ')', None if condition == 'missing-capacity' else 80), expect('count(' + capacity + ')', None if condition == 'missing-capacity' else 2)]
                for target, expr in zip(diagnostic['targets'], offsets):
                    expected = None
                    if condition == 'partial-offset':
                        expected = 50 if 'allocation_bytes' in target['expr'].split(' and on')[0] else 60
                    checks.append(expect('sum(' + expr + ')', expected))
                cases.append({'name': name + ' ' + condition, 'interval': '15s', 'input_series': inputs, 'promql_expr_test': checks})
        with tempfile.TemporaryDirectory(prefix='oie-storage-semantics-') as temp:
            tests = Path(temp) / 'tests.yml'
            tests.write_text(yaml.safe_dump({'tests': cases}, sort_keys=False))
            result = subprocess.run([os.environ.get('PROMTOOL', 'promtool'), 'test', 'rules', str(tests)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        print(f'Validated {len(cases)} capacity/offset coverage scenarios.')

    def test_actual_queries(self):
        promtool = os.environ.get('PROMTOOL', 'promtool')
        records = []
        for name, d in DASHBOARDS.items():
            for panel in panels(d['panels']):
                for target in panel.get('targets', []):
                    if target.get('expr'):
                        records.append({'record': f'oie_test_{name}_{panel["id"]}_{target["refId"]}', 'expr': interpolate(target['expr'])})
            for i, ann in enumerate(d['annotations']['list'][1:]):
                records.append({'record': f'oie_test_{name}_annotation_{i}', 'expr': interpolate(ann['target']['expr'])})
            for var in d['templating']['list']:
                q = var.get('definition', '')
                if q.startswith('query_result('):
                    records.append({'record': f'oie_test_{name}_variable_{var["name"]}', 'expr': interpolate(q[len('query_result('):-1])})
        triage = 'oie_test_cluster_25001_A'
        volume = 'oie_test_instance_25002_A'
        volume_expr = get_panel('instance', 25002)['targets'][0]['expr']
        records.append({'record': 'oie_test_selected_volume', 'expr': interpolate(volume_expr, {'${gvar_oie_volume_uuid}': 'b572dff2-3d2e-4bed-b740-6faa8d88d104'})})
        records.append({'record': 'oie_test_absent_volume', 'expr': interpolate(volume_expr, {'${gvar_oie_volume_uuid}': 'other-volume'})})
        t = lambda col: f'sum({triage}{{oie_column="{col}"}})'
        v = lambda col: f'round(sum({volume}{{oie_column="{col}"}}), 0.001)'
        cases = []
        def case(name, data, checks):
            cases.append({'name': name, 'interval': '15s', 'input_series': data, 'promql_expr_test': checks})
        case('fresh resources and per-attachment arithmetic', fixture(), [expect(t('telemetry'), 2), expect(t('peak'), 70), expect(t('age'), 0), expect(v('total_iops'), 40), expect(v('read_iops'), 10), expect(v('write_iops'), 30), expect(v('read_bytes'), 1048576), expect(v('write_bytes'), 2097152), expect(v('read_latency'), 10), expect(v('write_latency'), 20), expect(f'count({volume})', 7)])
        data = fixture()
        for axis in ['read', 'write']:
            for suffix in ['requests_total', 'seconds_total', 'gbytes_total']:
                change(data, f'oie_instance_disk_{axis}_{suffix}', '0+0x8')
        case('idle is zero IOPS and no latency observation', data, [expect(v('total_iops'), 0), expect(v('read_latency'), -2), expect(v('write_latency'), -2)])
        data = fixture()
        change(data, 'oie_instance_disk_read_seconds_total')
        case('missing service time does not hide measured operations', data, [expect(v('read_iops'), 10), expect(v('read_latency'), -1), expect(v('total_iops'), 40)])
        data = fixture()
        change(data, 'oie_instance_disk_read_seconds_total', '0 1.5 3 4.5 6 _ 9 10.5 12')
        case('mismatched latency counter coverage is unavailable', data, [expect(v('read_latency'), -1), expect(v('write_latency'), 20)])
        data = fixture()
        change(data, 'oie_instance_disk_write_requests_total')
        case('read plus write requires both measurements', data, [expect(v('total_iops'), -1), expect(v('read_iops'), 10), expect(v('write_latency'), -1)])
        for metric, values in [('up', '1+0x7 0'), ('oie_host_libvirt_ok', '1+0x7 0'), ('oie_host_libvirt_stale_seconds', '120+0x8')]:
            data = fixture()
            change(data, metric, values)
            case('unavailable current source ' + metric, data, [expect(v('total_iops'), -1), expect(v('read_latency'), -1), expect(t('cpu'), -1), expect(t('telemetry'), 1)])
        data = fixture()
        change(data, 'up', '1+0x5 0 1 1')
        case('recovery does not average across failed scrape as idle time', data, [expect(v('total_iops'), -1), expect(t('telemetry'), 2)])
        data = fixture()
        change(data, 'oie_instance_resource_axis_fresh', '0+0x8', 'cpu')
        change(data, 'oie_instance_resource_axis_last_success_timestamp_seconds', '30+0x8', 'cpu')
        case('retained high score is not presented as current', data, [expect(t('cpu'), -1), expect(t('peak'), 40), expect(t('telemetry'), 1), expect(t('age'), 90)])
        data = fixture()
        change(data, 'oie_instance_resource_axis_available', '0+0x8', 'mem')
        change(data, 'oie_instance_resource_mem_severity')
        case('unavailable axis is explicit without lowering other axes', data, [expect(t('mem'), -1), expect(t('cpu'), 70), expect(t('telemetry'), 1)])
        data = fixture()
        for axis in ['cpu', 'mem', 'disk', 'net']:
            change(data, 'oie_instance_resource_axis_last_success_timestamp_seconds', '1+0x8', axis)
        case('frozen state flags are not fresh indefinitely', data, [expect(t('telemetry'), 1), expect(t('cpu'), -1), expect(t('age'), 119)])
        data = fixture()
        other = VM | {'instance_uuid': '22222222-2222-2222-2222-222222222222'}
        data.append(series('oie_instance_info', '1+0x8', other))
        data.append(series('oie_instance_inventory_info', '1+0x8', other))
        case('duplicate names preserve UUID identity and unmeasured rows', data, [expect(f'count({triage}{{oie_column="cpu"}})', 2), expect(f'count(oie_test_cluster_variable_gvar_oie_instance_uuid)', 2)])
        data = fixture()
        retype = DISK | {'destination_volume_uuid': 'volume-22222222-2222-2222-2222-222222222222', 'destination_disk_type': 'premium'}
        data += [series('oie_instance_disk_retype_start_timestamp_seconds', '30+0x8', retype), series('oie_instance_disk_retype_ready_timestamp_seconds', '60+0x8', retype), series('oie_instance_disk_retype_end_timestamp_seconds', '90+0x8', retype), series('process_start_time_seconds', '15+0x4 75+0x3', HOST)]
        case('retained lifecycle values keep their timestamp in milliseconds', data, [expect('sum(oie_test_cluster_annotation_0{oie_event="Retype first observed"})', 30000), expect('sum(oie_test_cluster_annotation_0{oie_event="Copy ready observed"})', 60000), expect('sum(oie_test_cluster_annotation_0{oie_event="Retype terminal observation"})', 90000), expect('sum(oie_test_cluster_annotation_1)', 75000)])
        data = fixture()
        change(data, 'up', '1+0x3 0 0 1 1 1')
        case('outage and recovery annotations clear after transition', data, [expect('sum(oie_test_cluster_annotation_2)', 1, '1m'), expect('sum(oie_test_cluster_annotation_3)', 1), expect('sum(oie_test_cluster_annotation_2)', None)])
        case('healthy monitoring has no outage or recovery annotations', fixture(), [expect('sum(oie_test_cluster_annotation_2)'), expect('sum(oie_test_cluster_annotation_3)')])
        case('bare UUID filter matches the RBD image prefix without broadening', fixture(), [expect('sum(oie_test_selected_volume{oie_column="total_iops"})', 40), expect('count(oie_test_absent_volume)')])
        data = [series('up', '1+0x8', HOST), series('oie_instance_inventory_info', '1 stale', VM)]
        case('historical VM names remain selectable after inventory disappears', data, [expect('count(oie_test_cluster_variable_gvar_oie_instance_uuid)', 1), expect(f'count({triage})')])
        with tempfile.TemporaryDirectory(prefix='oie-dashboard-tests-') as temp:
            temp = Path(temp)
            rule_file = temp / 'rules.yml'
            rule_file.write_text(yaml.safe_dump({'groups': [{'name': 'oie_dashboards', 'interval': '15s', 'rules': records}]}, sort_keys=False))
            test_file = temp / 'tests.yml'
            test_file.write_text(yaml.safe_dump({'rule_files': [str(rule_file)], 'evaluation_interval': '15s', 'tests': cases}, sort_keys=False))
            for args in [['check', 'rules', str(rule_file)], ['test', 'rules', str(test_file)]]:
                if args[0] == 'test':
                    names = {triage, volume, 'oie_test_selected_volume', 'oie_test_absent_volume', 'oie_test_cluster_variable_gvar_oie_instance_uuid'} | {f'oie_test_cluster_annotation_{i}' for i in range(4)}
                    focused = [r for r in records if r['record'] in names]
                    rule_file.write_text(yaml.safe_dump({'groups': [{'name': 'oie_dashboards', 'interval': '15s', 'rules': focused}]}, sort_keys=False))
                result = subprocess.run([promtool] + args, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            print(f'Validated {len(records)} PromQL expressions and {len(cases)} telemetry scenarios.')


if __name__ == '__main__':
    unittest.main()
