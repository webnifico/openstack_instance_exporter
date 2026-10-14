#!/usr/bin/env python3
"""Exercise actual dashboard queries with large inventories and incomplete sources."""
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

from oie_dashboards_test import DASHBOARDS, HOST, VM, get_panel, interpolate, panels, series
from oie_dashboard_overview_test import FEEDS, source, feed, vm


def expect(expr, value=None):
    return {'expr': expr, 'eval_time': '5m',
            'exp_samples': [] if value is None else [{'labels': '{}', 'value': value}]}


def inventory(labels=None, state='running'):
    return series('oie_instance_inventory_info', '1+0x20', (labels or VM) | {'state_desc': state})


class ScalableViews(unittest.TestCase):
    def test_names_and_overview_order(self):
        for name, dashboard in DASHBOARDS.items():
            for panel in panels(dashboard['panels']):
                if 'range end' in panel.get('title', '').lower():
                    self.assertEqual(name, 'hypervisor')
                    self.assertIn(panel['id'], (27234, 27264))
                    self.assertTrue(all(t['instant'] and not t['range'] for t in panel['targets']))
                self.assertFalse(any(t['id'] == 'renameByRegex' and ('…' in str(t) or '...' in str(t)) for t in panel.get('transformations', [])))
                for target in panel.get('targets', []):
                    legend = target.get('legendFormat', '')
                    if 'instance_uuid' in legend:
                        self.assertIn('server_name', legend, (name, panel['id']))
                        if panel['type'] == 'timeseries':
                            self.assertEqual(panel['gridPos']['w'], 24)
                            self.assertEqual(panel['options']['legend']['displayMode'], 'table')
                    if 'project_uuid' in legend:
                        self.assertIn('project_name', legend, (name, panel['id']))
                    if 'instance_uuid' in legend or 'project_uuid' in legend:
                        for aggregation in re.finditer(r'\b(\w+)\s+by\s*\(([^)]*)\)', target.get('expr', '')):
                            labels = {v.strip() for v in aggregation.group(2).split(',')}
                            # Scheduler completeness counts measurement identities;
                            # names still belong in every displayed/ranked aggregation.
                            cpu_cohort = (aggregation.group(1) == 'count' and
                                          labels == {'job', 'instance', 'instance_uuid'} and
                                          'oie_instance_cpu_vcpu_count' in target['expr'] and
                                          'oie_instance_cpu_steal_seconds_total' in target['expr'])
                            if cpu_cohort:
                                continue
                            if 'instance_uuid' in labels:
                                self.assertIn('server_name', labels)
                            if 'project_uuid' in labels:
                                self.assertIn('project_name', labels)
            cards = [get_panel(name, pid) for pid in ([27012, 27011, 27010, 22002, 22003, 22004] if name == 'threats' else [25011, 25010, 25012, 25013])]
            self.assertEqual(len({p['gridPos']['y'] for p in cards}), 1, name)
            self.assertEqual([p['gridPos']['x'] for p in cards], [0, 4, 8, 12, 16, 20] if name == 'threats' else [0, 6, 12, 18])
            if name != 'threats':
                self.assertIn(get_panel(name, 25001), dashboard['panels'])
            self.assertTrue({38000, 38001, 38002}.isdisjoint(
                p['id'] for p in panels(dashboard['panels'])))
            for variable in dashboard['templating']['list']:
                if variable['name'] == 'gvar_oie_project_uuid':
                    self.assertIn('project_name', variable['definition'])
                    self.assertIn('(?<value>', variable['regex'])

    def test_scope_and_native_presentation(self):
        for name in ['cluster', 'hypervisor', 'project']:
            p = get_panel(name, 25003)
            organize = next(t['options'] for t in p['transformations'] if t['id'] == 'organize')
            self.assertNotIn('instance_uuid', organize['renameByName'])
            self.assertNotIn('server_name', organize['renameByName'])
            self.assertNotIn('topk(', p['targets'][0]['expr'])
            self.assertEqual(get_panel(name, 25001)['type'], 'stat')
        for name, d in DASHBOARDS.items():
            for p in panels(d['panels']):
                if p['type'] == 'state-timeline':
                    self.assertEqual(p['options']['perPage'], 8)
                    self.assertTrue(all('topk(' not in t['expr'] for t in p['targets']))
                else:
                    self.assertNotIn('perPage', p.get('options', {}))
                self.assertNotIn('pageSize', p.get('options', {}))
                if p['type'] == 'row':
                    self.assertTrue(p['collapsed'])
                if p['type'] == 'table':
                    self.assertFalse(p['options']['enablePagination'])
                    for target in p.get('targets', []):
                        self.assertNotIn('topk(', target.get('expr', ''))
                    self.assertTrue(p['options']['showHeader'])
                    self.assertGreaterEqual(p['gridPos']['h'], 10)
                    properties = [prop for o in p['fieldConfig']['overrides'] for prop in o['properties']]
                    self.assertFalse(any(prop['id'] == 'custom.hidden' for prop in properties))
        selected = next(v for v in DASHBOARDS['instance']['templating']['list'] if v['name'] == 'gvar_oie_instance_uuid')
        self.assertTrue(selected['includeAll'])
        self.assertEqual(selected['current']['value'], ['$__all'])
        self.assertTrue(selected['multi'])
        for p in panels(DASHBOARDS['instance']['panels']):
            for t in p.get('targets', []):
                self.assertNotIn('instance_uuid="$gvar_oie_instance_uuid"', t.get('expr', ''))
        self.assertEqual(get_panel('threats', 3065)['type'], 'table')

    def test_actual_aggregation_failure_and_scale_queries(self):
        records, cases = {}, []

        def q(name, pid, ref='A', replacements=None):
            target = next(t for t in get_panel(name, pid)['targets'] if t['refId'] == ref)
            expr = interpolate(target['expr'], replacements)
            key = (name, pid, ref, expr)
            if key not in records:
                records[key] = {'record': f'oie_scale_{len(records)}', 'expr': expr}
            return records[key]['record']

        def total(name, pid, ref='A'):
            return 'sum(' + q(name, pid, ref) + ')'

        def cell(name, pid, column):
            return 'sum(' + q(name, pid) + '{oie_column="' + column + '"})'

        def case(name, data, checks):
            cases.append({'name': name, 'interval': '15s', 'input_series': data, 'promql_expr_test': checks})

        # Inventory groups retain UUID identity and do not send one row per VM.
        rows = [inventory(VM | {'instance_uuid': f'vm-{i}', 'project_uuid': f'project-{i % 40}',
                               'project_name': 'Duplicate project name'}, 'running' if (i // 40) % 2 else 'shutoff')
                for i in range(2000)]
        inv = q('cluster', 25003)
        case('2000 domains become all 40 project rows', source() + rows, [
            expect('count(' + inv + '{oie_column="observed"})', 40),
            expect(cell('cluster', 25003, 'observed'), 2000),
            expect(cell('cluster', 25003, 'running'), 1000),
            expect(cell('cluster', 25003, 'shutoff'), 1000),
            expect(total('cluster', 27200, 'B'), 40),
            expect(total('cluster', 27200, 'C'), 2000)])
        case('same display names preserve two UUID identities', source() + [inventory(), inventory(VM | {'instance_uuid': 'vm-b'})], [expect(cell('cluster', 25003, 'observed'), 2)])
        case('duplicate metadata samples do not multiply a domain', source() + [inventory(), inventory(VM | {'server_name': 'renamed'})], [expect(cell('cluster', 25003, 'observed'), 1)])
        other_host = HOST | {'instance': 'compute-b:9120'}
        case('migration is honestly counted as two host observations', source() + source(other_host) + [inventory(), inventory(VM | other_host)], [expect(cell('cluster', 25003, 'observed'), 2)])
        case('failed libvirt does not invent an empty inventory', source(oie_host_libvirt_ok=0) + [inventory()], [expect(cell('cluster', 25003, 'observed')), expect(total('cluster', 27200, 'C'))])
        case('unknown observed state stays in other states', source() + [inventory(state='paused')], [expect(cell('cluster', 25003, 'other'), 1), expect(cell('cluster', 25003, 'running'), 0)])
        case('project filter applies before aggregation', source() + [inventory()], [expect('sum(' + q('cluster', 25003, replacements={'$gvar_oie_project_uuid': 'unselected'}) + ')')])

        source_refs = ['A', 'B', 'C', 'D', 'E', 'F']
        checks = lambda expected: [expect(total('cluster', 23001, ref), v) for ref, v in zip(source_refs, expected)]
        case('two healthy sources return two usable counts and four zeros', source(), checks([1, 0, 0, 1, 0, 0]) + [expect(total('cluster', 27232), 0), expect('count(' + q('cluster', 27231) + ')')])
        case('scrape failure does not retain healthy source status', source(up=0), checks([0, 1, 0, 0, 1, 0]))
        case('stale libvirt is unusable even when last collection succeeded', source(oie_host_libvirt_stale_seconds=61), checks([0, 1, 0, 1, 0, 0]))
        case('never-successful source is unusable', source(oie_host_conntrack_stale_seconds=-1), checks([1, 0, 0, 0, 1, 0]))
        absent_interval = [s for s in source() if not s['series'].startswith('oie_host_collection_interval_seconds{')]
        case('missing freshness policy is unknown', absent_interval, checks([0, 0, 1, 0, 0, 1]))
        absent_ok = [s for s in source() if not s['series'].startswith('oie_host_libvirt_ok{')]
        case('missing status is unknown rather than healthy', absent_ok, checks([0, 0, 1, 1, 0, 0]))
        case('no target inventory leaves all source counts unavailable', [], checks([None] * 6) + [expect(total('cluster', 27232))])
        many_hosts = []
        for i in range(200):
            many_hosts += source(HOST | {'instance': f'compute-{i}:9120'}, oie_host_libvirt_ok=0 if i < 14 else 1)
        case('200 hosts yield six history series and all fourteen exceptions', many_hosts, checks([186, 14, 0, 200, 0, 0]) + [
            expect(total('cluster', 27232), 14),
            expect('count(' + q('cluster', 27231) + '{oie_column="libvirt"})', 14),
            expect(cell('cluster', 27231, 'sources'), 14)])

        # A feed row covers a list, including disabled, missing and unreachable hosts.
        feed_data = []
        for i in range(12):
            host = HOST | {'instance': f'feed-{i}:9120'}
            feed_data += source(host, up=0 if i == 3 else 1)
            for metric, _ in FEEDS:
                if i != 4:
                    feed_data += feed(metric, -1 if i == 1 else 0 if i == 2 else 1, host)
        ft = q('threats', 3065)
        case('sixty expected host-list pairs remain five complete coverage rows', feed_data, [
            expect('count(' + ft + '{oie_column="targets"})', 5), expect(cell('threats', 3065, 'targets'), 60),
            expect(cell('threats', 3065, 'usable'), 40), expect(cell('threats', 3065, 'unusable'), 5),
            expect(cell('threats', 3065, 'disabled'), 5), expect(cell('threats', 3065, 'unknown'), 10)])
        case('disabled feed is not an unusable or healthy enabled feed', source() + feed(state=-1), [expect(cell('threats', 3065, 'disabled'), 1), expect(cell('threats', 3065, 'usable'), 0), expect(cell('threats', 3065, 'unusable'), 0)])
        case('no feed telemetry is unavailable', source(), [expect(cell('threats', 3065, 'targets')), expect(total('threats', 27265))])
        unknown_feed = source() + [series('oie_host_threat_feed_fresh', '7+0x20', HOST | {'list': 'new-observed-list'})]
        case('new list is discovered and an unknown state is explicit', unknown_feed, [expect(cell('threats', 3065, 'targets'), 1), expect(cell('threats', 3065, 'unknown'), 1)])

        # All is the default; explicit multi/single UUID selections retain identity.
        selected = source() + [inventory(), inventory(VM | {'instance_uuid': 'vm-b'})]
        case('instance defaults to all selected-scope observations', selected, [expect('count(' + q('instance', 25003) + ')', 2)])
        for selection, count in [('.*', 2), (VM['instance_uuid'] + '|vm-b', 2), (VM['instance_uuid'], 1), ('missing-vm', None)]:
            case('instance UUID selection ' + selection, selected, [expect('count(' + q('instance', 25003, replacements={'$gvar_oie_instance_uuid': selection}) + ')', count)])
        case('single instance source summary only includes its observed host', selected + source(other_host, up=0), [expect(total('instance', 27232, 'C'), 1), expect(total('instance', 27030, 'A'), 1)])
        case('single instance reachability excludes unrelated hosts', selected + source(other_host, up=0), [
            expect(total('instance', 25010), 1), expect(total('instance', 25011), 0)])

        # Human names survive real aggregations without becoming identity keys.
        named = []
        for uuid, project, flows in [('vm-one', 'project-one', 5), ('vm-two', 'project-two', 7)]:
            labels = VM | {'instance_uuid': uuid, 'server_name': 'Same VM name', 'project_uuid': project, 'project_name': 'Same project name', 'direction': 'outbound'}
            named.append(series('oie_instance_threat_spamhaus_active_flows', f'{flows}+0x20', labels))
        chart = q('threats', 3023)
        case('duplicate human names retain both UUID identities and values', named, [
            expect('count(' + chart + '{server_name="Same VM name",project_name="Same project name"})', 2),
            expect('sum(' + chart + ')', 12), expect('sum(' + chart + '{instance_uuid="vm-one",project_uuid="project-one"})', 5)])
        nameless = VM | {'server_name': '', 'project_name': '', 'direction': 'outbound'}
        case('missing names are explicit and retain full UUID identity', [series('oie_instance_threat_spamhaus_active_flows', '3+0x20', nameless)], [
            expect('sum(' + chart + '{server_name="Name unavailable",project_name="Name unavailable",instance_uuid="' + VM['instance_uuid'] + '"})', 3)])
        # Candidate evidence survives absent CPU; bounded rows retain a shared identity.
        candidate = series('oie_instance_mining_suspected', '1+0x20', VM | {'ip': '192.0.2.1', 'family': '4', 'port': '14444', 'port_name': 'pool', 'confidence': 'high_persistent'})
        raw = source() + vm(active=(0, 0)) + [series('oie_instance_info', '1+0x20', VM), series('oie_instance_outbound_flows', '0+0x20', VM), candidate]
        cpu_rows = q('cluster', 22001) + '{oie_column="cpu"}'
        case('mining evidence without CPU remains visible', raw,
             [expect('count(' + q('cluster', 22001) + '{oie_column="candidate"})', 1),
              expect('count(' + cpu_rows + ')', 1),
              expect('count(' + cpu_rows + ' != ' + cpu_rows + ')', 1),
              expect(total('cluster', 27220), 1)])
        operations = []
        for i in range(1, 26):
            labels = VM | {'disk_path': f'vd{i}', 'disk_type': 'source-pool', 'volume_uuid': f'volume-{i}',
                           'destination_disk_type': 'destination-pool', 'destination_volume_uuid': f'destination-{i}'}
            operations += [series('oie_instance_disk_retype_active', '1+0x20', labels),
                           series('oie_instance_disk_retype_start_timestamp_seconds', f'{i}+0x20', labels),
                           series('oie_instance_disk_retype_status_code', '5+0x20', labels),
                           series('oie_instance_disk_retype_observation_healthy', '1+0x20', labels),
                           series('oie_instance_disk_retype_progress_percent', '100+0x20', labels)]
        for name, pid in [('cluster', 24001), ('project', 24002)]:
            record = q(name, pid)
            case(f'{name} active retypes keep all complete operation identities', source() + operations, [
                expect('count(' + record + '{retype_field="status"})', 25),
                expect('count(' + record + '{retype_field="progress"})', 25),
                expect('sum(' + record + '{retype_field="start"})', 325000),
                expect(total(name, 27240, 'A'), 1),
                expect(total(name, 27240, 'C'), 25)])

        matches = source() + feed()
        for i in range(125):
            matches += vm(VM | {'instance_uuid': f'matched-{i}'}, active=(i + 1, 0))
        broad = {'${gvar_oie_top_n}': '1000000'}
        current = q('threats', 27022, replacements=broad)
        case('all 125 current threat matches remain visible', matches, [
            expect('count(' + current + '{oie_column="active"})', 125),
            expect('count(' + current + '{oie_column="contacts"})', 125),
            expect('sum(' + q('threats', 27222, 'A', broad) + ')', 125)])

        cpu_inputs = source()
        for uuid, value in [('vm-a', 10), ('vm-b', 90)]:
            identity = VM | {'instance_uuid': uuid, 'server_name': 'Duplicate name'}
            cpu_inputs += [series('oie_instance_cpu_vcpu_percent', f'{value}+0x20', identity),
                           series('oie_instance_state_code', '1+0x20', identity)]
        for selection, limit, expected_count, expected_sum in [('.*', '10', 2, 100), ('vm-a|vm-b', '1', 1, 90), ('vm-a', '10', 1, 10), ('vm-a|vm-b', '1000000', 2, 100)]:
            cpu = q('instance', 2021, replacements={'$gvar_oie_instance_uuid': selection, '${gvar_oie_top_n}': limit})
            case('instance CPU graph selection ' + selection + ' Top N ' + limit, cpu_inputs, [expect('count(' + cpu + ')', expected_count), expect('sum(' + cpu + ')', expected_sum)])

        # Selected-range outcome tables also retain complete operation scope.
        terminal = []
        for i in range(1, 26):
            labels = VM | {'disk_path': f'vd{i}', 'disk_type': 'source-pool', 'volume_uuid': f'volume-{i}',
                           'destination_disk_type': 'destination-pool', 'destination_volume_uuid': f'destination-{i}'}
            terminal += [series('oie_instance_disk_retype_status_code', '2+0x20', labels),
                         series('oie_instance_disk_retype_start_timestamp_seconds', f'{i}+0x20', labels),
                         series('oie_instance_disk_retype_end_timestamp_seconds', f'{i + 60}+0x20', labels)]
        for name, pid in [('cluster', 24003), ('project', 24004)]:
            record = q(name, pid)
            case(name + ' outcome history includes all 25 operations', source() + terminal, [
                expect('count(' + record + '{retype_field="status"})', 25),
                expect('count(' + record + '{retype_field="end"})', 25)])
        twelve_hosts = []
        for i in range(12):
            host = HOST | {'instance': f'compute-{i}:9120'}
            twelve_hosts += source(host)
            for metric, _ in FEEDS:
                twelve_hosts += feed(metric, 1, host)
        case('12 healthy hosts have zero missing-status counts and complete source histories', twelve_hosts, [expect(total('hypervisor', 27030, 'A'), 12), expect(total('hypervisor', 27030, 'C'), 0), expect(total('hypervisor', 27030, 'D'), 12), expect(total('hypervisor', 27030, 'F'), 0), expect('count(' + q('hypervisor', 27234, 'A') + ')', 12), expect('count(' + q('hypervisor', 27234, 'B') + ')', 12), expect('count(' + q('hypervisor', 27264) + ')', 60)])

        missing_libvirt = [entry for entry in twelve_hosts
                           if not entry['series'].startswith('oie_host_libvirt_ok{')]
        libvirt_result = q('hypervisor', 27234, 'B')
        case('known targets retain unknown cells when the entire Libvirt result is absent', missing_libvirt, [
            expect('count(' + libvirt_result + ')', 12),
            expect('count(' + libvirt_result + ' != ' + libvirt_result + ')', 12),
            expect('count(' + libvirt_result + ' == 1)', None)])
        failed_hosts = [dict(entry, values='0+0x20') if entry['series'].startswith('up{') else entry
                        for entry in twelve_hosts]
        case('unreachable targets never display an old collector success', failed_hosts, [
            expect('count(' + libvirt_result + ')', 12),
            expect('count(' + libvirt_result + ' != ' + libvirt_result + ')', 12)])

        # A graph limit of one must never hide current mining or threat rows.
        all_candidates = source()
        for i in range(25):
            labels = VM | {'instance_uuid': f'miner-{i}', 'server_name': f'worker-{i:02d}'}
            all_candidates += vm(labels, active=(0, 0)) + [inventory(labels), series('oie_instance_info', '1+0x20', labels), series('oie_instance_outbound_flows', '0+0x20', labels),
                series('oie_instance_mining_suspected', '1+0x20', labels | {'ip': f'192.0.2.{i+1}', 'family': '4', 'port': '14444', 'port_name': 'pool', 'confidence': 'high_persistent'})]
        for name in ['cluster', 'instance', 'threats']:
            candidate_rows = q(name, 22001, replacements={'${gvar_oie_top_n}': '1'})
            case(name + ' all 25 mining endpoints survive a graph limit of one and absent CPU', all_candidates, [expect('count(' + candidate_rows + '{oie_column="candidate"})', 25)])
        one_graph = q('threats', 27022, replacements={'${gvar_oie_top_n}': '1'})
        case('graph Top N one preserves all 125 current table rows', matches, [expect('count(' + one_graph + '{oie_column="active"})', 125)])

        with tempfile.TemporaryDirectory(prefix='oie-dashboard-scale-') as temp:
            p = Path(temp)
            (p / 'rules.yml').write_text(yaml.safe_dump({'groups': [{'name': 'dashboard_scale', 'interval': '15s', 'rules': list(records.values())}]}))
            (p / 'tests.yml').write_text(yaml.safe_dump({'rule_files': ['rules.yml'], 'evaluation_interval': '15s', 'tests': cases}))
            result = subprocess.run([os.environ.get('PROMTOOL', 'promtool'), 'test', 'rules', 'tests.yml'], cwd=p, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        print(f'Validated {len(cases)} scale, identity and missing-data scenarios against {len(records)} actual queries, including 2000 domains and 200 hosts.')


if __name__ == '__main__':
    unittest.main()
