#!/usr/bin/env python3
"""Evaluate current threat views and protect dashboard identity/navigation layout."""
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

from oie_dashboards_test import DASHBOARDS, HOST, VM, get_panel, interpolate, panels, series


FEEDS = [('spamhaus', 'spamhaus'), ('emergingthreats', 'EMERGING'),
         ('customlist', 'CUSTOMLIST'), ('tor_exit', 'TOREXIT'), ('tor_relay', 'TORRELAY')]


def source(host=None, **changes):
    defaults = {'up': 1, 'oie_host_libvirt_ok': 1, 'oie_host_conntrack_raw_ok': 1,
                'oie_host_libvirt_stale_seconds': 0, 'oie_host_conntrack_stale_seconds': 0,
                'oie_host_collection_interval_seconds': 15, 'oie_host_volume_retype_monitoring_enabled': 1}
    return [series(metric, f'{value}+0x20', host or HOST) for metric, value in (defaults | changes).items()]


def feed(metric='spamhaus', state=1, host=None):
    label = dict(FEEDS)[metric]
    return [series('oie_host_threat_feed_fresh', f'{state}+0x20', (host or HOST) | {'list': label})]


def vm(labels=None, feeds=('spamhaus',), active=(2, 3), state=1, contacts=None):
    labels = labels or VM
    data = [series('oie_instance_state_code', f'{state}+0x20', labels)]
    for metric in feeds:
        for direction, count in zip(['outbound', 'inbound'], active):
            ident = labels | {'direction': direction}
            data += [series(f'oie_instance_threat_{metric}_active_flows', f'{count}+0x20', ident),
                     series(f'oie_instance_threat_{metric}_contacts_total', contacts or '0+15x20', ident)]
    return data


def remove(data, metric):
    return [entry for entry in data if not entry['series'].startswith(metric + '{')]


def expected(expr, value=None, at='5m'):
    if value is not None:
        expr = f'round(({expr}), 1 / 1048576)'
    return {'expr': expr, 'eval_time': at,
            'exp_samples': [] if value is None else [{'labels': '{}', 'value': value}]}


class OverviewLayout(unittest.TestCase):
    def test_sections_and_grid(self):
        for name, dashboard in DASHBOARDS.items():
            with self.subTest(dashboard=name):
                rows = [p for p in dashboard['panels'] if p['type'] == 'row']
                self.assertTrue(rows[-1]['title'].startswith('Exporter and collection'))
                self.assertTrue(all(row['collapsed'] for row in rows))
                if name != 'threats':
                    storage = [i for i, row in enumerate(rows) if row['title'].startswith('Storage')]
                    network = [i for i, row in enumerate(rows) if row['title'].startswith('Network')]
                    self.assertEqual(storage, list(range(min(storage), max(storage) + 1)))
                    self.assertLess(max(storage), min(network))
                else:
                    self.assertIn(27020, [p['id'] for p in panels(dashboard['panels'])])
                    self.assertIn(22002, [p['id'] for p in dashboard['panels']])
                groups = [dashboard['panels']] + [row['panels'] for row in rows if row['collapsed']]
                for group in groups:
                    for index, left in enumerate(group):
                        a = left['gridPos']
                        self.assertGreater(a['w'], 0)
                        self.assertGreater(a['h'], 0)
                        self.assertGreaterEqual(a['x'], 0)
                        self.assertLessEqual(a['x'] + a['w'], 24)
                        for right in group[index + 1:]:
                            b = right['gridPos']
                            overlap = (a['x'] < b['x'] + b['w'] and b['x'] < a['x'] + a['w'] and
                                       a['y'] < b['y'] + b['h'] and b['y'] < a['y'] + a['h'])
                            self.assertFalse(overlap, (name, left['id'], right['id']))
                for index, row in enumerate(dashboard['panels']):
                    if row['type'] != 'row':
                        continue
                    if row['collapsed']:
                        self.assertTrue(row['panels'], (name, row['title']))
                    else:
                        self.assertEqual(row['panels'], [])
                        self.assertLess(index + 1, len(dashboard['panels']))
                        self.assertNotEqual(dashboard['panels'][index + 1]['type'], 'row')

    def test_table_legends_and_readable_heights(self):
        for name, dashboard in DASHBOARDS.items():
            for panel in panels(dashboard['panels']):
                with self.subTest(dashboard=name, panel=panel['id']):
                    if panel['type'] == 'timeseries':
                        legend = panel['options']['legend']
                        self.assertEqual(legend['displayMode'], 'table')
                        self.assertEqual(legend['placement'], 'bottom')
                        self.assertTrue(legend['showLegend'])
                        self.assertNotIn('width', legend)
                        self.assertEqual(legend['calcs'][0], 'last')
                        self.assertNotIn('lastNotNull', legend['calcs'])
                        # Grafana 12.3 reserves at most 35% of the plot body for
                        # the legend. Keep room for its header and four rows;
                        # shrinking every graph to 8 grid units is not safe.
                        self.assertGreaterEqual(panel['gridPos']['h'], 11)
                        self.assertLessEqual(panel['gridPos']['h'], 11)
                    elif panel['type'] in ('stat', 'gauge'):
                        self.assertNotIn('legend', panel.get('options', {}))
                    elif panel['type'] == 'table':
                        self.assertGreaterEqual(panel['gridPos']['h'], 10)
                        self.assertFalse(panel['options']['enablePagination'])
                        if not (name == 'threats' and panel['id'] == 27020):
                            self.assertEqual(panel['gridPos']['w'], 24)

    def test_visual_rows_are_balanced_and_gap_free(self):
        for name, dashboard in DASHBOARDS.items():
            visual_rows = {}
            for panel in dashboard['panels']:
                visual_rows.setdefault(panel['gridPos']['y'], []).append(panel)
            next_y = 0
            for y, row in sorted(visual_rows.items()):
                self.assertEqual(y, next_y, (name, y, 'vertical gap'))
                self.assertEqual(len({p['gridPos']['h'] for p in row}), 1,
                                 (name, y, 'uneven bottoms'))
                next_x = 0
                for panel in sorted(row, key=lambda p: p['gridPos']['x']):
                    self.assertEqual(panel['gridPos']['x'], next_x, (name, panel['id']))
                    next_x += panel['gridPos']['w']
                self.assertEqual(next_x, 24, (name, y, 'empty right half'))
                next_y = y + row[0]['gridPos']['h']

    def test_related_comparisons_are_side_by_side(self):
        pairs = {
            'cluster': [(26002, 26003), (1237, 1238), (1241, 1240),
                        (912, 913), (1218, 1221), (1225, 1226)],
            'hypervisor': [(2001, 2002), (1233, 1235), (1212, 1214),
                           (1250, 1251), (1252, 1253), (1248, 1249),
                           (4003, 1247), (1224, 1272)],
            'project': [(1271, 1270), (1215, 1216), (26002, 26003),
                        (1230, 1255), (1202, 1259), (1257, 1258),
                        (1205, 1261), (1204, 1260)],
            'threats': [(3061, 3062), (3063, 3064)],
        }
        for name, comparisons in pairs.items():
            for left_id, right_id in comparisons:
                a, b = (get_panel(name, pid)['gridPos'] for pid in (left_id, right_id))
                self.assertEqual((a['x'], b['x'], a['w'], b['w']), (0, 12, 12, 12))
                self.assertEqual((a['y'], a['h']), (b['y'], b['h']))
        # Both UUIDs plus device/IP context do not fit reliably in a half-width
        # native table legend. Do not trade numeric alignment for overflow.
        for name, dashboard in DASHBOARDS.items():
            for panel in panels(dashboard['panels']):
                if panel['type'] == 'timeseries' and any(
                        'instance_uuid' in t.get('legendFormat', '')
                        for t in panel.get('targets', [])):
                    self.assertEqual(panel['gridPos']['w'], 24, (name, panel['id']))

    def test_storage_coverage_stays_with_source_latency(self):
        for name in ('cluster', 'hypervisor', 'project'):
            membership = {}
            parent_id = None
            for panel in panels(DASHBOARDS[name]['panels']):
                if panel['type'] == 'row':
                    parent_id = panel['id']
                else:
                    membership[panel['id']] = parent_id
            for panel_id in range(26001, 26006):
                self.assertEqual(membership[panel_id], 26000, (name, panel_id))
        visible = [p['id'] for p in DASHBOARDS['instance']['panels']]
        self.assertLess(visible.index(27043), visible.index(27041))

    def test_rank_context_without_repeated_title_suffixes(self):
        for name in ('instance', 'threats'):
            scope = get_panel(name, 25000)['options']['content']
            self.assertIn('${gvar_oie_top_n:text}', scope)
            self.assertIn('${gvar_oie_rank_by:text}', scope)
            for panel in panels(DASHBOARDS[name]['panels']):
                self.assertNotIn('[Rank:', panel.get('title', ''))

    def test_working_columns_preserve_link_identity(self):
        for name, dashboard in DASHBOARDS.items():
            for panel in panels(dashboard['panels']):
                if panel['type'] != 'table':
                    continue
                with self.subTest(dashboard=name, panel=panel['id']):
                    transforms = panel['transformations']
                    whitelist = next(t for t in transforms if t['id'] == 'filterFieldsByName')
                    organize = next(t for t in transforms if t['id'] == 'organize')
                    self.assertLess(transforms.index(whitelist), transforms.index(organize))
                    included = set(whitelist['options']['include']['names'])
                    names = organize['options']['renameByName']
                    self.assertEqual(included, set(names))
                    retained = {names.get(field, field) for field in included}
                    for override in panel['fieldConfig']['overrides']:
                        for prop in override['properties']:
                            if prop['id'] != 'links':
                                continue
                            for link in prop['value']:
                                fields = re.findall(r'__data\.fields\["([^"]+)"\]', link['url'])
                                self.assertTrue(set(fields) <= retained, (link, retained))
                    self.assertFalse(panel['options']['enablePagination'])
                    self.assertGreaterEqual(panel['gridPos']['h'], 8)
                    if 'Instance UUID' in retained and panel['id'] != 25004:
                        hidden = next(o for o in panel['fieldConfig']['overrides']
                                      if o['matcher'] == {'id': 'byName', 'options': 'Instance UUID'})
                        self.assertIn({'id': 'custom.hideFrom.viz', 'value': True}, hidden['properties'])
        for pid, prefix in [(25021, 'Storage')]:
            for panel in panels(DASHBOARDS['instance']['panels']):
                if panel['type'] == 'row':
                    parent = panel
                if panel['id'] == pid:
                    break
            self.assertTrue(parent['title'].startswith(prefix))

    def test_scrollable_history_states_and_gaps(self):
        for name, pid, history_id in [('hypervisor', 27234, 27334), ('hypervisor', 27264, 27364)]:
            p, history = get_panel(name, pid), get_panel(name, history_id)
            self.assertEqual(p['type'], 'table')
            self.assertFalse(p['options']['enablePagination'])
            self.assertNotIn('perPage', p['options'])
            self.assertNotIn('timeSeriesTable', [t['id'] for t in p['transformations']])
            cells = [prop['value'] for o in p['fieldConfig']['overrides'] for prop in o['properties']
                     if prop['id'] == 'custom.cellOptions']
            self.assertTrue(cells)
            self.assertTrue(all(c['type'] == 'color-text' for c in cells))
            for target in p['targets']:
                self.assertTrue(target['instant'])
                self.assertFalse(target['range'])
                self.assertEqual(target['format'], 'table')
            self.assertEqual(history['type'], 'table')
            self.assertFalse(history['options']['enablePagination'])
            group = next(t for t in history['transformations'] if t['id'] == 'groupBy')
            self.assertEqual(group['options']['fields']['Time']['aggregations'], ['first', 'last', 'count'])
            self.assertTrue({'job', 'instance', 'State'} <= set(group['options']['fields']))
            for target in history['targets']:
                self.assertTrue(target['range'])
                self.assertFalse(target['instant'])
                self.assertNotIn('topk(', target['expr'])
                self.assertNotIn('last_over_time(', target['expr'])


class CurrentObservationQueries(unittest.TestCase):
    def test_actual_dashboard_queries(self):
        records, cases = {}, []

        def query(pid, name='threats', replacements=None):
            expression = interpolate(get_panel(name, pid)['targets'][0]['expr'], {'${__range_s}': '300'} | (replacements or {}))
            key = (pid, name, expression)
            if key not in records:
                records[key] = {'record': f'oie_overview_test_{len(records)}', 'expr': expression}
            return records[key]['record']

        def cell(column):
            return 'sum(' + query(27022) + '{oie_column="' + column + '"})'

        def case(name, data, checks):
            unique = {}
            for entry in data:
                if entry['series'] in unique:
                    self.assertEqual(unique[entry['series']], entry)
                unique[entry['series']] = entry
            cases.append({'name': name, 'interval': '15s', 'input_series': list(unique.values()), 'promql_expr_test': checks})

        count, rate = 'sum(' + query(27020) + ')', 'sum(' + query(27021) + ')'
        usable, unusable, down = ['sum(' + query(pid) + ')' for pid in [27010, 27011, 27012]]
        current = lambda: [expected(count, 1), expected(rate, 2), expected(cell('active'), 5), expected(cell('contacts'), 600)]
        absent = lambda: [expected(count), expected(rate), expected(cell('active')), expected(cell('contacts'))]
        base = source() + feed() + vm()
        case('positive observations combine directions but count a UUID once', base,
             current() + [expected(usable, 1), expected(unusable, 0), expected(down, 0)])
        case('observed clean values show zero while positive-only rows are empty', source() + feed() + vm(active=(0, 0)),
             [expected(count, 0), expected(rate, 2), expected(cell('active')), expected(cell('contacts'))])
        case('no metrics is unavailable', [], absent() + [expected(usable), expected(unusable), expected(down)])
        case('healthy host alone cannot invent instance observations', source() + feed(), absent())
        case('missing feed status hides retained positive samples', source() + vm(), absent() + [expected(unusable)])
        for state in [-1, 0]:
            case(f'feed state {state} is not a clean zero', source() + feed(state=state) + vm(),
                 absent() + [expected(unusable, int(state == 0))])
        for metric, value in [('up', 0), ('oie_host_libvirt_ok', 0), ('oie_host_conntrack_raw_ok', 0),
                              ('oie_host_libvirt_stale_seconds', 120), ('oie_host_conntrack_stale_seconds', 120),
                              ('oie_host_libvirt_stale_seconds', -1), ('oie_host_conntrack_stale_seconds', -1)]:
            case(f'{metric}={value} excludes retained observations', source(**{metric: value}) + feed() + vm(),
                 absent() + [expected(usable, 0)])
        for metric in ['up', 'oie_host_libvirt_ok', 'oie_host_conntrack_raw_ok', 'oie_host_libvirt_stale_seconds',
                       'oie_host_conntrack_stale_seconds', 'oie_host_collection_interval_seconds', 'oie_instance_state_code']:
            case(f'missing {metric} cannot establish current eligibility', remove(base, metric), absent())
        for state in [0, 2, 3, 5]:
            case(f'non-running instance state {state}', source() + feed() + vm(state=state), absent())
        for metric, label in FEEDS:
            case(f'feed-state mapping {metric}/{label}', source() + feed(metric) + vm(feeds=(metric,)), current())
        case('overlap retains five per-list match series, not unique connection claims',
             source() + sum((feed(metric) for metric, _ in FEEDS), []) + vm(feeds=tuple(m for m, _ in FEEDS)),
             [expected(count, 5), expected(rate, 10), expected(cell('active'), 25), expected(cell('contacts'), 3000),
              expected('count(' + query(27020) + ')', 5)])
        host_b = HOST | {'instance': 'compute-b:9120'}
        vm_b = VM | host_b | {'instance_uuid': 'other-instance'}
        other = source(host_b) + feed(host=host_b) + vm(vm_b)
        case('partial fleet retains good-host evidence', base + source(host_b, up=0) + feed(host=host_b) + vm(vm_b),
             current() + [expected(usable, 1), expected(down, 1)])
        case('same server name does not collapse distinct UUIDs', base + other,
             [expected(count, 2), expected(rate, 4), expected(cell('active'), 10), expected(cell('contacts'), 1200)])
        case('same UUID observed on two hosts counts once per list', base + source(host_b) + feed(host=host_b) + vm(VM | host_b),
             [expected(count, 1), expected('count(' + query(27022) + '{oie_column="active"})', 2)])
        for variable in ['$gvar_oie_project_uuid', '$gvar_oie_project_name', '$gvar_oie_instance_uuid', '${gvar_oie_hypervisor}']:
            case(f'{variable} narrows current observations', base,
                 [expected('sum(' + query(pid, replacements={variable: 'not-selected'}) + ')') for pid in [27020, 27021, 27022]])
        larger = VM | {'instance_uuid': 'busier-instance'}
        case('Top N graph selection leaves all instance/list table rows with matching columns',
             base + vm(larger, active=(10, 20)),
             [expected('count(' + query(27022, replacements={'${gvar_oie_top_n}': '1'}) + '{oie_column="active"})', 2),
              expected('sum(' + query(27022, replacements={'${gvar_oie_top_n}': '1'}) + '{oie_column="active"})', 35),
              expected('sum(' + query(27022, replacements={'${gvar_oie_top_n}': '1'}) + '{oie_column="contacts"})', 1200)])
        case('contact resets use increase and rate, not subtraction',
             source() + feed() + vm(contacts='100+15x9 15+15x10'),
             [expected(count, 1), expected(rate, 2), expected(cell('contacts'), 600)])
        # Retype outcomes are operation-centric and reconstructed from Prometheus
        # history after the exporter terminal grace has expired.
        operation = VM | {'disk_path': 'vda', 'disk_type': 'source-pool', 'volume_uuid': 'source-image',
                          'destination_disk_type': 'arbitrary-tier', 'destination_volume_uuid': 'destination-image'}
        history = [series('oie_instance_disk_retype_status_code', '1+0x4 5+0x4 2+0x10', operation),
                   series('oie_instance_disk_retype_start_timestamp_seconds', '15+0x20', operation),
                   series('oie_instance_disk_retype_ready_timestamp_seconds', '75+0x15', operation),
                   series('oie_instance_disk_retype_end_timestamp_seconds', '135+0x10', operation)]
        for name, pid in [('cluster', 24003), ('project', 24004)]:
            record = query(pid, name)
            case(f'{name} retype outcome retains exact terminal observation', source() + history,
                 [expected('count(' + record + '{retype_field="status"})', 1),
                  expected('sum(' + record + '{retype_field="status"})', 2),
                  expected('sum(' + record + '{retype_field="end"})', 135000)])
        with tempfile.TemporaryDirectory(prefix='oie-overview-') as tmp:
            folder = Path(tmp)
            (folder / 'rules.yml').write_text(yaml.safe_dump({'groups': [{'name': 'dashboard_overview', 'interval': '15s', 'rules': list(records.values())}]}))
            (folder / 'tests.yml').write_text(yaml.safe_dump({'rule_files': ['rules.yml'], 'evaluation_interval': '15s', 'tests': cases}))
            result = subprocess.run([os.environ.get('PROMTOOL', 'promtool'), 'test', 'rules', 'tests.yml'], cwd=folder, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        print(f'Validated {len(cases)} current-observation scenarios against {len(records)} actual dashboard queries.')


if __name__ == '__main__':
    unittest.main()
