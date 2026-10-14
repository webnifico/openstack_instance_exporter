#!/usr/bin/env python3
"""Presentation regression contracts and explicit data-frame/URL fixtures.

These tests do not start Grafana or evaluate PromQL. Frame fixtures model the
Grafana 12.3 table field naming and shared-column merge relevant to these panels;
actual expression evaluation remains in the Promtool suites.
"""
import copy
import json
import math
import re
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

from oie_dashboards_test import DASHBOARDS, get_panel, panels

ROOT = Path(__file__).resolve().parents[1]
HISTORIES = [('hypervisor', 27234, 27334), ('hypervisor', 27264, 27364)]
PAIRS = {1237: ('Read', 'Write'), 1238: ('Read', 'Write'), 1256: ('Read', 'Write'),
         1241: ('RX', 'TX'), 1240: ('RX', 'TX')}
FIXED = {('cluster', 1269)}


def strings(value, key=None):
    if isinstance(value, dict):
        for child_key, child in value.items():
            yield from strings(child, child_key)
    elif isinstance(value, list):
        for child in value:
            yield from strings(child, key)
    elif isinstance(value, str):
        yield key, value


def props(panel, field):
    result = {}
    for override in panel['fieldConfig']['overrides']:
        if override['matcher'] == {'id': 'byName', 'options': field}:
            result.update({p['id']: p['value'] for p in override['properties']})
    return result


def native_table_frames(rows_by_ref):
    """Fixture for Prometheus transformDFToTable; input rows = labels + value."""
    frames = []
    for ref, rows in rows_by_ref.items():
        value_name = f'Value #{ref}' if len(rows_by_ref) > 1 else 'Value'
        frames.append([dict(labels, **{value_name: value, 'Time': 60000}) for labels, value in rows])
    return frames


def apply_table_transforms(panel, frames):
    """Fixture model for the native table transforms; not a Grafana renderer."""
    frames = copy.deepcopy(frames)
    for transform in panel['transformations']:
        options = transform['options']
        if transform['id'] == 'renameByRegex':
            regex, replacement = options['regex'], options['renamePattern']
            frames = [[{re.sub(regex, replacement, k): v for k, v in row.items()}
                       for row in frame] for frame in frames]
        elif transform['id'] == 'groupBy':
            group_keys = [k for k, v in options['fields'].items() if v['operation'] == 'groupby']
            grouped_frames = []
            for frame in frames:
                groups = {}
                for row in frame:
                    key = tuple(row.get(k) for k in group_keys)
                    groups.setdefault(key, []).append(row)
                rows = []
                for key, members in groups.items():
                    result = dict(zip(group_keys, key))
                    for field, config in options['fields'].items():
                        if config['operation'] != 'aggregate':
                            continue
                        values = [row.get(field) for row in members]
                        for calc in config['aggregations']:
                            reduced = {'first': lambda: values[0], 'last': lambda: values[-1],
                                       'count': lambda: len(values)}[calc]()
                            result[f'{field} ({calc})'] = reduced
                    rows.append(result)
                grouped_frames.append(rows)
            frames = grouped_frames
        elif transform['id'] == 'filterFieldsByName':
            allowed = set(options['include']['names'])
            frames = [[{k: v for k, v in row.items() if k in allowed} for row in frame]
                      for frame in frames]
        elif transform['id'] == 'merge':
            result = []
            for frame in frames:
                for row in frame:
                    # Grafana only combines rows whose shared fields agree.
                    for existing in result:
                        shared = existing.keys() & row.keys()
                        if shared and all(existing[k] == row[k] for k in shared):
                            existing.update(row)
                            break
                    else:
                        result.append(dict(row))
            frames = [result]
        elif transform['id'] == 'organize':
            rename = options['renameByName']
            frames = [[{rename.get(k, k): v for k, v in row.items()} for row in frame]
                      for frame in frames]
        else:
            raise AssertionError('Unsupported fixture transform: ' + transform['id'])
    return frames[0] if frames else []


class StorageInventoryWording(unittest.TestCase):
    def test_cluster_disk_and_block_device_relationship_is_explicit(self):
        disks = get_panel('cluster', 1242)
        blocks = get_panel('cluster', 39011)
        self.assertEqual(disks['title'], 'Running VM disks by source')
        self.assertEqual(blocks['title'], 'Configured block devices')
        self.assertIn('A disk is one type of block device', disks['description'])
        self.assertIn('10 storage disks and 4 config drives', disks['description'])
        self.assertIn('Every disk is a block device, but not every block device is a disk', blocks['description'])
        self.assertIn('10 storage disks plus 4 config drives equals 14 configured block devices', blocks['description'])
        labels = {}
        for override in blocks['fieldConfig']['overrides']:
            matcher = override.get('matcher', {})
            if matcher.get('id') != 'byName':
                continue
            for prop in override.get('properties', []):
                if prop.get('id') == 'displayName':
                    labels[matcher.get('options')] = prop.get('value')
        self.assertEqual(labels.get('storage'), 'Storage disk')
        self.assertEqual(labels.get('config_drive'), 'Config drive')
        self.assertEqual(labels.get('swap'), 'Swap disk')


class TimeRangeLinks(unittest.TestCase):
    def test_all_navigation_uses_native_raw_time_once(self):
        count = 0
        for name, dashboard in DASHBOARDS.items():
            for link in dashboard['links']:
                self.assertTrue(link['keepTime'], name)
                self.assertNotIn('from=', link['url'])
                self.assertNotIn('to=', link['url'])
                self.assertNotIn('__url_time_range', link['url'])
                count += 1
            for panel in panels(dashboard['panels']):
                for key, value in strings(panel):
                    if key not in ('url', 'content') or '/d/' not in value:
                        continue
                    self.assertNotIn('from=${__from}', value)
                    self.assertNotIn('to=${__to}', value)
                    for url in re.findall(r'/d/[^\s)]+', value):
                        self.assertEqual(url.count('${__url_time_range}'), 1, (name, panel['id'], url))
                        count += 1
        self.assertGreater(count, 100)

    def test_relative_and_absolute_url_fixtures_preserve_scope(self):
        raw_ranges = [('now-1h', 'now'), ('now-24h', 'now'), ('now-7d/d', 'now/d'),
                      ('1750000000000', '1750003600000')]
        for dashboard in DASHBOARDS.values():
            for link in dashboard['links']:
                for start, end in raw_ranges:
                    url = link['url'] + '&' + urlencode({'from': start, 'to': end})
                    url = url.replace('${datasource:queryparam}', 'var-datasource=prometheus')
                    url = url.replace('${gvar_oie_hypervisor:queryparam}', 'var-gvar_oie_hypervisor=compute-a')
                    args = parse_qs(urlsplit(url).query)
                    self.assertEqual(args['from'], [start])
                    self.assertEqual(args['to'], [end])
                    self.assertEqual(args['var-datasource'], ['prometheus'])
                    self.assertEqual(args['var-gvar_oie_hypervisor'], ['compute-a'])


class StatusTableFrames(unittest.TestCase):
    def fixture(self, missing=()):
        data = {'A': [], 'B': []}
        # Same displayed hostname with distinct ports/jobs must not collapse.
        for job, endpoint in [('oie', 'compute-a:9120'), ('oie', 'compute-a:9121'),
                              ('other', 'compute-a:9120'), ('oie', 'compute-b:9120')]:
            for ref in data:
                labels = {'__name__': 'conntrack_ok' if ref == 'A' else 'libvirt_ok',
                          'job': job, 'instance': endpoint,
                          'oie_hypervisor': endpoint.split(':')[0], 'source_specific': ref}
                value = float('nan') if (ref, endpoint) in missing else 1
                data[ref].append((labels, value))
        return native_table_frames(data)

    def test_collector_one_row_per_full_exporter_identity(self):
        p = get_panel('hypervisor', 27234)
        self.assertEqual([t['id'] for t in p['transformations']],
                         ['filterFieldsByName', 'merge', 'organize'])
        included = p['transformations'][0]['options']['include']['names']
        self.assertNotIn('__name__', included)
        self.assertNotIn('Time', included)
        self.assertTrue({'job', 'instance'} <= set(included))
        result = apply_table_transforms(p, self.fixture())
        self.assertEqual(len(result), 4)
        self.assertEqual(len({(r['job'], r['Exporter target']) for r in result}), 4)
        for row in result:
            self.assertEqual((row['Conntrack'], row['Libvirt']), (1, 1))

    def test_missing_collector_stays_missing_not_zero_or_success(self):
        p = get_panel('hypervisor', 27234)
        for missing in [(('B', 'compute-b:9120'),),
                        tuple(('B', x) for x in ['compute-a:9120', 'compute-a:9121', 'compute-b:9120'])]:
            result = apply_table_transforms(p, self.fixture(missing))
            self.assertEqual(len(result), 4)
            for row in result:
                self.assertEqual(row['Conntrack'], 1)
                if ('B', row['Exporter target']) in missing:
                    self.assertTrue(math.isnan(row['Libvirt']))
        for target in p['targets']:
            self.assertTrue(target['instant'])
            self.assertFalse(target['range'])
            self.assertIn('or on (job, instance)', target['expr'])
            self.assertIn('* (0 / 0)', target['expr'])
        mappings = props(p, 'Libvirt')['mappings']
        self.assertTrue(any(m['type'] == 'special' and m['options']['match'] == 'nan' and
                            m['options']['result']['text'] == 'Unavailable' for m in mappings))

    def test_single_query_feed_value_name(self):
        p = get_panel('hypervisor', 27264)
        rows = [({'__name__': 'feed', 'job': 'oie', 'instance': 'compute-a:9120',
                  'oie_hypervisor': 'compute-a', 'list': feed}, state)
                for feed, state in [('spamhaus', 1), ('TORRELAY', 0), ('CUSTOMLIST', -1)]]
        result = apply_table_transforms(p, native_table_frames({'A': rows}))
        self.assertEqual(len(result), 3)
        self.assertEqual([r['Feed state'] for r in result], [1, 0, -1])
        self.assertNotIn('Value #A', json.dumps(p['transformations']))

    def test_histories_preserve_samples_not_interpolated_states(self):
        for name, table_id, history_id in HISTORIES:
            table, history = get_panel(name, table_id), get_panel(name, history_id)
            self.assertNotIn('sparkline', json.dumps(table))
            self.assertEqual(history['gridPos']['w'], 24)
            for target in history['targets']:
                self.assertTrue(target['range'])
                self.assertFalse(target['instant'])
                for unwanted in ('topk(', 'avg_over_time(', 'last_over_time('):
                    self.assertNotIn(unwanted, target['expr'])
            if name == 'hypervisor':
                self.assertEqual(history['type'], 'table')
                self.assertEqual(history['gridPos']['h'], 10)
                self.assertFalse(history['options']['enablePagination'])
                self.assertNotIn('perPage', history['options'])
                self.assertNotIn('sparkline', json.dumps(history))
                self.assertEqual([t['id'] for t in history['transformations']],
                                 ['renameByRegex', 'groupBy', 'merge', 'filterFieldsByName', 'organize'])
                state = props(history, 'Observed state')
                self.assertEqual(state['custom.cellOptions']['type'], 'color-text')
                self.assertTrue(state['mappings'])
            else:
                self.assertEqual(history['type'], 'state-timeline')
                self.assertEqual(history['gridPos']['h'], 8)
                self.assertEqual(history['options']['perPage'], 8)
                self.assertTrue(history['options']['mergeValues'])
                self.assertFalse(history['fieldConfig']['defaults']['custom']['spanNulls'])
                # Threshold mode masks the mapped lifecycle states with one
                # meaningless -infinity bucket in Grafana's timeline renderer.
                self.assertNotEqual(history['fieldConfig']['defaults']['color']['mode'], 'thresholds')
                self.assertNotIn('thresholds', history['fieldConfig']['defaults'])
                self.assertTrue(history['fieldConfig']['defaults']['mappings'])
                self.assertFalse(history.get('transformations'))
                reduce = table['transformations'][0]
                self.assertEqual(reduce['options']['reducers'], ['last'])
                self.assertTrue(reduce['options']['labelsToFields'])
                self.assertIn('instance_uuid', history['targets'][0]['legendFormat'])
                self.assertIn('destination_volume_uuid', history['targets'][0]['legendFormat'])

    def test_retype_history_is_operation_progress_plus_terminal_outcomes(self):
        for name, outcome_id, progress_id in [('cluster', 24003, 24303), ('project', 24004, 24304)]:
            progress = get_panel(name, progress_id)
            outcome = get_panel(name, outcome_id)
            self.assertEqual(progress['type'], 'timeseries')
            self.assertEqual(progress['title'], 'Attached-volume retype progress · selected range')
            self.assertEqual(progress['gridPos']['w'], 24)
            self.assertEqual(progress['fieldConfig']['defaults']['min'], 0)
            self.assertEqual(progress['fieldConfig']['defaults']['max'], 100)
            self.assertEqual(progress['fieldConfig']['defaults']['unit'], 'percent')
            self.assertEqual(progress['fieldConfig']['defaults']['custom']['lineStyle']['fill'], 'solid')
            self.assertEqual(len(progress['targets']), 1)
            target = progress['targets'][0]
            self.assertTrue(target['range'])
            self.assertFalse(target['instant'])
            self.assertIn('oie_instance_disk_retype_progress_percent', target['expr'])
            for identity in ('server_name', 'disk_path', 'volume_uuid', 'disk_type', 'destination_disk_type'):
                self.assertIn(identity, target['legendFormat'])

            self.assertEqual(outcome['type'], 'table')
            self.assertEqual(outcome['title'], 'Attached-volume retype outcomes · selected range')
            self.assertEqual(outcome['gridPos']['w'], 24)
            self.assertTrue(outcome['targets'][0]['instant'])
            expr = outcome['targets'][0]['expr']
            for metric in ('oie_instance_disk_retype_status_code',
                           'oie_instance_disk_retype_start_timestamp_seconds',
                           'oie_instance_disk_retype_ready_timestamp_seconds',
                           'oie_instance_disk_retype_end_timestamp_seconds'):
                self.assertIn(metric, expr)
            self.assertIn('last_over_time', expr)
            self.assertIn('Terminal Observed', json.dumps(outcome))
            self.assertIn('Observed Duration', json.dumps(outcome))
            self.assertNotIn('state-timeline', json.dumps(outcome))



class SampledHistoryFrames(unittest.TestCase):
    @staticmethod
    def frames(refs, count=3):
        result = []
        for ref, dimension, states in refs:
            rows = []
            for index in range(count):
                # Equal host display names must never erase distinct targets.
                instance = 'compute-a:' + str(9120 + index)
                for time, state in states:
                    rows.append({'job': 'oie', 'instance': instance, 'oie_hypervisor': 'compute-a',
                                 **dimension, 'Time': time, '__name__': 'raw_' + ref,
                                 ('Value #' + ref if len(refs) > 1 else 'Value'): state})
            result.append(rows)
        return result

    def test_repeated_states_have_first_last_samples_not_fake_intervals(self):
        p = get_panel('hypervisor', 27334)
        data = self.frames([
            ('A', {'oie_collector': 'Conntrack'}, [(0, 1), (30000, 1), (90000, 0), (180000, 1)]),
            ('B', {'oie_collector': 'Libvirt'}, [(0, 1), (30000, 1), (90000, 1), (180000, 1)])])
        rows = apply_table_transforms(p, data)
        self.assertEqual(len(rows), 9)
        selected = [r for r in rows if r['Exporter target'] == 'compute-a:9120']
        success = next(r for r in selected if r['Collector'] == 'Conntrack' and r['Observed state'] == 1)
        failure = next(r for r in selected if r['Observed state'] == 0)
        self.assertEqual((success['First sample'], success['Last sample'], success['Samples']), (0, 180000, 3))
        self.assertEqual((failure['First sample'], failure['Last sample'], failure['Samples']), (90000, 90000, 1))
        self.assertNotIn('Duration', success)
        self.assertIn('not a continuous-state duration', p['description'])
        self.assertIn('not exact transition times', p['description'])

    def test_absent_collector_never_fabricates_success(self):
        p = get_panel('hypervisor', 27334)
        for ref, collector in [('A', 'Conntrack'), ('B', 'Libvirt')]:
            rows = apply_table_transforms(p, self.frames([(ref, {'oie_collector': collector}, [(30000, 0)])]))
            self.assertEqual(len(rows), 3)
            self.assertTrue(all(r['Observed state'] == 0 and r['Samples'] == 1 for r in rows))
            self.assertEqual({r['Collector'] for r in rows}, {collector})
        self.assertEqual(apply_table_transforms(p, []), [])

    def test_jobs_endpoints_and_feeds_remain_independent(self):
        p = get_panel('hypervisor', 27364)
        frames = self.frames([('A', {'list': 'TORRELAY'}, [(0, -1), (15000, 1), (60000, 0)])])
        other_job = [dict(row, job='other') for row in frames[0]]
        other_feed = [dict(row, list='spamhaus') for row in frames[0]]
        frames[0].extend(other_job + other_feed)
        rows = apply_table_transforms(p, frames)
        self.assertEqual(len(rows), 27)
        self.assertEqual({r['Observed state'] for r in rows}, {-1, 0, 1})
        self.assertEqual(len({(r['job'],r['Exporter target'],r['Feed'],r['Observed state']) for r in rows}), 27)
        self.assertEqual(props(p, 'First sample')['unit'], 'dateTimeAsIso')
        self.assertEqual(props(p, 'Last sample')['unit'], 'dateTimeAsIso')
        self.assertTrue(props(p, 'Feed')['mappings'])

    def test_large_inventory_retains_every_target_state_without_top_n(self):
        p = get_panel('hypervisor', 27334)
        refs = [(ref, {'oie_collector': collector}, [(n * 15000, n % 2) for n in range(60)])
                for ref, collector in [('A', 'Conntrack'), ('B', 'Libvirt')]]
        rows = apply_table_transforms(p, self.frames(refs, count=200))
        self.assertEqual(len(rows), 800)
        self.assertTrue(all(r['Samples'] == 30 for r in rows))

    def test_queries_only_add_the_collector_dimension(self):
        p = get_panel('hypervisor', 27334)
        for ref, collector in [('A', 'Conntrack'), ('B', 'Libvirt')]:
            target = next(t for t in p['targets'] if t['refId'] == ref)
            self.assertTrue(target['expr'].startswith('label_replace(('))
            self.assertTrue(target['expr'].endswith(f'"oie_collector", "{collector}", "job", ".*")'))
            self.assertIn('and on (job, instance)', target['expr'])
            self.assertEqual(target['format'], 'table')


class ColourContracts(unittest.TestCase):
    def test_read_write_and_rx_tx_have_contrasting_fixed_colours(self):
        for pid, (primary, secondary) in PAIRS.items():
            p = get_panel('cluster', pid)
            d = p['fieldConfig']['defaults']
            self.assertEqual(d['custom']['gradientMode'], 'opacity')
            self.assertEqual(props(p, primary)['color'], {'mode': 'fixed', 'fixedColor': '#4DA6FF'})
            self.assertEqual(props(p, secondary)['color'], {'mode': 'fixed', 'fixedColor': '#FF9F43'})
            self.assertEqual(props(p, primary)['custom.lineStyle']['fill'], 'solid')
            self.assertEqual(props(p, secondary)['custom.lineStyle']['fill'], 'solid')
            self.assertNotIn('max', d)
            self.assertNotIn('axisSoftMax', d['custom'])
            self.assertNotIn('activity intensity', p['description'])

    def test_severity_gradient_is_only_on_single_fleet_utilization(self):
        actual = set()
        for name, dashboard in DASHBOARDS.items():
            for p in panels(dashboard['panels']):
                if p['type'] != 'timeseries':
                    continue
                d = p['fieldConfig']['defaults']
                self.assertFalse(d['color']['mode'].startswith('continuous-'), (name, p['id']))
                if d['custom'].get('gradientMode') == 'scheme':
                    actual.add((name, p['id']))
                for override in p['fieldConfig']['overrides']:
                    self.assertFalse(any(x['id'] == 'custom.gradientMode' and x['value'] == 'scheme'
                                         for x in override['properties']), (name, p['id']))
        self.assertEqual(actual, FIXED)
        d = get_panel('cluster', 1269)['fieldConfig']['defaults']
        self.assertEqual((d['min'], d['max']), (0, 100))
        self.assertEqual([s['value'] for s in d['thresholds']['steps']], [None, 80, 90])

    def test_multi_entity_comparisons_keep_name_based_identity(self):
        for name, dashboard in DASHBOARDS.items():
            for p in panels(dashboard['panels']):
                if p['type'] != 'timeseries':
                    continue
                dynamic = {t['refId'] for t in p.get('targets', []) if '{{' in t.get('legendFormat', '')}
                if not dynamic:
                    continue
                self.assertEqual(p['fieldConfig']['defaults']['color']['mode'], 'palette-classic-by-name',
                                 (name, p['id']))
                self.assertIn(p['fieldConfig']['defaults']['custom'].get('gradientMode'), ('none', 'opacity'))
                for override in p['fieldConfig']['overrides']:
                    matcher = override['matcher']
                    if matcher['id'] == 'byFrameRefID' and matcher['options'] in dynamic:
                        self.assertFalse(any(prop['id'] == 'color' for prop in override['properties']),
                                         (name, p['id'], matcher))

    def test_small_reference_graphs_do_not_reuse_one_colour(self):
        for pid in (1239,1263,1264,25151,1254,20001):
            p = get_panel('cluster', pid)
            colours = [props(p, t['legendFormat'])['color']['fixedColor'] for t in p['targets']]
            self.assertEqual(len(colours), len(set(colours)), pid)
            self.assertIn(p['fieldConfig']['defaults']['custom']['gradientMode'], ('none', 'opacity'))
        self.assertNotIn('thresholds', props(get_panel('cluster', 1263), 'Host Memory Available %'))


if __name__ == '__main__':
    unittest.main()
