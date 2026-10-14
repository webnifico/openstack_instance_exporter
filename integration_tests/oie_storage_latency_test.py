#!/usr/bin/env python3
"""Evaluate the shipped storage overview queries with promtool."""
import copy
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

from oie_dashboards_test import DASHBOARDS, DISK, HOST, VM, get_panel, interpolate, series


def source(host=None, **values):
    host = host or HOST
    defaults = {'up': 1, 'oie_host_libvirt_ok': 1, 'oie_host_libvirt_stale_seconds': 0,
                'oie_host_collection_interval_seconds': 15}
    return [series(metric, f'{value}+0x20', host) for metric, value in (defaults | values).items()]


def disk(labels=None, read=(10, 10), write=(20, 20), flush=(2, 5), state=1):
    """Direction tuples are operations/second and milliseconds/operation."""
    labels = labels or DISK
    vm = {key: value for key, value in labels.items() if key not in ['volume_uuid', 'disk_path', 'disk_type']}
    data = [series('oie_instance_state_code', f'{state}+0x20', vm),
            series('oie_instance_disk_info', '1+0x20', labels)]
    for direction, measurement in [('read', read), ('write', write), ('flush', flush)]:
        if measurement is None:
            continue
        iops, milliseconds = measurement
        data += [series(f'oie_instance_disk_{direction}_requests_total', f'0+{iops * 15}x20', labels),
                 series(f'oie_instance_disk_{direction}_seconds_total', f'0+{iops * milliseconds * 15 / 1000}x20', labels)]
    return data


def unique(data):
    result = {}
    for entry in data:
        if entry['series'] in result:
            assert result[entry['series']] == entry
        result[entry['series']] = entry
    return list(result.values())


def change(data, metric, values=None):
    for item in data[:]:
        if item['series'].startswith(metric + '{'):
            if values is None:
                data.remove(item)
            else:
                item['values'] = values


def expect(expr, value=None):
    # promtool 2.45 compares floats exactly. Ignore sub-nanosecond rounding in
    # displayed millisecond means without changing any dashboard expression.
    if value is not None:
        expr = f'round(({expr}), 1 / 1048576)'
    return {'expr': expr, 'eval_time': '5m',
            'exp_samples': [] if value is None else [{'labels': '{}', 'value': value}]}


class StorageOverview(unittest.TestCase):
    def test_layout_and_table_fields(self):
        for name in ['cluster', 'project', 'hypervisor']:
            dashboard = DASHBOARDS[name]
            visible = dashboard['panels']
            for left_index, left in enumerate(visible):
                a = left['gridPos']
                for right in visible[left_index + 1:]:
                    b = right['gridPos']
                    overlap = (a['x'] < b['x'] + b['w'] and b['x'] < a['x'] + a['w'] and
                               a['y'] < b['y'] + b['h'] and b['y'] < a['y'] + a['h'])
                    self.assertFalse(overlap, (name, left['id'], right['id']))
            for pid in [26002, 26003, 26004]:
                panel = get_panel(name, pid)
                self.assertEqual(panel['fieldConfig']['defaults']['unit'], 'ms')
                self.assertFalse(panel['fieldConfig']['defaults']['custom']['spanNulls'])
                self.assertNotIn('topk(', panel['targets'][0]['expr'])
            table = get_panel(name, 26005)
            self.assertTrue(table['targets'][0]['instant'])
            transform = table['transformations'][-1]['options']
            self.assertEqual(len(transform['indexByName']), {'cluster': 9, 'project': 11, 'hypervisor': 10}[name])
            for direction in ['read', 'write', 'flush']:
                override = next(item for item in table['fieldConfig']['overrides']
                                if item['matcher']['options'] == direction.title() + ' latency')
                properties = {item['id']: item['value'] for item in override['properties']}
                self.assertEqual(properties['noValue'], 'Unavailable')
                values = next(item['options'] for item in properties['mappings'] if item['type'] == 'value')
                self.assertEqual(values['-2']['text'], f'No {direction} I/O in 5m')
                self.assertEqual(values['-1']['text'], 'Unavailable')
            for pid in range(26001, 26006):
                for target in get_panel(name, pid)['targets']:
                    self.assertNotIn('oie:', target['expr'], 'Grafana overview must not need recording rules')
                    self.assertNotIn('disk_type=', target['expr'], 'Storage sources must be discovered')

    def test_actual_queries(self):
        records = {}
        cases = []

        def q(name, pid, ref='A', replacements=None):
            target = next(t for t in get_panel(name, pid)['targets'] if t['refId'] == ref)
            expr = interpolate(target['expr'], replacements)
            key = (name, pid, ref, expr)
            if key not in records:
                records[key] = {'record': f'oie_storage_test_{len(records)}', 'expr': expr}
            return records[key]['record']

        def graph(direction='read', name='cluster', replacements=None):
            return q(name, {'read': 26002, 'write': 26003, 'flush': 26004}[direction], replacements=replacements)

        def cell(column, name='cluster', labels=''):
            return 'sum(' + q(name, 26005) + '{oie_column="' + column + '"' + labels + '})'

        def case(name, data, checks):
            cases.append({'name': name, 'interval': '15s', 'input_series': unique(data), 'promql_expr_test': checks})

        def unavailable_checks():
            return [expect('sum(' + graph(direction, name) + ')')
                    for name in ['cluster', 'project', 'hypervisor'] for direction in ['read', 'write', 'flush']] + [
                expect(cell(direction + '_ms', name), -1)
                for name in ['cluster', 'project', 'hypervisor'] for direction in ['read', 'write', 'flush']] + [
                expect(cell('iops')), expect(cell('known'), 1),
                expect(cell('read_measured'), 0), expect(cell('write_measured'), 0), expect(cell('flush_measured'), 0)]

        base = source() + disk()
        checks = []
        for name in ['cluster', 'project', 'hypervisor']:
            for direction, latency in [('read', 10), ('write', 20), ('flush', 5)]:
                checks += [expect('sum(' + graph(direction, name) + ')', latency),
                           expect(cell(direction + '_ms', name), latency),
                           expect(cell(direction + '_measured', name), 1)]
            checks += [expect(cell('iops', name), 30), expect(cell('known', name), 1),
                       expect('sum(' + q(name, 26001) + ')', 1), expect('sum(' + q(name, 26001, 'B') + ')', 1)]
        case('all overview directions and coverage fields evaluate the actual JSON', base, checks)

        second = DISK | {'volume_uuid': 'volume-second', 'disk_path': 'vdb'}
        weighted = source() + disk() + disk(second, read=(30, 30), write=(10, 50), flush=(6, 15))
        case('unequal IOPS uses weighted latency, not mean of disk means', weighted, [
            expect('sum(' + graph() + ')', 25), expect('sum(' + graph('write') + ')', 30),
            expect('sum(' + graph('flush') + ')', 12.5), expect(cell('iops'), 70),
            expect(cell('known'), 2), expect(cell('read_measured'), 2)])

        new_type = DISK | {'disk_type': 'pool.unlisted-nvme', 'disk_path': 'vdc', 'volume_uuid': 'new-disk'}
        local = DISK | {'disk_type': 'local', 'disk_path': 'vdd', 'volume_uuid': '/srv/disks/root.qcow2'}
        case('arbitrary pool labels and file-backed sources are separate discovered groups', base + disk(new_type, read=(2, 2)) + disk(local, read=(5, 4)), [
            expect('sum(' + graph() + '{disk_type="pool.unlisted-nvme"})', 2),
            expect('sum(' + graph() + '{disk_type="local"})', 4), expect('count(' + graph() + ')', 3),
            expect('count(' + q('cluster', 26005) + '{oie_column="known"})', 3)])

        for direction in ['read', 'write', 'flush']:
            for missing in ['seconds_total', 'requests_total']:
                partial = disk(second, read=(30, 90), write=(10, 90), flush=(6, 90))
                change(partial, f'oie_instance_disk_{direction}_{missing}')
                expected = {'read': 10, 'write': 20, 'flush': 5}[direction]
                case(f'{direction} missing {missing} cannot dilute the measured cohort', base + partial, [
                    expect('sum(' + graph(direction) + ')', expected), expect(cell(direction + '_ms'), expected),
                    expect(cell(direction + '_measured'), 1), expect(cell('known'), 2)])

        mismatch = disk(second, read=(30, 90))
        change(mismatch, 'oie_instance_disk_read_seconds_total', '0+40.5x8 _ 405+40.5x10')
        case('mismatched time and operation sample counts exclude both sides', base + mismatch, [
            expect('sum(' + graph() + ')', 10), expect(cell('known'), 2), expect(cell('read_measured'), 1)])

        for suffix in ['seconds_total', 'requests_total']:
            data = source() + disk()
            change(data, 'oie_instance_disk_read_' + suffix, '0+15x19 stale')
            case('historical ' + suffix + ' alone is not current timing evidence', data, [
                expect('sum(' + graph() + ')'), expect(cell('read_ms'), -1), expect(cell('read_measured'), 0)])

        case('measured idle disks have zero IOPS but no latency observations', source() + disk(read=(0, 0), write=(0, 0), flush=(0, 0)), [
            expect('sum(' + graph(direction, name) + ')')
            for name in ['cluster', 'project', 'hypervisor'] for direction in ['read', 'write', 'flush']] + [
            expect(cell(direction + '_ms', name), -2)
            for name in ['cluster', 'project', 'hypervisor'] for direction in ['read', 'write', 'flush']] + [
            expect(cell('iops'), 0), expect(cell('known'), 1),
            expect(cell('read_measured'), 1), expect(cell('write_measured'), 1), expect(cell('flush_measured'), 1)])

        # Reproduce the disappearing-column case: no selected source has a
        # read observation, but each still needs an explicit Read latency field.
        labels = [DISK, new_type, local]
        read_idle = source() + [entry for label in labels for entry in disk(label, read=(0, 0))]
        checks = []
        for name in ['cluster', 'project', 'hypervisor']:
            checks.append(expect('sum(' + graph(name=name) + ')'))
            for direction, value in [('read', -2), ('write', 20), ('flush', 5)]:
                checks.append(expect('count(' + q(name, 26005) + '{oie_column="' + direction + '_ms"})', 3))
                for label in labels:
                    selector = ',disk_type="' + label['disk_type'] + '"'
                    checks += [expect(cell(direction + '_ms', name, selector), value),
                               expect(cell(direction + '_measured', name, selector), 1)]
        case('all read-idle sources retain Read latency while writes and flushes are active', read_idle, checks)

        mixed = source() + disk() + disk(new_type, read=(0, 0), write=(0, 0), flush=(0, 0)) + disk(local, read=None, write=None, flush=None)
        checks = []
        for name in ['cluster', 'project', 'hypervisor']:
            for direction, latency in [('read', 10), ('write', 20), ('flush', 5)]:
                checks += [expect('sum(' + graph(direction, name) + ')', latency),
                           expect('count(' + q(name, 26005) + '{oie_column="' + direction + '_ms"})', 3)]
                for label, value in [(DISK, latency), (new_type, -2), (local, -1)]:
                    selector = ',disk_type="' + label['disk_type'] + '"'
                    checks.append(expect(cell(direction + '_ms', name, selector), value))
        case('active idle and unavailable sources retain distinct latency cells', mixed, checks)

        for metric, value in [('up', 0), ('oie_host_libvirt_ok', 0), ('oie_host_libvirt_stale_seconds', 90),
                              ('oie_host_libvirt_stale_seconds', -1)]:
            case(f'unhealthy source {metric}={value} preserves inventory and exposes missing coverage', source(**{metric: value}) + disk(),
                 unavailable_checks() + [expect('sum(' + q('cluster', 26001) + ')', 0), expect('sum(' + q('cluster', 26001, 'B') + ')', 1)])
        for metric in ['oie_host_libvirt_stale_seconds', 'oie_host_collection_interval_seconds']:
            data = copy.deepcopy(base)
            change(data, metric)
            case('missing health metric ' + metric + ' does not look fresh', data, unavailable_checks())

        no_counters = source() + disk(read=None, write=None, flush=None)
        case('known disk without counters has unavailable measurements', no_counters, unavailable_checks())
        one_sample = copy.deepcopy(base)
        for entry in one_sample:
            if '_total{' in entry['series']:
                entry['values'] = '_x20 10'
        case('new disk requires at least two counter samples', one_sample, unavailable_checks())

        data = source() + disk(state=5)
        case('powered-off disks are excluded from the running workload overview', data, [
            expect('sum(' + graph() + ')'), expect('count(' + q('cluster', 26005) + ')')])

        reset = copy.deepcopy(base)
        change(reset, 'oie_instance_disk_read_requests_total', '0+150x9 0+150x10')
        change(reset, 'oie_instance_disk_read_seconds_total', '0+1.5x9 0+1.5x10')
        case('counter resets preserve the time per operation ratio', reset, [
            expect('sum(' + graph() + ')', 10), expect(cell('read_measured'), 1)])

        retyped = DISK | {'disk_type': 'pool-after-retype'}
        old_data = disk()
        for entry in old_data:
            if 'disk_' in entry['series']:
                start, _, step = entry['values'].partition('+')
                entry['values'] = start + '+' + step.split('x')[0] + 'x9 stale _x10'
        new_data = disk(retyped, read=(30, 30))
        for entry in new_data:
            if 'disk_' in entry['series']:
                entry['values'] = '_x10 ' + entry['values'].replace('x20', 'x10')
        case('retype discovers the new pool and excludes the former attachment history', source() + old_data + new_data, [
            expect('sum(' + graph() + '{disk_type="volumes"})'),
            expect('sum(' + graph() + '{disk_type="pool-after-retype"})', 30),
            expect('count(' + q('cluster', 26005) + '{oie_column="known"})', 1),
            expect(cell('read_measured'), 1)])

        other = DISK | {'instance': 'compute-b:9120', 'project_uuid': 'project-b', 'instance_uuid': 'vm-b', 'domain': 'instance-0002'}
        other_host = HOST | {'instance': other['instance']}
        scoped = base + source(other_host) + disk(other, read=(30, 30))
        case('project UUIDs and hypervisor targets remain distinct despite duplicate names', scoped, [
            expect('sum(' + graph() + ')', 25), expect('count(' + graph(name='project') + ')', 2),
            expect('sum(' + graph(name='project') + '{project_uuid="project-a"})', 10),
            expect('sum(' + graph(name='project') + '{project_uuid="project-b"})', 30),
            expect('count(' + graph(name='hypervisor') + ')', 2),
            expect('sum(' + graph(name='hypervisor') + '{instance="compute-b:9120"})', 30),
            expect('count(' + q('project', 26005) + '{oie_column="known"})', 2)])
        for variable, selected in [('$gvar_oie_project_uuid', 'project-a'), ('$gvar_oie_instance_uuid', VM['instance_uuid']),
                                   ('${gvar_oie_hypervisor}', 'compute-a')]:
            for name in ['cluster', 'project']:
                case(name + ' selector ' + variable + ' constrains all overview measurements', scoped, [
                    expect('sum(' + graph(name=name, replacements={variable: selected}) + ')', 10),
                    expect('sum(' + q(name, 26005, replacements={variable: selected}) + '{oie_column="known"})', 1)])
        case('hypervisor selector keeps its exact target', scoped, [
            expect('sum(' + graph(name='hypervisor', replacements={'${gvar_oie_hypervisor}': 'compute-b'}) + ')', 30)])
        case('unmatched selection is unavailable, not healthy zero', scoped, [
            expect('sum(' + graph(replacements={'${gvar_oie_hypervisor}': 'missing-host'}) + ')'),
            expect('sum(' + q('cluster', 26001, replacements={'${gvar_oie_hypervisor}': 'missing-host'}) + ')')])

        case('one failed target keeps healthy observations but lowers measurement coverage', base + source(other_host, up=0) + disk(other), [
            expect('sum(' + graph() + ')', 10), expect(cell('known'), 2), expect(cell('read_measured'), 1),
            expect('sum(' + q('cluster', 26001) + ')', 1), expect('sum(' + q('cluster', 26001, 'B') + ')', 2)])

        unrelated = DISK | {'job': 'another-exporter'}
        case('other scrape jobs cannot add workload or coverage', base + source(HOST | {'job': 'another-exporter'}) + disk(unrelated, read=(100, 1000)), [
            expect('sum(' + graph() + ')', 10), expect(cell('known'), 1), expect('sum(' + q('cluster', 26001, 'B') + ')', 1)])
        case('no targets or inventory leaves an empty overview', [], [
            expect('sum(' + graph() + ')'), expect('count(' + q('cluster', 26005) + ')'),
            expect('sum(' + q('cluster', 26001) + ')'), expect('sum(' + q('cluster', 26001, 'B') + ')')])

        with tempfile.TemporaryDirectory(prefix='oie-storage-overview-') as temp:
            rules = Path(temp) / 'rules.yml'
            rules.write_text(yaml.safe_dump({'groups': [{'name': 'storage', 'rules': list(records.values())}]}, sort_keys=False))
            tests = Path(temp) / 'tests.yml'
            # Records only wrap independent dashboard queries. Evaluate at the
            # asserted range end; input counters still have 15-second samples.
            tests.write_text(yaml.safe_dump({'rule_files': [str(rules)], 'evaluation_interval': '5m', 'tests': cases}, sort_keys=False))
            result = subprocess.run([os.environ.get('PROMTOOL', 'promtool'), 'test', 'rules', str(tests)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        print(f'Validated {len(cases)} storage aggregation, discovery, scope and missing-data scenarios using {len(records)} shipped/interpolated queries.')


if __name__ == '__main__':
    unittest.main()
