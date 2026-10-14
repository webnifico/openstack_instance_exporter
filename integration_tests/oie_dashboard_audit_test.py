#!/usr/bin/env python3
"""Regress current-source, cohort, ranking and missing-field dashboard semantics.

Every recording rule comes from the shipped dashboard JSON. Set PROMTOOL to
the native executable; fixtures describe exporter observations, not queries.
"""
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

from oie_dashboards_test import DISK, HOST, VM, get_panel, interpolate, series
from oie_dashboard_empty_hosts_test import host, workload
from oie_dashboard_overview_test import feed, source, vm
from oie_storage_latency_test import disk, unique


class Matrix:
    def __init__(self):
        self.records = {}
        self.cases = []

    def query(self, name, panel_id, ref='A', replacements=None):
        expr = self.expression(name, panel_id, ref, replacements)
        key = (name, panel_id, ref, expr)
        if key not in self.records:
            self.records[key] = {'record': f'oie_audit_{len(self.records)}', 'expr': expr}
        return self.records[key]['record']

    @staticmethod
    def expression(name, panel_id, ref='A', replacements=None):
        target = next(t for t in get_panel(name, panel_id)['targets'] if t['refId'] == ref)
        return interpolate(target['expr'], replacements)

    @staticmethod
    def expect(expr, value=None, at='2m'):
        if value is not None:
            expr = 'round((' + expr + '), 0.000001)'
        return {'expr': expr, 'eval_time': at,
                'exp_samples': [] if value is None else [{'labels': '{}', 'value': value}]}

    def value(self, name, panel_id, value=None, ref='A', at='2m', replacements=None):
        return self.expect('sum(' + self.query(name, panel_id, ref, replacements) + ')', value, at)

    def nan(self, query, count=1, at='2m'):
        # Presence and NaN are separate assertions: an absent column is not unknown.
        return [self.expect('count(' + query + ')', count, at),
                self.expect('count(' + query + ' != ' + query + ')', count, at)]

    def add(self, name, data, checks):
        self.cases.append({'name': name, 'interval': '15s',
                           'input_series': unique(data), 'promql_expr_test': checks})


def cluster_cases(m):
    observed = host('compute-busy', active=1) + workload()
    complete = observed + [series('oie_host_mem_available_mib', '4096+0x8',
                                 {'job': HOST['job'], 'instance': 'compute-busy:9120'})]
    missing_vm = {'job': HOST['job'], 'instance': 'compute-busy:9120',
                  'domain': 'instance-2', 'instance_uuid': 'missing-vm',
                  'project_uuid': 'project-1', 'user_uuid': 'user-1', 'libvirt_active': '1'}
    missing = complete + [series('oie_instance_inventory_info', '1+0x8', missing_vm)]
    current = [(1239, 'A', 25), (1239, 'B', 10), (1263, 'A', 12.5),
               (1263, 'B', 25), (1263, 'D', 25), (1264, 'A', 1024 * 2**20)]
    m.add('Cluster known VM missing both CPU/RAM dimensions and usage is incomplete', missing,
          [m.value('cluster', pid, ref=ref) for pid, ref, _ in current] +
          [m.value('cluster', 1263, 50, 'C'), m.value('cluster', 1264, 4096 * 2**20, 'D')])
    m.add('Cluster complete cohort preserves measurements and units', complete,
          [m.value('cluster', pid, value, ref) for pid, ref, value in current] +
          [m.value('cluster', 1238, 10), m.value('cluster', 1238, 20, 'B'),
           m.value('cluster', 1240, 10), m.value('cluster', 1237, 2**30)])
    m.add('Cluster complete fleet rates cannot hide a failed selected target',
          observed + host('compute-down', up=0),
          [m.value('cluster', pid, ref=ref) for pid in [1237, 1238, 1256, 1241, 1240]
           for ref in ['A', 'B']])
    retained = source(oie_host_libvirt_ok=0, oie_host_conntrack_raw_ok=0,
                      oie_host_conntrack_stale_seconds=300) + [
        series('oie_instance_info', '1+0x20', VM),
        series('oie_instance_conntrack_ip_flows', '100+0x20', VM),
        series('oie_instance_cpu_vcpu_count', '4+0x20', VM),
        series('oie_instance_disk_read_requests_total', '1000+0x20', DISK),
        series('oie_instance_net_rx_packets_total', '1000+0x20', VM | {'ifname': 'tap1'})]
    m.add('Cluster cached failed sources are gaps while configured vCPUs remain', retained,
          [m.value('cluster', pid) for pid in [1238, 1240, 1254]] +
          [m.value('cluster', 1244, 4)])
    for ok, age in [(0, 0), (1, 61), (1, -1), (1, 0)]:
        data = source(oie_host_conntrack_raw_ok=ok, oie_host_conntrack_stale_seconds=age) + [
            series('oie_host_conntrack_entries', '100+0x20', HOST),
            series('oie_host_conntrack_max', '400+0x20', HOST),
            series('oie_instance_conntrack_ip_flows', '100+0x20', VM)]
        valid = ok == 1 and age == 0
        m.add(f'Cluster conntrack raw_ok={ok} age={age} uses actual source health', data,
              [m.value('cluster', 1254, 100 if valid else None),
               m.value('cluster', 20001, 100 if valid else None),
               m.value('cluster', 20001, 400, 'B'),
               m.value('cluster', 1269, 25 if valid else None)])


def hypervisor_cases(m):
    ident = {'job': HOST['job'], 'instance': 'compute-busy:9120', 'domain': 'instance-2',
             'instance_uuid': 'missing-vm', 'project_uuid': 'project-1', 'user_uuid': 'user-1'}
    incomplete = host('compute-busy', active=2) + workload() + [
        series('oie_instance_inventory_info', '1+0x8', ident | {'libvirt_active': '1'})]
    ids = [1212, 1214, 1233, 1235, 1245, 1269, 1270, 1271, 1308]
    m.add('Hypervisor known VM missing both dimensions and usage stays NaN', incomplete,
          [check for pid in ids for check in m.nan(m.query('hypervisor', pid))])
    m.add('Hypervisor usage without matching allocation cannot inflate RAM ratio',
          incomplete + [series('oie_instance_mem_used_mib', '1024+0x8', ident)],
          m.nan(m.query('hypervisor', 1270)))
    partial = [s for s in workload() if not s['series'].startswith('oie_instance_cpu_steal_seconds_total{')]
    partial += [series('oie_instance_cpu_steal_seconds_total', '0+0.3x8',
                       ident | {'domain': 'instance-1', 'instance_uuid': 'compute-busy-vm', 'vcpu': '0'})]
    m.add('Hypervisor incomplete vCPU scheduler cohort is NaN',
          host('compute-busy', active=1) + partial, m.nan(m.query('hypervisor', 1305)))
    good = [s for s in workload() if not s['series'].startswith('oie_instance_cpu_steal_seconds_total{')]
    cpu = ident | {'domain': 'instance-1', 'instance_uuid': 'compute-busy-vm'}
    good += [series('oie_instance_cpu_steal_seconds_total', '0+0.075x8', cpu | {'vcpu': str(v)})
             for v in range(4)]
    values = {1212: 4, 1214: 4096 * 2**20, 1233: 50, 1235: 50, 1245: 25,
              1269: 12.5, 1270: 25, 1271: 1024 * 2**20, 1308: 4096, 1305: 20}
    m.add('Hypervisor complete CPU/RAM and scheduler cohorts retain denominators',
          host('compute-busy', active=1) + good,
          [m.value('hypervisor', pid, value) for pid, value in values.items()])
    m.add('Hypervisor healthy empty inventory is explicit zero', host('compute-empty'),
          [m.value('hypervisor', 27200, 0, 'B'), m.value('hypervisor', 27200, 0, 'C'),
           m.value('hypervisor', 25012, 0), m.value('hypervisor', 1308, 8192)])
    m.add('Hypervisor failed selected source cannot establish healthy empty inventory',
          host('compute-empty') + host('compute-down', up=0),
          [m.value('hypervisor', 27200, ref='B'), m.value('hypervisor', 27200, ref='C'),
           m.value('hypervisor', 25012, -1), m.value('hypervisor', 25013, -1)])
    m.add('Hypervisor known host remains visible without physical node telemetry',
          host('compute-empty'), [check for pid in [2001, 2002, 2003, 4002, 2004, 4001]
                                  for check in m.nan(m.query('hypervisor', pid))])
    m.add('Hypervisor receive drop counters survive missing transmit companions',
          host('compute-busy', active=1) +
          [s for s in good if not s['series'].startswith('oie_instance_net_tx_dropped_total{')],
          [m.value('hypervisor', 4010, 0.4)])


def project_cases(m):
    at = '5m'
    def value(pid, value=None, ref='A', replacements=None):
        return m.value('project', pid, value, ref, at, replacements)
    m.add('Project write latency survives idle read companion',
          source() + disk(read=(0, 0), write=(20, 20)), [value(1305), value(1305, 0.02, 'B')])
    m.add('Project write IOPS survives absent optional flush companion',
          source() + disk(flush=None), [value(1307, 20, 'B')])
    tor = source() + feed('tor_relay') + vm(feeds=('tor_relay',), active=(7, 0))
    m.add('Project Tor flows and contacts survive absent Spamhaus companions', tor,
          [value(1407, 7, 'C'), value(1408, 120, 'C')])
    m.add('Project unusable feed excludes retained threat activity',
          source() + feed('tor_relay', state=0) + vm(feeds=('tor_relay',), active=(7, 0)),
          [value(1407, ref='C')])
    second_disk = DISK | {'instance_uuid': 'vm-second', 'domain': 'instance-0002',
                          'project_uuid': 'project-b'}
    top = {'${gvar_oie_top_projects}': '1'}
    m.add('Project Top1 ranks write-only projects by their actual write latency',
          source() + disk(read=(0, 0), write=(20, 20)) +
          disk(second_disk, read=(0, 0), write=(20, 50)),
          [value(1305, 0.05, 'B', top),
           m.expect('count(' + m.query('project', 1305, 'B', top) + ')', 1, at)])
    other = VM | {'instance_uuid': 'vm-second', 'domain': 'instance-0002'}
    inventory = [series('oie_instance_inventory_info', '1+0x20',
                        x | {'libvirt_active': '1', 'state_desc': 'running'}) for x in [VM, other]]
    current = source() + inventory + [series('oie_instance_cpu_vcpu_count', '4+0x20', VM),
        series('oie_instance_cpu_vcpu_percent', '25+0x20', VM),
        series('oie_instance_mem_allocated_mib', '1024+0x20', VM),
        series('oie_instance_mem_used_mib', '512+0x20', VM)]
    m.add('Project known VM missing CPU/RAM dimensions and usage is incomplete', current,
          [value(pid) for pid in [1271, 1270, 1309]])
    m.add('Project unmatched used RAM is excluded from complete efficiency totals',
          current + [series('oie_instance_mem_used_mib', '256+0x20', other)],
          [value(pid) for pid in [1270, 1309]])
    complete = current + [series('oie_instance_cpu_vcpu_count', '2+0x20', other),
        series('oie_instance_cpu_vcpu_percent', '100+0x20', other),
        series('oie_instance_mem_allocated_mib', '1024+0x20', other),
        series('oie_instance_mem_used_mib', '256+0x20', other)]
    m.add('Project complete cohorts preserve weighted CPU and matched RAM denominators',
          complete, [value(1271, 50), value(1270, 37.5), value(1309, 1342177280)])
    m.add('Project source failure preserves documented configured allocation',
          source(oie_host_libvirt_ok=0) + [series('oie_instance_cpu_vcpu_count', '2+0x20', VM)],
          [value(1215, 2)])
    m.add('Project stopped VM preserves legitimate rate-window history',
          source() + [series('oie_instance_disk_read_requests_total', '0+15x18 stale _x1', DISK)],
          [m.expect('count(' + m.query('project', 1202) + ')', 1, at)])
    other_host = HOST | {'instance': 'compute-b:9120'}
    other_vm = VM | other_host | {'instance_uuid': 'failed-vm', 'domain': 'instance-0002'}
    other_disk = DISK | other_vm
    m.add('Project qualified activity keeps usable subset and excludes failed source',
          source() + source(other_host, oie_host_libvirt_ok=0, oie_host_conntrack_raw_ok=0) +
          disk(read=(20, 10)) + disk(other_disk, read=(100, 10)) +
          [series('oie_instance_conntrack_ip_flows', '10+0x20', VM),
           series('oie_instance_conntrack_ip_flows', '100+0x20', other_vm)],
          [value(1202, 20), value(1206, 10)])


def instance_cases(m):
    base = source() + [series('oie_instance_info', '1+0x20', VM),
        series('oie_instance_state_code', '1+0x20', VM),
        series('oie_instance_mem_used_mib', '512+0x20', VM),
        series('oie_instance_mem_allocated_mib', '1024+0x20', VM),
        series('oie_instance_cpu_vcpu_percent', '25+0x20', VM)]
    for data, title in [(base, 'healthy selected VM'),
                        (base + [series('up', '0+0x20', HOST | {'instance': 'unrelated:9120'})],
                         'healthy VM with unrelated failed target')]:
        m.add('Instance RAM percentage remains local to ' + title, data,
              [m.value('instance', 2023, 50, at='5m')])
    stale = [dict(s, values='0+0x20') if s['series'].startswith('oie_host_libvirt_ok{') else s
             for s in base]
    stale += [series('oie_instance_disk_read_gib_total', '100+0x20', DISK),
              series('oie_instance_mem_minor_faults_total', '100+0x20', VM)]
    m.add('Instance retained failed-source CPU RAM and counters remain gaps', stale,
          [m.value('instance', pid, at='5m') for pid in [2021, 2031, 2072, 2024, 2074]])
    m.add('Instance write latency survives absent read companions', base +
          [series('oie_instance_disk_write_seconds_total', '0+0.3x20', DISK),
           series('oie_instance_disk_write_requests_total', '0+15x20', DISK)],
          [m.value('instance', 2074, 20, 'B', at='5m')])
    m.add('Instance Tor observations survive absent Spamhaus companions', base +
          [series('oie_instance_threat_tor_exit_active_flows', '2+0x20',
                  VM | {'direction': 'outbound', 'ip': '192.0.2.1', 'family': '4'})],
          [m.value('instance', 2083, 2, at='5m')])
    counters = [series('oie_instance_cpu_steal_seconds_total', '0+15x20', VM | {'vcpu': '0'})]
    scheduler = base + [series('oie_instance_cpu_vcpu_count', '2+0x20', VM)]
    m.add('Instance partial scheduler cohort leaves a gap', scheduler + counters,
          [m.value('instance', 2024, at='5m')])
    m.add('Instance complete scheduler cohort preserves total wait milliseconds',
          scheduler + counters +
          [series('oie_instance_cpu_steal_seconds_total', '0+15x20', VM | {'vcpu': '1'})],
          [m.value('instance', 2024, 2000, at='5m')])
    long_base = [dict(s, values=s['values'].replace('x20', 'x48')) for s in scheduler]
    def counter(kind, vcpu, values):
        return series('oie_instance_cpu_' + kind + '_seconds_total', values,
                      VM | {'vcpu': str(vcpu)})
    delay = counter('steal', 0, '0+15x48')
    other_delay = counter('steal', 1, '0+30x48')
    scenarios = [
        ('preferred delay and per-vCPU wait fallback',
         [delay, counter('wait', 0, '0+150x48'), counter('wait', 1, '0+30x48')], 3000, '10m'),
        ('missing current counter despite retained rate history',
         [delay, counter('steal', 1, '0+30x36 stale _x11')], None, '10m'),
        ('excess counters cannot masquerade as a complete cohort',
         [delay, other_delay, counter('wait', 2, '0+45x48')], None, '10m'),
        ('complete idle counters remain measured zero',
         [counter('steal', 0, '0+0x48'), counter('wait', 1, '0+0x48')], 0, '10m'),
        ('complete cohort preserves rolling rate tail',
         [counter('steal', 0, '0+15x20 300+0x27'),
          counter('wait', 1, '0+30x20 600+0x27')], 2625, '5m45s'),
        ('counter resets still use reset-aware rate semantics',
         [delay, counter('wait', 1, '0+30x20 0+30x27')], 2900, '10m')]
    for title, counters, value, at in scenarios:
        # Compare the rolling tail with the independent raw counter rates. This
        # retains the timestamp and reset semantics across test evaluation cadences.
        check = (m.expect('sum(' + m.expression('instance', 2024) + ') - 1000 * '
                          '(sum(rate(oie_instance_cpu_steal_seconds_total[5m])) + '
                          'sum(rate(oie_instance_cpu_wait_seconds_total[5m])))', 0, at)
                 if at == '5m45s' else m.value('instance', 2024, value, at=at))
        m.add('Instance scheduler ' + title, long_base + counters,
              [check])
    m.add('Instance scheduler unknown allocated cohort leaves a gap',
          [s for s in long_base if not s['series'].startswith('oie_instance_cpu_vcpu_count{')] +
          [delay, other_delay], [m.value('instance', 2024, at='10m')])


def optional_and_state_cases(m):
    operation = DISK | {'destination_disk_type': 'ultra',
                        'destination_volume_uuid': 'volume-destination'}
    active = [series('oie_instance_disk_retype_active', '1+0x20', operation),
              series('oie_instance_disk_retype_status_code', '1+0x20', operation),
              series('oie_instance_disk_retype_start_timestamp_seconds', '30+0x20', operation),
              series('oie_instance_disk_retype_observation_healthy', '1+0x20', operation)]
    terminal = [series('oie_instance_disk_retype_status_code', '2+0x20', operation),
                series('oie_instance_disk_retype_start_timestamp_seconds', '30+0x20', operation),
                series('oie_instance_disk_retype_end_timestamp_seconds', '90+0x20', operation)]
    for name, active_id, terminal_id in [('cluster', 24001, 24003), ('project', 24002, 24004),
                                        ('hypervisor', 24005, 24006), ('instance', 24005, 24006)]:
        query = m.query(name, active_id)
        checks = [m.expect('count(' + query + ')', 6)]
        for field in ['progress', 'ready']:
            checks += m.nan(query + '{retype_field="' + field + '"}')
        m.add(name + ' active retype keeps unavailable optional columns', source() + active, checks)
        query = m.query(name, terminal_id)
        m.add(name + ' captured retype keeps unavailable ready field and measured duration',
              source() + terminal, [m.expect('count(' + query + ')', 5),
                                   m.expect('sum(' + query + '{retype_field="duration"})', 60)] +
              m.nan(query + '{retype_field="ready"}'))
        positive = active + [series('oie_instance_disk_retype_progress_percent', '42.3+0x20', operation),
                             series('oie_instance_disk_retype_ready_timestamp_seconds', '60+0x20', operation)]
        query = m.query(name, active_id)
        m.add(name + ' actual optional retype measurements win over NaN seeds', source() + positive,
              [m.expect('sum(' + query + '{retype_field="progress"})', 42.3),
               m.expect('sum(' + query + '{retype_field="ready"})', 60000)])
    paused = series('oie_instance_inventory_info', '1+0x20',
                    VM | {'libvirt_active': '1', 'state_desc': 'paused'})
    running = series('oie_instance_inventory_info', '1+0x20',
                     VM | {'instance_uuid': 'running-vm', 'libvirt_active': '1', 'state_desc': 'running'})
    for name in ['cluster', 'project', 'instance', 'hypervisor']:
        m.add(name + ' active paused VM is not a Running VM', source() + [paused],
              [m.value(name, 25012, 0)])
        m.add(name + ' Running count includes only running state', source() + [paused, running],
              [m.value(name, 25012, 1)])
    for name in ['cluster', 'project']:
        m.add(name + ' healthy empty selected inventory is zero', source(),
              [m.value(name, 25012, 0), m.value(name, 25013, 0),
               m.value(name, 27200, 0, 'B'), m.value(name, 27200, 0, 'C')])
        failed = source() + source(HOST | {'instance': 'compute-b:9120'}, oie_host_libvirt_ok=0)
        m.add(name + ' incomplete selected inventory cannot present subset as complete', failed,
              [m.value(name, 25012, -1), m.value(name, 25013, -1),
               m.value(name, 27200, ref='B'), m.value(name, 27200, ref='C')])
        for title, data, value in [('healthy empty monitor', source(), 0),
                                   ('unusable monitor source', source(oie_host_libvirt_ok=0), None),
                                   ('one failed selected monitor source', failed, None)]:
            m.add(name + ' retype zero requires ' + title, data,
                  [m.value(name, 27240, value, ref) for ref in ['B', 'C', 'D']])
        m.add(name + ' positive retype evidence survives bounded source outage',
              source(oie_host_libvirt_ok=0) + active, [m.value(name, 27240, 1, 'B')])
        m.add(name + ' captured retype outcomes remain valid through source outage',
              source(oie_host_libvirt_ok=0) + terminal, [m.value(name, 27240, 1, 'E')])


def mining_and_threat_cases(m):
    candidate = series('oie_instance_mining_suspected', '1+0x20',
                       VM | {'ip': '192.0.2.1', 'family': '4', 'port': '14444',
                             'port_name': 'pool', 'confidence': 'high_persistent'})
    context = [series('oie_instance_info', '1+0x20', VM),
               series('oie_instance_state_code', '1+0x20', VM),
               series('oie_instance_outbound_flows', '0+0x20', VM)]
    for name in ['cluster', 'instance', 'threats']:
        table = m.query(name, 22001)
        m.add(name + ' mining evidence preserves unavailable CPU field', source() + context + [candidate],
              [m.expect('count(' + table + '{oie_column="candidate"})', 1),
               m.value(name, 27220, 1)] + m.nan(table + '{oie_column="cpu"}'))
        m.add(name + ' measured mining CPU wins over unavailable field seed',
              source() + context + [candidate, series('oie_instance_cpu_vcpu_percent', '90+0x20', VM)],
              [m.expect('count(' + table + '{oie_column="cpu"})', 1),
               m.expect('sum(' + table + '{oie_column="cpu"})', 90)])
        m.add(name + ' healthy mining coverage with no candidate is zero', source() + context,
              [m.value(name, 27220, 0), m.value(name, 22002, 0)])
        m.add(name + ' unknown mining coverage cannot look clear',
              source(oie_host_conntrack_raw_ok=0) + context + [candidate],
              [m.value(name, 27220), m.value(name, 22002, -1), m.expect('count(' + table + ')')])
    contacts = source() + feed() + vm(active=(5, 0), contacts='_x19 1')
    table = m.query('threats', 27022)
    m.add('Threat matching row survives one-sample contacts without inventing zero', contacts,
          [m.expect('count(' + table + '{oie_column="active"})', 1, '5m')] +
          m.nan(table + '{oie_column="contacts"}', at='5m'))
    data = (source() + feed('tor_relay') + feed('customlist') + feed('emergingthreats') +
            vm(feeds=('tor_relay', 'customlist', 'emergingthreats')))
    m.add('Threat graphs preserve Tor custom and emerging lists without Spamhaus', data,
          [m.value('threats', pid, 5, at='5m') for pid in [3022, 3024, 3025]])


def matrix():
    result = Matrix()
    for build in [cluster_cases, hypervisor_cases, project_cases, instance_cases,
                  optional_and_state_cases, mining_and_threat_cases]:
        build(result)
    return result


class DashboardAudit(unittest.TestCase):
    def test_actual_dashboard_audit_queries(self):
        promtool = os.environ.get('PROMTOOL', 'promtool')
        tests = matrix()
        with tempfile.TemporaryDirectory(prefix='oie-dashboard-audit-') as temp:
            temp = Path(temp)
            for index, case in enumerate(tests.cases):
                with self.subTest(scenario=case['name']):
                    # Unrelated range/ranking queries need not run at every fixture
                    # timestamp. Keep only this scenario's real dashboard targets.
                    used = {name for check in case['promql_expr_test']
                            for name in re.findall(r'\boie_audit_\d+\b', check['expr'])}
                    records = [record for record in tests.records.values() if record['record'] in used]
                    directory = temp / str(index)
                    directory.mkdir()
                    rules = directory / 'rules.yml'
                    rules.write_text(yaml.safe_dump({'groups': [{'name': 'dashboard_audit',
                        'interval': '15s', 'rules': records}]}, sort_keys=False))
                    fixtures = directory / 'tests.yml'
                    fixtures.write_text(yaml.safe_dump({'rule_files': ['rules.yml'],
                        'evaluation_interval': '15s', 'tests': [case]}, sort_keys=False))
                    checked = subprocess.run([promtool, 'test', 'rules', str(fixtures)],
                                             cwd=directory, capture_output=True, text=True)
                    self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)
        print(f'Evaluated {len(tests.cases)} audit scenarios against {len(tests.records)} actual dashboard targets.')


if __name__ == '__main__':
    unittest.main()
