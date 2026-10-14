#!/usr/bin/env python3
"""Native Prometheus lifecycle and false-positive scenarios for every OIE alert.

No local imitation of PromQL is used. Set PROMTOOL to execute the cases.
The fixture-coverage check runs independently of Promtool availability.
"""
from __future__ import annotations
import copy
import json
import math
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml
from oie_alerts_test import COMMON, HOST, VM, PROMTOOL, alerts, check, health, render, replace, series

DISK = VM | {'disk_path': 'vda', 'disk_type': 'premium', 'volume_uuid': 'volume-a'}
NIC = VM | {'ifname': 'tap-a'}
IP = VM | {'ip': '10.0.0.5', 'family': 'ipv4'}
DEFINITIONS = {r['alert']: r for g in yaml.safe_load(render())['groups'] for r in g['rules'] if 'alert' in r}


def duration_seconds(value):
    value = str(value or '0s').strip()
    total = 0
    for amount, unit in __import__('re').findall(r'(\d+)([smhd])', value):
        total += int(amount) * {'s': 1, 'm': 60, 'h': 3600, 'd': 86400}[unit]
    return total


def positive_fixtures():
    """Raw observations with independent, documented above-threshold values."""
    out = {}

    def add(short, observations=(), changes=None, warm=False):
        name = 'OpenStackInstance' + short
        end = 530 if warm else 45
        data = health(end=end) + list(observations)
        for metric, value in (changes or {}).items():
            replace(data, metric, value)
        out[name] = {'data': data, 'end': end, 'warm': warm}

    add('ExporterUnavailable', changes={'up': '0x45'})
    for suffix, metric, value in [
        ('HighCPUUsage', 'cpu_vcpu_percent', '97x45'),
        ('HighStealRate', 'cpu_steal_seconds_total', '0+12x45'),
        ('HighMemorySwapInRate', 'mem_swap_in_bytes_total', '0+6000000000x45'),
        # Deliberately above the 3000/s hard limit; an exact-boundary floating
        # rate is unsuitable for a cross-cadence positive lifecycle fixture.
        ('HighMajorFaultRate', 'mem_major_faults_total', '0+240000x45'),
    ]:
        add(suffix, [series('oie_instance_' + metric, value, VM)])
    for tier in ['local', 'volumes', 'premium', 'ultra']:
        disk = DISK | {'disk_type': tier}
        add('HighDiskIOPS' + tier.title(), [series('oie_instance_disk_read_iops', '12000x45', disk),
                                         series('oie_instance_disk_write_iops', '12000x45', disk)])
    add('HighDiskIOPSOther', [series('oie_instance_disk_read_iops', '6000x45', DISK | {'disk_type': 'vms'}),
                                series('oie_instance_disk_write_iops', '4000x45', DISK | {'disk_type': 'vms'})])
    add('DiskActivityIncrease', [series('oie_instance_disk_read_iops', '100x480 2000x49', DISK),
                                 series('oie_instance_disk_write_iops', '100x480 2000x49', DISK)], warm=True)
    add('HighDiskThroughput', [series('oie_instance_disk_read_gib_total', '0+10x45', DISK),
                               series('oie_instance_disk_write_gib_total', '0+10x45', DISK)])
    for direction in ['read', 'write', 'flush']:
        add('Disk' + direction.title() + 'LatencyHigh', [
            series('oie_instance_disk_' + direction + '_requests_total', '0+600x45', DISK),
            series('oie_instance_disk_' + direction + '_seconds_total', '0+180x45', DISK)])
    for d, name in [('rx', 'Incoming'), ('tx', 'Outgoing')]:
        add('High' + name + 'PacketRate', [series('oie_instance_net_' + d + '_packets_total', '0+9000000x45', NIC)])
        add('HighBandwidthRate' + d.upper(), [series('oie_instance_net_' + d + '_gib_total', '0+15x45', NIC)])
        add('Network' + ('Receive' if d == 'rx' else 'Transmit') + 'DropRatioHigh', [
            series('oie_instance_net_' + d + '_packets_total', '0+10000x45', NIC),
            series('oie_instance_net_' + d + '_dropped_total', '0+1000x45', NIC)])
    add('ConntrackFlowsBurst', [series('oie_instance_conntrack_ip_flows', '2000x480 45000x49', IP)], warm=True)
    for direction, title in [('rx', 'Receive'), ('tx', 'Transmit')]:
        add('Network' + title + 'ErrorRatioHigh', [
            series('oie_instance_net_' + direction + '_packets_total', '0+9000x45', NIC),
            series('oie_instance_net_' + direction + '_errors_total', '0+1000x45', NIC),
        ])
    add('HighConntrackFlowsSustained', [series('oie_instance_conntrack_ip_flows', '72000x45', IP)])
    add('PossibleFlood', [series('oie_instance_conntrack_ip_flows', '30000x45', IP),
                          series('oie_instance_net_rx_packets_total', '0+10000x45', NIC),
                          series('oie_instance_net_rx_dropped_total', '0+1000x45', NIC)])
    for d in ['outbound', 'inbound']:
        for suffix, values in [
            ('PortScanBurst', {'unique_dst_ports': 300, 'unique_remotes': 50, 'flows': 10000}),
            ('SingleTargetFlood' if d == 'outbound' else 'SingleSourceFlood',
             {'max_flows_single_remote': 110000, 'flows': 115000}),
            ('SprayOnSinglePort', {'unique_remotes': 400, 'unique_dst_ports': 2, 'flows': 10000}),
            ('ZombieFlowLowThroughput', {'flows': 7000, 'bytes_per_flow': 100, 'packets_per_flow': 5}),
            ('ExtremeRemoteFanout', {'unique_remotes': 12000}),
        ]:
            observations = [series('oie_instance_' + d + '_' + metric, str(value) + 'x45', IP)
                            for metric, value in values.items()]
            if suffix == 'ZombieFlowLowThroughput':
                observations.append(series('oie_instance_conntrack_ip_flows', '70000x45', IP))
            add(d.title() + suffix, observations)
    for title, signal, feed in [('TorExit', 'tor_exit', 'TOREXIT'), ('TorRelay', 'tor_relay', 'TORRELAY'),
                              ('Spamhaus', 'spamhaus', 'spamhaus'), ('EmergingThreats', 'emergingthreats', 'EMERGING'),
                              ('CustomList', 'customlist', 'CUSTOMLIST')]:
        add(title + 'RepeatedContact', [series('oie_instance_threat_' + signal + '_active_flows', '2x45', VM | {'direction': 'out'})])
        add('Exporter' + title + ('' if title == 'CustomList' else 'List') + 'RefreshStale')
        data = out['OpenStackInstanceExporter' + title + ('' if title == 'CustomList' else 'List') + 'RefreshStale']['data']
        next(s for s in data if s['series'].startswith('oie_host_threat_feed_fresh{') and f'list="{feed}"' in s['series'])['values'] = '0x45'
    for short, observations, changes in [
        ('ProcessCPUHigh', [series('process_cpu_seconds_total', '0+60x45')], {}),
        ('HostThreatListed', [series('oie_host_threat_provider_ip_listed', '1x45', HOST | {'list': 'spamhaus', 'ip': '192.0.2.1', 'family': 'ipv4'})], {}),
        ('HostConntrackUtilizationHigh', [series('oie_host_conntrack_utilization', '0.9x45')], {}),
        ('CollectionCycleNearInterval', [series('oie_host_collection_cycle_duration_seconds', '14x45')], {}),
        ('HostCPUPressureSustained', [series('oie_host_cpu_usage_percent', '98x45')], {}),
        ('HostMemoryPressureSustained', [series('oie_host_mem_available_mib', '10x45'), series('oie_host_mem_mib_total', '1000x45')], {}),
        ('HostConntrackReadErrors', [series('oie_host_conntrack_read_errors_total', '0+10x45')], {}),
        ('ConntrackRawReaderFailed', [], {'oie_host_conntrack_raw_ok': '0x45'}),
        ('ConntrackReadStale', [], {'oie_host_conntrack_last_success_timestamp_seconds': '1x45'}),
        ('LibvirtCollectionUnhealthy', [], {'oie_host_libvirt_ok': '0x45'}),
        ('LibvirtDataStale', [], {'oie_host_libvirt_last_success_timestamp_seconds': '1x45'}),
        ('HostCPUContentionCritical', [series('oie_host_cpu_usage_percent', '98x45'),
             series('oie_instance_cpu_vcpu_count', '2x45', VM),
             series('oie_instance_cpu_steal_seconds_total', '0+12x45', VM | {'vcpu': '0'})], {}),
        ('HostMemoryPressureCritical', [series('oie_host_mem_available_mib', '10x45'), series('oie_host_mem_mib_total', '1000x45'),
             series('oie_instance_mem_swap_in_bytes_total', '0+125829120x45', VM)], {}),
    ]:
        add('Exporter' + short, observations, changes)
    add('VolumeRetypeReadyStalled', [series('oie_instance_disk_retype_status_code', '6x45', DISK)])
    add('VolumeRetypeObservationUnhealthy', [series('oie_instance_disk_retype_observation_healthy', '0x45', DISK)])
    add('MiningSuspected', [series('oie_instance_mining_suspected', '1x45', VM | {'confidence': 'shared_persistent'}),
                            series('oie_instance_cpu_vcpu_percent', '90x45', VM)])
    add('MiningCandidatePersistent', [series('oie_instance_mining_suspected', '1x45', VM | {'confidence': 'high_persistent'})])
    # Adaptive consumption needs a real established baseline, not a cold
    # absolute limit. Alert names/holds remain stable; input workloads change.
    for tier in ['local','volumes','premium','ultra','other']:
        disk=DISK | {'disk_type': 'vms' if tier=='other' else tier}
        add('HighDiskIOPS'+tier.title(), [series('oie_instance_disk_read_iops','50x480 2500x49',disk),
            series('oie_instance_disk_write_iops','50x480 2500x49',disk)], warm=True)
    throughput=[series('oie_instance_disk_'+op+'_gib_total','0+0.001x480 0.481+10x49',DISK) for op in ('read','write')]
    add('DiskActivityIncrease',throughput,warm=True)
    add('HighDiskThroughput',throughput + [series('oie_instance_disk_read_requests_total','0+600x530',DISK),
        series('oie_instance_disk_read_seconds_total','0+180x530',DISK)],warm=True)
    for direction,title in [('rx','Incoming'),('tx','Outgoing')]:
        add('High'+title+'PacketRate',[series('oie_instance_net_'+direction+'_packets_total','0+600x480 288600+9000000x49',NIC)],warm=True)
        add('HighBandwidthRate'+direction.upper(),[series('oie_instance_net_'+direction+'_gib_total','0+0.001x480 0.481+15x49',NIC)],warm=True)
    add('HighConntrackFlowsSustained',[series('oie_instance_conntrack_ip_flows','2000x480 72000x49',IP),
        series('oie_host_conntrack_utilization','0.1x480 0.9x49',HOST)],warm=True)
    # Notification fixtures require real corroboration. The separate noise cases
    # keep the same busy workload and remove only that corroboration.
    out.pop('OpenStackInstanceDiskActivityIncrease')
    for name, fixture in out.items():
        data=fixture['data'];end=fixture['end']
        def extra(metric, values, labels):
            identity=series(metric,values,labels)['series']
            if not any(item['series']==identity for item in data):
                data.append(series(metric,values,labels))
        if 'HighDiskIOPS' in name:
            source=next(item for item in data if item['series'].startswith('oie_instance_disk_read_iops{'))
            labels=dict(re.findall(r'(\w+)="([^"\n]*)"',source['series']))
            extra('oie_instance_disk_read_requests_total',f'0+600x{end}',labels)
            extra('oie_instance_disk_read_seconds_total',f'0+180x{end}',labels)
        if name.endswith('HighCPUUsage'):
            extra('oie_instance_cpu_steal_seconds_total',f'0+12x{end}',VM | {'vcpu':'0'})
        if name.endswith('HighMajorFaultRate'):
            extra('oie_instance_mem_swap_in_bytes_total',f'0+125829120x{end}',VM)
        if name.endswith(('HighIncomingPacketRate','HighOutgoingPacketRate','HighBandwidthRateRX','HighBandwidthRateTX')):
            extra('oie_instance_net_rx_packets_total',f'0+10000x{end}',NIC)
            extra('oie_instance_net_rx_dropped_total',f'0+1000000x{end}',NIC)
        if name.endswith(('ConntrackFlowsBurst','TorExitRepeatedContact','TorRelayRepeatedContact')) or any(x in name for x in ['PortScanBurst','SingleTargetFlood','SingleSourceFlood','SprayOnSinglePort','ExtremeRemoteFanout','ZombieFlowLowThroughput']):
            extra('oie_host_conntrack_utilization',f'0.9x{end}',HOST)
        if name.endswith('MiningCandidatePersistent'):
            extra('oie_instance_cpu_vcpu_percent',f'50x{end}',VM)
        if name.endswith('ExporterProcessCPUHigh'):
            extra('oie_host_collection_cycle_duration_seconds',f'14x{end}',HOST)

    return out


def expanded_values(spec):
    """Expand Promtool fixture notation; this does not evaluate PromQL."""
    values = []
    for token in spec.split():
        match = re.fullmatch(r'(_|stale)(?:x(\d+))?', token)
        if match:
            values.extend([match[1]] * (int(match[2] or 0) + 1))
            continue
        match = re.fullmatch(r'(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)(?:([+-])([0-9.eE+-]+))?(?:x(\d+))?', token)
        if not match:
            raise ValueError('Unsupported fixture token: ' + token)
        start, sign, step, repeat = match.groups()
        delta = float(step or 0) * (-1 if sign == '-' else 1)
        values.extend(float(start) + i * delta for i in range(int(repeat or 0) + 1))
    return values


def healthy_value(identity, last, minute):
    metric = identity.split('{', 1)[0]
    if metric.endswith('_last_success_timestamp_seconds'):
        return minute * 60
    if metric in ('up', 'oie_host_libvirt_ok', 'oie_host_conntrack_raw_ok',
                  'oie_instance_state_code', 'oie_instance_disk_retype_observation_healthy'):
        return 1
    if metric.startswith('oie_instance_resource_axis_') or metric == 'oie_host_threat_feed_fresh':
        return 1
    if metric == 'oie_host_collection_interval_seconds':
        return 15
    if metric == 'oie_host_mem_mib_total':
        return 1000
    if metric == 'oie_host_mem_available_mib':
        return 500
    if metric == 'oie_instance_cpu_vcpu_count':
        return 2
    if metric.endswith('_total'):
        # Stop activity without resetting counters or removing their series.
        return last
    return 0


def lifecycle_cases():
    tests = []
    for name, fixture in positive_fixtures().items():
        end, data = fixture['end'], copy.deepcopy(fixture['data'])
        for item in data:
            points = expanded_values(item['values'])
            for minute in range(end + 1, end + 13):
                points.append(healthy_value(item['series'], points[-1], minute))
            item['values'] = ' '.join(str(v) for v in points)
        hold = duration_seconds(DEFINITIONS[name].get('for', '0s'))
        onset = 480 * 60 if fixture['warm'] else 0
        before = onset + max(hold - 60, 0)
        checks = [check(alerts(name), 1, f'{end-2}m'), check(alerts(name), 0, f'{end+12}m')]
        expected_identity = {'alertname': name, 'alertstate': 'firing'} | HOST | DEFINITIONS[name]['labels']
        if not name.startswith('OpenStackInstanceExporter'):
            expected_identity['instance_uuid'] = VM['instance_uuid']
        scoped_alert = 'ALERTS{' + ','.join(k+'='+json.dumps(v) for k,v in sorted(expected_identity.items())) + '}'
        checks.append(check('count('+scoped_alert+') or vector(0)', 1, f'{end-2}m'))
        if hold > 0:
            checks.append(check(alerts(name), 0, f'{before}s'))
            # Pending is asserted before the hold, independently of eventual firing.
            pending = onset + 6 * 60
            if hold <= 5 * 60:
                pending = 60
                if name.endswith(('HighStealRate', 'HighMemorySwapInRate', 'HostCPUContentionCritical', 'HostMemoryPressureCritical')):
                    pending = 240
                elif name.endswith('PossibleFlood'):
                    pending = 120
                elif name.endswith('ConntrackReadStale'):
                    pending = 180
                elif name.endswith('LibvirtDataStale'):
                    pending = 300
                elif name.endswith('SingleTargetFlood') or name.endswith('SingleSourceFlood'):
                    pending = 120
            checks.append(check(alerts(name, 'pending'), 1, f'{pending}s'))
        tests.append({'name': name, 'interval': '1m', 'input_series': data, 'promql_expr_test': checks})
    return tests


def normal_cases():
    """Every positive fixture has a healthy non-firing counterpart, not empty input."""
    tests = []
    for name, fixture in positive_fixtures().items():
        data = copy.deepcopy(fixture['data'])
        for item in data:
            item['values'] = ' '.join(str(healthy_value(item['series'], 0, minute))
                                      for minute in range(61))
        tests.append({'name': 'normal: ' + name, 'interval': '1m', 'input_series': data,
                      'promql_expr_test': [check(alerts(name), 0, '40m'),
                                           check(alerts(name, 'pending'), 0, '40m')]})
    return tests


def resample_case(case, seconds):
    """Change the input cadence while preserving minute-by-minute workload intent."""
    result = copy.deepcopy(case)
    result['interval'] = str(seconds) + 's'
    for item in result.get('input_series', []):
        points = expanded_values(item['values'])
        interpolated = []
        metric = item['series'].split('{', 1)[0]
        for second in range(0, (len(points) - 1) * 60 + 1, seconds):
            i, fraction = divmod(second, 60)
            value = points[i]
            # Counter rates and advancing observation timestamps are linearly
            # interpolated; categorical states and workload gauges are held.
            if (metric.endswith('_total') or metric.endswith('_timestamp_seconds')) and fraction:
                nxt = points[i+1]
                if isinstance(value, (int, float)) and isinstance(nxt, (int, float)) and nxt >= value:
                    value += (nxt - value) * fraction / 60
            interpolated.append(str(value))
        item['values'] = ' '.join(interpolated)
    return result


def mitigation_cases():
    cases = []
    def add(name, data, checks):
        cases.append({'name': name, 'interval': '1m', 'input_series': copy.deepcopy(data), 'promql_expr_test': checks})

    base = health() + [series('oie_host_conntrack_utilization', '0.9x60')]
    for metric, sequence in [('oie_host_conntrack_raw_ok', '1x2 0x57'),
                             ('oie_host_conntrack_last_success_timestamp_seconds', '0+60x2 120x57'),
                             ('up', '1x2 0x57')]:
        data = copy.deepcopy(base); replace(data, metric, sequence)
        add('retained host pressure cannot qualify: ' + metric, data, [check(alerts('.*HostConntrackUtilizationHigh'), 0, '10m')])
    data = copy.deepcopy(base); replace(data, 'oie_host_conntrack_raw_ok', '1x15 0x44')
    add('firing pressure clears on collection failure', data, [check(alerts('.*HostConntrackUtilizationHigh'), 1, '10m'), check(alerts('.*HostConntrackUtilizationHigh'), 0, '17m')])
    data = copy.deepcopy(base); replace(data, 'oie_host_libvirt_ok', '0x60'); replace(data, 'oie_host_conntrack_raw_ok', '0x60')
    add('Libvirt failure is not reported as a separate attempted conntrack failure', data, [check(alerts('.*ConntrackRawReaderFailed'), 0)])
    # Normal established high occupancy must not become a new burst or a claimed flood.
    data = health(end=530) + [series('oie_instance_conntrack_ip_flows', '60000x530', IP)]
    add('normal connection-heavy service', data, [check(alerts('.*ConntrackFlowsBurst'), 0, '520m'), check(alerts('.*PossibleFlood'), 0, '520m'), check(alerts('.*HighConntrackFlowsSustained'), 0, '520m')])
    data = health(end=530) + [series('oie_instance_conntrack_ip_flows', '10x480 40x49', IP)]
    add('tiny relative increase fails absolute floor', data, [check(alerts('.*ConntrackFlowsBurst'), 0, '520m')])
    data = health() + [series('oie_instance_conntrack_ip_flows', '50000x60', IP)]
    add('cold baseline is unavailable not manufactured from zero', data, [check('count(oie:activity:baseline{signal="conntrack_flows"}) or vector(0)', 0), check(alerts('.*ConntrackFlowsBurst'), 0), check(alerts('.*PossibleFlood'), 0)])
    data = health(end=530) + [series('oie_instance_conntrack_ip_flows', '2000x480 50000x49', IP)]
    replace(data, 'oie_host_conntrack_raw_ok', '0x480 1x49')
    add('failed collections do not populate baseline', data, [check('count(oie:activity:baseline) or vector(0)', 0, '520m'), check(alerts('.*ConntrackFlowsBurst'), 0, '520m')])
    # Busy raw traffic is not enough for the fast possible-flood warning.
    data = health() + [series('oie_instance_conntrack_ip_flows', '30000x60', IP), series('oie_instance_net_rx_packets_total', '0+9000000x60', NIC)]
    add('high traffic without loss or history does not claim flood', data, [check(alerts('.*PossibleFlood'), 0)])
    data.append(series('oie_instance_net_rx_dropped_total', '0+900000x60', NIC))
    add('flood impact path needs no inbound behavior metrics or baseline', data, [check(alerts('.*PossibleFlood'), 1, '6m')])
    # Another VM's measured drops cannot qualify this VM's high counts.
    for item in data:
        if item['series'].startswith('oie_instance_net_'):
            item['series'] = item['series'].replace('instance_uuid="vm-a"', 'instance_uuid="vm-b"')
    add('different VM cannot lend loss evidence', data, [check(alerts('.*PossibleFlood'), 0)])
    # Critical qualification must not remove a warning during the critical hold.
    data = health() + [series('oie_host_cpu_usage_percent', '98x60'), series('oie_instance_cpu_vcpu_count', '2x60', VM),
                       series('oie_instance_cpu_steal_seconds_total', '0x25 0+12x34', VM | {'vcpu': '0'})]
    add('host warning remains while critical is pending', data, [check(alerts('.*HostCPUPressureSustained'), 1, '28m'), check(alerts('.*HostCPUContentionCritical'), 0, '28m'), check(alerts('.*HostCPUContentionCritical'), 1, '40m'), check(alerts('.*HostCPUPressureSustained'), 1, '40m')])
    # High mining tier intentionally works without any CPU telemetry.
    data = health() + [series('oie_instance_mining_suspected', '1x60', VM | {'confidence': 'high'})]
    add('high mining tier does not require CPU', data, [check(alerts('.*MiningSuspected'), 1)])
    for tier, cpu, expected in [('shared', 30, 0), ('shared', 40, 1), ('shared_persistent', 50, 0), ('shared_persistent', 70, 1), ('high_persistent', 30, 0), ('high_persistent', 50, 1)]:
        data = health() + [series('oie_instance_mining_suspected', '1x60', VM | {'confidence': tier}), series('oie_instance_cpu_vcpu_percent', str(cpu) + 'x60', VM)]
        add('mining CPU: ' + tier + '/' + str(cpu), data, [check(alerts('.*MiningCandidatePersistent' if tier == 'high_persistent' else '.*MiningSuspected'), expected)])
    data = health() + [series('oie_instance_mining_suspected', '1x60', VM | {'confidence': 'shared'}), series('oie_instance_cpu_vcpu_percent', '90x10 stale _x49', VM)]
    add('old CPU tail cannot qualify mining', data, [check(alerts('.*MiningSuspected'), 0)])
    for operations, expected in [(1, 0), (600, 1)]:
        data = health() + [series('oie_instance_disk_read_requests_total', f'0+{operations}x60', DISK), series('oie_instance_disk_read_seconds_total', f'0+{operations*.3}x60', DISK)]
        add('disk latency observation floor ' + str(operations), data, [check(alerts('.*DiskReadLatencyHigh'), expected)])
    data = health() + [series('oie_instance_disk_read_requests_total', '0+600x60', DISK), series('oie_instance_disk_read_seconds_total', '0+180x10 stale _x49', DISK)]
    add('missing disk timing cannot sustain latency', data, [check(alerts('.*DiskReadLatencyHigh'), 0)])
    for packets, drops, expected in [(2, 1, 0), (1000, 100, 1)]:
        data = health() + [series('oie_instance_net_rx_packets_total', f'0+{packets}x60', NIC), series('oie_instance_net_rx_dropped_total', f'0+{drops}x60', NIC)]
        add('packet drop denominator ' + str(packets), data, [check(alerts('.*NetworkReceiveDropRatioHigh'), expected)])
    data = health() + [series('oie_instance_disk_read_iops', '12000x60', DISK), series('oie_instance_disk_write_iops', '12000x60', DISK)]
    for item in data:
        if 'axis="disk"' in item['series'] and item['series'].startswith('oie_instance_resource_axis_fresh'):
            item['values'] = '0x60'
    add('retained disk workload cannot qualify consumption', data, [check(alerts('.*HighDiskIOPS.*'), 0)])
    data = copy.deepcopy(positive_fixtures()['OpenStackInstanceHighDiskIOPSPremium']['data'])
    replace(data, 'oie_host_threat_feed_fresh', '0x530')
    add('unrelated feed failure does not suppress disk consumption', data, [check(alerts('.*HighDiskIOPSPremium'), 1, '520m')])
    for state, expected in [(-1, 0), (1, 0), (0, 1)]:
        data = health()
        for item in data:
            if item['series'].startswith('oie_host_threat_feed_fresh') and 'list="spamhaus"' in item['series']:
                item['values'] = str(state) + 'x60'
        add('feed state ' + str(state), data, [check(alerts('.*SpamhausListRefreshStale'), expected)])
    data = health() + [series('oie_instance_threat_spamhaus_active_flows', '2x60', VM | {'direction': 'any'})]
    add('combined-direction reputation without impact does not notify', data, [check(alerts('.*SpamhausRepeatedContact'), 0)])
    return cases


def disk_policy_cases():
    cases=[]
    disk=DISK | {'disk_type':'volumes'}
    for name,read,write,expected in [
        ('steady heavy workload is normal','20000x530','20000x530',0),
        ('material established change','50x480 1500x49','50x480 1500x49',1),
        ('tiny relative change','1x480 4x49','1x480 4x49',0),
        ('brief benchmark clears before hold','50x480 1500x10 50x38','50x530',0),
        ('unknown history does not mean zero','_x480 1500x49','_x480 1500x49',0)]:
        data=health(end=530)+[series('oie_instance_disk_read_iops',read,disk),series('oie_instance_disk_write_iops',write,disk),
              series('oie_instance_disk_read_requests_total','0+600x530',disk),series('oie_instance_disk_read_seconds_total','0+180x530',disk)]
        cases.append({'name':name,'interval':'1m','input_series':data,
                      'promql_expr_test':[check(alerts('.*HighDiskIOPSVolumes'),expected,'520m')]})
    return cases


def regression_cases():
    cases = []
    def add(name, inputs, checks):
        cases.append({'name': name, 'interval': '1m', 'input_series': inputs, 'promql_expr_test': checks})
    data = health() + [series('oie_instance_conntrack_ip_flows', '30000x60', IP),
                       series('oie_instance_net_rx_packets_total', '0+10000x60', NIC),
                       series('oie_instance_net_rx_dropped_total', '0+1000x60', NIC)]
    add('two-minute fast window supports a one-minute evaluation interval', data, [
        check('count(oie:activity:fast{signal="conntrack_flows"}) or vector(0)', 1, '3m'),
        check(alerts('.*PossibleFlood'), 1, '6m')])
    data = health() + [series('oie_host_conntrack_utilization', '0.9x60')]
    replace(data, 'oie_host_conntrack_last_success_timestamp_seconds', '1x60')
    add('frozen zero age gauge cannot hide a stopped background collector', data, [
        check('count(oie:conntrack_ready) or vector(0)', 0, '4m'),
        check(alerts('.*HostConntrackUtilizationHigh'), 0, '10m'),
        check(alerts('.*ConntrackReadStale'), 1, '10m')])
    data = health() + [series('oie_host_conntrack_utilization', '0.9x60')]
    replace(data, 'oie_host_conntrack_last_success_timestamp_seconds', '0x60')
    add('never-successful timestamp cannot qualify pressure', data, [check(alerts('.*HostConntrackUtilizationHigh'), 0)])
    data = health() + [series('oie_host_conntrack_utilization', '0.9x60')]
    replace(data, 'oie_host_conntrack_last_success_timestamp_seconds', '100000x60')
    add('future timestamp cannot qualify pressure', data, [check(alerts('.*HostConntrackUtilizationHigh'), 0)])
    data = health() + [series('oie_host_conntrack_utilization', '0.9x60')]
    replace(data, 'oie_host_conntrack_last_success_timestamp_seconds', '0 0 45+60x58')
    add('one-minute scrape phase and collection delay fit freshness budget', data, [
        check('count(oie:conntrack_ready) or vector(0)', 1, '4m'),
        check(alerts('.*HostConntrackUtilizationHigh'), 1, '10m')])
    for direction in ['inbound', 'outbound']:
        data = health() + [series('oie_instance_' + direction + '_unique_dst_ports', '300x60', IP),
                          series('oie_instance_' + direction + '_new_dst_ports', '300 0x59', IP),
                          series('oie_instance_' + direction + '_unique_remotes', '50x60', IP),
                          series('oie_instance_' + direction + '_flows', '10000x60', IP)]
        data.append(series('oie_host_conntrack_utilization','0.9x60',HOST))
        add(direction + ' sustained port breadth does not require perpetual rediscovery', data,
            [check(alerts('OpenStackInstance' + direction.title() + 'PortScanBurst'), 1, '20m')])
        data = health() + [series('oie_instance_' + direction + '_unique_dst_ports', '2x60', IP),
                          series('oie_instance_' + direction + '_unique_remotes', '400x60', IP),
                          series('oie_instance_' + direction + '_new_remotes', '400 0x59', IP),
                          series('oie_instance_' + direction + '_flows', '10000x60', IP)]
        data.append(series('oie_host_conntrack_utilization','0.9x60',HOST))
        add(direction + ' sustained remote breadth does not require perpetual rediscovery', data,
            [check(alerts('OpenStackInstance' + direction.title() + 'SprayOnSinglePort'), 1, '20m')])
        data = health()  # Direction disabled: detailed metrics are absent.
        add(direction + ' disabled analysis does not manufacture a scan', data,
            [check(alerts('OpenStackInstance' + direction.title() + 'PortScanBurst'), 0)])
    for pool in ['vms','unknown','custom-nvme','']:
        disk=DISK | {'disk_type':pool}
        data=health(end=530)+[series('oie_instance_disk_read_iops','50x480 6000x49',disk),series('oie_instance_disk_write_iops','50x480 3000x49',disk)]
        data += [series('oie_instance_disk_read_requests_total','0+600x530',disk),series('oie_instance_disk_read_seconds_total','0+180x530',disk)]
        add('adaptive fallback preserves source identity: '+pool,data,[check(alerts('.*HighDiskIOPSOther'),1,'520m'),check(alerts('.*HighDiskIOPS(Local|Volumes|Premium|Ultra)'),0,'520m')])
    data=copy.deepcopy(positive_fixtures()['OpenStackInstanceHighDiskIOPSPremium']['data'])
    add('named source never duplicates Other notification',data,[check(alerts('.*HighDiskIOPSPremium'),1,'520m'),check(alerts('.*HighDiskIOPSOther'),0,'520m')])
    for obsolete in [4000,10000]:
        data=copy.deepcopy(positive_fixtures()['OpenStackInstanceHighDiskIOPSOther']['data'])
        data.append(series('oie:disk_iops:review_limit',str(obsolete)+'x530',{'job':HOST['job'],'disk_type':'vms'}))
        add('retired tier cap does not alter adaptive alerts '+str(obsolete),data,[check(alerts('.*HighDiskIOPSOther'),1,'520m')])
    disk=DISK | {'disk_type':'volumes'}
    data=health(end=600)+[series('oie_instance_disk_read_iops','50x480 1500x119',disk),series('oie_instance_disk_write_iops','50x480 1500x119',disk)]
    data += [series('oie_instance_disk_read_requests_total','0+600x600',disk),series('oie_instance_disk_read_seconds_total','0+180x600',disk)]
    replace(data,'oie_host_libvirt_ok','1x510 0x4 1x84')
    add('an interrupted adaptive disk hold restarts',data,[check(alerts('.*HighDiskIOPSVolumes'),0,'520m'),check(alerts('.*HighDiskIOPSVolumes'),1,'550m')])
    data = health() + [series('oie_instance_cpu_vcpu_percent', '20x5 100x3 20x51', VM)]
    add('brief CPU benchmark is not sustained consumption', data, [check(alerts('.*HighCPUUsage'), 0)])
    # Counter reset without a new rate must not create a drop/latency event.
    data = health() + [series('oie_instance_net_rx_packets_total', '100000x20 0x39', NIC),
                       series('oie_instance_net_rx_dropped_total', '10000x20 0x39', NIC)]
    add('counter reset does not manufacture packet loss', data, [check(alerts('.*NetworkReceiveDropRatioHigh'), 0)])
    return cases


def notification_noise_cases():
    """Busy but healthy and wrongly-attributed impact must not notify.

    These preserve the activity, network shape and port evidence of positive
    cases. They are not idle/empty-input substitutes for false-positive testing.
    """
    cases=[]
    def add(name,data,checks):
        cases.append({'name':name,'interval':'1m','input_series':data,'promql_expr_test':checks})
    fixtures=positive_fixtures()
    workload_names=['HighCPUUsage','HighMajorFaultRate','HighDiskThroughput',
        'HighIncomingPacketRate','HighOutgoingPacketRate','HighBandwidthRateRX','HighBandwidthRateTX',
        'ConntrackFlowsBurst','HighConntrackFlowsSustained','PossibleFlood',
        'TorExitRepeatedContact','TorRelayRepeatedContact','ExporterProcessCPUHigh']
    workload_names += ['HighDiskIOPS'+tier for tier in ['Local','Volumes','Premium','Ultra','Other']]
    for d in ['Outbound','Inbound']:
        workload_names += [d+s for s in ['PortScanBurst','SingleTargetFlood' if d=='Outbound' else 'SingleSourceFlood','SprayOnSinglePort','ExtremeRemoteFanout','ZombieFlowLowThroughput']]
    impact_metrics=['cpu_steal_seconds_total','mem_swap_in_bytes_total','disk_read_seconds_total',
        'net_rx_dropped_total','net_tx_dropped_total','net_rx_errors_total','net_tx_errors_total',
        'conntrack_utilization','collection_cycle_duration_seconds']
    for short in workload_names:
        name='OpenStackInstance'+short;fixture=fixtures[name];end=fixture['end']
        for mode in ['healthy','missing']:
            data=copy.deepcopy(fixture['data'])
            for item in list(data):
                metric=item['series'].split('{')[0]
                if any(metric.endswith(m) for m in impact_metrics):
                    if mode=='missing':data.remove(item)
                    else:item['values']=f'0x{end}'
            add(f'busy {mode} corroboration: {short}',data,[check(alerts(),0,f'{end-2}m'),check(alerts(state='pending'),0,f'{end-2}m')])
    # Same VM, different device must not lend latency or packet impact.
    for short,metric_prefix,label,replacement in [
        ('HighDiskIOPSPremium','oie_instance_disk_read_','disk_path','vdb'),
        ('HighBandwidthRateTX','oie_instance_net_rx_','ifname','tap-b')]:
        fixture=fixtures['OpenStackInstance'+short];data=copy.deepcopy(fixture['data'])
        for item in data:
            if item['series'].startswith(metric_prefix) and not item['series'].startswith('oie_instance_disk_read_iops'):
                item['series']=re.sub(label+r'="[^"]*"',label+'="'+replacement+'"',item['series'])
        add('other resource cannot lend impact: '+short,data,[check(alerts('OpenStackInstance'+short),0,'520m')])
    # Even two running VMs on the same target cannot share CPU/loss corroboration.
    for short,prefix in [('HighCPUUsage','oie_instance_cpu_steal_'),('PossibleFlood','oie_instance_net_')]:
        fixture=fixtures['OpenStackInstance'+short];data=copy.deepcopy(fixture['data'])
        for item in data:
            if item['series'].startswith(prefix):item['series']=item['series'].replace('instance_uuid="vm-a"','instance_uuid="vm-b"')
        for item in health():
            if 'instance_uuid="vm-a"' in item['series']:
                candidate=copy.deepcopy(item);candidate['series']=candidate['series'].replace('instance_uuid="vm-a"','instance_uuid="vm-b"');data.append(candidate)
        add('other running VM cannot lend impact: '+short,data,[check(alerts('OpenStackInstance'+short),0)])
    for title,metric in [('Spamhaus','spamhaus'),('EmergingThreats','emergingthreats'),('CustomList','customlist')]:
        for direction,pressure,expected in [('out',0.1,1),('in',0.9,0),('any',0.1,0),('any',0.9,1)]:
            data=health()+[series('oie_instance_threat_'+metric+'_active_flows','2x60',VM | {'direction':direction}),series('oie_host_conntrack_utilization',str(pressure)+'x60',HOST)]
            add(f'reputation {title} scope={direction} pressure={pressure}',data,[check(alerts('.*'+title+'RepeatedContact'),expected)])
    for cpu,expected in [(0,0),(30,0),(50,1)]:
        data=health()+[series('oie_instance_mining_suspected','1x60',VM | {'confidence':'high_persistent'}),series('oie_instance_cpu_vcpu_percent',str(cpu)+'x60',VM)]
        add('dedicated-port candidate CPU '+str(cpu),data,[check(alerts('.*MiningCandidatePersistent'),expected),check(alerts('.*MiningSuspected'),0)])
    data=health()+[series('oie_instance_mining_suspected','1x60',VM | {'confidence':c}) for c in ['high','high_persistent']]+[series('oie_instance_cpu_vcpu_percent','50x60',VM)]
    add('strong mining evidence does not duplicate candidate notification',data,[check(alerts('.*MiningSuspected'),1),check(alerts('.*MiningCandidatePersistent'),0)])
    # Actual loss while no baseline exists still qualifies. A large adaptive
    # change without packet impact must not become a flood after warm-up either.
    data=health(end=530)+[series('oie_instance_conntrack_ip_flows','1000x480 50000x49',IP),series('oie_instance_net_rx_packets_total','0+600x480 288600+9000000x49',NIC)]
    add('flow and packet baseline changes without loss are not a flood',data,[check(alerts('.*PossibleFlood'),0,'520m')])
    # Loss on another target with the same VM UUID must not cross the host key.
    data=copy.deepcopy(fixtures['OpenStackInstancePossibleFlood']['data'])
    for item in data:
        if item['series'].startswith('oie_instance_net_'):item['series']=item['series'].replace('compute-a:9120','compute-b:9120')
    add('other exporter target cannot lend impact',data,[check(alerts('.*PossibleFlood'),0)])
    return cases


class FixtureCoverage(unittest.TestCase):
    def test_all_shipped_alerts_have_lifecycle_observations(self):
        self.assertEqual(set(positive_fixtures()), set(DEFINITIONS))
        self.assertEqual(len(lifecycle_cases()), 62)
        self.assertEqual(len(normal_cases()), 62)
        self.assertGreaterEqual(len(mitigation_cases()), 30)
        self.assertEqual(len(disk_policy_cases()), 5)
        for case in lifecycle_cases() + normal_cases() + mitigation_cases() + disk_policy_cases() + regression_cases() + notification_noise_cases():
            identities = [s['series'] for s in case['input_series']]
            self.assertEqual(len(identities), len(set(identities)), case['name'])
            self.assertTrue(case['promql_expr_test'], case['name'])


    def test_each_fixture_preserves_workload_identity_at_all_scrape_cadences(self):
        for case in lifecycle_cases() + normal_cases() + regression_cases():
            for cadence in [15, 30, 60]:
                candidate=resample_case(case,cadence)
                self.assertEqual([i['series'] for i in case['input_series']],
                                 [i['series'] for i in candidate['input_series']])
                for before,after in zip(case['input_series'],candidate['input_series']):
                    a=expanded_values(before['values']);b=expanded_values(after['values'])
                    self.assertEqual(a,b[::60//cadence],case['name'])

    def test_every_lifecycle_restores_healthy_values_without_deleting_all_series(self):
        for case in lifecycle_cases():
            for item in case['input_series']:
                points=expanded_values(item['values'])
                self.assertTrue(all(isinstance(v,(int,float)) for v in points[-12:]),case['name'])
                if item['series'].startswith('up{'):
                    self.assertEqual(points[-1],1)



@unittest.skipUnless(PROMTOOL, 'Promtool is required to execute the native rule fixtures')
class NativePrometheusPolicy(unittest.TestCase):
    def run_cases(self, cases, evaluation_interval='30s', group_order=None):
        with tempfile.TemporaryDirectory(prefix='oie-policy-') as directory:
            root = Path(directory)
            (root/'rules.yml').write_text(render())
            (root/'tests.yml').write_text(yaml.safe_dump({'rule_files': [str(root/'rules.yml')],
                'evaluation_interval': evaluation_interval,
                'group_eval_order': group_order or [g['name'] for g in yaml.safe_load(render())['groups']],
                'tests': cases}, sort_keys=False))
            result = subprocess.run([PROMTOOL, 'test', 'rules', str(root/'tests.yml')], text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertNotIn('error executing template', result.stderr.lower())

    def test_all_alerts_fire_respect_holds_and_recover(self):
        for evaluation in ['15s', '30s', '60s']:
            for scrape in [15, 30, 60]:
                with self.subTest(evaluation=evaluation, scrape=scrape):
                    self.run_cases([resample_case(c, scrape) for c in lifecycle_cases() + normal_cases()], evaluation)

    def test_legitimate_workloads_missing_data_and_faults(self):
        self.run_cases(mitigation_cases())

    def test_disk_review_is_combined_per_volume_not_per_direction_or_vm(self):
        self.run_cases(disk_policy_cases())

    def test_regressions_at_common_evaluation_intervals(self):
        for cadence in ['15s', '30s', '60s']:
            with self.subTest(cadence=cadence):
                self.run_cases(regression_cases(), cadence)

    def test_busy_healthy_workloads_and_corroboration_identity(self):
        self.run_cases(notification_noise_cases(), '60s')

    def test_real_annotation_values_and_missing_optional_context(self):
        data = health() + [series('oie_host_conntrack_utilization', '0.9x60')]
        annotations = {'summary': 'Host conntrack pressure — compute-a:9120', 'description':
            'Host conntrack usage 90%; limit 80%. Check connection pools and top contributing instances. Host: compute-a:9120.'}
        self.run_cases([{'name': 'native annotation rendering', 'interval': '1m', 'input_series': data,
            'alert_rule_test': [{'eval_time': '10m', 'alertname': 'OpenStackInstanceExporterHostConntrackUtilizationHigh',
                'exp_alerts': [{'exp_labels': HOST | {'severity': 'warning', 'type': 'capacity'}, 'exp_annotations': annotations}]}]}])


if __name__ == '__main__':
    unittest.main()
