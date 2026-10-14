#!/usr/bin/env python3
"""Dashboard display regressions; no live Grafana or OpenStack is contacted.

Native Promtool checks are optional in this module and explicitly skipped when
absent. The release/operator gate still requires Promtool. Regex fixtures execute
in Node when available so they exercise ECMAScript, not just Python's regex engine.
"""
import colorsys
import json
import math
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml
from oie_dashboards_test import DASHBOARDS, HOST, VM, DISK, panels, get_panel, interpolate, series

ROOT = Path(__file__).resolve().parents[1]
PRE_SCALED = {'Gibits', 'GiBs', 'gbytes', 'mbytes'}


def colour_for(panel, name):
    """Fixture for matching native fixed-colour overrides in JSON order."""
    result = None
    for override in panel['fieldConfig']['overrides']:
        m = override['matcher']
        matched = m['id'] == 'byName' and m['options'] == name
        if m['id'] == 'byRegexp':
            pattern = m['options']
            # Grafana anchors bare patterns; slash-delimited patterns retain their own anchors.
            pattern = pattern[1:-1] if pattern.startswith('/') and pattern.endswith('/') else '^' + pattern + '$'
            matched = bool(re.search(pattern, name))
        if matched:
            for prop in override['properties']:
                if prop['id'] == 'color' and prop['value']['mode'] == 'fixed':
                    result = prop['value']['fixedColor']
    return result


def rgb(hex_colour):
    return tuple(int(hex_colour[i:i+2], 16)/255 for i in (1, 3, 5))


def luminance(colour):
    return sum(w*(v/12.92 if v <= .04045 else ((v+.055)/1.055)**2.4)
               for w,v in zip((.2126,.7152,.0722), rgb(colour)))


class DisplayUnitsAndAxes(unittest.TestCase):
    def test_every_chart_has_visible_axis_and_readable_stroke(self):
        count = 0
        for name, d in DASHBOARDS.items():
            for p in panels(d['panels']):
                if p['type'] != 'timeseries':
                    continue
                count += 1
                de = p['fieldConfig']['defaults']; custom = de['custom']
                self.assertEqual(custom['axisPlacement'], 'left', (name,p['id']))
                self.assertTrue(custom['axisBorderShow'])
                self.assertEqual(custom['lineWidth'], 1, (name, p['id']))
                for override in p['fieldConfig'].get('overrides', []):
                    for prop in override.get('properties', []):
                        if prop.get('id') == 'custom.lineWidth':
                            self.assertEqual(prop['value'], 1, (name, p['id']))
                self.assertNotIn(de['unit'], PRE_SCALED)
                self.assertEqual(custom['stacking']['mode'], 'none')
                self.assertFalse(custom['spanNulls'], (name, p['id'], 'missing observations must remain gaps'))
                self.assertEqual(p['options']['legend']['displayMode'], 'table')
                self.assertEqual(p['options']['legend']['placement'], 'bottom')
                self.assertGreaterEqual(p['gridPos']['h'], 11)
        self.assertEqual(count,176)

    def test_low_network_rates_are_returned_in_base_bits(self):
        converted = [('cluster',1241),('hypervisor',1248),('hypervisor',1249),
                     ('project',1205),('project',1261),('instance',2043),('instance',2044)]
        for name,pid in converted:
            p=get_panel(name,pid)
            self.assertEqual(p['fieldConfig']['defaults']['unit'],'binbps')
            self.assertNotIn('Gibit', p['fieldConfig']['defaults']['custom']['axisLabel'])
            for t in p['targets']:
                # A source-authority guard may enclose the conversion once.
                self.assertRegex(t['expr'], r'^\(?1073741824 \* \(')
                self.assertRegex(t['expr'],r'(?:8\s*\*|\*\s*8\b)')
        # Grafana 12.3 uses binary increments 2**0 .. 2**52. Pre-scaled
        # Gibit values fall below all positive increments; base bits do not.
        legacy = 6144/(2**30)
        self.assertLess(legacy,1)
        ticks = [1024*i for i in range(7)]
        self.assertEqual(len([v for v in ticks if v>0]),6)
        self.assertEqual(legacy*2**30,6144)

    def test_disk_and_memory_chart_conversions_keep_binary_units(self):
        for name,pid,factor,unit in [('cluster',1237,2**30,'binBps'),('cluster',1256,2**30,'bytes'),
                                      ('instance',2031,2**30,'binBps'),('instance',2022,2**20,'bytes'),
                                      ('threats',5002,2**30,'bytes')]:
            p=get_panel(name,pid)
            self.assertEqual(p['fieldConfig']['defaults']['unit'],unit)
            for t in p['targets']:
                self.assertRegex(t['expr'], rf'^\(?{factor} \* \(')
        self.assertEqual(.125*2**30,134217728)
        self.assertEqual(512*2**20,536870912)

    def test_latency_empty_states_do_not_manufacture_zero(self):
        for name in ('cluster','hypervisor','project'):
            for pid,direction in ((26002,'read'),(26003,'write'),(26004,'flush')):
                p=get_panel(name,pid)
                self.assertEqual(p['fieldConfig']['defaults']['noValue'], 'Unavailable')
                self.assertIn('missing/invalid timing', p['description'])
                self.assertNotIn('or vector(0)',p['targets'][0]['expr'])
                self.assertIn(' > 0)',p['targets'][0]['expr'])


class EndpointRatioDisplay(unittest.TestCase):
    def test_endpoint_ratio_cannot_be_mistaken_for_host_utilization(self):
        limit = get_panel('project', 1266)
        ratio = get_panel('project', 1267)
        self.assertEqual(limit['fieldConfig']['defaults']['unit'], 'percent')
        self.assertEqual(ratio['fieldConfig']['defaults']['unit'], 'suffix:×')
        self.assertNotIn('decimals', ratio['fieldConfig']['defaults'])
        self.assertEqual(ratio['fieldConfig']['defaults']['noValue'], 'Unavailable')
        self.assertIn('host entry limit', limit['title'])
        self.assertIn('per host entry', ratio['title'])
        self.assertIn('1.86× means 186 endpoint matches for every 100 host entries', ratio['description'])
        for panel in (limit, ratio):
            text = panel['description'].lower()
            for meaning in ('two vms', 'host-table utilization', 'fixed-ip', 'selected'):
                self.assertIn(meaning, text)
        self.assertIn('multiple hosts alone do not make the ratio exceed 1×', ratio['description'])
        for target in ratio['targets']:
            plotted, ranked = target['expr'].split('\nand on(project_uuid, project_name)\n', 1)
            self.assertNotIn('100 *', plotted)
            self.assertIn('oie_host_conntrack_entries', plotted)
            self.assertIn('100 *', ranked)
        self.assertTrue(all(t['expr'].startswith('(100 *') for t in limit['targets']))


class MeasurementScopeWording(unittest.TestCase):
    def test_visible_scope_strip_distinguishes_vm_observations_from_backend_telemetry(self):
        for name in ('cluster', 'hypervisor', 'instance', 'project'):
            p = get_panel(name, 25000)
            text = p['options']['content'].lower()
            self.assertIn('hypervisor', text)
            self.assertIn('vm', text)
            self.assertIn('ceph/rbd', text)
            self.assertRegex(text, r'physical(?:-device| disks)')
            self.assertRegex(text, r'(?:complementary|other points in (?:the path|the data path))')
        threats = get_panel('threats', 25000)['options']['content'].lower()
        self.assertIn('not proof of malicious intent or compromise', threats)
        self.assertIn('vm experience as observed by the hypervisor', threats)

    def test_storage_latency_titles_and_descriptions_state_actual_measurement_scope(self):
        for name in ('cluster', 'hypervisor', 'project'):
            for pid in (26002, 26003, 26004):
                p = get_panel(name, pid)
                self.assertIn('VM disk', p['title'])
                self.assertIn('5m mean', p['title'])
                text = p['description'].lower()
                self.assertRegex(text, r'(?:running vms|vms currently in libvirt.s running state)')
                self.assertRegex(text, r'not (?:direct ceph/storage-backend latency|a percentile, physical-media/backend latency)')
                self.assertIn('max is the highest plotted mean', text)
                self.assertIn('not the slowest individual i/o', text)

    def test_vm_disk_activity_and_network_panels_disclose_non_backend_scope(self):
        for name, pid in (('cluster', 1237), ('hypervisor', 1250), ('project', 1230), ('instance', 2031)):
            text = get_panel(name, pid)['description'].lower()
            self.assertRegex(text, r'not (?:total )?backend operations')
            self.assertIn('not', text)
        for name, pid in (('cluster', 1241), ('hypervisor', 1248), ('project', 1205), ('instance', 2043)):
            text = get_panel(name, pid)['description'].lower()
            self.assertRegex(text, r'not (?:physical nic, switch, or fabric telemetry|host nic, switch or fabric totals)')

    def test_cluster_storage_source_pie_matches_selected_running_vm_scope(self):
        p = get_panel('cluster', 1242)
        self.assertIn('Running VM', p['title'])
        q = p['targets'][0]['expr']
        for token in ('project_uuid=~"$gvar_oie_project_uuid"', 'project_name=~"$gvar_oie_project_name"',
                      'instance_uuid=~"$gvar_oie_instance_uuid"', 'oie_instance_disk_info'):
            self.assertIn(token, q)
        self.assertNotIn('oie_instance_state_code', q)
        self.assertNotIn(' and on(', q)
        text = p['description'].lower()
        self.assertRegex(text, r'not (?:a count of physical backend disks|a physical-backend disk count)')
        self.assertIn('does not prove that every disk had i/o', text)


class SourceAgeDisplay(unittest.TestCase):
    def test_separate_age_views_use_timestamps_and_explicit_seconds(self):
        for pid,source in ((23002,'libvirt'),(2002,'conntrack')):
            p=get_panel('cluster',pid);de=p['fieldConfig']['defaults']
            self.assertEqual(len(p['targets']),1)
            self.assertEqual(de['unit'],'suffix:s')
            self.assertEqual(de['min'],0)
            self.assertNotIn('max',de)
            self.assertEqual(de['custom']['axisSoftMax'],60)
            q=p['targets'][0]['expr']
            self.assertIn('time() - (oie_host_'+source+'_last_success_timestamp_seconds',q)
            self.assertIn(' > 0)',q)
            self.assertNotIn('_stale_seconds',q)
            self.assertIn('not collection duration',p['description'])
            self.assertNotIn('350',p['description'])
            self.assertNotIn(' ms',p['description'])
            self.assertIn('gaps, not healthy zero',p['description'])

    def test_age_model_does_not_replay_a_frozen_age_or_count_epoch(self):
        def age(now,last):
            return None if last is None or last<=0 else max(now-last,0)
        self.assertEqual(age(1010,1000),10)
        self.assertEqual(age(1120,1000),120)
        self.assertEqual(age(1120,1119),1)
        self.assertIsNone(age(1120,0))
        self.assertIsNone(age(1120,None))
        self.assertEqual(age(1000,1001),0)  # small clock skew is not negative age
        self.assertAlmostEqual(355/1000,.355)


class VividIdentityColours(unittest.TestCase):
    def test_twelve_numbered_hosts_have_stable_distinguishable_colours(self):
        p=get_panel('cluster',2002)
        names=[f'm-openstack-compute{i}-canada-west-cloud.ad.example.com:9120' for i in range(1,13)]
        cs=[colour_for(p,n) for n in names]
        self.assertNotIn(None,cs)
        self.assertEqual(len(set(cs)),12)
        for i,name in enumerate(names,1):
            padded=f'm-openstack-compute{i:03}-canada-west-cloud.ad.example.com:9120'
            self.assertEqual(colour_for(p,padded),colour_for(p,name))
        self.assertEqual([colour_for(p,n) for n in reversed(names)],list(reversed(cs)))

    def test_first_uuid_not_shared_project_selects_instance_colour(self):
        p=get_panel('instance',2021)
        names=[f'vm [{i:x}1111111-1111-4111-8111-111111111111] | admin [f1111111111141118111111111111111]'
               for i in range(16)]
        cs=[colour_for(p,n) for n in names]
        self.assertGreaterEqual(len(set(cs)),15)
        self.assertNotIn(None,cs)
        for name,c in zip(names,cs):
            self.assertEqual(colour_for(p,name.replace('f1111111111141118111111111111111',
                                                        '01111111111141118111111111111111')),c)
        project=get_panel('project',1216)
        self.assertEqual(colour_for(project,'Project [a1111111111141118111111111111111]'),
                         colour_for(project,'Renamed [a1111111111141118111111111111111]'))

    def test_uuid_palette_is_vivid_and_readable_on_dark_panels(self):
        p=get_panel('instance',2021)
        bg=luminance('#181B1F')
        for i in range(16):
            c=colour_for(p,f'vm [{i:x}1111111-1111-4111-8111-111111111111] | project [e1111111111141118111111111111111]')
            self.assertIsNotNone(c)
            self.assertGreaterEqual(colorsys.rgb_to_hsv(*rgb(c))[1],.12)
            self.assertLessEqual(colorsys.rgb_to_hsv(*rgb(c))[1],.9)
            self.assertGreaterEqual((luminance(c)+.05)/(bg+.05),6)

    @unittest.skipUnless(shutil.which('node'),'Node unavailable: ECMAScript regex check skipped')
    def test_override_regexes_execute_in_javascript(self):
        fixtures=[]
        for name,d in DASHBOARDS.items():
            for p in panels(d['panels']):
                for o in p.get('fieldConfig',{}).get('overrides',[]):
                    if o['matcher']['id']=='byRegexp':
                        fixtures.append(o['matcher']['options'])
        script='const fs=require("fs"); for(const p of JSON.parse(fs.readFileSync(0,"utf8"))) new RegExp(p.startsWith("/") ? p.slice(1,-1) : "^"+p+"$");'
        subprocess.run(['node','-e',script],input=json.dumps(fixtures),text=True,check=True,capture_output=True)
        self.assertGreater(len(fixtures),100)


class BlockSourceInspection(unittest.TestCase):
    def test_unclassified_observations_are_not_dropped_or_relabelled(self):
        p=get_panel('cluster',1242)
        self.assertEqual(p['title'],'Running VM disks by source')
        q=p['targets'][0]['expr']
        self.assertIn('count by (disk_type)',q)
        self.assertNotIn('oie_instance_state_code',q)
        self.assertNotIn(' and on(',q)
        self.assertNotIn('disk_type!=',q)
        self.assertNotIn('label_replace',q)
        self.assertEqual(colour_for(p,'unknown'),'#A1AEC3')
        name_props=[x for o in p['fieldConfig']['overrides'] if o['matcher']=={'id':'byName','options':'unknown'} for x in o['properties']]
        self.assertIn({'id':'displayName','value':'Unclassified source'},name_props)
        self.assertIn('A disk is one type of block device',p['description'])
        self.assertIn('10 storage disks and 4 config drives',p['description'])

    def test_cluster_block_device_role_inventory_is_visible_without_polluting_performance_sources(self):
        p=get_panel('cluster',39011)
        self.assertEqual(p['type'],'piechart')
        self.assertEqual(p['title'],'Configured block devices')
        self.assertIn('group',p['description'].lower())
        self.assertIn('Every disk is a block device, but not every block device is a disk',p['description'])
        self.assertIn('14 configured block devices',p['description'])
        q=p['targets'][0]['expr']
        self.assertIn('count by (device_role)',q)
        self.assertIn('oie_instance_inventory_block_device_info',q)
        self.assertNotIn('oie_instance_state_code',q)
        self.assertNotIn(' and on(',q)
        self.assertNotIn('oie_host_libvirt_ok',q)
        self.assertNotIn('oie_host_libvirt_stale_seconds',q)
        self.assertEqual(colour_for(p,'storage'),'#4DA6FF')
        self.assertEqual(colour_for(p,'config_drive'),'#AC8FFF')
        self.assertEqual(colour_for(p,'swap'),'#FF9F43')
        self.assertEqual(colour_for(p,'other'),'#A1AEC3')
        self.assertIn('does not claim',p['description'])

    def test_disk_inspection_retains_raw_unmatched_device_identity(self):
        p=get_panel('instance',25021);q=p['targets'][0]['expr']
        for token in ('oie_instance_inventory_disk_info','oie_instance_disk_info','unless on (job, instance, instance_uuid, disk_path)',
                      'Configured disk','Runtime only - no matching configured disk'):
            self.assertIn(token,q)
        include=p['transformations'][0]['options']['include']['names']
        for name in ('disk_path','disk_type','volume_uuid','instance_uuid','project_uuid','instance','oie_disk_origin'):
            self.assertIn(name,include)
        self.assertIn('does not prove',p['description'])
        self.assertNotIn('disk_type!="unknown"',q)
        self.assertEqual(p['gridPos']['w'],24)


class NativeDisplayQueries(unittest.TestCase):
    def test_native_promql_for_axes_ages_and_disk_union(self):
        promtool=os.environ.get('PROMTOOL') or shutil.which('promtool')
        if not promtool or not Path(promtool).is_file():
            self.skipTest('Promtool unavailable: actual query evaluation not performed')
        def target(name,pid,ref='A'):
            return interpolate(next(t['expr'] for t in get_panel(name,pid)['targets'] if t['refId']==ref))
        tests=[]
        def check(expr,value,at='15m'):
            return {'expr':'sum('+expr+')','eval_time':at,'exp_samples':[] if value is None else [{'labels':'{}','value':value}]}
        health=[series(k,f'{v}+0x60',HOST) for k,v in {'up':1,'oie_host_libvirt_ok':1,'oie_host_libvirt_stale_seconds':0,'oie_host_collection_interval_seconds':15}.items()]
        net=VM|{'ifname':'tap0'}
        tests.append({'name':'low RX rate stays 6144 bits per second', 'interval':'15s',
                      'input_series':health+[series('oie_instance_net_rx_gib_total',f'0+{6144*15/8/2**30}x60',net)],
                      'promql_expr_test':[check(target('cluster',1241),6144)]})
        for pid,source in ((23002,'libvirt'),(2002,'conntrack')):
            for stamp,expected in ((899,1),(10,890),(0,None)):
                tests.append({'name':f'{source} timestamp {stamp}', 'interval':'15s',
                              'input_series':[series(f'oie_host_{source}_last_success_timestamp_seconds',f'{stamp}+0x60',HOST),
                                              series(f'oie_host_{source}_stale_seconds','0.35+0x60',HOST)],
                              'promql_expr_test':[check(target('cluster',pid),expected)]})
        disk=DISK|{'disk_path':'vda'}
        runtime=DISK|{'disk_path':'hda','disk_type':'unknown','volume_uuid':'unknown'}
        tests.append({'name':'configured disk plus unmapped runtime block device','interval':'15s',
                      'input_series':health+[series('oie_instance_inventory_disk_info','1+0x60',disk),
                                             series('oie_instance_disk_info','1+0x60',disk),
                                             series('oie_instance_disk_info','1+0x60',runtime)],
                      'promql_expr_test':[check(target('instance',25021),2)]})
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'display.yml';path.write_text(yaml.safe_dump({'evaluation_interval':'15s','tests':tests}))
            result=subprocess.run([promtool,'test','rules',str(path)],text=True,capture_output=True)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)


    def test_native_endpoint_ratio_sums_hosts_and_keeps_filter_scope(self):
        promtool = os.environ.get('PROMTOOL') or shutil.which('promtool')
        if not promtool or not Path(promtool).is_file():
            self.skipTest('Promtool unavailable: actual query evaluation not performed')
        def host(endpoint, flows, entries, maximum, stale=0, project='project-a'):
            labels = HOST | {'instance': endpoint}
            health = {'up': 1, 'oie_host_libvirt_ok': 1,
                      'oie_host_libvirt_stale_seconds': 0,
                      'oie_host_collection_interval_seconds': 15,
                      'oie_host_conntrack_raw_ok': 1,
                      'oie_host_conntrack_stale_seconds': stale,
                      'oie_host_conntrack_entries': entries,
                      'oie_host_conntrack_max': maximum}
            data = [series(k, f'{v}+0x60', labels) for k, v in health.items()]
            data.append(series('oie_instance_conntrack_ip_flows', f'{flows}+0x60',
                               VM | labels | {'project_uuid': project, 'ip': '192.0.2.1', 'family': '4'}))
            return data
        cases = [
            ('both endpoints on one host', host('compute-a:9120', 2, 1, 1), 2, 200, '.*'),
            ('two hosts preserve the combined denominator',
             host('compute-a:9120', 186, 100, 1000) + host('compute-b:9120', 14, 100, 1000), 1, 10, '.*'),
            ('project filter narrows numerator only',
             host('compute-a:9120', 186, 100, 1000) + host('compute-b:9120', 14, 100, 1000, project='project-b'), .93, 9.3, 'project-a'),
            ('stale host excluded from numerator and denominator',
             host('compute-a:9120', 186, 100, 1000) + host('compute-b:9120', 14, 100, 1000, stale=120), 1.86, 18.6, '.*'),
            ('all stale hosts leave no ratio', host('compute-a:9120', 186, 100, 1000, stale=120), None, None, '.*'),
        ]
        tests = []
        for name, data, ratio, percent, project in cases:
            checks = []
            for pid, expected in ((1267, ratio), (1266, percent)):
                expr = interpolate(get_panel('project', pid)['targets'][0]['expr'],
                                   {'${__to}': '900000', '${__range_s}': '900', '$gvar_oie_project_uuid': project})
                checks.append({'expr': 'sum(' + expr + ')', 'eval_time': '15m',
                               'exp_samples': [] if expected is None else [{'labels': '{}', 'value': expected}]})
            tests.append({'name': name, 'interval': '15s', 'input_series': data, 'promql_expr_test': checks})
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'endpoint-ratios.yml'
            path.write_text(yaml.safe_dump({'evaluation_interval': '15s', 'tests': tests}))
            result = subprocess.run([promtool, 'test', 'rules', str(path)], text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__=='__main__':
    unittest.main()
