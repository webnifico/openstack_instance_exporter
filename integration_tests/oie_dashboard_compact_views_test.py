#!/usr/bin/env python3
"""Native checks for compact scheduler, disk and retype views."""
import copy
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import yaml
from oie_dashboards_test import DASHBOARDS, HOST, VM, DISK, get_panel, interpolate, panels, series
from oie_dashboard_overview_test import source
from oie_storage_latency_test import disk, unique, change, expect

class CompactViews(unittest.TestCase):
    def test_layout_budget_and_identity(self):
        self.assertEqual(sum(p['type']=='row' for d in DASHBOARDS.values() for p in panels(d['panels'])),52)
        expected={'instance':69,'hypervisor':62}
        for name,count in expected.items():
            all_panels=list(panels(DASHBOARDS[name]['panels']))
            self.assertEqual(len(all_panels),count)
            self.assertTrue(all(r.get('collapsed') for r in all_panels if r['type']=='row'))
            self.assertEqual(len({p['id'] for p in all_panels}),len(all_panels))
            for row in DASHBOARDS[name]['panels']:
                for i,a in enumerate(row.get('panels',[])):
                    x=a['gridPos']
                    for b in row['panels'][i+1:]:
                        y=b['gridPos']
                        overlap=x['x']<y['x']+y['w'] and y['x']<x['x']+x['w'] and x['y']<y['y']+y['h'] and y['y']<x['y']+x['h']
                        self.assertFalse(overlap,(name,a['id'],b['id']))
            for pid in (24005,24006):
                p=get_panel(name,pid)
                self.assertEqual(p['gridPos']['w'],24)
                self.assertFalse(p['options']['enablePagination'])
                self.assertIn('destination_volume_uuid',p['targets'][0]['expr'])
        latency=get_panel('instance',2074)
        self.assertEqual(len(latency['targets']),3)
        self.assertEqual(latency['fieldConfig']['defaults']['unit'],'ms')
        self.assertNotIn(2075,{p['id'] for p in panels(DASHBOARDS['instance']['panels'])})
        self.assertEqual(get_panel('instance',2024)['fieldConfig']['defaults']['unit'],'suffix:ms/s')

    def test_native_measurements(self):
        promtool=os.environ.get('PROMTOOL')
        if not promtool:self.skipTest('PROMTOOL is required for native queries')
        records={};cases=[]
        def q(name,pid,ref='A',replace=None):
            target=next(t for t in get_panel(name,pid)['targets'] if t['refId']==ref)
            expr=interpolate(target['expr'],replace)
            if expr not in records:records[expr]='oie_compact_'+str(len(records))
            return records[expr]
        def case(name,data,checks):cases.append({'name':name,'interval':'15s','input_series':unique(data),'promql_expr_test':checks})
        cpu=q('instance',2024)
        state=[series('oie_instance_state_code','1+0x20',VM)]
        # Two aliases on vCPU0 must not add together; vCPU1 only has the fallback.
        cpu_data=source()+state+[series('oie_instance_cpu_vcpu_count','2+0x20',VM),series('oie_instance_cpu_steal_seconds_total','0+3x20',VM|{'vcpu':'0'}),series('oie_instance_cpu_wait_seconds_total','0+12x20',VM|{'vcpu':'0'}),series('oie_instance_cpu_wait_seconds_total','0+1.5x20',VM|{'vcpu':'1'})]
        case('scheduler sums vCPUs and prefers delay over wait',cpu_data,[expect('sum('+cpu+')',300)])
        data=copy.deepcopy(cpu_data);change(data,'oie_instance_cpu_steal_seconds_total');case('wait fallback when delay is absent',data,[expect('sum('+cpu+')',900)])
        for metric in ('up','oie_host_libvirt_ok','oie_instance_state_code'):
            data=copy.deepcopy(cpu_data);change(data,metric,'0+0x20');case('scheduler unavailable '+metric,data,[expect('sum('+cpu+')')])
        data=copy.deepcopy(cpu_data);change(data,'oie_instance_cpu_steal_seconds_total','0+3x19 stale');change(data,'oie_instance_cpu_wait_seconds_total','0+3x19 stale');case('scheduler never reuses stale counters',data,[expect('sum('+cpu+')')])
        second=DISK|{'disk_path':'vdb','volume_uuid':'volume-second'}
        disks=source()+disk()+disk(second,read=(30,30),write=(10,50),flush=(6,15))
        for ref,first,last in [('A',10,30),('B',20,50),('C',5,15)]:
            v=q('instance',2074,ref);case('per-disk latency '+ref,disks,[expect('count('+v+')',2),expect('sum('+v+'{disk_path="vda"})',first),expect('sum('+v+'{disk_path="vdb"})',last)])
        flush=q('instance',2074,'C');data=copy.deepcopy(disks);change(data,'oie_instance_disk_flush_requests_total');case('missing flush requests stays missing',data,[expect('sum('+flush+')')])
        case('zero flush requests stays missing',source()+disk(flush=(0,5)),[expect('sum('+flush+')')])
        case('failed source hides latency',source(oie_host_libvirt_ok=0)+disk(),[expect('sum('+flush+')')])
        case('inactive VM hides latency',source()+disk(state=5),[expect('sum('+flush+')')])
        filtered=q('instance',2074,'C',{'${gvar_oie_volume_uuid}':'second'});case('volume selector restricts latency to one disk',disks,[expect('count('+filtered+')',1),expect('sum('+filtered+')',15)])
        op=DISK|{'destination_disk_type':'premium','destination_volume_uuid':'volume-destination'}
        op2=op|{'disk_path':'vdb','volume_uuid':'volume-second','destination_volume_uuid':'volume-destination-2'}
        active=[]
        for labels in (op,op2):
            for suffix,value in [('active',1),('status_code',1),('progress_percent',35),('observation_healthy',0),('start_timestamp_seconds',15)]:active.append(series('oie_instance_disk_retype_'+suffix,f'{value}+0x20',labels))
        for name in ('instance','hypervisor'):
            v=q(name,24005);case(name+' retype identity and unhealthy observations retained',source()+active,[expect('count('+v+'{retype_field="status"})',2),expect('sum('+v+'{retype_field="progress"})',70),expect('sum('+v+'{retype_field="observation"})',0)])
            history=[series('oie_instance_disk_retype_status_code','1+0x7 2 stale',op),series('oie_instance_disk_retype_start_timestamp_seconds','15+0x8 stale',op),series('oie_instance_disk_retype_end_timestamp_seconds','0+0x7 120 stale',op)]
            v=q(name,24006);case(name+' captured outcomes survive terminal metric disappearance',source()+history,[expect('sum('+v+'{retype_field="status"})',2),expect('sum('+v+'{retype_field="end"})',120000)])
            scoped=q(name,24005,replace={'${gvar_oie_hypervisor}':'compute-b'});case(name+' host selection honored',source()+active,[expect('count('+scoped+')')])
        v=q('instance',24005,replace={'${gvar_oie_volume_uuid}':'second'});case('retype source volume filter',source()+active,[expect('count('+v+'{retype_field="status"})',1)])
        with tempfile.TemporaryDirectory() as folder:
            folder=Path(folder);rule=folder/'rules.yml';test=folder/'tests.yml'
            rule.write_text(yaml.safe_dump({'groups':[{'name':'actual-dashboard-queries','rules':[{'record':name,'expr':expr} for expr,name in records.items()]}]},sort_keys=False))
            test.write_text(yaml.safe_dump({'rule_files':[str(rule)],'evaluation_interval':'15s','tests':cases},sort_keys=False))
            result=subprocess.run([promtool,'test','rules',str(test)],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        print(f'Validated {len(cases)} compact-view scenarios against {len(records)} actual dashboard targets.')

if __name__=='__main__':unittest.main()
