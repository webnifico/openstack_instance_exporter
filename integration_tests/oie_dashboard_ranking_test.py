#!/usr/bin/env python3
"""Regression checks for Top N, plotted throughput and scheduler-wait units."""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml
from oie_dashboards_test import DASHBOARDS, VM, get_panel, interpolate, panels, series
from oie_dashboard_overview_test import source

PROMTOOL = os.environ.get('PROMTOOL') or shutil.which('promtool')


class RankingPresentation(unittest.TestCase):
    def test_largest_maximum_is_visible_first_without_changing_series_identity(self):
        for name, dashboard in DASHBOARDS.items():
            for panel in panels(dashboard['panels']):
                if panel['type'] != 'timeseries':
                    continue
                legend = panel['options']['legend']
                self.assertEqual(legend['sortBy'], 'Max', (name, panel['id']))
                self.assertTrue(legend['sortDesc'])
                self.assertIn('max', legend['calcs'])
                self.assertTrue(legend['showLegend'])
                # A legend limit would hide valid lines from the accompanying key.
                self.assertFalse(legend.get('limit'))
                self.assertEqual(panel['fieldConfig']['defaults']['custom']['stacking']['mode'], 'none')
                for target in panel.get('targets', []):
                    if 'topk(' in target.get('expr', ''):
                        self.assertIn('[${__range_s}s:$__interval] @ end()', target['expr'])
                        self.assertNotIn('[${__range_s}s:]', target['expr'])
            for variable in dashboard['templating']['list']:
                if 'rank_' in variable['name']:
                    self.assertEqual(variable['current']['value'], 'max_over_time')
                    self.assertEqual({v['value'] for v in variable['options']},
                                     {'last_over_time', 'max_over_time', 'avg_over_time'})

    @unittest.skipUnless(PROMTOOL, 'Native Promtool required')
    def test_actual_queries_preserve_top_n_and_plotted_units(self):
        def query(name, pid, count='10', rank='max_over_time'):
            return interpolate(get_panel(name, pid)['targets'][0]['expr'],
                               {'${gvar_oie_top_n}': count, '${gvar_oie_rank_by:raw}': rank})

        def check(expr, value):
            return {'expr': expr, 'eval_time': '5m',
                    'exp_samples': [{'labels': '{}', 'value': value}]}

        # The largest series deliberately sorts last by name. Six available
        # measurements must produce 1/3/6/6 results for N=1/3/10/All, not N rows.
        inputs = source()
        rates = [2, 180, 8, 7, 6, 5]
        for i, mib_per_second in enumerate(rates):
            labels = VM | {'instance_uuid': f'vm-{i}',
                           'server_name': 'Z peak' if i == 1 else f'A small {i}',
                           'volume_uuid': f'volume-{i}', 'disk_path': 'vda'}
            inputs.append(series('oie_instance_disk_write_gib_total',
                                 f'0+{mib_per_second / 1024 * 15}x20', labels))
        checks = []
        for count, expected_count, expected_sum in [('1', 1, 180), ('3', 3, 195),
                                                     ('10', 6, 208), ('1000000', 6, 208)]:
            expr = query('instance', 2032, count)
            checks += [check('count(' + expr + ')', expected_count),
                       check('sum(' + expr + ') / 1048576', expected_sum)]
        cases = [{'name': 'Top N is an upper bound; throughput returns base bytes/s',
                  'interval': '15s', 'input_series': inputs, 'promql_expr_test': checks}]

        # One VM peaks at 180 MiB/s, then settles to 1; another stays at 8.
        # Max and Last observed intentionally select different series. The
        # fixed range-end selection must retain one identity over the graph.
        moving = source()
        for ident, rates in [('peak', [180]*8+[1]*12), ('steady', [8]*20)]:
            values = [0.0]
            for rate in rates:
                values.append(values[-1] + rate / 1024 * 15)
            moving.append(series('oie_instance_disk_write_gib_total',
                                 ' '.join(str(v) for v in values), VM | {'instance_uuid': ident}))
        peak = query('instance', 2032, '1')
        last = query('instance', 2032, '1', 'last_over_time')
        cases.append({'name': 'Peak ranking includes a historic spike and does not rotate identities',
                      'interval': '15s', 'input_series': moving, 'promql_expr_test': [
                          check('sum(' + peak + ') / 1048576', 1),
                          check('sum(' + last + ') / 1048576', 8),
                          check('count(count_over_time((' + peak + ')[5m:15s]))', 1),
                          check('max(max_over_time((' + peak + ')[5m:15s])) / 1048576', 180)]})

        data = source() + [series('oie_instance_state_code', '1x20', VM),
                           series('oie_instance_inventory_info', '1x20',
                                  VM | {'libvirt_active': '1', 'state_desc': 'running'}),
                           series('oie_instance_cpu_vcpu_count', '1x20', VM),
                           series('oie_instance_cpu_steal_seconds_total', '0+0.75x20', VM | {'vcpu': '0'}),
                           series('oie_instance_cpu_wait_seconds_total', '0+1.5x20', VM | {'vcpu': '0'})]
        checks = []
        for name, pid in [('instance', 2024), ('project', 1304), ('hypervisor', 1305)]:
            p = get_panel(name, pid)
            self.assertEqual(p['fieldConfig']['defaults']['unit'], 'suffix:ms/s')
            checks.append(check('sum(' + query(name, pid) + ')', 50))
        cases.append({'name': 'Scheduler waiting uses milliseconds/s and preserves steal-before-wait fallback',
                      'interval': '15s', 'input_series': data, 'promql_expr_test': checks})
        with tempfile.TemporaryDirectory(prefix='oie-ranking-') as folder:
            path = Path(folder) / 'tests.yml'
            path.write_text(yaml.safe_dump({'rule_files': [], 'evaluation_interval': '15s', 'tests': cases},
                                           sort_keys=False))
            result = subprocess.run([PROMTOOL, 'test', 'rules', str(path)], text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    @unittest.skipUnless(PROMTOOL, 'Native Promtool required')
    def test_ranking_and_plotting_share_samples_for_short_lived_vms(self):
        # Three long-lived VMs plus one high-rate VM whose observations fall
        # between a two-minute graph's sample points. Previously, Prometheus's
        # implicit subquery step could pick that invisible VM, consuming a slot
        # and leaving only two plotted series with Top 3 selected. Conversely,
        # a coarser ranking step could miss a peak visible on a finer graph.
        for evaluation_step in ('15s', '2m'):
            cases = []
            for disk_panel, metric in [(2031, 'read'), (2032, 'write')]:
                # Keep current source authority throughout the ten-minute
                # ranking and plotting window, including the short-lived VM.
                inputs = [entry | {'values': entry['values'].replace('x20', 'x40')}
                          for entry in source()]
                inputs += [series(f'oie_instance_disk_{metric}_gib_total',
                                 f'0+{rate / 1024 * 15}x40',
                                 VM | {'instance_uuid': f'steady-{rate}'})
                          for rate in (8, 7, 6)]
                inputs.append(series(f'oie_instance_disk_{metric}_gib_total',
                                     '_x9 0 2.63671875 stale',
                                     VM | {'instance_uuid': 'short-lived'}))
                for plot_step, sees_short_vm in [('15s', 1), ('1m', 1), ('2m', 0)]:
                    for rank in ('max_over_time', 'avg_over_time', 'last_over_time'):
                        for limit, count in [('1', 1), ('3', 3), ('10', 3 + sees_short_vm)]:
                            expr = interpolate(get_panel('instance', disk_panel)['targets'][0]['expr'], {
                                '${gvar_oie_top_n}': limit, '${gvar_oie_rank_by:raw}': rank,
                                '${__range_s}': '600', '$__interval': plot_step})
                            plotted = f'count_over_time(({expr})[10m:{plot_step}])'
                            short_vm = 'label_replace(vector(1), "instance_uuid", "short-lived", "", "")'
                            checks = [
                                (f'count({plotted})', count),
                                (f'count(({plotted}) and on (instance_uuid) {short_vm}) or vector(0)', sees_short_vm),
                            ]
                            cases.append({'name': f'{metric}/{rank}/N={limit}/plot={plot_step}/evaluation={evaluation_step}',
                                          'interval': '15s', 'input_series': inputs,
                                          'promql_expr_test': [
                                              {'expr': q, 'eval_time': '10m',
                                               'exp_samples': [{'labels': '{}', 'value': value}]}
                                              for q, value in checks]})
            with tempfile.TemporaryDirectory(prefix='oie-ranking-sampling-') as folder:
                path = Path(folder) / 'tests.yml'
                path.write_text(yaml.safe_dump({'rule_files': [], 'evaluation_interval': evaluation_step,
                                               'tests': cases}, sort_keys=False))
                result = subprocess.run([PROMTOOL, 'test', 'rules', str(path)], text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
