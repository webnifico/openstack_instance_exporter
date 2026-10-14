#!/usr/bin/env python3
"""Regression coverage for instance-facing dashboard language and inventory layout."""
import unittest

from oie_dashboards_test import DASHBOARDS, get_panel, panels


class InstanceLanguageAndInventoryLayout(unittest.TestCase):
    def test_resource_dashboards_use_instance_language(self):
        for name in ('cluster', 'hypervisor', 'instance', 'project'):
            self.assertEqual(get_panel(name, 25012)['title'], 'Running instances')
            self.assertEqual(get_panel(name, 25013)['title'], 'Inactive instances')
            blob = str(DASHBOARDS[name])
            self.assertNotIn('Active domains', blob)
            self.assertNotIn('Observed domains', blob)
            self.assertNotIn('Special block devices · configured inventory', blob)

    def test_observed_inventory_explains_relationship_to_running_instances(self):
        for name in ('cluster', 'hypervisor', 'project'):
            summary = get_panel(name, 27200)
            text = summary['description'].lower()
            self.assertRegex(text, r'observed instances includes (?:every instance definition|running, paused and inactive definitions)')
            if name == 'cluster':
                self.assertIn('matching projects counts the distinct project uuid/name identities', text)
                self.assertEqual({t['refId']: t['legendFormat'] for t in summary['targets']},
                                 {'B': 'Matching projects', 'C': 'Observed instances'})
            else:
                self.assertRegex(text, r'running instances is (?:therefore )?a subset')
            table = get_panel(name, 25003)
            text = table['description'].lower()
            self.assertRegex(text, r'(?:including both running and inactive instances|observed instances includes running, paused and inactive definitions)')
            self.assertIn('running, shutoff and other states', text)

    def test_cluster_removes_duplicate_running_instance_stat(self):
        ids = {p.get('id') for p in panels(DASHBOARDS['cluster']['panels'])}
        self.assertNotIn(1266, ids)
        self.assertEqual(get_panel('cluster', 1244)['title'], 'Observed VM vCPU allocation')
        self.assertEqual(get_panel('cluster', 1275)['title'], 'Instance states')
        self.assertEqual(get_panel('cluster', 1243)['title'], 'Instances by flavor')

    def test_every_collapsible_row_starts_collapsed(self):
        rows = []
        for d in DASHBOARDS.values():
            rows.extend(p for p in panels(d['panels']) if p.get('type') == 'row')
        self.assertGreater(len(rows), 0)
        self.assertTrue(all(p.get('collapsed') is True for p in rows))


if __name__ == '__main__':
    unittest.main()
