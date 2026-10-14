#!/usr/bin/env python3
"""Guard measurement-only dashboards and retained retype views."""
import json
import re
import unittest
from oie_dashboards_test import DASHBOARDS, panels

class IndependentDashboards(unittest.TestCase):
    def test_no_custom_triage_or_rule_dependencies(self):
        for name, dashboard in DASHBOARDS.items():
            text = json.dumps(dashboard)
            self.assertIsNone(re.search(r'\bALERTS(?:_FOR_STATE)?\b|\boie:[a-z_:]+', text), name)
            self.assertNotIn('Dashboard policy age', text)
            self.assertNotIn('Triage', text)
            ids = {p['id'] for p in panels(dashboard['panels'])}
            self.assertNotIn(39800, ids)
            for panel in panels(dashboard['panels']):
                for target in panel.get('targets', []):
                    if 'panelId' in target:
                        self.assertIn(target['panelId'], ids, name)

    def test_dedicated_retype_panels_remain(self):
        for name in ('cluster', 'project', 'instance', 'hypervisor'):
            retypes = [p for p in panels(DASHBOARDS[name]['panels'])
                       if any('oie_instance_disk_retype_' in t.get('expr', '') for t in p.get('targets', []))]
            self.assertTrue(retypes, name)
        for name in ('cluster', 'project'):
            overview = next(p for p in panels(DASHBOARDS[name]['panels']) if p['id'] == 27240)
            self.assertEqual(overview['options']['colorMode'], 'value')
            for color in ('#4DA6FF', '#F2B544', '#FF6B7D', '#42D6A4', '#A1AEC3'):
                self.assertIn(color, json.dumps(overview))

if __name__ == '__main__': unittest.main()
