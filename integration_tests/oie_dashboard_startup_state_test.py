#!/usr/bin/env python3
import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
DASH = ROOT / 'examples' / 'grafana_dashboard_example'
FILES = sorted(DASH.glob('openstack_instance_exporter_*.json'))


def walk(panels):
    for panel in panels:
        yield panel
        yield from walk(panel.get('panels', []))


class DashboardStartupState(unittest.TestCase):
    def dashboards(self):
        for path in FILES:
            yield path, json.loads(path.read_text())

    def test_every_collapsible_row_starts_collapsed_with_its_panels(self):
        for path, doc in self.dashboards():
            rows = [p for p in walk(doc.get('panels', [])) if p.get('type') == 'row']
            self.assertTrue(rows, path.name)
            for row in rows:
                self.assertIs(row.get('collapsed'), True, f"{path.name}: {row.get('title')}")
                self.assertTrue(row.get('panels'), f"{path.name}: empty collapsed row")
            first_row = next(i for i, p in enumerate(doc['panels']) if p['type'] == 'row')
            self.assertTrue(all(p['type'] == 'row' for p in doc['panels'][first_row:]))

    def test_generic_name_palette_is_not_left_uncontrolled(self):
        for path, doc in self.dashboards():
            for panel in walk(doc.get('panels', [])):
                if panel.get('type') not in {'timeseries', 'piechart'}:
                    continue
                mode = panel.get('fieldConfig', {}).get('defaults', {}).get('color', {}).get('mode')
                if mode != 'palette-classic-by-name':
                    continue
                fixed = [
                    prop for ov in panel.get('fieldConfig', {}).get('overrides', [])
                    for prop in ov.get('properties', [])
                    if prop.get('id') == 'color' and prop.get('value', {}).get('mode') == 'fixed'
                ]
                self.assertTrue(fixed, f"{path.name}: uncontrolled name palette in {panel.get('title')}")

    def test_cluster_inventory_and_age_panels_are_readable(self):
        path = DASH / 'openstack_instance_exporter_cluster.json'
        doc = json.loads(path.read_text())
        by_id = {p.get('id'): p for p in walk(doc['panels']) if 'id' in p}

        self.assertNotIn(39010, by_id)
        self.assertNotIn(1266, by_id)
        self.assertEqual(by_id[25012]['title'], 'Running instances')
        self.assertEqual(by_id[25013]['title'], 'Inactive instances')

        flavors = by_id[1243]
        self.assertEqual(flavors['fieldConfig']['defaults']['color']['mode'], 'palette-classic')

        state = by_id[23003]
        colors = {
            prop['value']['fixedColor']
            for ov in state['fieldConfig']['overrides']
            for prop in ov.get('properties', [])
            if prop.get('id') == 'color' and prop.get('value', {}).get('mode') == 'fixed'
        }
        self.assertTrue({'#4DA6FF', '#42D6A4', '#FF9F43', '#AC8FFF'}.issubset(colors))

        for panel_id in (23002, 2002):
            panel = by_id[panel_id]
            self.assertEqual(panel['fieldConfig']['defaults']['unit'], 'suffix:s')
            self.assertIn('Seconds', panel['fieldConfig']['defaults']['custom']['axisLabel'])
            self.assertIn('not Prometheus scrape duration', panel['description'])
            self.assertNotIn('last-success age', panel['title'].lower())


if __name__ == '__main__':
    unittest.main()
