#!/usr/bin/env python3
"""Inventory/presentation contracts; does not claim to run Grafana or PromQL."""
import unittest
from oie_dashboards_test import DASHBOARDS, get_panel, panels
from oie_dashboard_presentation_test import apply_table_transforms, native_table_frames


class BlockDeviceInventory(unittest.TestCase):
    def test_configured_device_inventory_is_kept_where_it_is_useful(self):
        # The standalone special-device stat was redundant and is intentionally absent.
        for name in ('cluster', 'hypervisor', 'project', 'instance'):
            ids = {p.get('id') for p in panels(DASHBOARDS[name]['panels'])}
            self.assertNotIn(39010, ids)

        # Cluster keeps the useful relationship view: all configured block devices by role.
        panel = get_panel('cluster', 39011)
        self.assertEqual(panel['type'], 'piechart')
        self.assertEqual(len(panel['targets']), 1)
        self.assertIn('every disk is a block device', panel['description'].lower())
        query = panel['targets'][0]['expr']
        for token in ('oie_instance_inventory_block_device_info',
                      '$gvar_oie_project_uuid', '$gvar_oie_project_name',
                      '$gvar_oie_instance_uuid', '${gvar_oie_hypervisor}'):
            self.assertIn(token, query)
        self.assertNotIn('oie_host_libvirt_ok', query)
        self.assertNotIn('last_success_timestamp_seconds', query)
        self.assertNotIn('oie:', query)


    def test_inventory_table_preserves_vm_and_device_identity(self):
        panel = get_panel('instance', 39011)
        self.assertTrue(panel['targets'][0]['instant'])
        self.assertEqual(panel['targets'][0]['format'], 'table')
        rows = [({'job': 'openstack-instance-exporter', 'instance': 'compute5:9120',
                  'instance_uuid': 'vm1', 'server_name': 'nginx', 'project_uuid': 'p1',
                  'project_name': 'admin', 'device_path': device, 'device_type': dtype,
                  'device_role': role, 'source_type': 'vms', 'source_id': source}, 1)
                for device, dtype, role, source in (
                    ('vda', 'disk', 'storage', 'vm_disk'),
                    ('hda', 'cdrom', 'config_drive', 'vm_disk.config'),
                    ('vdb', 'disk', 'swap', 'vm_disk.swap'))]
        frames = apply_table_transforms(panel, native_table_frames({'A': rows}))
        self.assertEqual(len(frames), 3)
        self.assertEqual({r['Role'] for r in frames}, {'storage', 'config_drive', 'swap'})
        self.assertEqual({r['Instance UUID'] for r in frames}, {'vm1'})
        self.assertEqual({r['Device'] for r in frames}, {'vda', 'hda', 'vdb'})
        for r in frames:
            self.assertNotIn('Value', r)
            self.assertNotIn('Time', r)

    def test_no_layout_overlap_and_no_new_recording_dependency(self):
        def check_siblings(name, items):
            for i, panel in enumerate(items):
                a = panel['gridPos']
                for other in items[i+1:]:
                    b = other['gridPos']
                    self.assertFalse(a['x'] < b['x'] + b['w'] and b['x'] < a['x'] + a['w']
                                     and a['y'] < b['y'] + b['h'] and b['y'] < a['y'] + a['h'],
                                     (name, panel['id'], other['id']))
                check_siblings(name, panel.get('panels', []))

        for name, dashboard in DASHBOARDS.items():
            ps = list(panels(dashboard['panels']))
            self.assertEqual(len({p['id'] for p in ps}), len(ps))
            # Collapsed-row children have their own local layout coordinates, so
            # overlap is meaningful only among panels with the same parent.
            check_siblings(name, dashboard['panels'])
            for pid in (39011,):
                found = [p for p in ps if p['id'] == pid]
                for p in found:
                    self.assertNotIn('oie:', str(p['targets']))

    def test_age_units_do_not_contradict_the_explanation(self):
        for pid in (23002, 2002):
            p = get_panel('cluster', pid)
            self.assertEqual(p['fieldConfig']['defaults']['unit'], 'suffix:s')
            self.assertIn('Seconds', p['fieldConfig']['defaults']['custom']['axisLabel'])
            self.assertNotIn(' ms', p['description'])
            self.assertNotIn('350', p['description'])
            self.assertLess(len(p['description']), 450)


if __name__ == '__main__':
    unittest.main()
