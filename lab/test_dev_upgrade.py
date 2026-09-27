"""Upgrade preflight must reject incompatible state before any mutation."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import dev


class UpgradePreflight(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.addCleanup(patch.stopall)
        patch.object(dev, 'ROOT', self.root).start()
        self.state = dict(epoch='epoch', tenant='tenant', project='project', pool='pool', source_id='source')
        self.project = 'pool/pgws/t_tenant/p_project'
        (self.root/'host.json').write_text(json.dumps(dict(epoch='epoch', id='dev-host', dataset='pool/pgws')))
        self.folder = self.root/'host/objects/source/1'
        self.folder.mkdir(parents=True)
        self.item = {'phase': 'streaming', 'task': {'command': dict(epoch='epoch', tenant='tenant',
                     project='project', host='dev-host', workspace='source', generation=1)},
                     'volume': {'name': self.project+'/baselines/source/g1', 'guid': 'baseline-guid'}}
        self.save_item()
        self.baseline = {'guid': 'baseline-guid', 'org.pgws:tenant': 'tenant', 'org.pgws:project': 'project',
                         'org.pgws:resource': 'source', 'org.pgws:generation': '1'}
        self.props = {'guid': 'project-guid', 'used': '100', 'quota': '0', 'org.pgws:managed': 'on',
                      'org.pgws:tenant': '-', 'org.pgws:project': '-', 'mountpoint': 'none', 'canmount': 'on'}
        patch.object(dev, 'run', side_effect=self.read_properties).start()

    def save_item(self):
        (self.folder/'state.json').write_text(json.dumps(self.item))

    def read_properties(self, args):
        self.assertEqual(args[:2], ['zfs', 'get'])
        props = self.props if args[-1] == self.project else self.baseline
        return ''.join(k+'\t'+v+'\n' for k, v in props.items()).encode()

    def test_legacy_baseline_has_explicit_bounded_migration(self):
        plan = dev.upgrade_storage_plan(self.state)
        self.assertTrue(plan['legacy'])
        self.assertEqual(plan['record']['dataset'], {'name': self.project, 'guid': 'project-guid'})
        self.assertEqual(plan['record']['quota_bytes'], 2 << 30)
        self.assertFalse(Path(plan['path']).exists())

    def test_replaced_baseline_rejected(self):
        self.baseline['guid'] = 'replacement'
        with self.assertRaisesRegex(RuntimeError, 'GUID'):
            dev.upgrade_storage_plan(self.state)

    def test_foreign_scope_rejected(self):
        self.item['task']['command']['tenant'] = 'other'
        self.save_item()
        with self.assertRaisesRegex(RuntimeError, 'scope'):
            dev.upgrade_storage_plan(self.state)

    def test_legacy_guard_rejected_before_zfs_mutation(self):
        guard = self.folder/'ingress'
        guard.mkdir()
        (guard/'config.json').write_text('{}')
        self.item.update(phase='ready', guard_directory=str(guard))
        self.save_item()
        with self.assertRaisesRegex(RuntimeError, 'guard is incompatible'):
            dev.upgrade_storage_plan(self.state)

    def test_missing_runtime_receipt_rejected(self):
        guard = self.folder/'ingress'
        guard.mkdir()
        (guard/'config.json').write_text(json.dumps({'runtime_stop_file': str(self.folder/'safety-stop.json')}))
        (guard/'receipt.json').write_text('{}')
        self.item.update(phase='ready', guard_directory=str(guard))
        self.save_item()
        with self.assertRaisesRegex(RuntimeError, 'durable runtime lease'):
            dev.upgrade_storage_plan(self.state)

    def test_allocation_limit_and_project_replacement_rejected(self):
        self.props['used'] = str(2 << 30)
        with self.assertRaisesRegex(RuntimeError, 'cannot fit'):
            dev.upgrade_storage_plan(self.state)
        self.props['used'] = '100'
        plan = dev.upgrade_storage_plan(self.state)
        path = Path(plan['path'])
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps(plan['record']))
        self.assertFalse(dev.upgrade_storage_plan(self.state)['legacy'])
        self.props['guid'] = 'replaced'
        with self.assertRaisesRegex(RuntimeError, 'durable allocation'):
            dev.upgrade_storage_plan(self.state)


if __name__ == '__main__':
    unittest.main()
