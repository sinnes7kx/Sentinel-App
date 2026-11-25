import tempfile
import unittest
from pathlib import Path
from sentinel.store import Store


class RemediationStorageTests(unittest.TestCase):
    def test_persisted_status_is_separate_from_evidence_and_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'history.sqlite3'
            original = {'target': 'https://fixture.invalid/', 'started': '2026-01-01',
                        'findings': [{'id': 'CSP', 'evidence': 'Observed'}]}
            store = Store(path)
            try:
                project = store.project('Example')
                other = store.project('Other')
                scan = store.save(project, original)
                retest = store.save(project, original)
                self.assertEqual(store.remediation(project, scan), {})
                row = store.set_remediation(project, scan, 0, 'Investigating')
                self.assertEqual(row['state'], 'Investigating')
                self.assertTrue(row['updated'])
                store.set_remediation(project, scan, 0, 'Remediation applied')
                self.assertEqual(store.result(project, scan), original)
                self.assertEqual(store.remediation(project, retest), {})
                self.assertEqual(store.remediation(other, scan), {})
                for args in ((other, scan, 0, 'Open'), (project, scan, 1, 'Open'),
                             (project, scan, -1, 'Open'), (project, scan, 0, 'Verified fixed')):
                    with self.subTest(args=args), self.assertRaises(ValueError):
                        store.set_remediation(*args)
            finally:
                store.close()
            store = Store(path)
            try:
                self.assertEqual(store.remediation(project, scan)[0]['state'], 'Remediation applied')
                self.assertEqual(store.result(project, scan), original)
            finally:
                store.close()
