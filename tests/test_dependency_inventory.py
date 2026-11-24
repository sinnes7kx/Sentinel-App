import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from sentinel.dependencies import assess, parse_pip_inspect


class InventoryTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.inventory = Path(directory.name) / 'inventory.json'
        self.feed = Path(directory.name) / 'feed.json'
        self.feed.write_text(json.dumps([{'id': 'x_TEST-1', 'affected': [
            {'package': {'name': 'demo', 'ecosystem': 'PyPI'}, 'ranges': [
                {'type': 'ECOSYSTEM', 'events': [{'introduced': '0'}, {'fixed': '2'}]}]}]}]), encoding='utf-8')

    def write_inventory(self, version='1', **kwargs):
        item = {'metadata': {'name': 'demo', 'version': version}, **kwargs}
        self.inventory.write_text(json.dumps({'version': '1', 'installed': [item]}), encoding='utf-8')

    def test_pip_inventory_offline_and_private_metadata_omitted(self):
        self.write_inventory(metadata_location='PRIVATE', installer='SECRET')
        with patch('socket.socket', side_effect=AssertionError('No network')):
            result = assess(self.inventory, self.feed, 'pip-inspect')
        self.assertEqual(result['summary']['affected'], 1)
        self.assertNotIn('PRIVATE', str(result))
        self.assertNotIn('SECRET', str(result))
        self.assertEqual(result['packages'][0]['advisory_results'][0]['reasons'], ['ecosystem_range'])

    def test_direct_url_is_unassessed_without_echoing_credentials(self):
        self.write_inventory(direct_url={'url': 'https://user:SECRET@example.test/private', 'dir_info': {'editable': True}})
        result = assess(self.inventory, self.feed, 'pip-inspect')
        self.assertEqual(result['summary']['unsupported_inventory_entries'], 1)
        self.assertEqual(result['packages'], [])
        self.assertNotIn('SECRET', str(result))

    def test_fixed_version_is_no_match_only_in_supplied_feed(self):
        self.write_inventory('2')
        result = assess(self.inventory, self.feed, 'pip-inspect')
        self.assertEqual(result['packages'][0]['status'], 'no_match_in_supplied_feed')
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['packages'][0]['evaluated_nonmatching_advisory_ids'], ['x_TEST-1'])

    def test_conflicting_package_versions_preserved(self):
        text = json.dumps({'version': '1', 'installed': [
            {'metadata': {'name': 'demo', 'version': '1'}},
            {'metadata': {'name': 'DEMO', 'version': '2'}}]})
        self.assertEqual(parse_pip_inspect(text)[0], [('demo', '1'), ('demo', '2')])

    def test_invalid_reports_fail_closed(self):
        for data in ([], {}, {'version': '2', 'installed': []}, {'version': '1', 'installed': {}}):
            with self.subTest(data=data), self.assertRaises(ValueError):
                parse_pip_inspect(json.dumps(data))

    def test_invalid_entries_report_positions_only(self):
        data = {'version': '1', 'installed': [None, {'metadata': {'name': 'SECRET', 'version': []}}]}
        packages, problems = parse_pip_inspect(json.dumps(data))
        self.assertFalse(packages)
        self.assertEqual(len(problems), 2)
        self.assertNotIn('SECRET', str(problems))

    def test_metadata_whitespace_cannot_create_a_package_name(self):
        data = {'version': '1', 'installed': [{'metadata': {'name': 'demo\n', 'version': '1'}}]}
        self.assertEqual(parse_pip_inspect(json.dumps(data))[0], [])

    def test_bundled_example(self):
        result = assess(Path('examples/dependencies/requirements.txt'), Path('examples/dependencies/advisories-synthetic.json'))
        self.assertEqual(result['summary']['affected'], 1)
        self.assertEqual(result['packages'][0]['advisory_ids'], ['x_SENTINEL-DEMO-1'])

    def test_cli_inventory_and_missing_optional_dependency(self):
        self.write_inventory()
        args = ['-m', 'sentinel.dependencies', '--pip-inspect', str(self.inventory), '--advisories', str(self.feed)]
        result = subprocess.run([sys.executable, *args], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(json.loads(result.stdout)['summary']['affected'], 1)
        missing = subprocess.run([sys.executable, '-S', *args], capture_output=True, text=True)
        self.assertEqual(missing.returncode, 2)
        self.assertIn('requirements-intelligence.txt', missing.stderr)
        self.assertNotIn('Traceback', missing.stderr)

    def test_multiple_entries_for_one_advisory_are_unioned(self):
        self.write_inventory()
        record = json.loads(self.feed.read_text())[0]
        record['affected'].insert(0, {'package': {'name': 'demo', 'ecosystem': 'PyPI'}, 'versions': ['5']})
        self.feed.write_text(json.dumps([record]), encoding='utf-8')
        package = assess(self.inventory, self.feed, 'pip-inspect')['packages'][0]
        self.assertEqual(package['advisory_ids'], ['x_TEST-1'])
        self.assertEqual(package['unresolved_advisory_ids'], [])
