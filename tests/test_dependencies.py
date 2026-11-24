import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from sentinel.dependencies import assess, parse_requirements, validate_records


def advisory(**changes):
    result = {'id': 'x_TEST-1', 'affected': [{'package': {'name': 'Demo_Package', 'ecosystem': 'PyPI'}, 'versions': ['1.0']}]}
    result.update(changes)
    return result


class DependencyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.requirements = Path(self.temp.name) / 'requirements.txt'
        self.feed = Path(self.temp.name) / 'advisories.json'
        self.requirements.write_text('demo-package==1.0\n', encoding='utf-8')
        self.feed.write_text(json.dumps([advisory()]), encoding='utf-8')

    def run_assessment(self, records=None):
        if records is not None:
            self.feed.write_text(json.dumps(records), encoding='utf-8')
        return assess(self.requirements, self.feed)

    def test_exact_match_normalizes_package_and_stays_offline(self):
        with patch('socket.socket', side_effect=AssertionError('Network forbidden')):
            result = self.run_assessment()
        self.assertEqual(result['packages'][0]['advisory_ids'], ['x_TEST-1'])
        self.assertEqual(result['packages'][0]['status'], 'affected')
        self.assertEqual(len(result['advisories_sha256']), 64)

    def test_equivalent_version_is_matched(self):
        self.requirements.write_text('demo-package==1.0.0\n', encoding='utf-8')
        result = self.run_assessment()
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['packages'][0]['status'], 'affected')
        self.assertEqual(result['packages'][0]['unresolved_advisory_ids'], [])

    def test_range_only_record_matches(self):
        record = advisory()
        record['affected'][0].pop('versions')
        record['affected'][0]['ranges'] = [{'type': 'ECOSYSTEM', 'events': [{'introduced': '0'}, {'fixed': '2.0'}]}]
        self.assertEqual(self.run_assessment([record])['packages'][0]['status'], 'affected')

    def test_withdrawn_and_other_ecosystem_not_matched(self):
        other = advisory(id='x_TEST-2')
        other['affected'][0]['package']['ecosystem'] = 'npm'
        result = self.run_assessment([advisory(withdrawn='2026-01-01T00:00:00Z'), other])
        self.assertEqual(result['packages'][0]['advisory_ids'], [])

    def test_private_requirement_lines_never_echoed(self):
        packages, unsupported = parse_requirements('--index-url https://user:SECRET@example.test\n-r private.txt\ndemo>=1\ndemo==1.*\ndemo==1; os_name=="nt"\ndemo[extra]==1\n')
        self.assertFalse(packages)
        self.assertEqual(len(unsupported), 6)
        self.assertNotIn('SECRET', str(unsupported))
        self.assertNotIn('private.txt', str(unsupported))

    def test_comments_and_duplicates(self):
        packages, unsupported = parse_requirements('# local\nDemo_Package==1.0 # pin\ndemo-package==1.0\n')
        self.assertEqual(packages, [('demo-package', '1.0')])
        self.assertFalse(unsupported)

    def test_empty_feed_and_empty_inventory_partial(self):
        self.assertEqual(self.run_assessment([])['packages'][0]['status'], 'unknown')
        self.requirements.write_text('', encoding='utf-8')
        self.assertEqual(self.run_assessment([])['status'], 'partial')

    def test_invalid_feed_fails_closed(self):
        for records in ({}, [None], [advisory(), advisory()], [advisory(affected=[{'package': {}}])]):
            with self.subTest(records=records), self.assertRaises(ValueError):
                validate_records(records)

    def test_cli_exit_codes(self):
        args = [sys.executable, '-m', 'sentinel.dependencies', '--requirements', str(self.requirements), '--advisories', str(self.feed)]
        found = subprocess.run(args, capture_output=True, text=True)
        self.assertEqual(found.returncode, 1, found.stderr)
        self.assertEqual(json.loads(found.stdout)['packages'][0]['status'], 'affected')
        self.feed.write_text('[]', encoding='utf-8')
        self.assertEqual(subprocess.run(args, capture_output=True).returncode, 2)
        self.feed.write_text('invalid JSON SECRET', encoding='utf-8')
        invalid = subprocess.run(args, capture_output=True, text=True)
        self.assertEqual(invalid.returncode, 2)
        self.assertNotIn('SECRET', invalid.stderr)
