import unittest

from sentinel.dependencies import validate_records
from sentinel.version_match import match_affected


def affected(events, kind='ECOSYSTEM', versions=None):
    return {'package': {'name': 'demo', 'ecosystem': 'PyPI'},
            'versions': versions or [], 'ranges': [{'type': kind, 'events': events}]}


class VersionRangeTests(unittest.TestCase):
    def assert_matches(self, version, entry, expected):
        validate_records([{'id': 'x_TEST-1', 'affected': [entry]}])
        self.assertIs(match_affected(version, entry)[0], expected)

    def test_introduced_inclusive_fixed_exclusive(self):
        entry = affected([{'introduced': '1.2'}, {'fixed': '2.0'}])
        for version, expected in [('1.1', False), ('1.2', True), ('1.9', True), ('2.0', False), ('2.1', False)]:
            with self.subTest(version=version):
                self.assert_matches(version, entry, expected)

    def test_multiple_intervals_and_unsorted_events(self):
        entry = affected([{'fixed': '4'}, {'introduced': '3'}, {'fixed': '2'}, {'introduced': '1'}])
        for version, expected in [('0.9', False), ('1', True), ('2', False), ('2.5', False), ('3', True), ('4', False)]:
            with self.subTest(version=version):
                self.assert_matches(version, entry, expected)

    def test_zero_introduction_is_before_prereleases_of_zero(self):
        self.assert_matches('0.dev0', affected([{'introduced': '0'}]), True)

    def test_last_affected_is_inclusive(self):
        entry = affected([{'introduced': '0'}, {'last_affected': '2.0'}])
        self.assert_matches('2.0.0', entry, True)
        self.assert_matches('2.0.post1', entry, False)

    def test_limits_are_exclusive_and_union(self):
        entry = affected([{'introduced': '0'}, {'limit': '2'}, {'limit': '3'}])
        self.assert_matches('2.5', entry, True)
        self.assert_matches('3', entry, False)

    def test_infinite_limit(self):
        self.assert_matches('999', affected([{'introduced': '0'}, {'limit': '*'}]), True)

    def test_prerelease_postrelease_and_epoch_order(self):
        cases = [
            ('2.0rc1', [{'introduced': '0'}, {'fixed': '2.0'}], True),
            ('2.0', [{'introduced': '0'}, {'fixed': '2.0rc1'}], False),
            ('1.0.post1', [{'introduced': '1.0'}, {'fixed': '1.0.post2'}], True),
            ('1!1.0', [{'introduced': '0'}, {'fixed': '1!2.0'}], True),
            ('2!0.1', [{'introduced': '0'}, {'fixed': '1!2.0'}], False),
            ('1.0.dev1', [{'introduced': '0'}, {'fixed': '1.0a1'}], True),
        ]
        for version, events, expected in cases:
            with self.subTest(version=version, events=events):
                self.assert_matches(version, affected(events), expected)

    def test_normalized_explicit_versions(self):
        for version in ('1.0.0', 'v1.0', '1.0.0.0'):
            self.assert_matches(version, {'versions': ['1.0'], 'package': {'name': 'demo', 'ecosystem': 'PyPI'}}, True)

    def test_invalid_versions_remain_unknown(self):
        self.assert_matches('invalid', affected([{'introduced': '0'}, {'fixed': '2'}]), None)
        self.assert_matches('1', affected([{'introduced': 'invalid'}, {'fixed': '2'}]), None)

    def test_local_builds_remain_unknown(self):
        self.assert_matches('1.0+patched', affected([{'introduced': '0'}, {'fixed': '2'}]), None)
        self.assert_matches('1', affected([{'introduced': '0'}, {'fixed': '2+custom'}]), None)

    def test_git_and_semver_are_not_reinterpreted_as_pep440(self):
        for kind in ('GIT', 'SEMVER', 'FUTURE'):
            self.assert_matches('1', affected([{'introduced': '0'}, {'fixed': '2'}], kind), None)

    def test_explicit_match_survives_unsupported_range(self):
        self.assert_matches('1.0', affected([{'introduced': '0'}], 'GIT', ['1.0']), True)

    def test_nonmatch_does_not_hide_unsupported_range(self):
        entry = affected([{'introduced': '0'}, {'fixed': '1'}])
        entry['ranges'].append({'type': 'GIT', 'events': [{'introduced': '0'}]})
        self.assert_matches('2', entry, None)

    def test_union_of_multiple_ranges(self):
        entry = affected([{'introduced': '0'}, {'fixed': '1'}])
        entry['ranges'].append({'type': 'ECOSYSTEM', 'events': [{'introduced': '2'}, {'fixed': '3'}]})
        self.assert_matches('2.5', entry, True)

    def test_conflicting_boundaries_remain_unknown(self):
        self.assert_matches('1', affected([{'introduced': '1.0'}, {'fixed': '1.0.0'}]), None)
        self.assert_matches('1', affected([{'introduced': '0'}, {'fixed': '2'}, {'last_affected': '3'}]), None)

    def test_no_introduction_or_empty_information_remains_unknown(self):
        self.assert_matches('1', affected([{'fixed': '2'}]), None)
        self.assertIsNone(match_affected('1', {'versions': [], 'ranges': []})[0])

    def test_structurally_malformed_events_rejected(self):
        for events in ([], [None], [{}], [{'introduced': 0}], [{'introduced': '0', 'fixed': '2'}], [{'surprise': '2'}]):
            with self.subTest(events=events), self.assertRaises(ValueError):
                validate_records([{'id': 'x_TEST-1', 'affected': [affected(events)]}])

    def test_invalid_later_event_cannot_be_hidden_by_earlier_match(self):
        self.assert_matches('1', affected([{'introduced': '0'}, {'fixed': 'not-a-version'}]), None)
