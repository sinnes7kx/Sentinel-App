import unittest
from copy import deepcopy

from sentinel.remediation_checklist import checklist, counts, filtered


def finding(title, severity):
    return {'id': title, 'title': title, 'severity': severity,
            'evidence': 'Fixture evidence', 'remediation': 'Review configuration'}


class ChecklistTests(unittest.TestCase):
    def test_priority_and_exact_duplicates(self):
        low = finding('Low finding', 'low')
        result = {'findings': [low, finding('High finding', 'high'), dict(low)]}
        reviews = {1: {'state': 'Investigating'}}
        before = deepcopy((result, reviews))
        rows = checklist(result, reviews)
        self.assertEqual([(r.index, r.state, r.occurrences) for r in rows],
                         [(1, 'Investigating', 1), (0, 'Open', 2)])
        self.assertEqual((result, reviews), before)
        self.assertEqual(counts(rows), {'Open': 1, 'Investigating': 1,
                                         'Remediation applied': 0, 'Retest required': 0})

    def test_filter_and_manual_state(self):
        result = {'findings': [finding('A', 'medium'), finding('B', 'medium')]}
        rows = checklist(result, {0: {'state': 'Remediation applied'}, 1: {'state': 'Retest required'}})
        self.assertEqual([r.index for r in filtered(rows, 'Retest required')], [1])
        self.assertEqual(filtered(rows, 'Open'), [])
        self.assertEqual(filtered(rows, 'All'), rows)
        with self.assertRaises(ValueError):
            filtered(rows, 'Fixed')

    def test_missing_and_unrecognized_review_state(self):
        self.assertEqual(checklist(None, {}), [])
        rows = checklist({'findings': [finding('A', 'info')]}, {0: {'state': 'Unknown'}})
        self.assertEqual(rows[0].state, 'Open')
