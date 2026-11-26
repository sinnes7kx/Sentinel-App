import unittest
from unittest.mock import Mock
from sentinel.readiness import inventory


class ReadinessTests(unittest.TestCase):
    def test_missing_optional_tools_does_not_disable_builtin(self):
        rows = inventory(lookup=lambda spec: None, which=lambda name: None)
        self.assertEqual(rows[0].state, 'Available')
        self.assertTrue(all(row.state == 'Not detected' for row in rows[1:]))

    def test_detection_is_not_execution_verification(self):
        lookup = Mock(return_value='/local/tool')
        which = Mock(return_value='/local/client')
        rows = inventory(lookup=lookup, which=which)
        self.assertEqual(lookup.call_count, 4)
        self.assertEqual(which.call_count, 2)
        self.assertTrue(all(row.state == 'Detected' for row in rows[1:5]))
        self.assertTrue(all('unverified' in row.explanation for row in rows[1:5]))
        self.assertTrue(all(row.state == 'Client detected' for row in rows[5:]))
        self.assertFalse(any(row.state == 'Ready' for row in rows))


if __name__ == '__main__':
    unittest.main()
