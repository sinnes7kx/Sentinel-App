import unittest
from threading import Event
from unittest.mock import patch
from sentinel.database_lab import demonstrate_database


class DatabaseLabTests(unittest.TestCase):
    def test_real_sqlite_distinguishes_data_from_expression(self):
        result = demonstrate_database()
        self.assertEqual(result['status'], 'completed')
        normal, unexpected = result['rows']
        self.assertEqual((normal['weak_count'], normal['protected_count']), (1, 1))
        self.assertEqual((unexpected['weak_count'], unexpected['protected_count']), (1, 0))
        self.assertTrue(unexpected['weak_second_row'])
        self.assertFalse(unexpected['protected_second_row'])
        self.assertTrue(all(row['expected'] for row in result['rows']))

    def test_cancel_before_start_never_opens_database(self):
        cancel = Event()
        cancel.set()
        with patch('sentinel.database_lab.sqlite3.connect') as connect:
            self.assertEqual(demonstrate_database(cancel), {'status': 'cancelled', 'rows': []})
            connect.assert_not_called()

    def test_only_in_memory_database_is_opened(self):
        import sqlite3
        with patch('sentinel.database_lab.sqlite3.connect', wraps=sqlite3.connect) as connect:
            self.assertEqual(demonstrate_database()['status'], 'completed')
            connect.assert_called_once_with(':memory:')
