import unittest
from unittest.mock import patch, Mock
from sentinel.store import Store
from sentinel.desktop_theme import _tile


class PerformanceTests(unittest.TestCase):
    def test_history_summary_does_not_decode_full_results(self):
        store = Store(':memory:')
        try:
            a, b = store.project('A'), store.project('B')
            def save(project, target, status):
                return store.save(project, {'target': target, 'started': '2026-01-01T00:00:00',
                                            'status': status, 'findings': [{'evidence': 'example'}]})
            older = save(a, 'https://example.invalid/', 'completed')
            save(a, 'https://other.invalid/', 'completed')
            save(b, 'https://example.invalid/', 'completed')
            latest = save(a, 'https://example.invalid/', 'partial')
            with patch('sentinel.store.json.loads', side_effect=AssertionError('eager decode')):
                rows = store.history_summary(a)
            self.assertEqual([row[0] for row in rows], [latest, older + 1, older])
            self.assertEqual(rows[0][2], 'partial')
            self.assertEqual(len(list(store.earlier_results(a, latest, 'https://example.invalid/'))), 1)
            self.assertEqual(store.result(a, older)['status'], 'completed')
            self.assertIsNone(store.result(b, older))
        finally:
            store.close()

    def test_rounded_tile_batches_rows_and_preserves_pixels(self):
        image = Mock()
        radius = 8
        size = 2 * radius + 3
        with patch('sentinel.desktop_theme.tk.PhotoImage', return_value=image):
            self.assertIs(_tile(None, '#111111', radius, '#222222'), image)
        self.assertLessEqual(image.put.call_count, size)
        pixels = {}
        for call in image.put.call_args_list:
            x, y = call.kwargs['to']
            for offset, color in enumerate(call.args[0].strip('{}').split()):
                pixels[(x + offset, y)] = color
        expected = {}
        for y in range(size):
            for x in range(size):
                dx = max(radius - x - .5, x + .5 - (size - radius), 0)
                dy = max(radius - y - .5, y + .5 - (size - radius), 0)
                distance = (dx * dx + dy * dy) ** .5
                if distance <= radius:
                    edge = distance > radius - 1 or x == 0 or y == 0 or x == size - 1 or y == size - 1
                    expected[x, y] = '#222222' if edge else '#111111'
        self.assertEqual(pixels, expected)
