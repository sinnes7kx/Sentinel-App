import time
import tkinter as tk
import unittest
from sentinel.dependency_window import DependencyWindow


class DependencyWindowTests(unittest.TestCase):
    def test_example_can_be_assessed_and_explained(self):
        try:
            root = tk.Tk()
        except tk.TclError:
            import os
            if os.environ.get('SENTINEL_REQUIRE_GUI'):
                raise
            self.skipTest('Graphical display unavailable')
        root.withdraw()
        try:
            window = DependencyWindow(root)
            window.withdraw()
            window.inventory.set('examples/dependencies/requirements.txt')
            window.feed.set('examples/dependencies/advisories-synthetic.json')
            window.start()
            deadline = time.monotonic() + 5
            while window.busy and time.monotonic() < deadline:
                root.update()
                time.sleep(0.01)
            self.assertFalse(window.busy)
            self.assertEqual(window.result['summary']['affected'], 1)
            window.tree.selection_set('0')
            window.selected()
            self.assertIn('x_SENTINEL-DEMO-1', window.detail.get('1.0', 'end'))
            self.assertIn('NEXT STEP', window.detail.get('1.0', 'end'))
        finally:
            root.destroy()
