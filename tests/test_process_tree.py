"""Real local child-process regressions; no security tools or network targets."""
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

from sentinel.tools.runner import run


CHILD = '''
from pathlib import Path
import sys, time
ready, late = map(Path, sys.argv[1:])
ready.write_text("started")
time.sleep(2.5)
late.write_text("survived")
'''

PARENT = '''
from pathlib import Path
import subprocess, sys, time
# Allow the Windows launcher to be assigned to its Job Object before spawning.
time.sleep(0.4)
subprocess.Popen([sys.executable, "-c", sys.argv[1], sys.argv[2], sys.argv[3]])
deadline = time.monotonic() + 5
while not Path(sys.argv[2]).exists() and time.monotonic() < deadline:
    time.sleep(0.02)
print("parent finished", flush=True)
if sys.argv[4] == "wait":
    time.sleep(30)
'''


class ProcessTreeTests(unittest.TestCase):
    def exercise(self, mode):
        with tempfile.TemporaryDirectory() as tmp:
            ready, late = Path(tmp) / 'ready', Path(tmp) / 'late'
            cancel = threading.Event()
            done = threading.Event()

            def cancel_after_child_starts():
                deadline = time.monotonic() + 6
                while not done.is_set() and time.monotonic() < deadline:
                    if ready.exists():
                        cancel.set()
                        return
                    done.wait(0.02)

            watcher = None
            if mode == 'cancel':
                watcher = threading.Thread(target=cancel_after_child_starts, daemon=True)
                watcher.start()
            try:
                result = run([sys.executable, '-c', PARENT, CHILD, str(ready), str(late),
                              'exit' if mode == 'exit' else 'wait'],
                             1.8 if mode == 'timeout' else 8, cancel)
            finally:
                done.set()
                if watcher is not None:
                    watcher.join(1)
            self.assertTrue(ready.exists(), 'Child must actually start for this test')
            if mode == 'cancel':
                self.assertTrue(result.cancelled)
            elif mode == 'timeout':
                self.assertTrue(result.timed_out)
            else:
                self.assertEqual(result.returncode, 0)
                self.assertFalse(result.truncated)
                self.assertIn('parent finished', result.stdout)
            # A surviving child would write this marker after its sleep.
            time.sleep(2.7)
            self.assertFalse(late.exists(), 'Descendant survived group cleanup')

    def test_cancel_stops_child(self):
        self.exercise('cancel')

    def test_timeout_stops_child(self):
        self.exercise('timeout')

    def test_normal_parent_exit_stops_child_with_inherited_pipes(self):
        self.exercise('exit')
