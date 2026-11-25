import unittest
from html.parser import HTMLParser
from pathlib import Path
from sentinel.help_examples import cve_example, zap_example


class Frames(HTMLParser):
    def __init__(self):
        super().__init__()
        self.frames = []

    def handle_starttag(self, tag, attrs):
        if tag == 'iframe':
            self.frames.append(dict(attrs))


class BeginnerExamplesTests(unittest.TestCase):
    def test_fake_cve_matches_real_parser_without_file(self):
        result = cve_example()
        self.assertEqual(len(result['matches']), 1)
        self.assertEqual(result['product'], 'practice:demo_app')

    def test_fake_zap_report_uses_real_parser(self):
        result = zap_example()
        self.assertEqual(result['Alert types reported'], 1)
        self.assertEqual(result['Risk counts'], {'low': 1})
        self.assertIn('Not a new scan', result['Review limitation'])

    def test_fixed_browser_demo_has_sandbox_and_no_external_frames(self):
        page = Path(__file__).resolve().parents[1] / 'sentinel' / 'xss_practice.html'
        parser = Frames()
        parser.feed(page.read_text(encoding='utf-8'))
        self.assertEqual(len(parser.frames), 2)
        weak, safe = parser.frames
        self.assertEqual(weak['sandbox'], 'allow-scripts')
        self.assertIsNone(safe['sandbox'])
        for frame in parser.frames:
            self.assertNotIn('src', frame)
            self.assertIn("default-src 'none'", frame['srcdoc'])
        self.assertIn('<script>', weak['srcdoc'])
        self.assertNotIn('<script>', safe['srcdoc'])
        self.assertIn('&lt;script&gt;', safe['srcdoc'])
