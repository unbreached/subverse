"""Offline tests for the headless-screenshot argv builder."""

import unittest

from subverse.platform_utils import _screenshot_argv


class ScreenshotArgvTest(unittest.TestCase):
    def _argv(self, no_sandbox):
        return _screenshot_argv("chrome", "--headless=new", "file:///x.html",
                                "/tmp/o.png", 1240, 1400, 2, no_sandbox=no_sandbox)

    def test_sandbox_on_by_default_omits_no_sandbox(self):
        argv = self._argv(no_sandbox=False)
        self.assertNotIn("--no-sandbox", argv)

    def test_no_sandbox_included_only_when_requested(self):
        argv = self._argv(no_sandbox=True)
        self.assertIn("--no-sandbox", argv)

    def test_carries_core_flags(self):
        argv = self._argv(no_sandbox=False)
        self.assertEqual(argv[0], "chrome")
        self.assertIn("--headless=new", argv)
        self.assertIn("--screenshot=/tmp/o.png", argv)
        self.assertIn("file:///x.html", argv)


if __name__ == "__main__":
    unittest.main()
