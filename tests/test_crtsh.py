"""Offline tests for the crt.sh parser/filter.

These feed canned crt.sh JSON (the exact shapes the service returns, including
its noise) to the pure parser, so no network is touched. Run with:

    python -m unittest discover -s tests
"""

import unittest

from subverse.crtsh import parse_crtsh_json, merge_targets

# A response shaped like real crt.sh output, including the noise observed live:
#   - a CA / intermediate string with spaces
#   - subject email addresses
#   - a *. wildcard entry
#   - a single name_value holding several names separated by newlines
#   - a look-alike domain that merely contains the apex as a substring
#   - mixed case
_SAMPLE = """
[
  {"name_value": "www.example.com\\ndev.example.com"},
  {"name_value": "*.example.com"},
  {"name_value": "API.Example.com"},
  {"name_value": "as207960 test intermediate - example.com"},
  {"name_value": "user@example.com"},
  {"name_value": "subjectname@example.com"},
  {"name_value": "m.testexample.com"},
  {"name_value": "legacy-staging.example.com"},
  {"common_name": "old.example.com", "name_value": "old.example.com"}
]
"""


class ParseCrtShTest(unittest.TestCase):
    def test_extracts_subdomains_ending_in_apex(self):
        got = parse_crtsh_json(_SAMPLE, "example.com")
        self.assertIn("www.example.com", got)
        self.assertIn("dev.example.com", got)
        self.assertIn("legacy-staging.example.com", got)
        self.assertIn("old.example.com", got)

    def test_splits_multivalue_name_fields(self):
        # one name_value held both www and dev separated by a newline
        got = parse_crtsh_json('[{"name_value": "a.example.com\\nb.example.com"}]',
                               "example.com")
        self.assertIn("a.example.com", got)
        self.assertIn("b.example.com", got)

    def test_strips_wildcard_prefix(self):
        got = parse_crtsh_json('[{"name_value": "*.example.com"}]', "example.com")
        # "*.example.com" becomes the apex, not a literal "*" host
        self.assertNotIn("*.example.com", got)
        self.assertNotIn("*", "".join(got))

    def test_lowercases(self):
        got = parse_crtsh_json('[{"name_value": "API.Example.COM"}]', "example.com")
        self.assertIn("api.example.com", got)
        self.assertNotIn("API.Example.COM", got)

    def test_drops_emails(self):
        got = parse_crtsh_json(_SAMPLE, "example.com")
        self.assertFalse(any("@" in h for h in got))

    def test_drops_entries_with_spaces(self):
        got = parse_crtsh_json(_SAMPLE, "example.com")
        self.assertFalse(any(" " in h for h in got))

    def test_drops_lookalike_domains(self):
        # m.testexample.com ends with "example.com" as a substring but is NOT
        # a subdomain of example.com, so it must be excluded.
        got = parse_crtsh_json(_SAMPLE, "example.com")
        self.assertNotIn("m.testexample.com", got)
        self.assertFalse(any(h.endswith("testexample.com") for h in got))

    def test_includes_the_apex_itself(self):
        got = parse_crtsh_json('[{"name_value": "www.example.com"}]', "example.com")
        self.assertIn("example.com", got)

    def test_result_is_sorted_and_deduped(self):
        got = parse_crtsh_json(_SAMPLE, "example.com")
        self.assertEqual(got, sorted(set(got)))

    def test_empty_response_still_returns_apex(self):
        self.assertEqual(parse_crtsh_json("[]", "example.com"), ["example.com"])

    def test_bad_json_raises_valueerror(self):
        with self.assertRaises(ValueError):
            parse_crtsh_json("not json", "example.com")


class MergeTargetsTest(unittest.TestCase):
    def test_merges_and_preserves_order_existing_first(self):
        existing = [("www.example.com", "from file")]
        new = [("dev.example.com", "")]
        self.assertEqual(
            merge_targets(existing, new),
            [("www.example.com", "from file"), ("dev.example.com", "")],
        )

    def test_dedupes_case_insensitively_keeping_first_note(self):
        existing = [("www.example.com", "prod web")]
        new = [("WWW.example.com", "")]
        # the duplicate from crt.sh must not overwrite the file's note
        self.assertEqual(merge_targets(existing, new),
                         [("www.example.com", "prod web")])

    def test_drops_blank_hosts(self):
        self.assertEqual(merge_targets([("", "x")], [("a.example.com", "")]),
                         [("a.example.com", "")])


if __name__ == "__main__":
    unittest.main()
