import unittest
from analyzer import analyze, fingerprint, parse

class Tests(unittest.TestCase):
    def test_fingerprint_normalizes_numbers(self):
        self.assertEqual(fingerprint("timeout 1000ms"), fingerprint("timeout 5000ms"))
    def test_invalid_line_is_rejected(self):
        events, rejected = parse("bad line")
        self.assertEqual((len(events), rejected), (0, 1))
    def test_critical_service_has_highest_risk(self):
        events, _ = parse("2026-01-01T00:00:00Z INFO api - ok\n2026-01-01T00:00:01Z CRITICAL db - down")
        self.assertEqual(analyze(events)["services"][0]["name"], "db")

if __name__ == "__main__":
    unittest.main()
