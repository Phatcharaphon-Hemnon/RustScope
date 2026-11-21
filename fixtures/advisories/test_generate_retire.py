import unittest

from generate_retire import filter_repository


class RetireSnapshotTest(unittest.TestCase):
    def test_keeps_only_url_extractors_and_advisory_fields(self):
        library = {
            "npmname": "sample",
            "extractors": {"uri": ["uri"], "filename": ["name"], "filecontent": ["content"],
                           "hashes": {"hash": "1.0.0"}},
            "vulnerabilities": [{
                "below": "2.0.0", "atOrAbove": "1.0.0", "severity": "high", "info": ["url"],
                "identifiers": {"CVE": ["CVE-2000-0000"], "issue": "123", "summary": "text"},
            }],
        }
        self.assertEqual(
            filter_repository({
                "sample": library, "retire-example": library,
                "content-only": dict(library, extractors={"filecontent": ["content"]}),
                "ignore-list": dict(library, vulnerabilities=[]),
            }),
            {"sample": {
                "extractors": {"uri": ["uri"], "filename": ["name"]},
                "vulnerabilities": [{
                    "below": "2.0.0", "atOrAbove": "1.0.0", "severity": "high",
                    "identifiers": {"CVE": ["CVE-2000-0000"], "issue": ["123"]},
                }],
            }},
        )
