import copy
import json

from analyzer import threat_level
from exporter import export_feed
from merger import build_etda_index, extract_av_detects, merge_records, resolve_family
from tests.helpers import CLASSES, OfflineTestCase, card, etda, report, sample, save_json


class FamilyTests(OfflineTestCase):
    def resolve(self, signature, *cards):
        index, groups = build_etda_index(etda(*cards))
        return resolve_family(signature, index, groups)

    def test_unicode_case_and_punctuation_do_not_prevent_matching(self):
        self.assertEqual(self.resolve("ＥＸＡＭＰＬＥ-ＲＡＴ"),
                         (["Example RAT"], ["Backdoor"], "matched_etda"))

    def test_alias_keeps_original_signature_and_canonical_family(self):
        result = self.resolve("Demo", card(aliases=["Demo", "demo"],
                                           types=["Backdoor", "Keylogger", "Keylogger"]))
        self.assertEqual(result, (["Demo", "Example RAT"],
                                  ["Backdoor", "Trojan-Spy"], "matched_etda"))

    def test_missing_signature_and_unknown_family_stay_unclassified(self):
        for signature in (None, "", "   "):
            with self.subTest(signature=signature):
                self.assertEqual(self.resolve(signature), ([], [], "signature_missing"))
        self.assertEqual(self.resolve("Unknown RAT"),
                         (["Unknown RAT"], [], "family_not_found"))


    def test_shared_alias_in_independent_cards_is_ambiguous(self):
        result = self.resolve("Shared", card(aliases=["Shared"]),
                              card("Second", "card-2", ["Ransomware"], ["Shared"]))
        self.assertEqual(result, (["Shared"], [], "ambiguous_family"))

    def test_same_as_links_merge_families_and_classes_through_external_uuid(self):
        link = {"type": "same-as", "dest-uuid": "external-card"}
        result = self.resolve("Example RAT", card(related=[link]),
                              card("Second", "card-2", ["Ransomware"], related=[link]))
        self.assertEqual(result, (["Example RAT", "Second"],
                                  ["Backdoor", "Trojan-Ransom"], "matched_etda"))


    def test_loader_description_refers_to_the_tool_itself(self):
        tool = card("GuLoader", types=["Loader"], description=(
            "GuLoader is a downloader, written partly in VB6. It delivers RAT payloads."))
        self.assertEqual(self.resolve("GuLoader", tool)[1], ["Trojan-Downloader"])
        tool["description"] = "AnotherTool is a downloader. NotGuLoader is a dropper."
        self.assertEqual(self.resolve("GuLoader", tool)[1], [])


    def test_av_labels_are_filtered_trimmed_and_deduplicated(self):
        scans = {
            "first": {"category": "malicious", "result": " Demo.Trojan "},
            "second": {"category": "suspicious", "result": "Demo.Trojan"},
            "third": {"category": "undetected", "result": "NotADetection"},
            "fourth": {"category": "timeout", "result": "Timeout"},
            "fifth": {"category": "failure", "result": "Error"},
            "sixth": {"category": "malicious", "result": None},
        }
        self.assertEqual(extract_av_detects(report("a" * 64, last_analysis_results=scans)),
                         ["Demo.Trojan"])


class MergeTests(OfflineTestCase):
    def setUp(self):
        super().setUp()
        self.sample = sample()
        self.report_path = self.directory / (self.sample["sha256_hash"] + ".json")
        save_json(self.report_path, report(self.sample["sha256_hash"]))

    def merge(self, samples=None):
        return merge_records(samples or [self.sample], etda(), self.directory, CLASSES)


    def test_report_with_another_hash_or_md5_is_rejected(self):
        wrong_id = report("f" * 64)
        wrong_md5 = report(self.sample["sha256_hash"], md5="f" * 32)
        for payload in (wrong_id, wrong_md5):
            save_json(self.report_path, payload)
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                self.merge()


class RiskTests(OfflineTestCase):
    def test_known_classes_get_low_medium_high_and_empty_gets_unknown(self):
        cases = [(["Spam"], "LOW"), (["Trojan-Downloader"], "MEDIUM"),
                 (["Trojan-PSW"], "HIGH"), ([], "UNKNOWN")]
        for classes, expected in cases:
            with self.subTest(classes=classes):
                self.assertEqual(threat_level(classes, CLASSES), expected)

    def test_highest_class_risk_wins_instead_of_counting_classes(self):
        cases = [(["Adware", "Spam"], "LOW"),
                 (["Spam", "Trojan-Downloader"], "MEDIUM"),
                 (["Trojan-Downloader", "Backdoor"], "HIGH")]
        for classes, expected in cases:
            with self.subTest(classes=classes):
                self.assertEqual(threat_level(classes, CLASSES), expected)


class ExportTests(OfflineTestCase):
    def setUp(self):
        super().setUp()
        self.path = self.directory / "feed.jsonl"
        self.path.write_bytes(b"previous feed\n")
        self.records = [{"md5": f"{i:032x}", "sha256": f"{i:064x}",
                         "malware_class": ["Backdoor"], "malware_family": ["Пример"],
                         "av_detects": ["Demo.Trojan"], "threat_level": "HIGH"}
                        for i in range(1, 101)]

    def test_jsonl_has_100_objects_utf8_and_deterministic_lf_output(self):
        export_feed(self.records, self.path, CLASSES)
        first = self.path.read_bytes()
        self.assertNotIn(b"\r", first)
        self.assertTrue(first.endswith(b"\n"))
        self.assertIn("Пример".encode("utf-8"), first)
        self.assertEqual([json.loads(line) for line in first.decode().splitlines()], self.records)
        export_feed(self.records, self.path, CLASSES)
        self.assertEqual(first, self.path.read_bytes())


    def test_invalid_records_and_duplicate_hashes_keep_previous_file(self):
        for records in (self.records[:-1], self.records + [self.records[0]]):
            with self.subTest(size=len(records)), self.assertRaises(ValueError):
                export_feed(records, self.path, CLASSES)
            self.assertEqual(self.path.read_bytes(), b"previous feed\n")
        changes = [{"sha256": self.records[1]["sha256"]}, {"md5": "bad"},
                   {"extra": "field"}, {"malware_class": ["InventedClass"]},
                   {"malware_family": ["same", "same"]}, {"av_detects": [None]},
                   {"threat_level": "invalid"}, {"malware_class": []}]
        for change in changes:
            records = copy.deepcopy(self.records)
            records[0].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                export_feed(records, self.path, CLASSES)
            self.assertEqual(self.path.read_bytes(), b"previous feed\n")
