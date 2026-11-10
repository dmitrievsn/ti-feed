import json
from unittest.mock import patch

from importers import malwarebazaar, virustotal as vt
from tests.helpers import Clock, OfflineTestCase, report, response, sample, save_json


class SourceTests(OfflineTestCase):
    def test_malwarebazaar_requests_100_samples_with_auth_header(self):
        payload = {"query_status": "ok", "data": [sample(i) for i in range(1, 101)]}
        with patch("importers.malwarebazaar.requests.post", return_value=response(payload)) as post:
            self.assertEqual(malwarebazaar.fetch_malwarebazaar("dummy-key"), payload)
        self.assertEqual(post.call_args.args, (malwarebazaar.API_URL,))
        self.assertEqual(post.call_args.kwargs["headers"], {"Auth-Key": "dummy-key"})
        self.assertEqual(post.call_args.kwargs["data"], {"query": "get_recent", "selector": "100"})


class VirusTotalClientTests(OfflineTestCase):
    def setUp(self):
        super().setUp()
        self.sha256 = "a" * 64
        self.clock = Clock()
        for name, replacement in (("monotonic", self.clock.monotonic),
                                  ("sleep", self.clock.sleep)):
            timer = patch(f"importers.virustotal.time.{name}", replacement)
            timer.start()
            self.addCleanup(timer.stop)


    def test_requests_stay_within_four_per_rolling_minute(self):
        starts = []

        def get(url, **kwargs):
            starts.append(self.clock.now)
            return response(report(url.rsplit("/", 1)[1]))

        with patch("requests.Session.get", side_effect=get):
            with vt.VirusTotalClient("dummy-key") as client:
                for i in range(8):
                    client.fetch_report(f"{i:064x}")
        self.assertTrue(all(right - left >= 16 for left, right in zip(starts, starts[1:])))
        for start in starts:
            self.assertLessEqual(sum(start <= value < start + 60 for value in starts), 4)


    def test_authentication_errors_stop_on_first_request(self):
        for status in (401, 403):
            with (self.subTest(status=status),
                  patch("requests.Session.get", return_value=response({}, status)) as get):
                with vt.VirusTotalClient("dummy-key") as client:
                    with self.assertRaises(vt.VirusTotalFatalError):
                        client.fetch_report(self.sha256)
                self.assertEqual(get.call_count, 1)

    def test_quota_retry_after_is_honored_without_real_sleep(self):
        replies = [response({}, 429, {"Retry-After": "120"}), response(report(self.sha256))]
        with patch("requests.Session.get", side_effect=replies) as get:
            with vt.VirusTotalClient("dummy-key") as client:
                self.assertEqual(client.fetch_report(self.sha256), report(self.sha256))
        self.assertEqual(get.call_count, 2)
        self.assertIn(120, self.clock.pauses)

    def test_repeated_quota_error_has_a_bounded_number_of_attempts(self):
        with patch("requests.Session.get", side_effect=[response({}, 429) for _ in range(3)]) as get:
            with vt.VirusTotalClient("dummy-key") as client:
                with self.assertRaises(vt.VirusTotalFatalError):
                    client.fetch_report(self.sha256)
        self.assertEqual(get.call_count, 3)


class CollectionTests(OfflineTestCase):
    def setUp(self):
        super().setUp()
        self.cache = self.directory / "cache"
        self.hashes = [f"{i:064x}" for i in range(1, 7)]
        self.source = self.cache / "malwarebazaar.json"
        save_json(self.source, {"query_status": "ok", "data": [sample(i) for i in range(1, 101)]})
        self.source_bytes = self.source.read_bytes()

    def run_collection(self, action=report, refresh=False):
        with patch("importers.virustotal.VirusTotalClient") as factory:
            client = factory.return_value.__enter__.return_value
            client.fetch_report.side_effect = action
            code = vt.collect_reports(self.hashes, "dummy-key", self.cache, refresh=refresh)
        self.assertEqual(self.source.read_bytes(), self.source_bytes)
        summary = json.loads((self.cache / "virustotal_summary.json").read_text(encoding="utf-8"))
        return code, [call.args[0] for call in client.fetch_report.call_args_list], summary

    def test_successful_restart_uses_cached_reports_without_requests(self):
        code, calls, summary = self.run_collection()
        self.assertEqual((code, calls), (0, self.hashes))
        self.assertTrue(summary["all_reports_available"])
        code, calls, summary = self.run_collection(AssertionError("Unexpected request"))
        self.assertEqual((code, calls, summary["counts"]["cached"]), (0, [], 6))

    def test_keyboard_interrupt_preserves_progress_and_restart_continues(self):
        def interrupted(sha256):
            if sha256 == self.hashes[2]:
                raise KeyboardInterrupt
            return report(sha256)

        code, _, summary = self.run_collection(interrupted)
        self.assertEqual(code, 130)
        self.assertEqual(summary["counts"]["downloaded"], 2)
        self.assertEqual(summary["counts"]["pending"], 4)
        code, calls, _ = self.run_collection()
        self.assertEqual((code, calls), (0, self.hashes[2:]))
