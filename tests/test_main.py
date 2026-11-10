import json
from unittest.mock import patch

import main as app
from tests.helpers import OfflineTestCase, etda, report, sample, save_json


class MainTests(OfflineTestCase):
    def setUp(self):
        super().setUp()
        self.cache = self.directory / "cache"
        self.output = self.directory / "output"
        self.bazaar = {"query_status": "ok", "data": [
            sample(i, "Example RAT" if i % 2 else None) for i in range(1, 101)
        ]}
        save_json(self.cache / "malwarebazaar.json", self.bazaar)
        save_json(self.cache / "etda.json", etda())
        for value in self.bazaar["data"]:
            sha256 = value["sha256_hash"]
            save_json(self.cache / "virustotal" / f"{sha256}.json", report(sha256))
        for name, value in (("CACHE_DIR", self.cache), ("OUTPUT_DIR", self.output),
                            ("MALWAREBAZAAR_API_KEY", ""), ("VIRUSTOTAL_API_KEY", "")):
            setting = patch.object(app, name, value)
            setting.start()
            self.addCleanup(setting.stop)

    def test_build_runs_without_keys_and_preserves_input_files(self):
        inputs = {path: path.read_bytes() for path in self.cache.rglob("*.json")}
        with (patch.object(app, "fetch_malwarebazaar") as mb,
              patch.object(app, "fetch_etda") as directory,
              patch.object(app, "collect_reports") as collect):
            self.assertEqual(app.main(["--mode", "build"]), 0)
        mb.assert_not_called()
        directory.assert_not_called()
        collect.assert_not_called()
        raw = (self.output / "feed.jsonl").read_bytes()
        records = [json.loads(line) for line in raw.decode("utf-8").splitlines()]
        self.assertEqual(len(records), 100)
        self.assertEqual(len({record["sha256"] for record in records}), 100)
        self.assertEqual([record["sha256"] for record in records],
                         [value["sha256_hash"] for value in self.bazaar["data"]])
        self.assertEqual(sum(record["threat_level"] == "HIGH" for record in records), 50)
        self.assertEqual(sum(record["threat_level"] == "UNKNOWN" for record in records), 50)
        self.assertEqual(app.main(["--mode", "build"]), 0)
        self.assertEqual(raw, (self.output / "feed.jsonl").read_bytes())
        self.assertEqual(inputs, {path: path.read_bytes() for path in self.cache.rglob("*.json")})
