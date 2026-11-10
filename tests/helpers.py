import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import requests


ROOT = Path(__file__).resolve().parents[1]
CLASSES = json.loads((ROOT / "data/malware_classes.json").read_text(encoding="utf-8"))


def sample(index=1, signature="Example RAT"):
    return {"sha256_hash": f"{index:064x}", "md5_hash": f"{index:032x}",
            "signature": signature}


def report(sha256, **attributes):
    return {"data": {"id": sha256, "type": "file", "attributes": {
        "sha256": sha256, "md5": sha256[-32:], "last_analysis_results": {},
        **attributes,
    }}}


def card(name="Example RAT", uid="card-1", types=("Backdoor",),
         aliases=(), related=(), description=""):
    return {"uuid": uid, "value": name, "description": description,
            "meta": {"type": list(types), "synonyms": list(aliases)},
            "related": list(related)}


def etda(*cards):
    return {"type": "tgc-tools", "values": list(cards) or [card()]}


def save_json(path, payload):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")


def response(payload, status=200, headers=None):
    result = requests.Response()
    result.status_code = status
    result._content = json.dumps(payload).encode("utf-8")
    result.headers.update(headers or {})
    return result


class OfflineTestCase(unittest.TestCase):
    def setUp(self):
        network = patch("requests.sessions.Session.request",
                        side_effect=AssertionError("Тест попытался обратиться к API"))
        network.start()
        self.addCleanup(network.stop)
        output = patch("sys.stdout", new=io.StringIO())
        output.start()
        self.addCleanup(output.stop)
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)


class Clock:
    def __init__(self):
        self.now = 0.0
        self.pauses = []

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.pauses.append(seconds)
        self.now += seconds
