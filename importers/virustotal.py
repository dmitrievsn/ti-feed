import json
import math
import re
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

import requests

from config import REQUEST_TIMEOUT


API_URL = "https://www.virustotal.com/api/v3/files"
REQUEST_INTERVAL = 16
MAX_ATTEMPTS = 3
MAX_RETRY_WAIT = 300


class VirusTotalFatalError(RuntimeError):
    """Ошибка, после которой следует остановить весь сбор."""


class VirusTotalNotReadyError(RuntimeError):
    """Источник сообщает, что ресурс пока недоступен."""


def normalize_sha256(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", value):
        raise ValueError("В списке образцов обнаружен некорректный SHA-256.")
    return value.lower()


def validate_report(report, sha256):
    if not isinstance(report, dict):
        raise ValueError("VirusTotal вернул неожиданный формат отчёта.")
    data = report.get("data")
    if (
        not isinstance(data, dict)
        or data.get("type") != "file"
        or data.get("id") != sha256
        or not isinstance(data.get("attributes"), dict)
    ):
        raise ValueError("Отчёт VirusTotal не соответствует запрошенному SHA-256.")


def error_code(response):
    try:
        payload = response.json()
    except ValueError:
        return ""
    if isinstance(payload, dict) and isinstance(payload.get("error"), dict):
        code = payload["error"].get("code")
        return code if isinstance(code, str) else ""
    return ""


def retry_delay(response):
    delay = 60.0
    value = response.headers.get("Retry-After") if response is not None else None
    if value:
        try:
            requested = float(value)
        except ValueError:
            try:
                deadline = parsedate_to_datetime(value)
                if deadline.tzinfo is None:
                    deadline = deadline.replace(tzinfo=timezone.utc)
                requested = (deadline - datetime.now(timezone.utc)).total_seconds()
            except (TypeError, ValueError, OverflowError):
                requested = 60.0
        if math.isfinite(requested):
            delay = max(delay, requested)
    return delay


class VirusTotalClient:
    def __init__(self, api_key, timeout=30):
        if not api_key or not api_key.strip():
            raise ValueError("Укажи VIRUSTOTAL_API_KEY в файле .env.")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"x-apikey": api_key.strip()})
        # Пауза перед первым запросом также помогает при быстром перезапуске.
        self.next_request_at = time.monotonic() + REQUEST_INTERVAL

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.session.close()

    def wait_for_request(self):
        delay = self.next_request_at - time.monotonic()
        if delay > 0:
            time.sleep(delay)
        self.next_request_at = time.monotonic() + REQUEST_INTERVAL

    def pause_before_retry(self, attempt, reason, response=None):
        delay = retry_delay(response)
        if delay > MAX_RETRY_WAIT:
            raise VirusTotalFatalError(
                f"VirusTotal требует паузу {delay:.0f} сек. "
                "Сбор остановлен; повтори запуск позже."
            )
        print(
            f"[VT] {reason}. Попытка {attempt}/{MAX_ATTEMPTS}; "
            f"повтор через {delay:.0f} сек.",
            flush=True,
        )
        time.sleep(delay)

    def fetch_report(self, sha256):
        sha256 = normalize_sha256(sha256)
        for attempt in range(1, MAX_ATTEMPTS + 1):
            self.wait_for_request()
            try:
                response = self.session.get(
                    f"{API_URL}/{sha256}",
                    timeout=self.timeout,
                    allow_redirects=False,
                )
            except requests.RequestException as error:
                if attempt == MAX_ATTEMPTS:
                    raise RuntimeError(
                        f"Не удалось получить отчёт: {type(error).__name__}."
                    ) from error
                self.pause_before_retry(attempt, "Ошибка соединения")
                continue

            with response:
                status = response.status_code
                if status == 200:
                    report = response.json()
                    validate_report(report, sha256)
                    return report

                code = error_code(response)
                if status == 404 and code == "NotFoundError":
                    return None
                if status == 400 and code == "NotAvailableYet":
                    raise VirusTotalNotReadyError("Отчёт пока недоступен в VirusTotal.")
                if status in (401, 403):
                    raise VirusTotalFatalError(
                        f"VirusTotal: HTTP {status} ({code or 'ошибка доступа'}). "
                        "Проверь API-ключ и активацию аккаунта."
                    )
                if status == 429 or 500 <= status <= 599:
                    if attempt == MAX_ATTEMPTS:
                        if status == 429:
                            raise VirusTotalFatalError(
                                "VirusTotal продолжает возвращать HTTP 429. "
                                "Проверь оставшуюся квоту и повтори запуск позже."
                            )
                        raise RuntimeError(f"VirusTotal: HTTP {status} после повторов.")
                    self.pause_before_retry(attempt, f"HTTP {status}", response)
                    continue
                raise RuntimeError(f"VirusTotal: HTTP {status} ({code or 'ошибка API'}).")


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def write_json(path, payload):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    try:
        temporary.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def load_hashes(path):
    path = Path(path)
    if not path.is_file():
        raise ValueError("Нет cache/malwarebazaar.json. Сначала выполни python main.py.")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("query_status") != "ok":
        raise ValueError("В кэше MalwareBazaar нет успешного ответа API.")
    samples = payload.get("data")
    if not isinstance(samples, list) or len(samples) != 100:
        raise ValueError("В кэше MalwareBazaar должно быть 100 записей.")
    if not all(isinstance(sample, dict) for sample in samples):
        raise ValueError("Неверный формат записей MalwareBazaar.")
    hashes = [normalize_sha256(sample.get("sha256_hash")) for sample in samples]
    if len(set(hashes)) != len(hashes):
        raise ValueError("В списке MalwareBazaar обнаружены повторяющиеся SHA-256.")
    return hashes


def update_summary(path, summary):
    counts = dict.fromkeys(("cached", "downloaded", "not_found", "not_ready", "error"), 0)
    for record in summary["results"].values():
        counts[record["status"]] += 1
    counts["pending"] = len(summary["hashes"]) - len(summary["results"])
    summary["counts"] = counts
    summary["all_reports_available"] = (
        counts["cached"] + counts["downloaded"] == len(summary["hashes"])
    )
    summary["updated_at"] = utc_now()
    write_json(path, summary)


def collect_reports(hashes, api_key, cache_dir, refresh=False):
    if not api_key or not api_key.strip():
        raise ValueError("Укажи VIRUSTOTAL_API_KEY в файле .env.")
    cache_dir = Path(cache_dir)
    reports_dir = cache_dir / "virustotal"
    summary_path = cache_dir / "virustotal_summary.json"
    summary = {
        "started_at": utc_now(),
        "hashes": hashes,
        "results": {},
        "stopped_reason": None,
    }
    update_summary(summary_path, summary)
    print(
        f"VirusTotal: {len(hashes)} хэшей. Отчёты: {reports_dir}\n"
        "Между запросами не менее 16 сек.",
        flush=True,
    )
    interrupted = False
    consecutive_errors = 0
    try:
        with VirusTotalClient(api_key, timeout=REQUEST_TIMEOUT) as client:
            for index, sha256 in enumerate(hashes, start=1):
                report_path = reports_dir / f"{sha256}.json"
                prefix = f"[VT {index}/{len(hashes)}] {sha256[:12]}"
                if report_path.is_file() and not refresh:
                    try:
                        report = json.loads(report_path.read_text(encoding="utf-8"))
                        validate_report(report, sha256)
                    except ValueError:
                        print(f"{prefix}: неверный кэш, запрашиваю заново.", flush=True)
                    else:
                        summary["results"][sha256] = {"status": "cached"}
                        update_summary(summary_path, summary)
                        print(f"{prefix}: из кэша.", flush=True)
                        continue

                print(f"{prefix}: запрашиваю отчёт...", flush=True)
                try:
                    report = client.fetch_report(sha256)
                except VirusTotalNotReadyError:
                    consecutive_errors = 0
                    summary["results"][sha256] = {
                        "status": "not_ready", "http_status": 400,
                        "error_code": "NotAvailableYet", "checked_at": utc_now(),
                    }
                    print(f"{prefix}: отчёт пока недоступен (NotAvailableYet).", flush=True)
                except VirusTotalFatalError as error:
                    summary["results"][sha256] = {
                        "status": "error", "message": str(error)
                    }
                    summary["stopped_reason"] = str(error)
                    print(f"{prefix}: {error}", flush=True)
                    break
                except (RuntimeError, ValueError) as error:
                    summary["results"][sha256] = {
                        "status": "error", "message": str(error)
                    }
                    consecutive_errors += 1
                    print(f"{prefix}: ошибка: {error}", flush=True)
                    if consecutive_errors >= 3:
                        summary["stopped_reason"] = "Три последовательные ошибки получения отчётов."
                else:
                    consecutive_errors = 0
                    if report is None:
                        summary["results"][sha256] = {
                            "status": "not_found", "http_status": 404,
                            "error_code": "NotFoundError", "checked_at": utc_now(),
                        }
                        print(f"{prefix}: отчёт не найден (HTTP 404).", flush=True)
                    else:
                        write_json(report_path, report)
                        summary["results"][sha256] = {"status": "downloaded"}
                        print(f"{prefix}: отчёт сохранён.", flush=True)

                update_summary(summary_path, summary)
                if summary["stopped_reason"]:
                    break
    except KeyboardInterrupt:
        interrupted = True
        summary["stopped_reason"] = "Сбор прерван пользователем."
    finally:
        summary["finished_at"] = utc_now()
        update_summary(summary_path, summary)

    counts = summary["counts"]
    print(
        f"\nОтчётов: {counts['cached'] + counts['downloaded']}/{len(hashes)} "
        f"(из кэша: {counts['cached']}, загружено: {counts['downloaded']}).\n"
        f"Не найдено: {counts['not_found']}; пока недоступно: {counts['not_ready']}; "
        f"ошибок: {counts['error']}; "
        f"не обработано: {counts['pending']}.\n"
        f"Сводка: {summary_path}",
        flush=True,
    )
    if summary["stopped_reason"]:
        print(f"Причина остановки: {summary['stopped_reason']}", flush=True)
    if interrupted:
        return 130
    return 1 if counts["error"] or summary["stopped_reason"] else 0
