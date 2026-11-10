import argparse
import json
from collections import Counter

from config import (
    CACHE_DIR,
    MALWAREBAZAAR_API_KEY,
    VIRUSTOTAL_API_KEY,
    REQUEST_TIMEOUT,
    OUTPUT_DIR,
    CLASSES_FILE,
)
from analyzer import analyze_records
from exporter import export_feed
from importers.etda import fetch_etda
from importers.malwarebazaar import fetch_malwarebazaar
from importers.virustotal import collect_reports, load_hashes, write_json
from merger import merge_records


def get_source(name, list_key, fetch, refresh):
    path = CACHE_DIR / f"{name}.json"
    from_cache = path.is_file() and not refresh
    result = json.loads(path.read_text(encoding="utf-8")) if from_cache else fetch()

    records = result.get(list_key) if isinstance(result, dict) else None
    if not isinstance(records, list) or not records:
        raise ValueError(f"{name}: отсутствует непустой список {list_key}.")

    if not from_cache:
        write_json(path, result)

    origin = "кэш" if from_cache else "API"
    print(f"{name}: {len(records)} записей ({origin}). Файл: {path}", flush=True)


def build_feed():
    load_hashes(CACHE_DIR / "malwarebazaar.json")
    bazaar = json.loads((CACHE_DIR / "malwarebazaar.json").read_text(encoding="utf-8"))
    etda = json.loads((CACHE_DIR / "etda.json").read_text(encoding="utf-8"))
    classes = json.loads(CLASSES_FILE.read_text(encoding="utf-8"))
    merged, stats, unmatched = merge_records(
        bazaar["data"], etda, CACHE_DIR / "virustotal", classes
    )
    records = analyze_records(merged, classes)
    path = export_feed(records, OUTPUT_DIR / "feed.jsonl", classes)
    counts = Counter(record["threat_level"] for record in records)
    print(f"Фид: {len(records)} записей. Файл: {path}", flush=True)
    print(
        f"ETDA: совпало {stats.get('matched_etda', 0)}; "
        f"нет signature {stats.get('signature_missing', 0)}; "
        f"нет семейства {stats.get('family_not_found', 0)}; "
        f"неоднозначно {stats.get('ambiguous_family', 0)}.",
        flush=True,
    )
    print("Уровни: " + ", ".join(f"{key}={counts[key]}" for key in ("LOW", "MEDIUM", "HIGH", "UNKNOWN")), flush=True)
    if unmatched:
        print("Без однозначной карточки ETDA: " + ", ".join(f"{name} ({count})" for name, count in sorted(unmatched.items())), flush=True)
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="Сборка TI-фида.")
    parser.add_argument(
        "--mode",
        choices=("all", "sources", "vt", "build"),
        default="all",
        help="all — весь процесс; sources — MalwareBazaar и ETDA; vt — отчёты; build — фид из кэша",
    )
    parser.add_argument(
        "--refresh",
        action="store_true",
        help="Заново запросить выбранные источники, включая готовые отчёты VT",
    )
    args = parser.parse_args(argv)

    if args.mode == "build":
        if args.refresh:
            parser.error("--mode build читает только кэш; для обновления выбери --mode all --refresh")
        return build_feed()

    if args.mode != "vt":
        get_source(
            "malwarebazaar",
            "data",
            lambda: fetch_malwarebazaar(
                MALWAREBAZAAR_API_KEY,
                timeout=REQUEST_TIMEOUT,
            ),
            args.refresh,
        )

    hashes = load_hashes(CACHE_DIR / "malwarebazaar.json")

    if args.mode != "vt":
        get_source("etda", "values", fetch_etda, args.refresh)

    if args.mode == "sources":
        return 0

    code = collect_reports(
        hashes,
        VIRUSTOTAL_API_KEY,
        CACHE_DIR,
        refresh=args.refresh,
    )
    if code or args.mode == "vt":
        return code
    return build_feed()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, RuntimeError, OSError) as error:
        raise SystemExit(f"Ошибка: {error}")
