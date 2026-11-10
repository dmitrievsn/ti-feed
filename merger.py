import json
import re
import unicodedata
from collections import Counter, defaultdict
from pathlib import Path

from importers.virustotal import normalize_sha256, validate_report


TYPE_TO_CLASS = {
    "Backdoor": "Backdoor",
    "Keylogger": "Trojan-Spy",
    "Credential stealer": "Trojan-PSW",
    "Downloader": "Trojan-Downloader",
    "Dropper": "Trojan-Dropper",
    "Ransomware": "Trojan-Ransom",
    "Banking trojan": "Trojan-Banker",
    "Rootkit": "Rootkit",
    "Worm": "Worm",
    "DDoS": "Trojan-DDoS",
}


def normalize_name(value):
    text = unicodedata.normalize("NFKC", value).casefold()
    return "".join(character for character in text if character.isalnum())


def build_etda_index(payload):
    if not isinstance(payload, dict) or payload.get("type") != "tgc-tools":
        raise ValueError("В cache/etda.json ожидается справочник tgc-tools.")
    tools = payload.get("values")
    if not isinstance(tools, list) or not tools:
        raise ValueError("В справочнике ETDA отсутствует список values.")

    parents = {}

    def find(value):
        parents.setdefault(value, value)
        if parents[value] != value:
            parents[value] = find(parents[value])
        return parents[value]

    def union(left, right):
        left, right = find(left), find(right)
        if left != right:
            parents[right] = left

    for tool in tools:
        if (
            not isinstance(tool, dict)
            or not isinstance(tool.get("uuid"), str)
            or not isinstance(tool.get("value"), str)
            or not tool["value"].strip()
        ):
            raise ValueError("Карточка ETDA не содержит uuid или названия.")
        find(tool["uuid"])
        for link in tool.get("related", []):
            if link.get("type") == "same-as" and isinstance(link.get("dest-uuid"), str):
                union(tool["uuid"], link["dest-uuid"])

    groups = defaultdict(list)
    for tool in tools:
        groups[find(tool["uuid"])].append(tool)

    index = defaultdict(set)
    for group_id, records in groups.items():
        for tool in records:
            aliases = tool.get("meta", {}).get("synonyms", [])
            if not isinstance(aliases, list):
                raise ValueError("Неверный список synonyms в карточке ETDA.")
            for name in [tool["value"], *aliases]:
                if isinstance(name, str) and normalize_name(name):
                    index[normalize_name(name)].add(group_id)
    return index, groups


def classes_from_tool(tool):
    types = tool.get("meta", {}).get("type", [])
    if not isinstance(types, list):
        raise ValueError("Неверный список type в карточке ETDA.")
    classes = {TYPE_TO_CLASS[value] for value in types if value in TYPE_TO_CLASS}

    # Loader не определяет, скачивается ли нагрузка или извлекается из тела.
    # Уточняем только при прямом утверждении о самой программе в описании.
    if "Loader" in types:
        description = " ".join(tool.get("description", "").split())
        for word, class_name in (
            ("downloader", "Trojan-Downloader"),
            ("dropper", "Trojan-Dropper"),
        ):
            pattern = rf"(?<!\w){re.escape(tool['value'])}\s+is\s+an?\s+{word}\b"
            if re.search(pattern, description, flags=re.IGNORECASE):
                classes.add(class_name)
    return classes


def resolve_family(signature, index, groups):
    if signature is None or signature == "":
        return [], [], "signature_missing"
    if not isinstance(signature, str):
        raise ValueError("Поле signature MalwareBazaar должно быть строкой или null.")
    signature = signature.strip()
    if not normalize_name(signature):
        return [], [], "signature_missing"

    matches = index.get(normalize_name(signature), set())
    if not matches:
        return [signature], [], "family_not_found"
    if len(matches) != 1:
        return [signature], [], "ambiguous_family"

    tools = groups[next(iter(matches))]
    families = {}
    for tool in tools:
        families.setdefault(normalize_name(tool["value"]), tool["value"].strip())
    families.setdefault(normalize_name(signature), signature)
    classes = set()
    for tool in tools:
        classes.update(classes_from_tool(tool))
    return sorted(families.values()), sorted(classes), "matched_etda"


def extract_av_detects(report):
    scans = report["data"]["attributes"].get("last_analysis_results")
    if not isinstance(scans, dict):
        raise ValueError("В отчёте VirusTotal нет last_analysis_results.")
    detects = set()
    for scan in scans.values():
        if not isinstance(scan, dict):
            raise ValueError("Неверный формат результата движка VirusTotal.")
        label = scan.get("result")
        if (
            scan.get("category") in ("malicious", "suspicious")
            and isinstance(label, str)
            and label.strip()
        ):
            detects.add(label.strip())
    return sorted(detects)


def merge_records(samples, etda, reports_dir, known_classes):
    index, groups = build_etda_index(etda)
    records = []
    stats = Counter()
    unmatched = Counter()
    seen = set()
    for sample in samples:
        sha256 = normalize_sha256(sample.get("sha256_hash"))
        md5 = sample.get("md5_hash")
        if not isinstance(md5, str) or not re.fullmatch(r"[0-9a-fA-F]{32}", md5):
            raise ValueError(f"Некорректный MD5 в MalwareBazaar: {sha256}.")
        if sha256 in seen:
            raise ValueError(f"Повторяющийся SHA-256 в исходных данных: {sha256}.")
        seen.add(sha256)

        report_path = Path(reports_dir) / f"{sha256}.json"
        if not report_path.is_file():
            raise ValueError(f"Нет отчёта VT для {sha256}. Запусти main.py --mode vt.")
        report = json.loads(report_path.read_text(encoding="utf-8"))
        validate_report(report, sha256)
        report_md5 = report["data"]["attributes"].get("md5")
        if isinstance(report_md5, str) and report_md5.lower() != md5.lower():
            raise ValueError(f"MD5 MalwareBazaar и VirusTotal различаются: {sha256}.")

        families, classes, status = resolve_family(sample.get("signature"), index, groups)
        if set(classes) - set(known_classes):
            raise ValueError("Маппинг содержит класс, которого нет в задании.")
        detects = extract_av_detects(report)
        records.append({
            "md5": md5.lower(),
            "sha256": sha256,
            "malware_class": classes,
            "malware_family": families,
            "av_detects": detects,
        })
        stats[status] += 1
        stats["without_classes"] += not classes
        stats["zero_av_detects"] += not detects
        if status in ("family_not_found", "ambiguous_family"):
            unmatched[sample["signature"]] += 1
    return records, dict(stats), dict(unmatched)
