import json
import re
from pathlib import Path


FIELDS = {"md5", "sha256", "malware_class", "malware_family", "av_detects", "threat_level"}
LEVELS = {"LOW", "MEDIUM", "HIGH", "UNKNOWN"}


def export_feed(records, output_path, known_classes):
    if len(records) != 100:
        raise ValueError("Фид должен содержать ровно 100 записей.")
    seen = set()
    lines = []
    for record in records:
        if set(record) != FIELDS:
            raise ValueError("Неверный набор полей записи фида.")
        for field, size in (("md5", 32), ("sha256", 64)):
            value = record[field]
            if not isinstance(value, str) or not re.fullmatch(rf"[0-9a-f]{{{size}}}", value):
                raise ValueError(f"Некорректный {field} в фиде.")
        if record["sha256"] in seen:
            raise ValueError("В фиде повторяются SHA-256.")
        seen.add(record["sha256"])
        for field in ("malware_class", "malware_family", "av_detects"):
            values = record[field]
            if (
                not isinstance(values, list)
                or not all(isinstance(value, str) and value.strip() for value in values)
                or len(values) != len(set(values))
            ):
                raise ValueError(f"Неверный список {field} в фиде.")
        if set(record["malware_class"]) - set(known_classes):
            raise ValueError("В фиде есть класс, которого нет в задании.")
        if record["threat_level"] not in LEVELS:
            raise ValueError("Неизвестный threat_level.")
        if (not record["malware_class"]) != (record["threat_level"] == "UNKNOWN"):
            raise ValueError("Пустые классы должны иметь уровень UNKNOWN.")
        lines.append(json.dumps(record, ensure_ascii=False, separators=(",", ":")))

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = output_path.with_name(output_path.name + ".tmp")
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as stream:
            stream.write("\n".join(lines) + "\n")
        temporary.replace(output_path)
    finally:
        temporary.unlink(missing_ok=True)
    return output_path
