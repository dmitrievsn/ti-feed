LOW_CLASSES = {
    "Spam", "Adware", "WebToolbar", "Hoax", "Trojan-Clicker",
}

HIGH_CLASSES = {
    "Exploit", "Trojan-DDoS", "Trojan-Ransom", "Trojan-Spy", "Trojan-IM",
    "Trojan-GameThief", "Trojan-PSW", "Trojan-Banker", "Backdoor", "Rootkit",
    "Bootkit", "Virus", "Worm", "IRC-Worm", "IM-Worm", "P2P-Worm",
    "Email-Worm", "Net-Worm",
}


def threat_level(classes, known_classes):
    if set(classes) - set(known_classes):
        raise ValueError("Нельзя оценить неизвестный класс ВПО.")
    if not classes:
        return "UNKNOWN"
    if set(classes) & HIGH_CLASSES:
        return "HIGH"
    if any(value not in LOW_CLASSES for value in classes):
        return "MEDIUM"
    return "LOW"


def analyze_records(records, known_classes):
    if (LOW_CLASSES | HIGH_CLASSES) - set(known_classes):
        raise ValueError("Классы аналитики не соответствуют справочнику задания.")
    return [
        {**record, "threat_level": threat_level(record["malware_class"], known_classes)}
        for record in records
    ]
