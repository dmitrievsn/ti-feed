import requests


ETDA_URL = "https://apt.etda.or.th/cgi-bin/getmisp.cgi?o=t"


def fetch_etda(timeout=60):
    """Получить справочник инструментов и семейств из ETDA."""
    response = requests.get(ETDA_URL, timeout=timeout)
    response.raise_for_status()

    result = response.json()
    if not isinstance(result, dict) or result.get("type") != "tgc-tools":
        raise ValueError("ETDA вернул неожиданный формат справочника.")

    tools = result.get("values")
    if not isinstance(tools, list) or not tools:
        raise ValueError("В ответе ETDA отсутствует непустой список values.")
    if not all(
        isinstance(tool, dict)
        and isinstance(tool.get("value"), str)
        and tool["value"].strip()
        for tool in tools
    ):
        raise ValueError("Справочник ETDA содержит записи без названия.")

    return result
