import os
import csv
import re
from datetime import datetime, timezone

import dns.resolver
import whois


# region: Вспомогательные константы, выражения и функции
VALID_EXTENSIONS = {".csv", ".txt"}


def _is_valid_extension(path: str) -> bool:
    """Проверка валидности расширения input-файла (.csv/.txt)."""
    ext = path.lower().rsplit(".", 1)[-1]
    return f".{ext}" in VALID_EXTENSIONS


_email_re = re.compile(
    r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
)


def _is_valid_email(email: str) -> bool:
    """
    Валидация формата email:
    - Не пустой
    - Есть @
    - Есть точка в доменной части
    """
    email = email.strip()
    if not email:
        return False
    return bool(_email_re.match(email))


def _get_domain(email: str) -> str:
    """Извлечение домена."""
    return email.strip().split("@", 1)[1].lower()


def _extract_expiration_date(whois_data):
    """Возвращает expiration_date или None."""
    exp = whois_data.get("expiration_date")

    if not exp:
        return None

    # Если список - берём первый элемент
    if isinstance(exp, list) and exp:
        exp = exp[0]

    # Иногда приходит str
    if isinstance(exp, str):
        try:
            exp = datetime.fromisoformat(exp.replace("Z", "+00:00"))
        except Exception:
            return None

    return exp if isinstance(exp, datetime) else None


def _whois_domain(domain: str) -> bool:
    """
    True - если домен живой (зарегистрирован и не истёк),
    False - если не найден / истёк / ошибка.
    """
    try:
        w = whois.whois(domain)
    except Exception:
        return False

    exp = _extract_expiration_date(w)
    if not exp:
        return False

    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)

    now = datetime.now(timezone.utc)
    return exp > now


def _mx_queries_domain(domain: str) -> bool:
    """
    Возвращает True, если у домена есть MX-записи.
    False - если MX нет или ошибка.
    """
    try:
        answers = dns.resolver.resolve(domain, "MX")
        return len(answers) > 0
    except Exception:
        return False


def _load_domain_cache(path: str | None) -> dict[str, dict]:
    """
    Кэш доменов в CSV-формате:
    domain,whois_alive,mx_exists,checked_at

    Нужен для экономии времени, исключая лишние запросы
    """
    cache: dict[str, dict] = {}
    if not path or not os.path.exists(path):
        return cache

    with open(path, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            domain = row.get("domain", "").strip().lower()
            if not domain:
                continue
            cache[domain] = {
                "whois_alive": row.get("whois_alive", "0") == "1",
                "mx_exists": row.get("mx_exists", "0") == "1",
                "checked_at": row.get("checked_at", ""),
            }
    return cache


def _save_domain_cache(path: str | None, cache: dict[str, dict]) -> None:
    """Сохранение обновленного/нового файла обработанных доменов."""
    if not path:
        return

    dirpath = os.path.dirname(path)
    if dirpath:
        os.makedirs(dirpath, exist_ok=True)

    with open(path, "w", encoding="utf-8", newline="") as f:
        fieldnames = ["domain", "whois_alive", "mx_exists", "checked_at"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for domain, info in cache.items():
            writer.writerow(
                {
                    "domain": domain,
                    "whois_alive": "1" if info.get("whois_alive") else "0",
                    "mx_exists": "1" if info.get("mx_exists") else "0",
                    "checked_at": info.get("checked_at")
                    or datetime.now(timezone.utc).isoformat(),
                }
            )


def _process_email(email: str, domain_cache: dict, writer: csv.DictWriter) -> None:
    """
    Обрабатывает один email:
    - Проверяет формат
    - Извлекает домен
    - Обновляет кэш доменов при необходимости
    - Пишет строку результата в writer
    """
    email = email.strip()
    if not _is_valid_email(email):
        return

    domain = _get_domain(email)

    # Если домена нет в кэше - проверяем WHOIS и MX
    if domain not in domain_cache:
        whois_alive = _whois_domain(domain)
        mx_exists = _mx_queries_domain(domain) if whois_alive else False

        domain_cache[domain] = {
            "whois_alive": whois_alive,
            "mx_exists": mx_exists,
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }
    else:
        whois_alive = domain_cache[domain]["whois_alive"]
        mx_exists = domain_cache[domain]["mx_exists"]

    writer.writerow(
        {
            "email": email,
            "domain": domain,
            "whois_alive": 1 if whois_alive else 0,
            "mx_exists": 1 if mx_exists else 0,
        }
    )
# endregion: Вспомогательные константы, выражения и функции

def validate_emails(
    emails_file: str,
    output_file: str = "output_data/output.csv",
    cached_domains: str | None = "./cached_domains/domains_cache.csv",
) -> None:
    """
    Данная функция:
    - Читаем входной файл (.csv/.txt)
    - Параллельно с чтением строк (emails) проверяем домен (сначала кэш потом запрос)
    - для каждой почты пишем строку в output_file.csv:
        email, domain, whois_alive, mx_exists
    - кэш доменов сохраняем/обновляем в cached_domains
    """
    if not _is_valid_extension(emails_file):
        raise ValueError("Входной файл должен быть .csv/.txt")

    # Загружаем кэшированные домены
    domain_cache = _load_domain_cache(cached_domains)

    ext = emails_file.lower().rsplit(".", 1)[-1]

    out_dir = os.path.dirname(output_file)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    with open(output_file, "w", encoding="utf-8", newline="") as out_f:
        fieldnames = ["email", "domain", "whois_alive", "mx_exists"]
        writer = csv.DictWriter(out_f, fieldnames=fieldnames)
        writer.writeheader()

        # Чтение входного файла
        if ext == "csv":
            # Ожидание колонки email; если нет - берём первую
            with open(emails_file, "r", encoding="utf-8", newline="") as in_f:
                reader = csv.DictReader(in_f)
                has_email_col = "email" in (reader.fieldnames or [])

                for row in reader:
                    if not row:
                        continue

                    email = (
                        row["email"].strip()
                        if has_email_col
                        else list(row.values())[0].strip()
                    )

                    _process_email(email, domain_cache, writer)


        elif ext == "txt":
            with open(emails_file, "r", encoding="utf-8") as in_f:
                for line in in_f:
                    email = line.strip()
                    _process_email(email, domain_cache, writer)

        else:
            raise ValueError("Поддерживаются только .csv и .txt")

    # Сохранение обновлённого кэша доменов
    _save_domain_cache(cached_domains, domain_cache)
