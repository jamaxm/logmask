"""Ядро маскирования: правила, псевдонимы, статистика.

Принципы:
- правило по ключу (password=, cvv=, phone=) надёжнее угадывания по виду значения;
- одинаковое значение внутри запуска получает одинаковую метку ([EMAIL_1]),
  чтобы по замаскированному логу можно было проследить клиента/сессию;
- оригинальные значения никогда не выводятся — ни в отчёт, ни в консоль.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import re
import secrets
import tomllib
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

DEFAULT_CONFIG = Path(__file__).with_name("rules.toml")

# Значения, которые уже «пустые» или замаскированы — не трогаем
_TRIVIAL = re.compile(r"(?i)^(|null|none|nil|undefined|true|false|\*+|x+|\[[A-Z_]+[^\]]*\])$")

# Для ключей, найденных по вхождению (lastLoginTime, tokenTtl): дата, время, короткое число
_NOT_SENSITIVE = re.compile(
    r"^(?:\d{4}-\d{2}-\d{2}(?:[ T]\d{2}:\d{2}(?::\d{2}(?:[.,]\d+)?)?)?(?:Z|[+-]\d{2}:?\d{2})?"
    r"|\d{2}:\d{2}(?::\d{2})?|\d{1,6}(?:\.\d+)?(?i:ms|s|m|h|d)?|(?i:true|false))$"
    r"|^[A-Z][A-Z_]{1,24}$")   # enum: loginResult=SUCCESS, tokenType=BEARER (регистр важен)

# Коды валют в номере счёта: 000 — сум в узбекских счетах, 860 UZS, 810/643 RUB,
# 398 KZT, 840 USD, 978 EUR, 826 GBP, 156 CNY, 392 JPY, 756 CHF, 933 BYN, 417 KGS, 972 TJS
_ACCOUNT_CURRENCIES = {"000", "860", "810", "643", "398", "840", "978", "826", "156", "392",
                       "756", "933", "417", "972"}

# Отдельно стоящее число из 10–20 цифр (опционально с именем поля перед ним)
_LONG_DIGITS = re.compile(r"\d{10}")
_SUSPECT = re.compile(r"(?<![\w.+*-])\d{10,20}(?![\w.*-])")
_ISO_FIELD_BEFORE = re.compile(r"(?i)\b(?:Field|DE|Bit|F)\s*\d")
# имя поля непосредственно перед числом: order_id=, "OpLogin" :: "
_KEY_BEFORE = re.compile(r"([@\w-]+)[\"']?\s*(?:=>|:=|::|[:=])\s*[\"']?$")


# ---------------------------------------------------------------- проверки

def luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def iban_ok(s: str) -> bool:
    s = s[4:] + s[:4]
    num = "".join(str(int(c, 36)) for c in s)
    return int(num) % 97 == 1


_KEY_TOKEN = re.compile(r"[A-ZА-ЯЁ]+(?![a-zа-яё])|[A-ZА-ЯЁ]?[a-zа-яё]+|\d+")


def key_tokens(key: str) -> list[str]:
    return [t.lower() for t in _KEY_TOKEN.findall(key)]


def has_word(tokens: list[str], word: list[str], prefix: bool = True) -> bool:
    """Есть ли в имени поля слово (или последовательность слов).
    prefix=True: последнее слово может продолжаться — coord ~ coordinates, phone ~ phones."""
    n = len(word)
    for i in range(len(tokens) - n + 1):
        if tokens[i:i + n - 1] == word[:-1]:
            last = tokens[i + n - 1]
            if last == word[-1] or (prefix and last.startswith(word[-1])):
                return True
    return False


def _digits(s: str) -> str:
    return re.sub(r"\D", "", s)


def card_prefix_ok(d: str) -> bool:
    """Номер начинается с реального префикса платёжной системы (IIN)."""
    p2, p4 = int(d[:2]), int(d[:4])
    return (2200 <= p4 <= 2204 or 2221 <= p4 <= 2720      # Мир, Mastercard 2-series
            or p2 in (30, 34, 35, 36, 37, 38)              # Diners, Amex, JCB
            or d[0] in "46"                                # Visa, Discover/UnionPay/Maestro
            or 50 <= p2 <= 59                              # Mastercard, Maestro
            or d[:4] in ("8600", "9860"))                  # Uzcard, Humo


def looks_like_datetime(d: str) -> bool:
    """20260930 / 20260930183252 / 20260930183252123 — дата и время слитно."""
    if len(d) < 8 or not 1970 <= int(d[:4]) <= 2099:
        return False
    limits = [(4, 6, 1, 12), (6, 8, 1, 31), (8, 10, 0, 23), (10, 12, 0, 59), (12, 14, 0, 60)]
    return all(lo <= int(d[a:b]) <= hi for a, b, lo, hi in limits if len(d) >= b)


def looks_like_epoch(d: str) -> bool:
    """Unix-время в секундах, миллисекундах, микро- и наносекундах (2001–2100 годы)."""
    if len(d) in (10, 13, 16, 19):
        return 1_000_000_000 <= int(d[:10]) <= 4_102_444_800
    return False


# ---------------------------------------------------------------- конфиг

@dataclass
class Config:
    style: str = "numbered"          # numbered | plain | hash
    salt: str = ""
    card_keep: str = "last4"         # none | last4
    ipv4: str = "full"               # full | subnet | off
    geo: str = "mask"                # mask | round
    geo_decimals: int = 1            # для geo = "round": 1 знак ≈ 11 км
    suspects: str = "warn"           # warn | mask | off — длинные нераспознанные числа
    suspect_ignore: list[str] = field(default_factory=list)
    bare_phones: list[tuple[str, int]] = field(default_factory=lambda: [("998", 9)])
    keys_contains: dict[str, list[str]] = field(default_factory=dict)
    contains_skip_last: set[str] = field(default_factory=set)   # PhoneModel, TransPhoneTime
    allow_keys: set[str] = field(default_factory=set)           # Start/End (BIN), KSN, RRN ...
    iso_fields: dict[int, str] = field(default_factory=dict)    # ISO 8583: номер поля -> метка
    iso_ignore: bool = True                                     # прочие поля ISO — не «подозрительные»
    ipv4_skip_words: set[str] = field(default_factory=set)      # CoreVersion, Build, ObjectId
    enabled: dict[str, bool] = field(default_factory=dict)
    keys: dict[str, list[str]] = field(default_factory=dict)
    allow: set[str] = field(default_factory=set)
    custom: list[tuple[str, str]] = field(default_factory=list)
    file_globs: list[str] = field(default_factory=lambda: ["*.log", "*.log.*", "*.txt", "*.out", "*.gz"])

    def on(self, rule: str) -> bool:
        return self.enabled.get(rule, True)

    @classmethod
    def load(cls, path: Path | None = None) -> "Config":
        path = path or DEFAULT_CONFIG
        data = tomllib.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
        ps = data.get("pseudonym", {})
        rules = data.get("rules", {})
        sus = data.get("suspects", {})
        phone = data.get("phone", {})
        return cls(
            style=ps.get("style", "numbered"),
            salt=os.environ.get("LOGMASK_SALT") or ps.get("salt", ""),
            card_keep=rules.get("card_keep", "last4"),
            ipv4=rules.get("ipv4", "full"),
            geo=rules.get("geo_mode", "mask"),
            geo_decimals=int(rules.get("geo_decimals", 1)),
            suspects=sus.get("mode", "warn"),
            suspect_ignore=[k.lower() for k in sus.get("ignore_keys", [])],
            bare_phones=([(b["code"], int(b["digits"])) for b in phone["bare"]]
                         if "bare" in phone else cls().bare_phones),
            keys_contains={k.upper(): v for k, v in data.get("keys_contains", {}).items()
                           if k != "skip_last_words"},
            contains_skip_last={w.lower() for w in data.get("keys_contains", {}).get("skip_last_words", [])},
            allow_keys={re.sub(r"[-_ @]", "", k.lower()) for k in data.get("allow", {}).get("keys", [])},
            iso_fields={int(n): v.upper() for n, v in data.get("iso8583", {}).get("fields", {}).items()},
            iso_ignore=data.get("iso8583", {}).get("others_not_suspect", True),
            ipv4_skip_words={w.lower() for w in data.get("ipv4", {}).get("skip_key_words", [])},
            enabled={k: v for k, v in rules.items() if isinstance(v, bool)},
            keys={k.upper(): v for k, v in data.get("keys", {}).items()},
            allow={a.lower() for a in data.get("allow", {}).get("values", [])},
            custom=[(c["label"].upper(), c["pattern"]) for c in data.get("custom", [])],
            file_globs=data.get("files", {}).get("globs", cls().file_globs),
        )


# ---------------------------------------------------------------- маскер

class Masker:
    def __init__(self, cfg: Config | None = None):
        self.cfg = cfg or Config.load()
        self.stats: Counter[str] = Counter()
        self._ids: dict[str, dict[str, int]] = {}
        self._in_private_key = False
        self._kind_cache: dict[str, tuple[str | None, bool]] = {}
        self.suspect_total = 0
        self.last_suspects: list[str] = []   # нераспознанные числа в последней строке
        if self.cfg.style == "hash" and not self.cfg.salt:
            # без соли хеш можно подобрать перебором — генерируем разовую
            self.cfg.salt = secrets.token_hex(16)
        self._rules = self._build_rules()
        self._suspect_ignore = set(self.cfg.suspect_ignore)

    # ---- метки

    def label(self, kind: str, value: str, suffix: str = "") -> str:
        self.stats[kind] += 1
        style = self.cfg.style
        if style == "plain":
            tag = kind
        elif style == "hash":
            h = hmac.new(self.cfg.salt.encode(), f"{kind}:{value}".encode(), hashlib.sha256)
            tag = f"{kind}:{h.hexdigest()[:8]}"
        else:
            seen = self._ids.setdefault(kind, {})
            n = seen.setdefault(value, len(seen) + 1)
            tag = f"{kind}_{n}"
        return f"[{tag}{suffix}]"

    def _allowed(self, value: str) -> bool:
        return value.lower() in self.cfg.allow

    # ---- правила: (имя, regex, обработчик match -> строка)

    def _build_rules(self) -> list[tuple[str, re.Pattern, Callable[[re.Match], str], Callable[[str], bool] | None]]:
        """Правила применяются по порядку. hint — дешёвая проверка строки (в нижнем регистре),
        без которой regex не запускается: ускоряет обработку в разы."""
        cfg, rules = self.cfg, []

        def has(*subs):
            if len(subs) == 1:
                return lambda low, s=subs[0]: s in low
            finder = re.compile("|".join(map(re.escape, subs))).search   # поиск в C, без цикла Python
            return lambda low: finder(low) is not None

        def add(name, pattern, handler, flags=0, hint=None):
            if cfg.on(name):
                rules.append((name, re.compile(pattern, flags), handler, hint))

        # Приватные ключи в одну строку (многострочные обрабатываются в mask_line)
        add("private_key",
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
            lambda m: self.label("PRIVATE_KEY", m.group(0)), hint=has("private key"))

        # ISO 8583: «Field 35  = …», «DE035: …», «F55=…» — маскируем значение до конца строки
        if cfg.iso_fields:
            add("iso8583", r"(?i)\b(Field|DE|Bit|F)(\s*)(0*\d{1,3})(\s*[=:]\s*)(\S[^\r\n]*?)(\s*)$",
                self._iso, hint=has("field", "de", "bit", "f"))

        # Track 2 в любом месте: PAN=YYMM + сервис-код и данные (в т.ч. частично скрытый ****)
        add("track2", r"(?<![\w*])[;%]?[\d*]{12,19}=\d{4}[\d*]{0,40}\??(?![\w*])",
            lambda m: self._val("CARD_DATA", m.group(0)), hint=has("="))

        # Authorization: Basic/Bearer/Digest <token>
        add("auth_header",
            r"(?i)\b(Basic|Bearer|Digest|Token|Negotiate)\s+([A-Za-z0-9\-._~+/]{8,}=*)(?=$|[\s,;\"'&)\]}])",
            lambda m: f"{m.group(1)} {self.label('TOKEN', m.group(2))}",
            hint=has("basic", "bearer", "digest", "token", "negotiate"))

        # Cookie / Set-Cookie: name=value; name2=value2
        add("cookie", r"(?i)\b((?:set-)?cookie\s*[:=]\s*)(.+)$", self._cookie, hint=has("cookie"))

        # user:password@ в URL (jdbc:, amqp:, https:)
        add("url_credentials", r"(?<=://)([^/\s:@]+):([^/\s@]+)@",
            lambda m: f"{m.group(1)}:{self.label('SECRET', m.group(2))}@", hint=has("://"))

        # JWT без Bearer
        add("jwt", r"\beyJ[\w-]{5,}\.[\w-]{5,}\.[\w-]*",
            lambda m: self.label("TOKEN", m.group(0)), hint=has("eyj"))

        # Известные форматы API-ключей
        add("api_tokens",
            r"\b(?:sk|pk|rk)[-_](?:live|test|proj)?[-_]?[A-Za-z0-9]{16,}"
            r"|\bgh[pousr]_[A-Za-z0-9]{30,}"
            r"|\bxox[abprs]-[A-Za-z0-9-]{10,}"
            r"|\bAKIA[0-9A-Z]{16}\b"
            r"|\bAIza[0-9A-Za-z\-_]{35}\b",
            lambda m: self.label("TOKEN", m.group(0)),
            hint=has("sk-", "sk_", "pk-", "pk_", "rk-", "rk_", "gh", "xox", "akia", "aiza"))

        # Форматные правила идут ДО правил по ключам: значение с пробелами
        # (phone=+998 90 123-45-67, pan=4111 1111 ...) должно замаскироваться целиком.
        # Карта: сплошные 13–19 цифр или группы 4-4-4-4 / 4-6-5 с одинаковым разделителем.
        # Не часть составного ID (…-20260930183252-2ab6…); префикс IIN, не дата и Луна — обязательны.
        add("card",
            r"(?<![\w*.])(?<!\w-)"
            r"(?:\d{13,19}|\d{4}([ -])\d{4}\1\d{4}\1\d{4}(?:\1\d{1,3})?|\d{4}([ -])\d{6}\2\d{5})"
            r"(?![\w*])(?!-\w)",
            self._card)

        # СНИЛС в характерном формате 123-456-789 01
        add("snils", r"\b\d{3}-\d{3}-\d{3}[ -]\d{2}\b",
            lambda m: self._val("DOC", m.group(0)), hint=has("-"))

        # Телефон без ключа: только с «+» или в оформленном виде 8 (916) 123-45-67.
        # Сплошные цифры без контекста не трогаем — это обычно order_id / метрики.
        add("phone",
            r"(?<![\w+])\+\d[\d\s\-()]{8,17}\d(?!\w)"
            r"|(?<![\w+])[78][\s-]?\(?\d{3}\)?[\s-]\d{3}[\s-]?\d{2}[\s-]?\d{2}(?!\w)",
            self._phone)

        # Номер без «+» и без имени поля — только с кодом страны из конфига: 998901234567
        for code, n in cfg.bare_phones:
            add("phone", rf"(?<![\w.+-])(?<!\w-){re.escape(code)}(?:[\s\-()]{{0,2}}\d){{{n}}}(?!\w)(?!-\w)",
                self._phone, hint=has(code))

        # Координаты парой: 41.311081, 69.279737 (от 5 знаков после точки — точность GPS)
        add("geo", r"(?<![\w.])(-?\d{1,2}\.\d{5,})(\s*,\s*)(-?\d{1,3}\.\d{5,})(?![\w.])",
            self._geo_pair, hint=has("."))

        add("email", r"(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)*\.[A-Za-z]{2,}\b",
            lambda m: self._val("EMAIL", m.group(0)), hint=has("@"))

        # Банковский счёт (UZ/RU/KZ): 20 цифр, в позициях 6–8 — код валюты.
        # 20208 000 9 00123456789 (UZ), 40817 810 0 99910004312 (RU)
        add("bank_account", r"(?<![\w.+-])(?<!\w-)\d{20}(?![\w.-])", self._account,
            hint=lambda low: bool(_LONG_DIGITS.search(low)))

        add("iban", r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b",
            lambda m: self._val("IBAN", m.group(0)) if iban_ok(m.group(0)) else m.group(0))

        # Ключ=значение, "ключ": "значение": один общий regex на любую пару,
        # а метка выбирается по имени ключа (точное совпадение или слово в имени: OpLogin, clientIp)
        self._key_kind = {self._norm_key(n): kind for kind, names in cfg.keys.items() for n in names}
        self._contains = [(key_tokens(n), kind) for kind, ns in cfg.keys_contains.items() for n in ns]
        self._kv_re = re.compile(self._kv_pattern(r"[@\w-]{1,64}"))
        if self._key_kind or self._contains:
            add("keys", self._kv_re.pattern, self._kv, hint=has("=", ":"))
        if self._key_kind:
            names = [n for ns in cfg.keys.values() for n in ns]
            keys = "|".join(sorted({self._key_regex(n) for n in names}, key=len, reverse=True))
            add("keys", rf"<({keys})>([^<]+)</\1>", self._xml, re.I, hint=has("</"))

        for label, pattern in cfg.custom:
            add("custom", pattern, lambda m, k=label: self._val(k, m.group(0)))

        if cfg.ipv4 != "off":
            add("ipv4", r"(?<![\w.])(?<!\w-)(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?![\w.])", self._ipv4,
                hint=has("."))

        add("ipv6", r"(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:.])", self._ipv6,
            hint=lambda low: "::" in low or low.count(":") >= 7)

        # UUID по умолчанию выключен: это чаще request/trace id, нужные для разбора
        if cfg.enabled.get("uuid", False):
            rules.append(("uuid", re.compile(
                r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I),
                lambda m: self._val("UUID", m.group(0)), has("-")))
        return rules

    @staticmethod
    def _norm_key(name: str) -> str:
        return re.sub(r"[-_ ]", "", name.lower())

    @staticmethod
    def _key_regex(name: str) -> str:
        # api_key == apiKey == api-key == API_KEY
        parts = re.split(r"[-_ ]", name)
        return r"[-_]?".join(re.escape(p) for p in parts if p)

    @staticmethod
    def _kv_pattern(keys: str) -> str:
        value = (r"\[[A-Z_]+[^\]]*\]"                # уже поставленная метка — не трогаем
                 r"|\[[^\[\]{}\"']*\]"                 # плоский массив [41.3, 69.2]
                 r'|\\"(?:[^"\\]|\\[^"])*\\"'       # \"экранированная строка\" внутри JSON
                 r'|"(?:[^"\\]|\\.)*"'             # "строка с пробелами"
                 r"|'[^']*'"                        # 'строка'
                 r"|(?![\[{])[^\s,;&{}\[\])\"'<>]+")  # значение до разделителя (не объект)
        return (rf"(?<![\w-])(?P<key>{keys})"
                rf"(?P<sep>\\?[\"']?\s*(?:=>|:=|::|[:=])\s*)(?P<val>{value})")

    # ---- обработчики

    def _val(self, kind: str, value: str) -> str:
        if _TRIVIAL.match(value) or self._allowed(value):
            return value
        if kind == "GEO" and self.cfg.geo == "round":
            return self._geo_round(value)
        return self.label(kind, value)

    def _kind_for(self, key: str) -> tuple[str | None, bool]:
        """(метка, найдено_по_слову_в_имени); результат кешируется — имён полей в логе немного."""
        cached = self._kind_cache.get(key)
        if cached is None:
            norm = self._norm_key(key)
            if norm in self._key_kind:
                cached = (self._key_kind[norm], False)
            else:
                tokens = key_tokens(key)
                if tokens and tokens[-1] in self.cfg.contains_skip_last:
                    cached = (None, True)          # PhoneModel, TransPhoneTime — это не сам телефон
                else:
                    cached = next(((kind, True) for word, kind in self._contains if has_word(tokens, word)),
                                  (None, True))
            self._kind_cache[key] = cached
        return cached

    def _kv(self, m: re.Match) -> str:
        kind, by_contains = self._kind_for(m.group("key"))
        if kind is None:
            # поле не чувствительное — но внутри значения может быть своя пара: "msg":"password=abc"
            val = m.group("val")
            if "=" in val or ":" in val:
                return m.group("key") + m.group("sep") + self._kv_re.sub(self._kv, val)
            return m.group(0)
        val, inner, q = m.group("val"), m.group("val"), ""
        for quote in ('\\"', '"', "'"):
            if len(val) >= 2 * len(quote) and val.startswith(quote) and val.endswith(quote):
                inner, q = val[len(quote):-len(quote)], quote
                break
        # lastLoginTime, tokenTtl: по вхождению ключа дату/время/короткое число не трогаем
        if by_contains and kind != "GEO" and (_NOT_SENSITIVE.match(inner) or (
                inner.isdigit() and (looks_like_datetime(inner) or looks_like_epoch(inner)))):
            return m.group(0)
        return f"{m.group('key')}{m.group('sep')}{q}{self._val(kind, inner)}{q}"

    def _geo_round(self, value: str) -> str:
        nums = re.findall(r"-?\d+\.\d+", value)
        if not nums:
            return self.label("GEO", value)
        self.stats["GEO"] += 1
        d = self.cfg.geo_decimals
        return re.sub(r"-?\d+\.\d+", lambda x: f"{float(x.group(0)):.{d}f}", value)

    def _geo_pair(self, m: re.Match) -> str:
        lat, _sep, lon = m.groups()
        la, lo = abs(float(lat)), abs(float(lon))
        if la > 90 or lo > 180 or (la < 1 and lo < 1) or self._allowed(m.group(0)):
            return m.group(0)
        if self.cfg.geo == "round":
            return self._geo_round(m.group(0))
        return self.label("GEO", m.group(0))

    def _xml(self, m: re.Match) -> str:
        kind, _ = self._kind_for(m.group(1))
        return f"<{m.group(1)}>{self._val(kind, m.group(2))}</{m.group(1)}>"

    def _cookie(self, m: re.Match) -> str:
        body = re.sub(r"([\w.-]+)=([^;\s]+)",
                      lambda c: f"{c.group(1)}={self._val('SECRET', c.group(2))}", m.group(2))
        return m.group(1) + body

    def _card(self, m: re.Match) -> str:
        digits = _digits(m.group(0))
        if (len(set(digits)) == 1 or not card_prefix_ok(digits) or looks_like_datetime(digits)
                or not luhn_ok(digits) or self._allowed_key(m)):
            return m.group(0)
        suffix = f" *{digits[-4:]}" if self.cfg.card_keep == "last4" else ""
        return self.label("CARD", digits, suffix)

    def _iso(self, m: re.Match) -> str:
        kind = self.cfg.iso_fields.get(int(m.group(3)))
        if kind is None or _TRIVIAL.match(m.group(5)):
            return m.group(0)
        return "".join(m.group(1, 2, 3, 4)) + self.label(kind, m.group(5)) + m.group(6)

    def _key_before(self, m: re.Match) -> str | None:
        """Имя поля прямо перед найденным значением: "Start" : 8600…, KSN = …, Field 37 = …"""
        k = _KEY_BEFORE.search(m.string, max(0, m.start() - 70), m.start())
        return k.group(1) if k else None

    def _allowed_key(self, m: re.Match) -> bool:
        if not self.cfg.allow_keys:
            return False
        key = self._key_before(m)
        return key is not None and re.sub(r"[-_ @]", "", key.lower()) in self.cfg.allow_keys

    def _account(self, m: re.Match) -> str:
        d = m.group(0)
        if (d[5:8] not in _ACCOUNT_CURRENCIES or looks_like_datetime(d) or self._allowed(d)
                or self._allowed_key(m)):
            return d
        return self.label("ACCOUNT", d)

    def _phone(self, m: re.Match) -> str:
        raw = m.group(0)
        digits = _digits(raw)
        if not 10 <= len(digits) <= 15 or self._allowed(raw) or self._allowed_key(m):
            return raw
        return self.label("PHONE", digits)

    def _ipv4(self, m: re.Match) -> str:
        octets = m.groups()
        if any(int(o) > 255 for o in octets) or self._allowed(m.group(0)):
            return m.group(0)
        if self.cfg.ipv4_skip_words:
            key = self._key_before(m)
            if key and set(key_tokens(key)) & self.cfg.ipv4_skip_words:
                return m.group(0)                  # CoreVersion: 1.2.3.4, ObjectId: 1.3.6.1
        if self.cfg.ipv4 == "subnet":
            return f"{octets[0]}.{octets[1]}.x.x"
        return self.label("IP", m.group(0))

    def _ipv6(self, m: re.Match) -> str:
        raw = m.group(0)
        if raw.count(":") < 2 or not re.search(r"[0-9A-Fa-f]{2,}", raw):
            return raw
        try:
            ipaddress.IPv6Address(raw)
        except ValueError:
            return raw
        return self._val("IP", raw)

    # ---- контроль: длинные числа, которые не распознало ни одно правило

    def _suspect(self, m: re.Match) -> str:
        num = m.group(0)
        if looks_like_datetime(num) or looks_like_epoch(num) or self._allowed(num):
            return num
        key = _KEY_BEFORE.search(m.string, max(0, m.start() - 70), m.start())
        if key:
            name = key.group(1)
            if (set(key_tokens(name)) & self._suspect_ignore
                    or re.sub(r"[-_ @]", "", name.lower()) in self.cfg.allow_keys):
                return num
            if self.cfg.iso_ignore and name.isdigit() and _ISO_FIELD_BEFORE.search(
                    m.string, max(0, key.start() - 8), key.start() + 1):
                return num                 # Field 37 = … — несекретные поля ISO 8583
        self.last_suspects.append(num)
        return self.label("NUM", num) if self.cfg.suspects == "mask" else num

    # ---- публичный API

    def mask_line(self, line: str) -> str:
        # многострочный приватный ключ: всё между BEGIN и END заменяем
        if self.cfg.on("private_key"):
            if self._in_private_key:
                if re.search(r"-----END [A-Z ]*PRIVATE KEY-----", line):
                    self._in_private_key = False
                    return line
                if not line.strip():
                    return line
                lead = line[:len(line) - len(line.lstrip())]
                return lead + "[PRIVATE_KEY]" + line[len(line.rstrip()):]
            if re.search(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", line) and "-----END" not in line:
                self._in_private_key = True
                self.stats["PRIVATE_KEY"] += 1
                return line

        low = line.lower()
        for _name, pattern, handler, hint in self._rules:
            if hint is None or hint(low):
                line = pattern.sub(handler, line)

        self.last_suspects = []
        if self.cfg.suspects != "off" and _LONG_DIGITS.search(line):
            line = _SUSPECT.sub(self._suspect, line)
            self.suspect_total += len(self.last_suspects)
        return line

    def mask(self, text: str) -> str:
        return "".join(self.mask_line(ln) for ln in text.splitlines(keepends=True))

    def reset_stats(self) -> tuple[Counter[str], int]:
        stats, self.stats = self.stats, Counter()
        sus, self.suspect_total = self.suspect_total, 0
        return stats, sus


def hide_digits(num: str) -> str:
    """998901234567 -> 998*******67 — в отчёте число не показывается целиком."""
    return num[:3] + "*" * (len(num) - 5) + num[-2:]
