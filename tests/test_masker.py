import gzip
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from masker import Config, Masker  # noqa: E402


def m(text: str, **cfg) -> str:
    c = Config.load()
    for k, v in cfg.items():
        setattr(c, k, v)
    return Masker(c).mask(text)


class TestSecrets(unittest.TestCase):
    def test_json_password_with_space(self):
        out = m('{"password":"p@ss w0rd","token":"abc123xyz"}')
        self.assertEqual(out, '{"password":"[SECRET_1]","token":"[SECRET_2]"}')

    def test_escaped_json(self):
        out = m(r'body={\"password\":\"hunter2\"}')
        self.assertNotIn("hunter2", out)

    def test_key_spelling_variants(self):
        for line in ["apiKey=abcdef1234", "API-KEY: abcdef1234", "api_key = abcdef1234"]:
            self.assertNotIn("abcdef1234", m(line), line)

    def test_basic_and_bearer(self):
        self.assertEqual(m("Authorization: Basic dXNlcjpwYXNz"), "Authorization: Basic [TOKEN_1]")
        self.assertEqual(m("Authorization: Bearer abc.def-123456"), "Authorization: Bearer [TOKEN_1]")

    def test_cookie(self):
        out = m("Cookie: JSESSIONID=ABCDEF1234567890; lang=ru")
        self.assertNotIn("ABCDEF1234567890", out)
        self.assertIn("JSESSIONID=[SECRET_1]", out)

    def test_bare_jwt(self):
        out = m("jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig_abc")
        self.assertEqual(out, "jwt [TOKEN_1]")

    def test_url_credentials_and_query(self):
        out = m("jdbc:postgresql://app:S3cret@db:5432/pay?password=x1y2&apikey=zzz999")
        self.assertNotIn("S3cret", out)
        self.assertNotIn("x1y2", out)
        self.assertNotIn("zzz999", out)
        self.assertIn("app:", out)  # логин оставляем — он полезен

    def test_xml(self):
        self.assertEqual(m("<cvv>123</cvv>"), "<cvv>[CARD_DATA_1]</cvv>")

    def test_known_tokens(self):
        out = m("key sk-live-abcdefghijklmnop1234 and AKIAABCDEFGHIJKLMNOP")
        self.assertEqual(out.count("[TOKEN_"), 2)

    def test_trivial_values_untouched(self):
        self.assertEqual(m("password=null token=*** pwd="), "password=null token=*** pwd=")

    def test_private_key_multiline(self):
        text = ("-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\nabc def\n"
                "-----END RSA PRIVATE KEY-----\nnext\n")
        out = m(text)
        self.assertNotIn("MIIEpAIBAAKCAQEA", out)
        self.assertNotIn("def", out)
        self.assertTrue(out.endswith("next\n"))


class TestPii(unittest.TestCase):
    def test_card_luhn_last4(self):
        self.assertEqual(m("card 4111 1111 1111 1111 ok"), "card [CARD_1 *1111] ok")
        self.assertEqual(m("card 4111 1111 1111 1112"), "card 4111 1111 1111 1112")  # не Луна

    def test_card_already_masked(self):
        self.assertEqual(m("pan 411111******1111"), "pan 411111******1111")

    def test_card_data_by_key(self):
        out = m("cvv=123 exp_date=12/27")
        self.assertNotIn("123", out)
        self.assertNotIn("12/27", out)

    def test_email_consistent(self):
        out = m("from a@b.com to c@d.org cc a@b.com")
        self.assertEqual(out, "from [EMAIL_1] to [EMAIL_2] cc [EMAIL_1]")

    def test_allowlist(self):
        self.assertEqual(m("to support@company.com", allow={"support@company.com"}),
                         "to support@company.com")

    def test_phones(self):
        self.assertEqual(m("+998 90 123-45-67"), "[PHONE_1]")
        self.assertEqual(m("8 (916) 123-45-67"), "[PHONE_1]")
        self.assertEqual(m("phone=998901234567"), "phone=[PHONE_1]")

    def test_key_value_with_spaces_masked_fully(self):
        self.assertEqual(m("phone=+998 90 123-45-67 ok"), "phone=[PHONE_1] ok")
        self.assertEqual(m("pan=4111 1111 1111 1111 ok"), "pan=[CARD_1 *1111] ok")

    def test_docs(self):
        out = m("passport=AA1234567 inn=123456789012 snils 123-456-789 01 фио=Иванов")
        for s in ["AA1234567", "123456789012", "123-456-789 01", "Иванов"]:
            self.assertNotIn(s, out)

    def test_iban_checksum(self):
        self.assertEqual(m("GB82WEST12345698765432"), "[IBAN_1]")
        self.assertEqual(m("AB12CDEFGHIJKLMNOP"), "AB12CDEFGHIJKLMNOP")

    def test_ip(self):
        self.assertEqual(m("ip 10.1.2.3"), "ip [IP_1]")                 # по умолчанию целиком
        self.assertEqual(m("ip 10.1.2.3", ipv4="subnet"), "ip 10.1.x.x")
        self.assertEqual(m("v6 2001:db8::1"), "v6 [IP_1]")


class TestNoFalsePositives(unittest.TestCase):
    """То, что нужно для разбора инцидента, должно остаться."""

    def test_keep(self):
        for line in [
            "2026-09-30 21:15:00,123 INFO took 1234567890 ns",
            "order_id=100200300400 epoch=1727712000000",
            "89161234567",                         # сплошные цифры без контекста
            "version 1.2.300 port 5432",
            "at com.company.Foo::bar 21:15:00",
            "mac 00:1a:2b:3c:4d:5e",
            "trace=4b829e55-c178-4682-88c7-a5090abb2a69",
            "bypass=true passed=10 service name=pay-service",
            "idempotency_key=abc",
        ]:
            self.assertEqual(m(line), line, line)


def luhn_complete(prefix: str) -> str:
    from masker import luhn_ok
    return next(prefix + str(d) for d in range(10) if luhn_ok(prefix + str(d)))


class TestRealLogCases(unittest.TestCase):
    """Случаи из реальных логов."""

    def test_oplogin_phone_double_colon(self):
        self.assertEqual(m('"OpLogin" :: "998901234567"'), '"OpLogin" :: "[PHONE_1]"')

    def test_bare_uz_phone_anywhere(self):
        self.assertEqual(m("sms to 998901234567 sent"), "sms to [PHONE_1] sent")
        self.assertEqual(m("sms to 998 90 123 45 67"), "sms to [PHONE_1]")

    def test_msgnum_with_datetime_is_not_card(self):
        line = '"@MsgNum" : "20260930183252-2ab6417f-aa20-4eae-8cb8-a583239f9ac2-0"'
        self.assertEqual(m(line), line)
        self.assertEqual(m("MsgNum=20260930183252"), "MsgNum=20260930183252")

    def test_card_prefixes(self):
        uzcard, humo = luhn_complete("860012345678901"), luhn_complete("986012345678901")
        self.assertEqual(m(f"card {uzcard}"), f"card [CARD_1 *{uzcard[-4:]}]")
        self.assertEqual(m(f"card {humo}"), f"card [CARD_1 *{humo[-4:]}]")
        bad = luhn_complete("123456789012345")        # Луна есть, префикса платёжной системы нет
        self.assertEqual(m(f"ref {bad}"), f"ref {bad}")

    def test_card_inside_compound_id(self):
        visa = "4111111111111111"
        self.assertEqual(m(f"id=abc-{visa}-x1"), f"id=abc-{visa}-x1")

    def test_mixed_separators_not_card(self):
        self.assertEqual(m("4111 1111-1111 1111"), "4111 1111-1111 1111")


class TestBankAccount(unittest.TestCase):
    def test_account_by_format(self):
        self.assertEqual(m('"receiverAccount":"20208000900123456789"'), '"receiverAccount":"[ACCOUNT_1]"')
        self.assertEqual(m("acc 40817810099910004312"), "acc [ACCOUNT_1]")

    def test_20_digits_without_currency_untouched(self):
        self.assertEqual(m("trace=12345123451234512345"), "trace=12345123451234512345")


class TestProcessing(unittest.TestCase):
    """ISO 8583 / EMV — по образцу реального application.log."""

    def test_iso_sensitive_fields(self):
        self.assertEqual(m("Field 14  = 2712"), "Field 14  = [CARD_DATA_1]")
        self.assertEqual(m("Field 35  = 4111********1234=2712101********"), "Field 35  = [CARD_DATA_1]")
        self.assertEqual(m("Field 55  = 9F2608A1B2C3D4E5F60718"), "Field 55  = [CARD_DATA_1]")
        self.assertEqual(m("DE052: ~12~"), "DE052: [SECRET_1]")

    def test_iso_other_fields_untouched_and_not_suspect(self):
        mk = Masker(Config.load())
        for line in ["Field 4   = 000000150000", "Field 37  = 627312345678", "Field 7   = 0930183252",
                     "Field 42  = 0000012345"]:
            self.assertEqual(mk.mask_line(line), line)
            self.assertEqual(mk.last_suspects, [], line)

    def test_track2_anywhere(self):
        self.assertEqual(m("t2=4111111111111111=27121010000000000000 ok"), "t2=[CARD_DATA_1] ok")

    def test_bin_range_and_service_keys(self):
        mk = Masker(Config.load())
        visa = "4111111111111111"      # проходит Луна, но это граница диапазона
        for line in [f'"Start" : {visa}', '"End" : 8600319999999999',
                     "KSN = 20208000900123456789", '"RRN" : "627312345678"', '"@TACDN" : "0010000000"']:
            self.assertEqual(mk.mask_line(line), line, line)
            self.assertEqual(mk.last_suspects, [], line)

    def test_property_of_phone_is_not_phone(self):
        for line in ['"PhoneModel" : "iPhone 14"', '"TransPhoneTime" : "20260930183252"',
                     '"EmailVerified" : "yes"']:
            self.assertEqual(m(line), line)
        self.assertNotIn("35-209900", m('"PhoneIMEI" : "35-209900-176148-1"'))


class TestGeo(unittest.TestCase):
    def test_geo_keys(self):
        out = m('"latitude": 41.311081, "longitude": 69.279737, "geo": {"lat": 41.31, "lon": 69.27}')
        for s in ["41.311081", "69.279737", "41.31", "69.27"]:
            self.assertNotIn(s, out)
        self.assertIn('"geo": {', out)                # объект не сломан

    def test_geo_by_word_in_key(self):
        self.assertEqual(m("userLatitude=41.311081"), "userLatitude=[GEO_1]")
        self.assertNotIn("Tashkent", m('"geoip_city_name": "Tashkent"'))

    def test_geo_pair_in_text(self):
        self.assertEqual(m("at 41.311081, 69.279737 ok"), "at [GEO_1] ok")
        for line in ["ratio 0.50000, 0.25000", "p50 12.3456, 15.7890"]:   # метрики — не координаты
            self.assertEqual(m(line), line)

    def test_geo_array(self):
        self.assertNotIn("69.2797", m('"coords": [69.2797, 41.3111]'))

    def test_geo_round(self):
        self.assertEqual(m("lat=41.311081 lon=69.279737", geo="round"), "lat=41.3 lon=69.3")

    def test_versions_and_oid_are_not_ip(self):
        for line in ['"CoreVersion" : "1.2.3.4"', '"Build" : "api5-2.10.0.15"', "[1]: ObjectId: 1.3.6.1"]:
            self.assertEqual(m(line), line)
        self.assertEqual(m("connect to 10.0.0.1"), "connect to [IP_1]")

    def test_config_options_are_not_labels(self):
        self.assertEqual(m('"HostResultStr" : "Approved"'), '"HostResultStr" : "Approved"')

    def test_ip_by_key_and_mapped_v6(self):
        self.assertEqual(m('"clientIp":"::ffff:10.0.0.1"'), '"clientIp":"[IP_1]"')
        self.assertEqual(m("XForwardedFor=1.2.3.4, 5.6.7.8"), "XForwardedFor=[IP_1], [IP_2]")


class TestKeyWords(unittest.TestCase):
    def test_word_not_substring(self):
        for line in ["portfolio=abc", "placeholder=xyz", "isMobileApp=android"]:
            self.assertEqual(m(line), line)

    def test_contains_keys_keep_dates_and_enums(self):
        for line in ['"loginResult": "SUCCESS"', '"lastLoginTime": "2026-09-30T18:32:52Z"',
                     "tokenTtl=3600", "tokenType=BEARER next=1"]:
            self.assertEqual(m(line), line)

    def test_secret_inside_other_value(self):
        self.assertEqual(m('"msg":"login failed password=abc123"'), '"msg":"login failed password=[SECRET_1]"')

    def test_contains_keys_mask(self):
        out = m("customerPhone=998 90 123 45 67 userLogin=ivanov passwordHash=abc123 x_api_key=k1k2k3")
        for s in ["123 45 67", "ivanov", "abc123", "k1k2k3"]:
            self.assertNotIn(s, out)


class TestSuspects(unittest.TestCase):
    def test_flags_unknown_long_number(self):
        mk = Masker(Config.load())
        mk.mask_line("client_account=123456789012345")   # count ≠ account
        self.assertEqual(mk.last_suspects, ["123456789012345"])

    def test_ignores_ids_dates_epoch(self):
        mk = Masker(Config.load())
        for line in ["order_id=100200300400", "MsgNum=20260930183252", "ts=1727712000000",
                     "took 1234567890 ns", "orderNo=55512345678"]:
            mk.mask_line(line)
            self.assertEqual(mk.last_suspects, [], line)

    def test_strict_masks(self):
        self.assertEqual(m("acc 123456789012345", suspects="mask"), "acc [NUM_1]")


class TestStyles(unittest.TestCase):
    def test_plain(self):
        self.assertEqual(m("a@b.com", style="plain"), "[EMAIL]")

    def test_hash_stable_with_salt(self):
        a = m("a@b.com", style="hash", salt="s")
        b = m("a@b.com", style="hash", salt="s")
        self.assertEqual(a, b)
        self.assertRegex(a, r"^\[EMAIL:[0-9a-f]{8}\]$")


class TestCli(unittest.TestCase):
    def run_cli(self, *args, input=None):
        return subprocess.run([sys.executable, str(ROOT / "logmask.py"), *args],
                              capture_output=True, input=input, cwd=ROOT)

    def test_file_gz_cp1251_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            (d / "a.log").write_bytes("Иванов password=qwerty\r\n".encode("cp1251"))
            with gzip.open(d / "b.log.gz", "wt", encoding="utf-8") as f:
                f.write("mail a@b.com\n")
            r = self.run_cli(str(d))
            self.assertEqual(r.returncode, 0, r.stderr.decode())

            a = (d / "a.masked.log").read_bytes().decode("cp1251")
            self.assertEqual(a, "Иванов password=[SECRET_1]\r\n")   # кодировка и CRLF сохранены
            with gzip.open(d / "b.masked.log.gz", "rt", encoding="utf-8") as f:
                self.assertEqual(f.read(), "mail [EMAIL_1]\n")
            self.assertIn("qwerty", (d / "a.log").read_bytes().decode("cp1251"))  # исходник цел

            r = self.run_cli(str(d / "a.log"))
            self.assertEqual(r.returncode, 2)                    # не перезаписываем без --force
            self.assertEqual(self.run_cli(str(d / "a.log"), "-f").returncode, 0)

    def test_check_hides_suspects(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "x.log"
            p.write_text("retry ref=770012345678901\n", encoding="utf-8")
            r = self.run_cli("--check", str(p))
            self.assertNotIn(b"770012345678901", r.stdout + r.stderr)
            self.assertIn("770**********01".encode(), r.stdout)
            self.assertEqual(r.returncode, 0)             # только подозрение — не «найдено»
            self.assertEqual(self.run_cli("--check", "--strict", str(p)).returncode, 1)

    def test_check_does_not_leak(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "x.log"
            p.write_text("ok\npassword=hunter2\n", encoding="utf-8")
            r = self.run_cli("--check", str(p))
            self.assertEqual(r.returncode, 1)
            self.assertNotIn(b"hunter2", r.stdout + r.stderr)
            self.assertIn(b"x.log:2", r.stdout)
            self.assertFalse((Path(d) / "x.masked.log").exists())

    def test_stdin(self):
        r = self.run_cli("-", input="token=abc123\n".encode())
        self.assertEqual(r.stdout.decode(), "token=[SECRET_1]\n")


if __name__ == "__main__":
    unittest.main()
