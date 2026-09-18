import unittest

from fh_tool_cli.crypt_unix import (
    crypt_kind,
    crypt_verify,
    extract_crypt_hash,
    md5_crypt,
    sha256_crypt,
)


class CryptUnixTests(unittest.TestCase):
    """测试向量来源:
    - md5 空 salt:`Fh@36BC10` -> `$1$$c29kb1Alc4Ic54TuMH2iv.` 是 HG5143F 实机 /var/telsu 验证过的 oracle。
    - md5 带 salt 与 sha256 各向量由 openssl passwd -1/-5 与系统 libcrypt(perl crypt)交叉核对。
    """

    def test_md5_crypt_empty_salt_matches_live_oracle(self) -> None:
        self.assertEqual(md5_crypt("Fh@36BC10", ""), "$1$$c29kb1Alc4Ic54TuMH2iv.")

    def test_md5_crypt_with_salt_matches_openssl(self) -> None:
        self.assertEqual(md5_crypt("Fh@36BC10", "abcd"), "$1$abcd$hlxCFPHYizW8pumWYX5C60")
        self.assertEqual(md5_crypt("Fh@36BC10", "abcdefgh"), "$1$abcdefgh$PjL4p/GNM7Eiuldk2oSNI.")

    def test_sha256_crypt_matches_openssl_vectors(self) -> None:
        self.assertEqual(
            sha256_crypt("Hello world!", "saltstring"),
            "$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5",
        )
        self.assertEqual(
            sha256_crypt("Hello world!", "toolongsaltstrin"),
            "$5$toolongsaltstrin$0vuwUia3Nx9V/DqToMS8YLcfXpEXmSaC8wgguLIbus2",
        )
        self.assertEqual(
            sha256_crypt("This is just a test", "saltstringsaltst"),
            "$5$saltstringsaltst$x/zpfu1wRdjMeUna2pNrIP8Ex4hjxvm4nrkMHIHcl65",
        )

    def test_sha256_crypt_rounds_variant(self) -> None:
        self.assertEqual(
            sha256_crypt("This is just a test", "saltstringsaltst", rounds=10000),
            "$5$rounds=10000$saltstringsaltst$1h3VTqiuy2fMWyyuLPV80ZYIo8TqOh8yscnQ.cFUNq.",
        )

    def test_crypt_verify_accepts_correct_password(self) -> None:
        self.assertTrue(crypt_verify("Fh@36BC10", "$1$$c29kb1Alc4Ic54TuMH2iv."))
        self.assertTrue(
            crypt_verify(
                "Hello world!",
                "$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5",
            )
        )

    def test_crypt_verify_rejects_wrong_password_and_unknown_format(self) -> None:
        self.assertFalse(
            crypt_verify("wrong", "$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5")
        )
        self.assertFalse(crypt_verify("Fh@36BC10", "$6$salt$junk"))
        self.assertFalse(crypt_verify("Fh@36BC10", "not-a-hash"))

    def test_crypt_verify_parses_rounds_prefix(self) -> None:
        self.assertTrue(
            crypt_verify(
                "This is just a test",
                "$5$rounds=10000$saltstringsaltst$1h3VTqiuy2fMWyyuLPV80ZYIo8TqOh8yscnQ.cFUNq.",
            )
        )

    def test_crypt_kind(self) -> None:
        self.assertEqual(crypt_kind("$1$$abc"), "$1$")
        self.assertEqual(crypt_kind("$5$fh$abc"), "$5$")
        self.assertIsNone(crypt_kind("root:$5$fh$abc"))
        self.assertIsNone(crypt_kind("plain"))

    def test_extract_crypt_hash_from_noisy_telnet_output(self) -> None:
        raw = (
            "Welcome to FiberHome\r\n"
            "BusyBox v1.30.1 () built-in shell (ash)\r\n"
            "# cat /var/telsu\r\n"
            "root:$5$fh$AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AB:0:0:Telnet user:/:/bin/ash\r\n"
            "# \r\n"
        )
        self.assertEqual(
            extract_crypt_hash(raw),
            "$5$fh$AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AB",
        )

    def test_extract_crypt_hash_md5_empty_salt(self) -> None:
        raw = "# cat /var/telsu\r\nroot:$1$$c29kb1Alc4Ic54TuMH2iv.:0:0:Telnet user:/:/bin/ash\r\n"
        self.assertEqual(extract_crypt_hash(raw), "$1$$c29kb1Alc4Ic54TuMH2iv.")

    def test_extract_crypt_hash_rounds_line(self) -> None:
        raw = (
            "root:$5$rounds=10000$saltstringsaltst$1h3VTqiuy2fMWyyuLPV80ZYIo8TqOh8yscnQ.cFUNq."
            ":0:0:Telnet user:/:/bin/ash"
        )
        self.assertEqual(
            extract_crypt_hash(raw),
            "$5$rounds=10000$saltstringsaltst$1h3VTqiuy2fMWyyuLPV80ZYIo8TqOh8yscnQ.cFUNq.",
        )

    def test_extract_crypt_hash_returns_none_on_error_output(self) -> None:
        self.assertIsNone(
            extract_crypt_hash("cat: can't open '/var/telsu': Permission denied")
        )
        self.assertIsNone(extract_crypt_hash("# cat /var/telsu\r\n# "))


if __name__ == "__main__":
    unittest.main()
