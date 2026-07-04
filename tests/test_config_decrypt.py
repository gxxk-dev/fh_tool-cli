from __future__ import annotations

import unittest

from fh_tool_cli.config_decrypt import decrypt_config_document, parse_uci_like
from fh_tool_cli.crypto import decrypt_config_encrymode2
from fh_tool_cli.errors import CliError


class ConfigDecryptTests(unittest.TestCase):
    def test_parse_uci_like_sections_options_and_lists(self) -> None:
        sections = parse_uci_like(
            """
            config wan 'main'
                option Username 'user'
                option Password 'secret value'
                list ServiceList 'INTERNET'
                list ServiceList 'TR069'
            """
        )

        self.assertEqual(len(sections), 1)
        self.assertEqual(sections[0].type, "wan")
        self.assertEqual(sections[0].name, "main")
        self.assertEqual(sections[0].options["Password"], "secret value")
        self.assertEqual(sections[0].lists["ServiceList"], ["INTERNET", "TR069"])

    def test_decrypts_encrymode2_uppercase_hex_with_zero_padding(self) -> None:
        self.assertEqual(
            decrypt_config_encrymode2(
                "709FF93C0597E9B77A163BCE8FC0138D",
                b"0123456789abcdef",
            ),
            "secret",
        )

    def test_attr_encrymode2_is_redacted_by_default_and_revealed_with_key(self) -> None:
        config = """
        config account 'admin'
            option Password '709FF93C0597E9B77A163BCE8FC0138D'
            option DisplayName 'admin'
        """
        attr = """
        config account 'admin'
            option Password 'encrymode=2'
        """

        redacted = decrypt_config_document(config, attr_text=attr)
        password = redacted["sections"][0]["options"]["Password"]
        self.assertEqual(password["value"], "[ENCRYPTED]")
        self.assertTrue(password["encrypted"])
        self.assertTrue(password["redacted"])

        revealed = decrypt_config_document(
            config,
            attr_text=attr,
            reveal_secrets=True,
            key="0123456789abcdef",
        )
        revealed_password = revealed["sections"][0]["options"]["Password"]
        self.assertEqual(revealed_password["value"], "secret")
        self.assertTrue(revealed_password["decrypted"])

    def test_reveal_encrypted_secret_requires_key(self) -> None:
        with self.assertRaises(CliError):
            decrypt_config_document(
                "config account 'admin'\n option Password '00'\n",
                attr_text="config account 'admin'\n option Password '2'\n",
                reveal_secrets=True,
            )

    def test_sensitive_values_are_redacted_without_attrconfig(self) -> None:
        document = decrypt_config_document(
            """
            config tr069 'acs'
                option URL 'http://acs.example.test'
                option Username 'acs-user'
            """
        )

        options = document["sections"][0]["options"]
        self.assertEqual(options["URL"]["value"], "[REDACTED]")
        self.assertEqual(options["Username"]["value"], "[REDACTED]")


if __name__ == "__main__":
    unittest.main()
