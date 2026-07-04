from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from fh_tool_cli.web_discovery import (
    classify_method,
    extract_ajax_entries,
    extract_params_from_context,
    merge_catalogs,
    static_catalog,
)


class WebDiscoveryTests(unittest.TestCase):
    def test_static_extractor_finds_ajaxmethod_from_html_and_js(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "www").mkdir()
            (root / "www" / "index.html").write_text(
                """
                <script src="/js/wan.js"></script>
                <form id="wan"><input name="Username"><input name="Password"></form>
                <script>
                $.ajax({type: "POST", url: "/cgi-bin/ajax", data: {
                  ajaxmethod: "set_wan_info",
                  VLANID: $("#vlan").val()
                }});
                </script>
                """,
                encoding="utf-8",
            )
            (root / "www" / "js").mkdir()
            (root / "www" / "js" / "wan.js").write_text(
                'fetch("/cgi-bin/ajax?ajaxmethod=get_allwan_info&WanName=1");',
                encoding="utf-8",
            )

            catalog = static_catalog(root)

        methods = {entry["method"]: entry for entry in catalog["methods"]}
        self.assertIn("set_wan_info", methods)
        self.assertIn("get_allwan_info", methods)
        self.assertEqual(methods["set_wan_info"]["kind"], "write")
        params = {param["name"]: param for param in methods["set_wan_info"]["params"]}
        self.assertIn("VLANID", params)
        self.assertIn("Password", params)
        self.assertTrue(params["Password"]["sensitive"])

    def test_param_extraction_covers_object_query_form_and_param_assign(self) -> None:
        context = """
        $.ajax({ data: { ajaxmethod: "set_fake", Enable: 1, "Password": secret } });
        param["VLANID"] = vlan;
        <input name="Username"><select name="Mode"></select>
        /cgi-bin/ajax?ajaxmethod=get_fake&IfName=eth1&token=x
        """

        params = extract_params_from_context(context)

        self.assertIn("Enable", params)
        self.assertIn("Password", params)
        self.assertIn("VLANID", params)
        self.assertIn("Username", params)
        self.assertIn("Mode", params)
        self.assertIn("IfName", params)
        self.assertIn("token", params)
        self.assertNotIn("ajaxmethod", params)

    def test_method_classification(self) -> None:
        self.assertEqual(classify_method("get_allwan_info"), "read")
        self.assertEqual(classify_method("set_wan_info"), "write")
        self.assertEqual(classify_method("delete_rule"), "write")
        self.assertEqual(classify_method("do_login"), "auth")
        self.assertEqual(classify_method("vlanbind"), "read")
        self.assertEqual(classify_method("customMethod"), "unknown")

    def test_catalog_merge_deduplicates_and_prefers_live_verification(self) -> None:
        static = {
            "target": {"base_url": None, "ajax_path": "/cgi-bin/ajax"},
            "methods": [
                {
                    "method": "set_wan_info",
                    "http_methods": ["POST"],
                    "kind": "write",
                    "sources": ["/js/wan.js"],
                    "params": [{"name": "Username", "sensitive": True}],
                    "verified": False,
                }
            ],
        }
        live = {
            "target": {"base_url": "http://192.168.1.1:8080/", "ajax_path": "/cgi-bin/ajax"},
            "methods": [
                {
                    "method": "set_wan_info",
                    "http_methods": ["POST"],
                    "kind": "write",
                    "sources": ["live-probe"],
                    "params": [{"name": "VLANID", "sensitive": False}],
                    "verified": True,
                    "status_code": 200,
                }
            ],
        }

        merged = merge_catalogs([static, live])

        self.assertEqual(len(merged["methods"]), 1)
        entry = merged["methods"][0]
        self.assertTrue(entry["verified"])
        self.assertEqual(entry["status_code"], 200)
        self.assertEqual(set(entry["sources"]), {"/js/wan.js", "live-probe"})
        self.assertEqual({param["name"] for param in entry["params"]}, {"Username", "VLANID"})

    def test_catalog_merge_preserves_custom_ajax_path(self) -> None:
        merged = merge_catalogs(
            [
                {
                    "target": {"base_url": "http://192.168.1.1:8080/", "ajax_path": "/custom/ajax"},
                    "methods": [],
                }
            ]
        )

        self.assertEqual(merged["target"]["ajax_path"], "/custom/ajax")

    def test_extract_ajax_entries_keeps_context_without_forcing_schema(self) -> None:
        entries = extract_ajax_entries('call("set_custom_info");', "fake.js")

        self.assertEqual(entries[0]["method"], "set_custom_info")
        self.assertEqual(entries[0]["params"], [])
        self.assertIn("contexts", entries[0])

    def test_context_snippets_redact_sensitive_literals(self) -> None:
        entries = extract_ajax_entries(
            '$.ajax({data:{ajaxmethod:"set_fake", Password:"plain", sessionid:"sid"}});',
            "fake.js",
        )

        snippet = entries[0]["contexts"][0]["snippet"]
        self.assertNotIn("plain", snippet)
        self.assertNotIn("sid", snippet)
        self.assertIn("[REDACTED]", snippet)


if __name__ == "__main__":
    unittest.main()
