from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from fh_tool_cli.backends.cfg_cmd import CfgCmdBackend
from fh_tool_cli.remote import (
    CLOUD_ENDPOINT_PATHS,
    SMARTSWITCH_FORBIDDEN_CHANGES,
    SMARTSWITCH_PATH,
    TR069_PATHS,
    cloud_disable_cloudclt,
    cloud_disable_smartswitch,
    cloud_status,
    remote_plan,
    tr069_harden_periodic_inform,
    tr069_randomize_connection_request,
    tr069_status,
    write_audit_report,
)


class RemoteTests(unittest.TestCase):
    def test_tr069_status_redacts_sensitive_values(self) -> None:
        values = {
            TR069_PATHS["acs_url"]: "http://acs.example.test",
            TR069_PATHS["acs_username"]: "acs-user",
            TR069_PATHS["acs_password"]: "acs-secret",
            TR069_PATHS["periodic_inform_enable"]: "1",
            TR069_PATHS["periodic_inform_interval"]: "3600",
            TR069_PATHS["connection_request_url"]: "http://device:7547",
            TR069_PATHS["connection_request_username"]: "cr-user",
            TR069_PATHS["connection_request_password"]: "cr-secret",
            TR069_PATHS["upgrades_managed"]: "1",
        }

        backend = CfgCmdBackend(lambda command: f"{command.split()[-1]}={values[command.split()[-1]]}")
        result = tr069_status(backend)

        status_values = result["tr069"]["values"]
        self.assertEqual(status_values["acs_password"]["value"], "[REDACTED]")
        self.assertEqual(status_values["periodic_inform_interval"]["value"], "3600")

    def test_cloud_status_detects_known_processes(self) -> None:
        values = {path: "" for path in CLOUD_ENDPOINT_PATHS.values()}
        backend = CfgCmdBackend(lambda command: f"{command.split()[-1]}={values[command.split()[-1]]}")

        def shell(command: str) -> str:
            if command == "ps":
                return "123 saf\n456 cloudclient\n"
            return ""

        result = cloud_status(backend, shell)

        processes = result["cloud"]["runtime"]["processes"]
        self.assertTrue(processes["saf"])
        self.assertTrue(processes["cloudclient"])
        self.assertFalse(processes["appmgr"])

    def test_cloud_status_summarizes_smartswitch_impact(self) -> None:
        values = {path: "" for path in CLOUD_ENDPOINT_PATHS.values()}
        values[SMARTSWITCH_PATH] = "1"
        backend = CfgCmdBackend(lambda command: f"{command.split()[-1]}={values[command.split()[-1]]}")

        result = cloud_status(backend)

        smart_switch = result["cloud"]["smart_switch"]
        self.assertEqual(smart_switch["path"], SMARTSWITCH_PATH)
        self.assertEqual(smart_switch["value"], "1")
        self.assertEqual(smart_switch["disable_value"], "0")
        self.assertEqual(smart_switch["risk"], "danger")
        self.assertIn("WAN VLAN", smart_switch["forbidden_changes"])

    def test_plan_is_read_only_until_gated_levels(self) -> None:
        plan = remote_plan("tr069")

        self.assertFalse(plan["actions"][0]["device_write"])
        self.assertEqual(plan["actions"][1]["risk"], "danger")
        self.assertEqual(plan["actions"][-1]["mode"], "manual-plan-only")

    def test_cloud_plan_includes_smartswitch_path_and_guardrails(self) -> None:
        plan = remote_plan("cloud")
        smart_switch = next(action for action in plan["actions"] if action["mode"] == "SmartSwitch")

        self.assertEqual(smart_switch["path"], SMARTSWITCH_PATH)
        self.assertEqual(smart_switch["target_value"], "0")
        self.assertEqual(smart_switch["risk"], "danger")
        self.assertEqual(smart_switch["forbidden_changes"], SMARTSWITCH_FORBIDDEN_CHANGES)

    def test_write_audit_report(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "report.md"
            result = write_audit_report({"tr069": {"ok": True}}, output)

            self.assertEqual(result["output"], str(output))
            self.assertIn("# fh-tool audit report", output.read_text(encoding="utf-8"))

    def test_tr069_harden_periodic_inform_uses_cfg_verify(self) -> None:
        values = {TR069_PATHS["periodic_inform_enable"]: "1"}

        def runner(command: str) -> str:
            if command.startswith("cfg_cmd set "):
                values[TR069_PATHS["periodic_inform_enable"]] = command.rsplit(" ", 1)[1]
                return "ok"
            if command.startswith("cfg_cmd get "):
                return f"{TR069_PATHS['periodic_inform_enable']}={values[TR069_PATHS['periodic_inform_enable']]}"
            raise AssertionError(command)

        result = tr069_harden_periodic_inform(CfgCmdBackend(runner), "off")

        self.assertTrue(result["verified"])
        self.assertEqual(result["value"], "0")

    def test_tr069_randomize_connection_request_redacts_password(self) -> None:
        values = {
            TR069_PATHS["connection_request_username"]: "",
            TR069_PATHS["connection_request_password"]: "",
        }

        def runner(command: str) -> str:
            if command.startswith("cfg_cmd set "):
                _, _, path, value = command.split(" ", 3)
                values[path] = value
                return "ok"
            if command.startswith("cfg_cmd get "):
                path = command.split()[-1]
                return f"{path}={values[path]}"
            raise AssertionError(command)

        result = tr069_randomize_connection_request(CfgCmdBackend(runner))

        self.assertTrue(result["generated"])
        self.assertEqual(result["connection_request_password"]["value"], "[REDACTED]")
        self.assertTrue(result["connection_request_password"]["verified"])

    def test_cloud_disable_cloudclt_runs_gated_command(self) -> None:
        calls: list[str] = []
        result = cloud_disable_cloudclt(calls.append)

        self.assertEqual(result["risk"], "danger")
        self.assertEqual(len(calls), 1)
        self.assertIn("cloudclt stop", calls[0])

    def test_cloud_disable_smartswitch_uses_cfg_verify(self) -> None:
        values = {SMARTSWITCH_PATH: "1"}
        set_paths: list[str] = []

        def runner(command: str) -> str:
            if command.startswith("cfg_cmd set "):
                _, _, path, value = command.split(" ", 3)
                set_paths.append(path)
                values[path] = value
                return "ok"
            if command.startswith("cfg_cmd get "):
                path = command.split()[-1]
                return f"{path}={values[path]}"
            raise AssertionError(command)

        result = cloud_disable_smartswitch(CfgCmdBackend(runner))

        self.assertEqual(set_paths, [SMARTSWITCH_PATH])
        self.assertEqual(values[SMARTSWITCH_PATH], "0")
        self.assertTrue(result["verified"])
        self.assertEqual(result["write"]["risk"], "danger")


if __name__ == "__main__":
    unittest.main()
