"""Regression tests for incorrect capability evidence and share omissions."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from typer.testing import CliRunner

from nxs.cli import app, resolve_credentials
from nxs.models import CommandRecord, Credential, ProtocolResult
from nxs.output import cred_label, extract_verbose_details, print_probe_summary, print_discovery_results, console
from nxs.parsers import parse_smb_shares, smb_metadata
from nxs.runner import (
    auth_state, exec_capability, probe_ports_per_target, record_dict,
    save_records, smb_capability, test_protocol as scan_protocol, verify_credential,
)

BANNER = "SMB 10.129.14.147 445 DC01 [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:timelapse.htb) (signing:True) (SMBv1:False) (Null Auth:True)"
LOGIN = "SMB 10.129.14.147 445 DC01 [+] timelapse.htb\\guest:"
SHARES = "\n".join([
    BANNER, LOGIN, "SMB 10.129.14.147 445 DC01 [*] Enumerated shares",
    "SMB 10.129.14.147 445 DC01 Share           Permissions            Remark",
    "SMB 10.129.14.147 445 DC01 -----           -----------            ------",
    "SMB 10.129.14.147 445 DC01 ADMIN$                                 Remote Admin",
    "SMB 10.129.14.147 445 DC01 IPC$            READ                   Remote IPC",
    "SMB 10.129.14.147 445 DC01 NETLOGON                               Logon server share",
    "SMB 10.129.14.147 445 DC01 Shares          READ",
    "SMB 10.129.14.147 445 DC01 Project Files   WRITE,READ            Notes",
    "SMB 10.129.14.147 445 DC01 Write Only      WRITE                 Uploads",
    "SMB 10.129.14.147 445 DC01 SYSVOL                                 Logon server share",
])


class ShareParserTests(unittest.TestCase):
    def test_share_named_shares_is_not_a_heading(self):
        rows = parse_smb_shares(SHARES)
        self.assertIn("Shares", [r.name for r in rows])
        self.assertIn("Project Files", [r.name for r in rows])
        self.assertIn("Project  Files", [r.name for r in parse_smb_shares(
            SHARES + "\nSMB 10.129.14.147 445 DC01 Project  Files   READ"
        )])
        self.assertEqual(next(r for r in rows if r.name == "Project Files").display_permissions, "READ+WRITE")
        self.assertEqual(next(r for r in rows if r.name == "Write Only").display_permissions, "WRITE")
        self.assertEqual(smb_capability(SHARES)[0], "WRITE")
        self.assertIn("Shares[READ]", smb_capability(SHARES)[1])
        self.assertIn("Project Files[READ+WRITE]", smb_capability(SHARES)[1])

    def test_long_and_spaced_share_names_with_permissions(self):
        output = SHARES + "\n" + "\n".join([
            "SMB 10.129.14.147 445 DC01 A very long project share name          READ,WRITE          Internal data",
            "SMB 10.129.14.147 445 DC01 Share          READ",
            "SMB 10.129.14.147 445 DC01 Project  Team  Files          WRITE,READ",
        ])
        rows = {row.name: row for row in parse_smb_shares(output)}
        self.assertEqual(rows["A very long project share name"].display_permissions, "READ+WRITE")
        self.assertEqual(rows["Share"].display_permissions, "READ")
        self.assertEqual(rows["Project  Team  Files"].display_permissions, "READ+WRITE")

    def test_share_table_requires_heading(self):
        self.assertEqual(parse_smb_shares(
            "SMB host 445 DC01 [*] Enumerated shares\n"
            "SMB host 445 DC01 ShareMe          READ"
        ), [])

    def test_metadata_is_information_not_a_share(self):
        meta = smb_metadata(SHARES)
        self.assertEqual(meta["Null Auth"], "True")
        self.assertEqual(meta["signing"], "True")
        self.assertFalse(any("Windows" in r.name for r in parse_smb_shares(SHARES)))

    def test_verbose_shows_all_share_names(self):
        res = ProtocolResult("smb", True, "READ", "Shares[READ]", records=[
            CommandRecord(["nxc", "smb", "host", "-u", "guest", "-p", "", "--shares"], 0, SHARES)
        ])
        details = extract_verbose_details(res)
        self.assertTrue(any("Shares" in x and "READ" in x for x in details))
        self.assertTrue(any("Project Files" in x for x in details))
        self.assertTrue(any("NETLOGON" in x for x in details))


class EvidenceTests(unittest.TestCase):
    def test_credential_label_shows_exact_password_or_hash(self):
        self.assertEqual(cred_label(Credential("alice", password="secret")), "alice:secret")
        self.assertEqual(cred_label(Credential("alice", ntlm_hash="aabbcc")), "alice:aabbcc")

    def test_generic_positive_is_not_an_auth_response(self):
        self.assertEqual(auth_state("SMB host 445 X [+] Enumeration completed", "guest", "", "")[0], None)

    def test_real_login_and_guest_mapping(self):
        self.assertEqual(auth_state(LOGIN, "guest", "", ""), (True, "auth ok"))
        guest = "SMB 10.129.14.147 445 DC01 [+] timelapse.htb\\~: (Guest)"
        self.assertEqual(auth_state(guest, "~", "", ""), (True, "guest mapped"))

    def test_non_authentication_error_is_not_bad_credentials(self):
        msg = "SMB 10.0.0.1 445 DC01 [-] Error enumerating shares: STATUS_ACCESS_DENIED"
        state, reason = auth_state(msg, "guest", "", "")
        self.assertIsNone(state)
        self.assertIn("Error enumerating shares", reason)
        rejected = "SMB 10.0.0.1 445 DC01 [-] LAB\\guest: STATUS_LOGON_FAILURE"
        self.assertFalse(auth_state(rejected, "guest", "", "")[0])

    def test_upn_and_domain_prefix_logins(self):
        self.assertTrue(auth_state(LOGIN, "guest@timelapse.htb", "", "")[0])
        self.assertTrue(auth_state(LOGIN, "timelapse.htb\\guest", "", "")[0])

    def test_connection_timeouts_are_inconclusive(self):
        self.assertIsNone(auth_state("TIMEOUT", "guest", "", "")[0])
        self.assertIsNone(auth_state("connection refused", "guest", "", "")[0])

    def test_exec_marker_beats_earlier_denial(self):
        result = exec_capability("[-] STATUS_ACCESS_DENIED\nVERIFY_123", "VERIFY_123")
        self.assertEqual(result[0], "EXEC")

    def test_exec_marker_must_be_standalone_output(self):
        marker = "NXS_VERIFY_123"
        error = f"[-] Could not execute cmd /c echo {marker}"
        self.assertNotEqual(exec_capability(error, marker)[0], "EXEC")
        response = f"WMI 10.0.0.1 135 DC01 {marker}"
        self.assertEqual(exec_capability(response, marker)[0], "EXEC")

    def test_raw_evidence_preserves_exact_secrets(self):
        record = CommandRecord(["nxc", "smb", "host", "-u", "alice", "-p", "secret"], 0,
                               "[+] DOMAIN\\alice:secret")
        self.assertIn("secret", str(record_dict(record)))
        self.assertIn("secret", str(ProtocolResult("smb", True, "AUTH", "ok", records=[record]).public_dict(raw=True)))
        with tempfile.TemporaryDirectory() as tmp:
            result = ProtocolResult("smb", True, "AUTH", "ok", records=[record])
            save_records(Path(tmp), "host", "alice", result)
            save_records(Path(tmp), "host", "alice", result)
            files = list(Path(tmp).rglob("*.txt"))
            self.assertEqual(len(files), 2)
            for f in files:
                self.assertIn("secret", f.read_text())
                self.assertEqual(f.stat().st_mode & 0o777, 0o600)

    def test_failed_login_reason_is_not_echoed_password(self):
        for proto, err in [("WMI", "RPC_S_SEC_PKG_ERROR"),
                           ("SMB", "STATUS_LOGON_FAILURE")]:
            output = f"{proto} host 445 DC01 [-] LAB\\alice:Welcome1 ({err})"
            ok, reason = auth_state(output, "alice", "", "")
            self.assertNotIn("Welcome1", reason)
            self.assertEqual(reason, err)
            self.assertIs(ok, None if err.startswith("RPC_") else False)

    def test_no_creds_uses_guest_only(self):
        creds = resolve_credentials(None, None, None, None, None)
        self.assertEqual([(c.user, c.password) for c in creds], [("guest", "")])
        self.assertEqual(cred_label(creds[0]), "guest")
        self.assertEqual(cred_label(Credential("", password="")), "null session")

    def test_guest_default_and_explicit_null_session_are_distinct(self):
        with patch("nxs.cli.resolve_targets", return_value=["host"]), \
             patch("nxs.cli._probe_targets", return_value={"host": ["smb"]}), \
             patch("nxs.cli.run_check", return_value=[
                 ProtocolResult("smb", False, "NO", "STATUS_LOGON_FAILURE")
             ]) as scan, \
             patch("nxs.cli.verify_credential") as gate:
            guest = CliRunner().invoke(app, ["host", "--json"])
            self.assertEqual(guest.exit_code, 0, guest.output)
            import json
            self.assertEqual(json.loads(guest.output)["user"], "guest")
            self.assertEqual(scan.call_args.args[1].user, "guest")
            self.assertEqual(scan.call_args.args[1].password, "")
            gate.assert_not_called()
            scan.reset_mock()
            null = CliRunner().invoke(app, ["host", "--null-session", "--json"])
            self.assertEqual(null.exit_code, 0, null.output)
            self.assertEqual(json.loads(null.output)["user"], "")
            self.assertEqual(scan.call_args.args[1].user, "")
            gate.assert_not_called()

    def test_discovery_summary_does_not_call_guest_access_anonymous(self):
        null = ProtocolResult("smb", True, "AUTH", "share enumeration failed: STATUS_ACCESS_DENIED")
        guest = ProtocolResult("smb", True, "READ", "Development[READ]")
        with patch.object(console, "print") as printer:
            print_discovery_results("host", {"null": [null], "guest": [guest]})
        displayed = "\n".join(str(call) for call in printer.call_args_list)
        self.assertIn("Development[READ]", displayed)
        self.assertIn("guest", displayed)
        self.assertIn("null: AUTH", displayed)
        self.assertEqual(displayed.count("[blue]SMB"), 1)

    def test_identical_discovery_results_are_collapsed(self):
        null = ProtocolResult("ldap", False, "UNCLEAR", "bind required (000004DC)")
        guest = ProtocolResult("ldap", False, "UNCLEAR", "bind required (000004DC)")
        with patch.object(console, "print") as printer:
            print_discovery_results("host", {"null": [null], "guest": [guest]})
        displayed = "\n".join(str(call) for call in printer.call_args_list)
        self.assertIn("null + guest", displayed)
        self.assertEqual(displayed.count("[blue]LDAP"), 1)

    def test_null_session_rejects_other_credentials(self):
        result = CliRunner().invoke(app, ["127.0.0.1", "--null-session", "-u", "guest"])
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("cannot be combined", result.output)


class ScannerTests(unittest.TestCase):
    @patch("nxs.runner.find_nxc", return_value="nxc")
    @patch("nxs.runner.run_command")
    def test_smb_probe_and_directory_listing(self, run, _nxc):
        run.side_effect = [
            CommandRecord([], 0, BANNER + "\n" + LOGIN),
            CommandRecord([], 0, SHARES),
            CommandRecord([], 0, "SMB host 445 DC01 dr-- 0 Tue Oct 26 01:10:06 2021 Dev"),
            CommandRecord([], 0, "SMB host 445 DC01 dr-- 0 Tue Oct 26 01:10:06 2021 Dev"),
        ]
        res = scan_protocol("host", "smb", Credential("guest", password=""), list_files=True)
        self.assertEqual(res.level, "WRITE")
        self.assertEqual(run.call_count, 4)
        cmds = [call.args[0] for call in run.call_args_list]
        listed = [cmd[cmd.index("--share") + 1] for cmd in cmds if "--share" in cmd]
        self.assertEqual(listed, ["Shares", "Project Files"])

    @patch("nxs.runner.find_nxc", return_value="nxc")
    @patch("nxs.runner.run_command")
    def test_optional_samr_enumeration_is_labeled(self, run, _nxc):
        run.side_effect = [
            CommandRecord([], 0, BANNER + "\n" + LOGIN),
            CommandRecord([], 0, SHARES),
            CommandRecord([], 0, LOGIN + "\nSMB host 445 DC01 [+] Enumerated 3 domain users"),
        ]
        res = scan_protocol("host", "smb", Credential("guest", password=""), enum_users=True)
        self.assertEqual(run.call_count, 3)
        self.assertIn("SAMR Enumerated 3 domain users", res.proof)

    @patch("nxs.runner.find_nxc", return_value="nxc")
    @patch("nxs.runner.run_command")
    def test_network_timeout_is_retried(self, run, _nxc):
        run.side_effect = [
            CommandRecord([], 124, "TIMEOUT"),
            CommandRecord([], 0, BANNER + "\n" + LOGIN),
            CommandRecord([], 0, SHARES),
        ]
        res = scan_protocol("host", "smb", Credential("guest", password=""), retries=1)
        self.assertEqual(res.level, "WRITE")
        self.assertEqual(run.call_count, 3)

    @patch("nxs.runner.find_nxc", return_value="nxc")
    @patch("nxs.runner.run_command")
    def test_ldap_read_uses_enumeration_proof_without_second_login(self, run, _nxc):
        run.side_effect = [
            CommandRecord([], 0, "LDAP 10.0.0.1 389 DC01 [+] LAB\\alice:"),
            CommandRecord([], 0, "LDAP 10.0.0.1 389 DC01 [*] Enumerated 3 domain users"),
        ]
        result = scan_protocol("dc01", "ldap", Credential("alice", password="test"))
        self.assertTrue(result.ok)
        self.assertEqual(result.level, "READ")
        self.assertIn("Enumerated 3", result.proof)

    @patch("nxs.runner.find_nxc", return_value="nxc")
    @patch("nxs.runner.run_command")
    def test_ldap_search_denied_after_valid_bind_is_auth(self, run, _nxc):
        run.return_value = CommandRecord(
            [], 0,
            "LDAP 10.0.0.1 389 DC01 [+] LAB\\alice:\n"
            "LDAP 10.0.0.1 389 DC01 [-] insufficientAccessRights",
        )
        result = scan_protocol("dc01", "ldap", Credential("alice", password="test"))
        self.assertEqual(result.level, "AUTH")
        self.assertTrue(result.ok)

    @patch("nxs.runner.find_nxc", return_value="nxc")
    @patch("nxs.runner.run_command")
    def test_gate_stops_invalid_ldap_credential(self, run, _nxc):
        run.return_value = CommandRecord([], 0,
            "LDAP host 389 DC01 [-] LAB\\alice:badpass STATUS_LOGON_FAILURE")
        result = verify_credential("host", Credential("alice", password="badpass"), ["ldap", "smb"])
        self.assertFalse(result.ok)
        self.assertEqual(result.level, "NO")
        self.assertEqual(run.call_count, 1)
        self.assertNotIn("badpass", result.proof)

    @patch("nxs.runner.find_nxc", return_value="nxc")
    @patch("nxs.runner.run_command")
    def test_gate_accepts_ldap_and_checks_no_second_protocol(self, run, _nxc):
        run.return_value = CommandRecord([], 0,
            "LDAP host 389 DC01 [+] LAB\\alice:goodpass")
        result = verify_credential("host", Credential("alice", password="goodpass"), ["ldap", "smb"])
        self.assertTrue(result.ok)
        self.assertEqual(run.call_count, 1)
        self.assertIn("LDAP", result.proof)

    @patch("nxs.runner.find_nxc", return_value="nxc")
    @patch("nxs.runner.run_command")
    def test_gate_rejects_guest_fallback_as_real_auth(self, run, _nxc):
        run.side_effect = [
            CommandRecord([], 0, "LDAP host [-] bind required (000004DC)"),
            CommandRecord([], 0, "SMB host [+] LAB\\alice:guess (Guest)"),
        ]
        result = verify_credential("host", Credential("alice", password="guess"), ["ldap", "smb"])
        self.assertFalse(result.ok)
        self.assertEqual(result.level, "UNCLEAR")
        self.assertEqual(run.call_count, 2)

    @patch("nxs.cli.verify_credential")
    @patch("nxs.cli.run_check")
    @patch("nxs.cli._probe_targets", return_value={"host": ["ldap", "smb"]})
    @patch("nxs.cli.resolve_targets", return_value=["host"])
    def test_cli_skips_capability_scan_after_failed_gate(self, targets, probes, scan, gate):
        gate.return_value = ProtocolResult("cred", False, "NO", "LDAP: STATUS_LOGON_FAILURE")
        response = CliRunner().invoke(app, ["host", "-u", "alice", "-p", "badpass", "--json"])
        self.assertEqual(response.exit_code, 0, response.output)
        self.assertIn('"password": "badpass"', response.output)
        self.assertIn('"level": "NO"', response.output)
        scan.assert_not_called()

    def test_combo_default_only_prints_verified_hits_and_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            users = Path(directory) / "users.txt"
            users.write_text("alice\nbob\ncarol\n")
            gates = {
                "alice": ProtocolResult("cred", False, "NO", "LDAP: STATUS_LOGON_FAILURE"),
                "bob": ProtocolResult("cred", False, "UNCLEAR", "guest fallback, credential not verified"),
                "carol": ProtocolResult("cred", True, "AUTH", "verified via LDAP: auth ok"),
            }

            seen = []

            def gate(target, credential, protocols, timeout, **kwargs):
                seen.append(credential.user)
                return gates[credential.user]

            def map_access(*args, **kwargs):
                self.assertCountEqual(seen, ["alice", "bob", "carol"])
                return [ProtocolResult("ldap", True, "READ", "Enumerated 3 users")]

            with patch("nxs.cli.resolve_targets", return_value=["host"]), \
                 patch("nxs.cli._probe_targets", return_value={"host": ["ldap", "smb"]}), \
                 patch("nxs.cli.verify_credential", side_effect=gate) as verify, \
                 patch("nxs.cli.run_check", side_effect=map_access) as scans, \
                 patch("nxs.cli.print_credential_check") as lines, \
                 patch("nxs.cli.print_scan_header") as headers, \
                 patch("nxs.cli.print_result_event") as rows, \
                 patch.object(console, "print") as outputs:
                result = CliRunner().invoke(app, ["host", "-u", str(users), "-p", "correct", "-C"])
                self.assertEqual(result.exit_code, 0, result.output)
                self.assertEqual(verify.call_count, 3)
                self.assertEqual(lines.call_count, 3)
                self.assertCountEqual([call.args[1].user for call in lines.call_args_list],
                                      ["alice", "bob", "carol"])
                self.assertEqual(scans.call_count, 1)
                self.assertEqual(headers.call_count, 1)
                self.assertEqual(headers.call_args.args[1].user, "carol")
                self.assertEqual([c.args[0].level for c in rows.call_args_list], ["READ"])
                shown = "\n".join(str(c) for c in outputs.call_args_list)
                self.assertIn("verified: 1", shown)
                self.assertIn("rejected: 1", shown)
                self.assertIn("inconclusive: 1", shown)
                self.assertCountEqual([call.args[2].level for call in lines.call_args_list], ["NO", "UNCLEAR", "AUTH"])

    def test_combo_verbose_prints_failure_diagnostics(self):
        with tempfile.TemporaryDirectory() as directory:
            users = Path(directory) / "users.txt"
            users.write_text("alice\nbob\n")
            with patch("nxs.cli.resolve_targets", return_value=["host"]), \
                 patch("nxs.cli._probe_targets", return_value={"host": ["ldap"]}), \
                 patch("nxs.cli.verify_credential", side_effect=[
                     ProtocolResult("cred", False, "NO", "LDAP: STATUS_LOGON_FAILURE"),
                     ProtocolResult("cred", False, "UNCLEAR", "LDAP: bind required"),
                 ]), \
                 patch("nxs.cli.run_check") as scans, \
                 patch("nxs.cli.print_scan_header") as headers, \
                 patch("nxs.cli.print_result_event") as rows:
                result = CliRunner().invoke(app, ["host", "-u", str(users), "-p", "wrong", "-C", "--verbose"])
                self.assertEqual(result.exit_code, 0, result.output)
                self.assertEqual(headers.call_count, 0)
                rows.assert_not_called()
                scans.assert_not_called()

    def test_linear_credential_format_keeps_password_and_reason(self):
        from nxs.output import print_credential_check
        cred = Credential("alice", password="test-pass")
        state = ProtocolResult(
            "cred", False, "UNCLEAR",
            "no verified login; LDAP: bind required; SMB: guest fallback",
        )
        with patch.object(console, "print") as printer:
            print_credential_check("host", cred, state)
        self.assertEqual(printer.call_count, 1)
        line = printer.call_args.args[0]
        self.assertIn("alice:test-pass", line)
        self.assertIn("UNCLEAR", line)
        self.assertIn("LDAP: bind required", line)
        self.assertIn("SMB: guest fallback", line)
        self.assertNotIn("no verified login;", line)
        self.assertNotIn("\\n", line)

    def test_quiet_output_keeps_credentials_on_hits(self):
        from nxs.output import print_results
        valid = Credential("alice", password="visible-secret")
        with patch("builtins.print") as out:
            print_results("host", valid, [
                ProtocolResult("cred", True, "AUTH", "verified via LDAP"),
                ProtocolResult("smb", False, "NO", "STATUS_LOGON_FAILURE"),
            ], quiet=True)
        self.assertEqual(out.call_count, 1)
        text = out.call_args.args[0]
        self.assertIn("alice:visible-secret", text)
        self.assertIn("CRED AUTH", text)
        self.assertNotIn("STATUS_LOGON_FAILURE", text)

    def test_no_port_probe_results_do_not_display_all_services(self):
        with patch.object(console, "print") as printer:
            print_probe_summary("host", ["host"], {}, ["smb", "ldap"])
        result = " ".join(str(call) for call in printer.call_args_list)
        self.assertIn("0/2", result)
        self.assertIn("none", result)

    def test_wmi_has_consistent_protocol_label(self):
        with patch.object(console, "print") as printer:
            print_probe_summary("host", ["host"], {"host": ["wmi", "ldap", "smb"]},
                                ["wmi", "ldap", "smb"])
            print_probe_summary("targets.txt", ["host", "other"],
                                {"host": ["wmi"], "other": []}, ["wmi", "ldap"])
        display = " ".join(str(call) for call in printer.call_args_list)
        self.assertIn("WMI", display)
        self.assertNotIn("RPC(135)", display)

    @patch("nxs.runner.find_nxc", return_value="nxc")
    @patch("nxs.runner.run_command")
    def test_winrm_verifies_powershell_output_by_default(self, run, _nxc):
        login = "WINRM-SSL 10.129.95.241 5986 PRINTER [+] return.local\\svc-printer:secret (Pwn3d!)"
        def response(command, *args, **kwargs):
            if "-X" in command:
                marker = command[command.index("-X") + 1].split()[-1]
                return CommandRecord(command, 0,
                    f"WINRM-SSL 10.129.95.241 5986 PRINTER {marker}")
            return CommandRecord(command, 0, login)

        run.side_effect = response
        result = scan_protocol("10.129.95.241", "winrm",
                               Credential("svc-printer", password="secret"))
        self.assertEqual(result.level, "EXEC")
        self.assertEqual(result.proof, "PowerShell command output verified")
        self.assertEqual(run.call_count, 2)
        self.assertIn("-X", run.call_args_list[1].args[0])

    @patch("nxs.runner.find_nxc", return_value="nxc")
    @patch("nxs.runner.run_command")
    def test_winrm_does_not_claim_exec_from_pwn3d_or_echoed_marker(self, run, _nxc):
        login = "WINRM-SSL 10.129.95.241 5986 PRINTER [+] return.local\\svc-printer:secret (Pwn3d!)"
        def response(command, *args, **kwargs):
            if "-X" in command:
                marker = command[command.index("-X") + 1].split()[-1]
                return CommandRecord(command, 0,
                    f"WINRM-SSL 10.129.95.241 5986 PRINTER [-] Failed to run Write-Output {marker}")
            return CommandRecord(command, 0, login)

        run.side_effect = response
        result = scan_protocol("10.129.95.241", "winrm",
                               Credential("svc-printer", password="secret"))
        self.assertEqual(result.level, "AUTH")
        self.assertNotIn("likely", result.proof)
        self.assertEqual(run.call_count, 2)

    @patch("nxs.runner.find_nxc", return_value="nxc")
    @patch("nxs.runner.run_command")
    def test_winrm_opt_out_and_opsec_do_not_claim_exec(self, run, _nxc):
        login = "WINRM-SSL 10.129.95.241 5986 PRINTER [+] return.local\\svc-printer:secret (Pwn3d!)"
        run.return_value = CommandRecord([], 0, login)
        cred = Credential("svc-printer", password="secret")
        skipped = scan_protocol("host", "winrm", cred, verify_exec=False)
        self.assertEqual(skipped.level, "AUTH")
        self.assertIn("command not tested", skipped.proof)
        self.assertEqual(run.call_count, 1)
        run.reset_mock()
        quiet = scan_protocol("host", "winrm", cred, opsec=True)
        self.assertEqual(quiet.level, "AUTH")
        self.assertIn("skipped", quiet.proof)
        self.assertEqual(run.call_count, 1)

    def test_ssl_prefixed_execution_marker(self):
        marker = "NXS_VERIFY_ABC123"
        output = f"WINRM-SSL 10.0.0.1 5986 PRINTER {marker}"
        self.assertEqual(exec_capability(output, marker)[0], "EXEC")

    @patch("nxs.runner.shutil.which", return_value=None)
    @patch("nxs.runner.tcp_port_open", side_effect=lambda host, port: port == 445)
    def test_missing_nmap_does_not_claim_all_ports_open(self, port, which):
        self.assertEqual(probe_ports_per_target(["host"], ["smb", "ldap", "wmi"]),
                         {"host": ["smb"]})


if __name__ == "__main__":
    unittest.main()
