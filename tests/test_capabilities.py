"""Regression tests for incorrect capability evidence and share omissions."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from nxs.cli import resolve_credentials
from nxs.models import CommandRecord, Credential, ProtocolResult
from nxs.output import cred_label, extract_verbose_details
from nxs.parsers import parse_smb_shares, smb_metadata
from nxs.runner import (
    auth_state, exec_capability, probe_ports_per_target, redact_command,
    redact_record, save_records, smb_capability, test_protocol as scan_protocol,
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
    def test_credential_label_does_not_leak_password_or_hash(self):
        self.assertNotIn("secret", cred_label(Credential("alice", password="secret")))
        self.assertNotIn("aabbcc", cred_label(Credential("alice", ntlm_hash="aabbcc")))

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

    def test_raw_evidence_redacts_secrets(self):
        record = CommandRecord(["nxc", "smb", "host", "-u", "alice", "-p", "secret"], 0,
                               "[+] DOMAIN\\alice:secret")
        self.assertNotIn("secret", str(redact_record(record)))
        self.assertNotIn("secret", str(ProtocolResult("smb", True, "AUTH", "ok", records=[record]).public_dict(raw=True)))
        self.assertNotIn("secret", str(redact_command(record.command)))
        with tempfile.TemporaryDirectory() as tmp:
            result = ProtocolResult("smb", True, "AUTH", "ok", records=[record])
            save_records(Path(tmp), "host", "alice", result)
            save_records(Path(tmp), "host", "alice", result)
            files = list(Path(tmp).rglob("*.txt"))
            self.assertEqual(len(files), 2)
            for f in files:
                self.assertNotIn("secret", f.read_text())
                self.assertEqual(f.stat().st_mode & 0o777, 0o600)

    def test_no_creds_tries_anonymous_and_guest(self):
        creds = resolve_credentials(None, None, None, None, None)
        self.assertEqual([(c.user, c.password) for c in creds], [("", ""), ("guest", "")])


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

    @patch("nxs.runner.shutil.which", return_value=None)
    @patch("nxs.runner.tcp_port_open", side_effect=lambda host, port: port == 445)
    def test_missing_nmap_does_not_claim_all_ports_open(self, port, which):
        self.assertEqual(probe_ports_per_target(["host"], ["smb", "ldap", "wmi"]),
                         {"host": ["smb"]})


if __name__ == "__main__":
    unittest.main()
