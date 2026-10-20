import socket
import subprocess
import unittest
from unittest.mock import patch

from nxs.models import Credential
from nxs.runner import PortProbeError, build_cmd, probe_ports_per_target, target_uses_ipv6


def resolve(host, port, type=None):
    entries = {
        "compatibility": [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("dead:beef::1001", 0, 0, 0))],
        "dual": [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.4", 0)),
                 (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("dead:beef::4", 0, 0, 0))],
    }
    if host not in entries:
        raise socket.gaierror("unknown host")
    return entries[host]


def xml(addr, family, port):
    return ('<nmaprun><host><status state="up"/>'
            f'<address addr="{addr}" addrtype="{family}"/>'
            f'<ports><port portid="{port}"><state state="open"/></port></ports>'
            '</host></nmaprun>')


class IPv6Tests(unittest.TestCase):
    @patch("nxs.runner.socket.getaddrinfo", side_effect=resolve)
    def test_resolve_hostname_and_preference(self, _getaddr):
        self.assertTrue(target_uses_ipv6("compatibility"))
        self.assertTrue(target_uses_ipv6("dead:beef::1001"))
        self.assertFalse(target_uses_ipv6("dual"))
        self.assertTrue(target_uses_ipv6("dual", force_ipv6=True))

    def test_nxc_global_option(self):
        cred = Credential(user="test", password="pass@123")
        self.assertEqual(build_cmd("nxc", "smb", "compatibility", cred, ipv6=True)[:4],
                         ["nxc", "-6", "smb", "compatibility"])
        self.assertEqual(build_cmd("nxc", "smb", "10.0.0.4", cred)[:3],
                         ["nxc", "smb", "10.0.0.4"])

    @patch("nxs.runner.shutil.which", return_value="/usr/bin/nmap")
    @patch("nxs.runner.socket.getaddrinfo", side_effect=resolve)
    @patch("nxs.runner.subprocess.run")
    def test_hostname_matches_resolved_ipv6(self, run, _getaddr, _which):
        run.return_value = subprocess.CompletedProcess([], 0, xml("dead:beef::1001", "ipv6", "445"), "")
        self.assertEqual(probe_ports_per_target(["compatibility"], ["smb"]),
                         {"compatibility": ["smb"]})
        self.assertIn("-6", run.call_args.args[0])

    @patch("nxs.runner.shutil.which", return_value="/usr/bin/nmap")
    @patch("nxs.runner.socket.getaddrinfo", side_effect=resolve)
    @patch("nxs.runner.subprocess.run")
    def test_mixed_families(self, run, _getaddr, _which):
        def fake(cmd, **kwargs):
            result = xml("dead:beef::1001", "ipv6", "445") if "-6" in cmd else xml("10.0.0.4", "ipv4", "22")
            return subprocess.CompletedProcess(cmd, 0, result, "")
        run.side_effect = fake
        self.assertEqual(
            probe_ports_per_target(["10.0.0.4", "compatibility"], ["ssh", "smb"]),
            {"10.0.0.4": ["ssh"], "compatibility": ["smb"]})
        self.assertEqual(run.call_count, 2)

    @patch("nxs.runner.shutil.which", return_value="/usr/bin/nmap")
    @patch("nxs.runner.subprocess.run")
    def test_nmap_failure_not_zero_ports(self, run, _which):
        run.return_value = subprocess.CompletedProcess([], 1, "", "IPv6 scan failed")
        with self.assertRaisesRegex(PortProbeError, "IPv6 scan failed"):
            probe_ports_per_target(["dead:beef::1001"], ["smb"])


if __name__ == "__main__":
    unittest.main()
