from __future__ import annotations

import ipaddress
import os
import secrets
import re
import socket
import shutil
import subprocess
import tempfile
import threading
import time
import xml.etree.ElementTree as ET
from pathlib import Path

from .models import CommandRecord, Credential, ProtocolResult
from .parsers import parse_smb_shares

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

HARD_FAILS = (
    "STATUS_LOGON_FAILURE",
    "STATUS_ACCOUNT_DISABLED",
    "STATUS_ACCOUNT_LOCKED_OUT",
    "STATUS_PASSWORD_EXPIRED",
    "STATUS_PASSWORD_MUST_CHANGE",
    "KDC_ERR_PREAUTH_FAILED",
    "Authentication failed",
    "LOGIN_FAILED",
)

EXEC_DENIED = (
    "STATUS_ACCESS_DENIED",
    "rpc_s_access_denied",
    "access is denied",
    "WinRM::WinRMAuthorizationError",
)


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text or "")


_active_procs: set[subprocess.Popen] = set()
_proc_lock = threading.Lock()
_pace_lock = threading.Lock()
_command_delay = 0.0
_next_launch = 0.0

def configure_pacing(delay: float) -> None:
    global _command_delay, _next_launch
    with _pace_lock:
        _command_delay = max(0.0, delay)
        _next_launch = 0.0


def kill_all_procs() -> None:
    with _proc_lock:
        for proc in _active_procs:
            try:
                proc.kill()
            except OSError:
                pass


_nxc_cache: str | None = None

def find_nxc() -> str:
    global _nxc_cache
    if _nxc_cache:
        return _nxc_cache
    path = shutil.which("nxc") or shutil.which("netexec")
    if not path:
        from rich.console import Console
        Console(stderr=True).print("[red][-][/red] nxc/netexec not found in PATH")
        raise SystemExit(1)
    _nxc_cache = path
    return path


def record_dict(record: CommandRecord) -> dict:
    """Preserve original command, exit code and output."""
    return {
        "command": list(record.command),
        "returncode": record.returncode,
        "output": record.output,
    }


def run_command(
    command: list[str],
    timeout: int,
    debug: bool = False,
    env: dict | None = None,
    remote_time: str | None = None,
) -> CommandRecord:
    global _next_launch
    if _command_delay > 0:
        with _pace_lock:
            remaining = _next_launch - time.monotonic()
            if remaining > 0:
                time.sleep(remaining)
            _next_launch = time.monotonic() + _command_delay
    if remote_time and shutil.which("faketime"):
        command = ["faketime", remote_time] + command
    if debug:
        print("[debug]", " ".join(command))
    try:
        proc = subprocess.Popen(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        with _proc_lock:
            _active_procs.add(proc)
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            return CommandRecord(command[:], 124, "TIMEOUT")
        finally:
            with _proc_lock:
                _active_procs.discard(proc)
        output = strip_ansi((stdout or "") + (stderr or ""))
        return CommandRecord(command[:], proc.returncode, output)
    except OSError as e:
        return CommandRecord(command[:], 1, str(e))


def auth_args(cred: Credential, kerberos: bool = False, kdc_host: str | None = None) -> list[str]:
    args = ["-u", cred.user]

    if cred.ccache_file:
        args += ["--use-kcache"]
    elif cred.ntlm_hash:
        args += ["-H", cred.ntlm_hash]
    else:
        args += ["-p", cred.password or ""]

    if cred.domain:
        args += ["-d", cred.domain]
    if kerberos or cred.ccache_file:
        args += ["-k"]
    if kdc_host:
        args += ["--kdcHost", kdc_host]

    return args


def build_cmd(
    nxc: str,
    protocol: str,
    target: str,
    cred: Credential,
    extra: list[str] | None = None,
    local_auth: bool = False,
    kerberos: bool = False,
    kdc_host: str | None = None,
    ipv6: bool = False,
) -> list[str]:
    command = [nxc] + (["-6"] if ipv6 else []) + [protocol, target] + auth_args(cred, kerberos, kdc_host)

    if local_auth and protocol in {"smb", "wmi"}:
        command.append("--local-auth")
    if extra:
        command += extra

    return command


PORT_MAP = {
    "smb": "445",
    "ldap": "389",
    "wmi": "135",
    "winrm": "5985",
    "ssh": "22",
    "rdp": "3389",
    "mssql": "1433",
    "ftp": "21",
    "vnc": "5900",
    "nfs": "2049",
}

WINRM_HTTPS_PORT = "5986"


def probe_port_map(protocols: list[str]) -> dict[str, str]:
    ports = {PORT_MAP[p]: p for p in protocols if p in PORT_MAP}
    if "winrm" in protocols:
        ports[WINRM_HTTPS_PORT] = "winrm"
    return ports

class PortProbeError(RuntimeError):
    """Port probe failed; do not report it as no open ports."""


def target_addresses(target: str) -> dict[int, set[str]]:
    """Use the system resolver, including /etc/hosts."""
    addrs = {socket.AF_INET: set(), socket.AF_INET6: set()}
    try:
        addr = ipaddress.ip_address(target)
    except ValueError:
        pass
    else:
        family = socket.AF_INET6 if addr.version == 6 else socket.AF_INET
        addrs[family].add(str(addr))
        return addrs
    try:
        infos = socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError):
        return addrs
    for family, _, _, _, sockaddr in infos:
        if family in addrs:
            addrs[family].add(sockaddr[0])
    return addrs


def target_uses_ipv6(target: str, force_ipv6: bool = False) -> bool:
    """Match NetExec: prefer IPv4 when both families resolve."""
    if force_ipv6:
        return True
    addrs = target_addresses(target)
    return not addrs[socket.AF_INET] and bool(addrs[socket.AF_INET6])


def check_port_state(target: str, protocol: str) -> str:
    ports = list(probe_port_map([protocol]))
    nmap = shutil.which("nmap")
    if not ports or not nmap:
        return "port closed / filtered"

    try:
        result = subprocess.run(
            [nmap] + (["-6"] if target_uses_ipv6(target) else []) +
            ["-sT", "-Pn", "-p", ",".join(ports), target],
            capture_output=True, text=True, timeout=5,
        )
        states = {}
        for line in result.stdout.splitlines():
            for port in ports:
                if f"{port}/tcp" not in line:
                    continue
                if "open" in line and "filtered" not in line:
                    return "port open"
                if "closed" in line:
                    states[port] = "closed"
                elif "filtered" in line:
                    states[port] = "filtered"
        if len(states) == len(ports) and all(state == "closed" for state in states.values()):
            return "port closed"
    except (OSError, subprocess.TimeoutExpired):
        pass
    return "port closed / filtered"

def tcp_port_open(target: str, port: int, timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection((target, port), timeout=timeout):
            return True
    except (OSError, TimeoutError):
        return False


def probe_ports(target: str, protocols: list[str], timeout: int = 5) -> list[str]:
    """Quick TCP probe — returns only protocols whose ports are open."""
    nmap = shutil.which("nmap")
    if not nmap:
        return [p for p in protocols if any(tcp_port_open(target, int(port)) for port, proto in probe_port_map([p]).items() if proto == p)]

    port_to_proto = probe_port_map(protocols)
    ports = list(port_to_proto)
    if not ports:
        return protocols[:]

    try:
        result = subprocess.run(
            [nmap] + (["-6"] if target_uses_ipv6(target) else []) + ["-sT", "-Pn", "-T4", "-p", ",".join(ports), target],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        reachable = []
        for line in result.stdout.splitlines():
            for port, proto in port_to_proto.items():
                if f"{port}/tcp" in line and "open" in line and "filtered" not in line:
                    if proto not in reachable:
                        reachable.append(proto)
        return reachable
    except Exception:
        return protocols[:]


def resolve_targets(target_str: str) -> list[str]:
    path = Path(target_str)
    if path.is_file():
        targets = []
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                targets.extend(resolve_targets(line))
        return targets or [target_str]

    if "/" in target_str:
        try:
            net = ipaddress.ip_network(target_str, strict=False)
            return [str(ip) for ip in net.hosts()]
        except ValueError:
            return [target_str]

    m = re.match(r"^((?:\d{1,3}\.){3})(\d{1,3})-(\d{1,3})$", target_str)
    if m:
        prefix, lo, hi = m.group(1), int(m.group(2)), int(m.group(3))
        return [f"{prefix}{i}" for i in range(lo, hi + 1)]

    m = re.match(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})-(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$", target_str)
    if m:
        try:
            start = int(ipaddress.ip_address(m.group(1)))
            end = int(ipaddress.ip_address(m.group(2)))
            return [str(ipaddress.ip_address(i)) for i in range(start, end + 1)]
        except ValueError:
            pass

    return [target_str]


def probe_ports_per_target(
    targets: list[str],
    protocols: list[str],
    timeout: int = 10,
    ipv6_targets: set[str] | None = None,
    opsec: bool = False,
) -> dict[str, list[str]]:
    """Probe each IP family separately; correlate resolved IPs with input names."""
    nmap = shutil.which("nmap")
    if not nmap:
        return {t: [p for p in protocols if any(tcp_port_open(t, int(port)) for port, proto in probe_port_map([p]).items() if proto == p)] for t in targets}

    port_to_proto = probe_port_map(protocols)
    ports = list(port_to_proto)
    if not ports:
        return {t: protocols[:] for t in targets}

    if ipv6_targets is None:
        ipv6_targets = {t for t in targets if target_uses_ipv6(t)}
    result_map = {t: [] for t in targets}

    for family, group in (
        (socket.AF_INET, [t for t in targets if t not in ipv6_targets]),
        (socket.AF_INET6, [t for t in targets if t in ipv6_targets]),
    ):
        if not group:
            continue
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(group))
            tmp_path = f.name
        try:
            cmd = [nmap] + (["-6"] if family == socket.AF_INET6 else [])
            cmd += ["-sT", "-Pn", "-T2" if opsec else "-T4", "--open", "-p", ",".join(ports), "-oX", "-", "-iL", tmp_path]
            try:
                result = subprocess.run(
                    cmd, capture_output=True, text=True,
                    timeout=max(timeout, len(group) * 3),
                )
            except subprocess.TimeoutExpired as exc:
                raise PortProbeError("Nmap timed out while scanning targets") from exc
            except OSError as exc:
                raise PortProbeError(f"Unable to start Nmap: {exc}") from exc
        finally:
            os.unlink(tmp_path)

        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()
            raise PortProbeError(detail or f"Nmap exited with status {result.returncode}")
        try:
            root = ET.fromstring(result.stdout)
        except ET.ParseError as exc:
            raise PortProbeError("Nmap returned invalid XML; port status is unknown") from exc

        aliases: dict[str, set[str]] = {}
        for target in group:
            aliases.setdefault(target.lower(), set()).add(target)
            for addr in target_addresses(target)[family]:
                aliases.setdefault(addr.lower(), set()).add(target)

        for host in root.findall(".//host"):
            status = host.find("status")
            if status is not None and status.get("state") != "up":
                continue
            addrtype = "ipv6" if family == socket.AF_INET6 else "ipv4"
            names = [el.get("addr", "").lower() for el in host.findall("address")
                     if el.get("addrtype") == addrtype]
            names += [el.get("name", "").lower() for el in host.findall("./hostnames/hostname")]
            matched: set[str] = set()
            for name in names:
                matched.update(aliases.get(name, set()))
            for port_el in host.findall("./ports/port"):
                state = port_el.find("state")
                if state is None or state.get("state") != "open":
                    continue
                proto = port_to_proto.get(port_el.get("portid", ""))
                if proto:
                    for target in matched:
                        if proto not in result_map[target]:
                            result_map[target].append(proto)

    return result_map


def auth_state(output: str, user: str, target: str, protocol: str) -> tuple[bool | None, str]:
    """Verify a login, never confuse the echoed password with an error reason."""
    if not output.strip():
        if target and protocol and check_port_state(target, protocol) == "port closed":
            return None, "port closed"
        return None, "empty response"

    low = output.lower()
    for error in HARD_FAILS:
        if error.lower() in low:
            return False, error
    if any(item in low for item in ("timeout", "connection refused", "no route", "unreachable")):
        return None, "connection timed out or unavailable"

    expected = user.rsplit("\\", 1)[-1].split("@", 1)[0].casefold()
    other_error = None
    for line in output.splitlines():
        match = re.search(r"\[(?P<status>[+-])\]\s+(?P<message>.*)$", line)
        if not match:
            continue
        message = match.group("message").strip()
        login = re.match(r"^(?:[^\\:\s]+\\)?([^:\s]*):", message)
        if login and login.group(1).casefold() == expected:
            if match.group("status") == "+":
                return True, "guest mapped" if "(Guest)" in message else "auth ok"
            # Most NetExec failures are DOMAIN\\user:password (ERROR).
            # The portion after ':' is the echoed password, not an error.
            failure = re.search(
                r"(STATUS_[A-Z0-9_]+|RPC_S_[A-Z0-9_]+|KDC_ERR_[A-Z0-9_]+|"
                r"NT_STATUS_[A-Z0-9_]+|invalidCredentials|LOGIN_FAILED)",
                message, re.I,
            )
            if failure:
                reason = failure.group(0)
                if reason in HARD_FAILS or reason.upper() in HARD_FAILS:
                    return False, reason
                return None, reason
            return None, "authentication response rejected without a reliable error code"
        if match.group("status") == "-":
            other_error = message

    if other_error:
        # Share enumeration errors are not login failures; keep their full reason.
        if other_error.lower().startswith("error enumerating shares:"):
            return None, other_error
        error = re.search(
            r"(STATUS_[A-Z0-9_]+|RPC_S_[A-Z0-9_]+|KDC_ERR_[A-Z0-9_]+|"
            r"NT_STATUS_[A-Z0-9_]+|invalidCredentials|LOGIN_FAILED)",
            other_error, re.I,
        )
        if error:
            code = error.group(0)
            return (False if code.upper() in HARD_FAILS else None), code
        return None, "unclassified protocol error"
    return None, "no verified authentication response"


def smb_capability(output: str) -> tuple[str, str]:
    shares = parse_smb_shares(output)
    usable = [s for s in shares if s.name.upper() not in {"IPC$", "ADMIN$", "C$"}
              and s.permissions]
    admin = [s for s in shares if s.name.upper() in {"ADMIN$", "C$"}
             and "WRITE" in s.permissions]
    if admin:
        return "ADMIN", ", ".join(f"{s.name}[{s.display_permissions}]" for s in admin + usable)
    if any("WRITE" in s.permissions for s in usable):
        return "WRITE", ", ".join(f"{s.name}[{s.display_permissions}]" for s in usable)
    if usable:
        return "READ", ", ".join(f"{s.name}[{s.display_permissions}]" for s in usable)
    return "AUTH", ("shares parsed; no readable/writable disk shares" if shares else "share table empty or unparseable")


def ldap_capability(output: str) -> tuple[str, str]:
    for line in output.splitlines():
        if re.search(r"\bEnumerated\s+\d+\s+(?:domain\s+)?users\b", line, re.I):
            return "READ", line.split("[*]")[-1].strip()
    return "AUTH", "bind reported; directory read unverified"


def verified_command_identity(output: str, marker: str, kind: str) -> str | None:
    """Find a real whoami/id output row AFTER an exact standalone marker."""
    from .parsers import clean_nxc_line

    lines = [clean_nxc_line(line).rstrip("\x00") for line in output.splitlines()]
    try:
        start = lines.index(marker)
    except ValueError:
        return None

    for line in lines[start + 1:]:
        if not line or line.startswith(("[*]", "[+]", "[-]", "[!]")):
            continue
        if kind == "windows":
            # Windows whoami returns DOMAIN\user, including e.g. NT AUTHORITY\SYSTEM.
            if re.fullmatch(r"[^\\\r\n:]+\\[^\\\r\n:\s]+", line):
                return line
        elif kind == "linux":
            # id emits numeric uid/gid and named identities; plain echoed strings fail.
            if re.fullmatch(r"uid=\d+\([^)]+\)\s+gid=\d+\([^)]+\)(?:\s+groups=.*)?", line):
                return line
    return None


def exec_capability(
    output: str, marker: str, *, identity_kind: str | None = None
) -> tuple[str, str]:
    """Require both a verified marker and whoami/id when identity_kind is given."""
    from .parsers import clean_nxc_line

    marker_seen = any(clean_nxc_line(line) == marker for line in output.splitlines())
    if marker_seen:
        if identity_kind:
            identity = verified_command_identity(output, marker, identity_kind)
            if identity:
                command = "whoami" if identity_kind == "windows" else "id"
                return "EXEC", f"{command}: {identity}"
            return "AUTH", "command marker returned but whoami/id output not verified"
        return "EXEC", "command execution verified"

    low = output.lower()
    if any(item.lower() in low for item in EXEC_DENIED):
        return "AUTH", "exec denied"
    for line in output.splitlines():
        if "[-]" in line:
            return "AUTH", "exec failed: " + line.split("[-]", 1)[1].strip()[:100]
    return "AUTH", "exec unverified (no command output)"



def ldap_problem(output: str) -> tuple[str, str] | None:
    for line in output.splitlines():
        if "[-]" not in line:
            continue
        error = line.split("[-]", 1)[1].strip().rstrip("\x00")
        low = error.lower()
        if "000004dc" in low or "successful bind must be completed" in low:
            return "UNCLEAR", "bind required (000004DC)"
        if "invalidcredentials" in low or "data 52e" in low:
            return "NO", "invalid credentials (LDAP 49)"
        if "insufficientaccessrights" in low or "insufficient access rights" in low:
            return "AUTH", "search denied (LDAP 50)"
        if "searchrequest" in low or "ldaperr" in low:
            return "UNCLEAR", "LDAP operation failed"
    return None


def save_records(save_dir: Path, target: str, user: str, result: ProtocolResult) -> None:
    """Save original evidence with private permissions and unique names."""
    safe_target = re.sub(r"[^A-Za-z0-9_.-]", "_", target)
    safe_user = re.sub(r"[^A-Za-z0-9_.-]", "_", user) or "anonymous"
    base = save_dir / safe_target / safe_user
    base.mkdir(mode=0o700, parents=True, exist_ok=True)
    base.chmod(0o700)

    for idx, record in enumerate(result.records, start=1):
        data = record_dict(record)
        path = base / f"{result.protocol}_{secrets.token_hex(6)}_{idx}.txt"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", errors="replace") as stream:
            stream.write("$ " + " ".join(data["command"]) + "\n\n" + data["output"])


def get_remote_time(target: str) -> str | None:
    # Try net time -S target
    net = shutil.which("net")
    if net:
        try:
            res = subprocess.run([net, "time", "-S", target], capture_output=True, text=True, timeout=5)
            if res.returncode == 0 and res.stdout.strip():
                # Parse with date -d
                date_cmd = shutil.which("date")
                if date_cmd:
                    parsed = subprocess.run([date_cmd, "-d", res.stdout.strip(), "+%Y-%m-%d %H:%M:%S"], capture_output=True, text=True, timeout=3)
                    if parsed.returncode == 0 and parsed.stdout.strip():
                        return parsed.stdout.strip()
        except Exception:
            pass

    # Try ntpdate -q target as fallback
    ntpdate = shutil.which("ntpdate")
    if ntpdate:
        try:
            res = subprocess.run([ntpdate, "-q", target], capture_output=True, text=True, timeout=5)
            # Find offset
            import re
            for line in res.stdout.splitlines():
                match = re.search(r"offset\s+([-+]?\d+\.\d+)", line)
                if match:
                    offset = float(match.group(1))
                    # Calculate remote time
                    import datetime
                    remote_dt = datetime.datetime.now() + datetime.timedelta(seconds=offset)
                    return remote_dt.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            pass

    return None


def verify_credential(
    target: str,
    cred: Credential,
    protocols: list[str],
    timeout: int = 60,
    *,
    local_auth: bool = False,
    try_local: bool = False,
    kerberos: bool = False,
    kdc_host: str | None = None,
    debug: bool = False,
    remote_time: str | None = None,
    ipv6: bool = False,
) -> ProtocolResult:
    """Verify a credential using exactly one reachable auth protocol.

    SMB is preferred because NetExec reports guest fallback explicitly.
    An SMB guest session does NOT validate the supplied username/password.
    If SMB is unavailable, use LDAP, then a remaining reachable protocol.
    Never silently treat an auth/tool error as an invalid password.
    """
    nxc = find_nxc()
    env = {**os.environ, "KRB5CCNAME": str(cred.ccache_file)} if cred.ccache_file else None
    priority = ("smb", "ldap", "winrm", "wmi")
    protocol = next((p for p in priority if p in protocols), None)
    if protocol is None:
        protocol = protocols[0] if protocols else None
    if protocol is None:
        return ProtocolResult("cred", False, "ERROR", "no reachable authentication protocol")

    modes = [local_auth]
    if try_local and not local_auth and protocol == "smb":
        modes.append(True)  # Explicit opt-in for retrying local authentication.
    records: list[CommandRecord] = []
    last_error = ""

    for mode in modes:
        record = run_command(
            build_cmd(nxc, protocol, target, cred, local_auth=mode,
                      kerberos=kerberos, kdc_host=kdc_host, ipv6=ipv6),
            timeout, debug, env=env, remote_time=remote_time,
        )
        records.append(record)
        ok, reason = auth_state(record.output, cred.user, target, protocol)
        if protocol == "ldap":
            issue = ldap_problem(record.output)
            if issue and issue[0] == "NO":
                ok, reason = False, issue[1]
            elif issue and issue[0] == "UNCLEAR":
                ok, reason = None, issue[1]

        if reason == "guest mapped":
            # Guest sessions work regardless of the password on guest-mapping hosts.
            return ProtocolResult(
                "cred", False, "GUEST",
                f"{protocol.upper()}: mapped to Guest, supplied password not verified",
                "local" if mode else "domain", records,
            )
        if ok is True:
            return ProtocolResult(
                "cred", True, "AUTH", f"{protocol.upper()}: login verified",
                "local" if mode else "domain", records,
            )
        if ok is False:
            return ProtocolResult(
                "cred", False, "NO", f"{protocol.upper()}: {reason}",
                "local" if mode else "domain", records,
            )
        last_error = f"{protocol.upper()}: {reason}"

    return ProtocolResult(
        "cred", False, "ERROR",
        last_error or f"{protocol.upper()}: no verifiable login response",
        "domain", records,
    )


def test_protocol(
    target: str,
    protocol: str,
    cred: Credential,
    timeout: int = 60,
    retries: int = 1,
    local_auth: bool = False,
    try_local: bool = False,
    kerberos: bool = False,
    kdc_host: str | None = None,
    debug: bool = False,
    delay: float = 0.0,
    remote_time: str | None = None,
    ipv6: bool = False,
    opsec: bool = False,
    list_files: bool = False,
    verify_exec: bool = True,
    enum_users: bool = False,
) -> ProtocolResult:
    nxc = find_nxc()
    ccache_env = {**os.environ, "KRB5CCNAME": str(cred.ccache_file)} if cred.ccache_file else None
    modes = [local_auth]

    if try_local and not local_auth and protocol in {"smb", "wmi"}:
        modes.append(True)

    all_records: list[CommandRecord] = []
    last_reason = "no clear auth result"

    for mode in modes:
        for attempt in range(retries + 1):
            login = run_command(
                build_cmd(nxc, protocol, target, cred, local_auth=mode, kerberos=kerberos, kdc_host=kdc_host, ipv6=ipv6),
                timeout,
                debug,
                env=ccache_env,
                remote_time=remote_time,
            )

            all_records.append(login)
            ok, reason = auth_state(login.output, cred.user, target, protocol)
            if protocol == "ldap":
                issue = ldap_problem(login.output)
                if issue:
                    state, message = issue
                    if state == "AUTH" and ok is not True:
                        state = "UNCLEAR"
                    return ProtocolResult(protocol, state == "AUTH", state, message, "local" if mode else "domain", all_records)
            last_reason = reason

            if ok is False:
                if mode != modes[-1]:
                    break
                return ProtocolResult(protocol, False, "NO", reason, "local" if mode else "domain", all_records)

            if ok is not True:
                continue
            if reason == "guest mapped" and (cred.password or cred.ntlm_hash):
                return ProtocolResult(
                    protocol, False, "UNCLEAR",
                    "guest fallback; supplied credential not verified",
                    "local" if mode else "domain", all_records,
                )

            level, proof = "AUTH", "auth ok"
            if protocol == "wmi":
                proof = "NXC login accepted; WMI management rights unverified"
            if protocol == "winrm":
                shell_checked = any("[+]" in line and "(Pwn3d!)" in line
                                    for line in login.output.splitlines())
                proof = ("WSMan shell enumeration passed; command not tested"
                         if shell_checked else "WinRM authenticated; shell unverified")

            if opsec and not (protocol == "smb" and (list_files or enum_users)):
                return ProtocolResult(protocol, True, "AUTH",
                                      "auth ok; capability checks skipped (--opsec)",
                                      "local" if mode else "domain", all_records)

            if protocol == "smb":
                shares = run_command(
                    build_cmd(nxc, protocol, target, cred, ["--shares"], mode, kerberos, kdc_host, ipv6=ipv6),
                    timeout,
                    debug,
                    env=ccache_env,
                    remote_time=remote_time,
                )
                all_records.append(shares)

                if "Enumerated shares" in shares.output:
                    level, proof = smb_capability(shares.output)
                    if list_files:
                        readable = [s.name for s in parse_smb_shares(shares.output)
                                    if "READ" in s.permissions and s.name.upper() not in
                                    {"IPC$", "ADMIN$", "C$"}]
                        for share in dict.fromkeys(readable):
                            listing = run_command(
                                build_cmd(nxc, protocol, target, cred, ["--share", share, "--dir"], mode, kerberos, kdc_host, ipv6=ipv6),
                                timeout, debug, env=ccache_env, remote_time=remote_time,
                            )
                            all_records.append(listing)
                else:
                    errors = [line.split("[-]", 1)[1].strip() for line in shares.output.splitlines() if "[-]" in line]
                    proof = ("share enumeration failed: " + errors[0][:100]) if errors else "share enumeration unverified"

                if enum_users:
                    users = run_command(
                        build_cmd(nxc, "smb", target, cred, ["--users"], mode,
                                  kerberos, kdc_host, ipv6=ipv6),
                        timeout, debug, env=ccache_env, remote_time=remote_time,
                    )
                    all_records.append(users)
                    match = re.search(r"Enumerated\s+\d+\s+(?:domain\s+)?users",
                                      users.output, re.I)
                    if match:
                        proof += "; SAMR " + match.group(0)
                    else:
                        proof += "; SAMR users: unavailable or unverified"

            elif protocol == "ldap":
                users = run_command(
                    build_cmd(nxc, protocol, target, cred, ["--users"], mode, kerberos, kdc_host, ipv6=ipv6),
                    timeout,
                    debug,
                    env=ccache_env,
                    remote_time=remote_time,
                )
                all_records.append(users)

                issue = ldap_problem(users.output)
                if issue:
                    level, proof = issue
                else:
                    level, proof = ldap_capability(users.output)

            elif protocol == "winrm":
                if verify_exec:
                    marker = "NXS_VERIFY_" + secrets.token_hex(8)
                    executed = run_command(
                        build_cmd(nxc, protocol, target, cred, ["-X", f"Write-Output {marker}; whoami"], mode, kerberos, kdc_host, ipv6=ipv6),
                        timeout, debug, env=ccache_env, remote_time=remote_time,
                    )
                    all_records.append(executed)
                    level, exec_proof = exec_capability(
                        executed.output, marker, identity_kind="windows",
                    )
                    proof = (f"PowerShell execution verified; {exec_proof}" if level == "EXEC"
                             else "WinRM authenticated; " + exec_proof)

            elif protocol in {"ssh", "wmi"}:
                marker = "NXS_VERIFY_" + secrets.token_hex(8)
                if protocol == "ssh":
                    cmd_args = ["-x", f"printf '%s\\n' {marker}; id"]
                else:
                    cmd_args = ["-x", f'cmd /c "echo {marker} & whoami"']
                exec_check = run_command(
                    build_cmd(nxc, protocol, target, cred, cmd_args, mode, kerberos, kdc_host, ipv6=ipv6),
                    timeout, debug, env=ccache_env, remote_time=remote_time,
                )
                all_records.append(exec_check)
                level, proof = exec_capability(
                    exec_check.output, marker,
                    identity_kind="linux" if protocol == "ssh" else "windows",
                )

            if reason == "guest mapped":
                proof += "; effective session: Guest"
            return ProtocolResult(protocol, level not in {"NO", "UNCLEAR"}, level, proof, "local" if mode else "domain", all_records)

    return ProtocolResult(protocol, False, "UNCLEAR", last_reason, "local" if local_auth else "domain", all_records)
