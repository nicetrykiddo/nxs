# nxs

[![PyPI version](https://img.shields.io/pypi/v/nxsctl.svg)](https://pypi.org/project/nxsctl/)

> What can this cred actually do?

`nxs` is a credential capability mapper powered by [NetExec](https://github.com/Pennyw0rth/NetExec). It takes a credential and checks it against 10 different protocols (SMB, LDAP, WMI, WinRM, SSH, RDP, MSSQL, FTP, VNC, NFS) to show you exactly what level of access you have on the target.

## Install

```bash
pipx install nxsctl
```

Requires [NetExec](https://github.com/Pennyw0rth/NetExec) (`nxc`) in PATH.

## Usage

Credential-free discovery tries **anonymous** and **guest** independently on each
reachable protocol. This is a small, fixed access check, **not** a password spray:

```bash
nxs dc01.example.test
```

SMB output shows readable/writable share names without requiring `--verbose`,
including shares literally named `Shares` and names containing spaces. `--list-files`
lists the **root only** of shares with READ access (not recursive), and `--enum-users`
performs optional SMB/SAMR user enumeration:

```bash
nxs dc01.example.test -u guest -p '' --list-files --enum-users
```

A reachable TCP 135 endpoint is displayed as **RPC(135)**, not confirmed WMI
management access. WMI `AUTH` alone is not proof of command execution or user enumeration.
Authentication, share permissions, and command execution are reported separately.
The `Null Auth` header is information advertised by NetExec and does not prove
anonymous file access.

Scan output, `--raw` JSON, `--debug` commands, and `--save` evidence redact
passwords and hashes. Evidence files are private and uniquely named.
When Nmap is absent, nxs uses direct TCP checks rather than assuming every port
is open. Multi-credential scans check every supplied credential on every
reachable protocol rather than skipping non-SMB-valid credentials.

```bash
nxs 10.10.10.10 -u john.doe -p 'Password123' -d domain.local
```

Password prompt if `-p` is omitted:

```bash
nxs 10.10.10.10 -u john.doe -d domain.local
```

Hash authentication:

```bash
nxs 10.10.10.10 -u john.doe -H NT_HASH -d domain.local
nxs 10.10.10.10 -u john.doe -H LM_HASH:NT_HASH -d domain.local
```

## Quickstart

IPv6-only hostnames (including `/etc/hosts`) are detected automatically. IPv4 is
preferred for dual-stack hosts unless `-6` is explicitly requested.

```bash
nxs compatibility -u test -p 'pass@123'
nxs compatibility -6 -u test -p 'pass@123'  # Force IPv6
nxs dead:beef::1001 -u test -p 'pass@123'
```

Mixed IPv4 and IPv6 target files are scanned in separate Nmap runs. Nmap failures
are reported instead of silently being treated as 0 open ports.


```bash
nxs 10.10.10.10 -u admin -p 'Password123!'

# Spray a file of credentials (format: user:pass or user:hash)
nxs 10.10.10.10 -f creds.txt

# Password spray — one password across a user list
nxs 10.10.10.10 -u users.txt -p 'Password123!'

# All combinations — every user × every password (-C/--combo)
nxs 10.10.10.10 -u users.txt -p passwords.txt -C

# Specific protocols
nxs 192.168.1.0/24 -u john.doe -H 'LM:NT' --protocols ssh,winrm
```

OPSEC mode (single-threaded, low retry):

```bash
nxs 10.10.10.10 -u john.doe -p 'Password123' -d domain.local --opsec
```

Kerberos:

```bash
nxs 10.10.10.10 -u john.doe -p 'Password123' -d domain.local -k --kdc-host dc01.domain.local

# Authenticate with a ccache ticket file (no password needed):
nxs 10.10.10.10 -T user.ccache

# Scan a directory of tickets:
nxs 10.10.10.10 -T ./tickets/
```

JSON output:

```bash
nxs 10.10.10.10 -u john.doe -p 'Password123' --json
nxs 10.10.10.10 -u john.doe -p 'Password123' --json --raw
```

Save raw proof:

```bash
nxs 10.10.10.10 -u john.doe -p 'Password123' --save loot/
```

Verbose output (detailed execution info, WIP...):

```bash
nxs 10.10.10.10 -u john.doe -p 'Password123' --verbose
```

## Example Output

```text
nxs v0.1.0 10.10.10.10 · john.doe@domain.local · 4 protocols

  [+] SMB    WRITE    Shared[READ+WRITE], Web[READ]
  [+] LDAP   READ     Enumerated 15 domain users
  [-] WINRM  NO       Authentication failed
```

With `--verbose`, detailed output is nested underneath. It expands share tables, metadata, and optional directory/user listings:

```text
nxs v0.1.0 10.10.10.10 · admin · 1 protocols

  [+] WINRM  EXEC     domain.local\admin
      ↳ USER INFORMATION
      ↳ ----------------
      ↳ User Name         SID
      ↳ ================= ============================================
      ↳ domain\admin      S-1-5-21-3623811015-3361044348-30300820-500
```

## Access Levels

| Level | Marker | Meaning |
|-------|--------|---------|
| `ADMIN` | `[+]` | Admin-level access |
| `EXEC` | `[+]` | Command execution |
| `WRITE` | `[+]` | Write access |
| `READ` | `[+]` | Read access |
| `AUTH` | `[*]` | Authenticated, no further access |
| `UNCLEAR` | `[?]` | Inconclusive result |
| `NO` | `[-]` | Authentication failed or port closed |

## Upgrading before a PyPI release

The GitHub code can be installed directly via:

```bash
pipx install --force 'git+https://github.com/nicetrykiddo/nxs.git'
```

The PyPI package does not update until a release is published.

## License

[MIT](LICENSE)
