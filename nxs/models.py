from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Credential:
    user: str
    password: str | None = None
    ntlm_hash: str | None = None
    domain: str | None = None


@dataclass
class CommandRecord:
    command: list[str]
    returncode: int
    output: str


@dataclass
class ProtocolResult:
    protocol: str
    ok: bool
    level: str
    proof: str
    mode: str = "domain"
    records: list[CommandRecord] = field(default_factory=list)

    def public_dict(self, raw: bool = False) -> dict[str, Any]:
        data = asdict(self)
        if not raw:
            data.pop("records", None)
        return data