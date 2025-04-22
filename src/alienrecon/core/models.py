from dataclasses import dataclass, field
from enum import Enum, auto
from typing import List, Dict, Any


class Phase(Enum):
    AWAIT_TARGET   = auto()
    AWAIT_NMAP_OK  = auto()
    RUNNING_NMAP   = auto()
    AWAIT_GOB_OK   = auto()
    RUNNING_GOB    = auto()


@dataclass
class Target:
    host: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanResult:
    tool: str
    target: Target
    data: Dict[str, Any]           # raw JSON‑ish dump

