# src/alienrecon/scanners/gobuster.py
from __future__ import annotations
import re, os, subprocess, logging
from typing import Any, Dict, List

from ..utils.io import tool_exists, run_subprocess
from ..core.models import Target, ScanResult

log = logging.getLogger("alienrecon.gobuster")

# …imports stay the same …

DEFAULT_POSITIVE = "200,204,301,302,307,403"

def scan(
    target: Target,
    port: int,
    wordlist: str,
    status_codes: str = DEFAULT_POSITIVE,
    threads: int = 50,
) -> ScanResult:
    # …tool / wordlist checks stay the same …

    proto = "https" if port in (443, 8443) else "http"
    url   = f"{proto}://{target.host}:{port}"

    cmd = [
        "gobuster", "dir",
        "-u", url,
        "-w", wordlist,
        "-t", str(threads),
        "-q",
        "-s", status_codes,   # positive list
        "-b", "",             # **disable default blacklist**
        "--no-error",
    ]

    out = run_subprocess(cmd)

    findings = [
        {"path": path, "status": int(code)}
        for path, code in re.findall(r"^(/\\S+) \\(Status: (\\d+)\\)$", out, re.M)
    ]
    return ScanResult("gobuster", target, {"port": port, "findings": findings})

