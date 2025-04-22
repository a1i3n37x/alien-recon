from typing import Any
import json, nmap
from ..utils.io import tool_exists
from ..core.models import Target, ScanResult

ARGS = "-sV -T4"


def scan(target: Target, args: str = ARGS) -> ScanResult:
    if not tool_exists("nmap"):
        raise RuntimeError("nmap binary not found")

    scanner = nmap.PortScanner()
    scanner.scan(hosts=target.host, arguments=args, sudo=False)

    # massage nmap.PortScanner() to plain dict
    hosts: list[dict[str, Any]] = []
    for h in scanner.all_hosts():
        ports = []
        for proto in scanner[h].all_protocols():
            for p in scanner[h][proto].keys():
                info = scanner[h][proto][p]
                if info["state"] == "open":
                    ports.append({"port": p, "svc": info["name"]})
        hosts.append({"host": h, "ports": ports})

    return ScanResult("nmap", target, {"hosts": hosts})

