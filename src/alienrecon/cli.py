"""AlienRecon CLI
-----------------
Entry‑point for the Alien Recon tool.
Provides an interactive shell plus one‑shot Typer commands.
"""

import shlex
import json
from pathlib import Path

import typer
import rich
from rich.markdown import Markdown
from rich.prompt import Prompt
from rich.console import Console
from typer import BadParameter

from .core.state import ReconState, Phase
from .scanners import nmap as nmap_scan, gobuster as gob_scan
from .agents.openai_client import chat

# ─────────────────────────────────────────────────────────────────────────────
# Globals & singletons
# ─────────────────────────────────────────────────────────────────────────────

app: typer.Typer = typer.Typer(add_completion=False, rich_markup_mode="rich")
console: Console = Console()

state = ReconState()                  # finite‑state machine (holds target, phase…)
history: list[dict] = []              # chat history for LLM context
SYS_PROMPT = "You are Alien Recon, the alien CTF mentor.  Stay ethical, concise, and directive."

# ─────────────────────────────────────────────────────────────────────────────
# Helper functions (not exposed as CLI commands)
# ─────────────────────────────────────────────────────────────────────────────

def _log_assistant(msg: str) -> None:
    """Print markdown + push to history as assistant."""
    console.print(Markdown(f"**Alien Recon:** {msg}"))
    history.append({"role": "assistant", "content": msg})


def _ask_nmap() -> None:
    msg = f"Shall I proceed with an Nmap scan (`-sV -T4`) on {state.target.host}?"
    _log_assistant(msg)
    state.phase = Phase.AWAIT_NMAP_OK


def _ask_gobuster() -> None:
    url = f"http://{state.target.host}:{state.port_for_gob}"
    msg = (
        f"Shall I proceed with a Gobuster directory scan on `[ {url} ]` (port {state.port_for_gob})?"
    )
    _log_assistant(msg)
    state.phase = Phase.AWAIT_GOB_OK


def _do_nmap() -> None:
    console.print("[cyan]Running Nmap…[/]")
    result = nmap_scan.scan(state.target)
    console.print_json(data=result.data)

    # Feed results to LLM
    history.append({"role": "user", "content": json.dumps(result.data, indent=2)})
    llm_reply = chat(history, "Here are the Nmap results above.", SYS_PROMPT)
    _log_assistant(llm_reply)

    # Detect web ports and prompt for Gobuster
    http_ports = {
        p["port"]
        for h in result.data["hosts"]
        for p in h["ports"]
        if p["svc"] in ("http", "https")
    }
    if http_ports:
        state.port_for_gob = min(http_ports)  # pick first/lowest port for demo
        _ask_gobuster()
    else:
        state.phase = Phase.AWAIT_TARGET


def _do_gobuster() -> None:
    wordlist = "/usr/share/seclists/Discovery/Web-Content/alien.txt"
    console.print(f"[cyan]Running Gobuster on port {state.port_for_gob}…[/]")
    res = gob_scan.scan(state.target, state.port_for_gob, wordlist)
    console.print_json(data=res.data)

    history.append({"role": "user", "content": json.dumps(res.data, indent=2)})
    llm_reply = chat(history, "Here are the Gobuster results above.", SYS_PROMPT)
    _log_assistant(llm_reply)

    state.phase = Phase.AWAIT_TARGET

# ─────────────────────────────────────────────────────────────────────────────
# Typer commands (one‑shot mode)
# ─────────────────────────────────────────────────────────────────────────────


@app.command()
def target(host: str) -> None:
    """Set / change target host (IP or domain)."""
    state.set_target(host)
    console.print(f"[bold green]Target locked → {host}[/]")
    _ask_nmap()


@app.command()
def yes() -> None:
    """Confirm the pending action (Nmap or Gobuster)."""
    if state.phase == Phase.AWAIT_NMAP_OK:
        _do_nmap()
    elif state.phase == Phase.AWAIT_GOB_OK:
        _do_gobuster()
    else:
        console.print("[yellow]Nothing pending confirmation.[/]")

# ─────────────────────────────────────────────────────────────────────────────
# Interactive REPL shell
# ─────────────────────────────────────────────────────────────────────────────


@app.command()
def shell() -> None:
    """Start an interactive Alien Recon session (type `exit` to quit)."""
    console.print("[green]Alien Recon shell — type 'exit' or Ctrl‑D to quit[/]")

    while True:
        try:
            line = Prompt.ask("[bold cyan]recon[/]")
            if line.strip() in {"exit", "quit"}:
                break
            args = shlex.split(line)
            try:
                app(args, standalone_mode=False)
            except SystemExit:
                pass  # suppress Typer's SystemExit so the loop continues
        except (EOFError, KeyboardInterrupt):
            break
        except BadParameter as exc:
            console.print(f"[red]{exc}[/]")


# ─────────────────────────────────────────────────────────────────────────────
# python -m alienrecon.cli entry‑point fallback
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app()

