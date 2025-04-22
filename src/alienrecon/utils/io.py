import shutil, subprocess, logging

log = logging.getLogger("alienrecon")


def tool_exists(name: str) -> bool:
    return shutil.which(name) is not None


def run_subprocess(cmd: list[str], timeout: int = 600) -> str:
    log.info("exec: %s", " ".join(cmd))
    res = subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout, check=False
    )
    if res.returncode != 0:
        log.warning("non‑zero exit (%d) stderr=%s", res.returncode, res.stderr.strip())
    return res.stdout

