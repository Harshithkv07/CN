"""Stage 4: kernel-level verification in an ephemeral Docker sandbox.

The candidate rule is merged into the firewall's current ruleset and handed to a throwaway
Alpine container that has no network, a read-only root filesystem and only NET_ADMIN. Inside it,
``iptables-restore --test`` does a dry run and the ruleset is then really committed into the
container's private netfilter tables. The rule is only accepted if the Linux exit code is 0.

The ruleset goes in base64-encoded through an environment variable and the entrypoint is fixed,
so model output is never interpolated into a shell command line (the old code did exactly that
with ``sh -c``).
"""

from __future__ import annotations

import base64
import time

from docker.errors import DockerException, ImageNotFound

from hrt.config import Settings
from hrt.dockerutil import get_client
from hrt.models import GuardrailCheck


def build_restore(baseline_text: str, extra_lines: list[str]) -> str:
    """Insert rules into the *filter table of an iptables-restore document, just before its COMMIT."""
    lines = baseline_text.strip().splitlines()
    out, in_filter, done = [], False, False
    for line in lines:
        if line.strip() == "*filter":
            in_filter = True
        if in_filter and line.strip() == "COMMIT" and not done:
            out.extend(extra_lines)
            done, in_filter = True, False
        out.append(line)
    if not done:
        out = ["*filter", ":INPUT ACCEPT [0:0]", ":FORWARD ACCEPT [0:0]", ":OUTPUT ACCEPT [0:0]", *extra_lines, "COMMIT"]
    return "\n".join(out) + "\n"


class KernelSandbox:
    def __init__(self, settings: Settings):
        self.image = settings.sandbox_image
        self._client = None

    @property
    def client(self):
        if self._client is None:
            self._client = get_client()
        return self._client

    def available(self) -> bool:
        try:
            self.client.ping()
            self.client.images.get(self.image)
            return True
        except (DockerException, ImageNotFound):
            return False

    def verify(self, restore_text: str) -> GuardrailCheck:
        t0 = time.perf_counter()
        payload = base64.b64encode(restore_text.encode()).decode()
        try:
            container = self.client.containers.run(
                self.image, detach=True, environment={"RULESET_B64": payload}, network_mode="none",
                cap_drop=["ALL"], cap_add=["NET_ADMIN", "NET_RAW"], read_only=True,
                tmpfs={"/tmp": "size=1m", "/run": "size=1m"}, mem_limit="64m", pids_limit=64,
                labels={"hrt": "sandbox"})
        except DockerException as exc:
            return GuardrailCheck(stage="kernel", passed=False, retryable=False,
                                  detail=f"sandbox unavailable: {exc}", elapsed_ms=(time.perf_counter() - t0) * 1e3)
        try:
            code = container.wait(timeout=60)["StatusCode"]
            out = container.logs(stdout=True, stderr=False).decode(errors="replace").strip()
            err = container.logs(stdout=False, stderr=True).decode(errors="replace").strip()
        finally:
            container.remove(force=True)
        elapsed = (time.perf_counter() - t0) * 1e3
        if code == 0:
            loaded = [ln for ln in out.splitlines() if ln.startswith(("-A", "-I"))]
            return GuardrailCheck(stage="kernel", passed=True, elapsed_ms=elapsed,
                                  detail=f"iptables-restore --test and commit exited 0; {len(loaded)} rules loaded in isolated netns")
        return GuardrailCheck(stage="kernel", passed=False, elapsed_ms=elapsed,
                              detail=f"exit code {code}: {err or out or 'no output'}"[:600])
