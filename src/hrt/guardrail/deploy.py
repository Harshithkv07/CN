"""Gated deployment to the lab firewall (the victim container's netfilter tables).

Only a rule that has passed all four guardrail stages and been approved (by an analyst, or by
auto-deploy in benchmark mode) reaches this module. It runs as a pre-validated argv, with no shell.
"""

from __future__ import annotations

from hrt.config import Settings
from hrt.dockerutil import get_client


class LabFirewall:
    def __init__(self, settings: Settings):
        self.name = settings.victim_container
        self._client = None

    @property
    def container(self):
        if self._client is None:
            self._client = get_client()
        return self._client.containers.get(self.name)

    def apply(self, argv: list[str]) -> tuple[bool, str]:
        if not argv or argv[0] != "iptables":
            return False, "refusing to run a non-iptables command"
        res = self.container.exec_run(argv, stdout=True, stderr=True)
        return res.exit_code == 0, res.output.decode(errors="replace").strip()

    def rules(self) -> list[str]:
        res = self.container.exec_run(["iptables", "-S"])
        return res.output.decode(errors="replace").splitlines() if res.exit_code == 0 else []

    def reset(self) -> tuple[bool, str]:
        res = self.container.exec_run(["iptables-restore", "/etc/hrt/baseline.rules"])
        return res.exit_code == 0, res.output.decode(errors="replace").strip()
