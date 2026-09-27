"""A resilient Docker client factory.

`docker.from_env()` assumes the default `docker_engine` named pipe / unix socket. Docker Desktop
(especially a per-user install) may only expose `dockerDesktopLinuxEngine`. This tries the
environment first, then known Desktop endpoints, so the pipeline works across setups.
"""

from __future__ import annotations

import docker

_CANDIDATES = [
    "npipe:////./pipe/dockerDesktopLinuxEngine",  # Docker Desktop (Windows, incl. per-user)
    "npipe:////./pipe/docker_engine",             # classic Windows pipe
    "unix:///var/run/docker.sock",                # Linux / macOS
]

_client: docker.DockerClient | None = None


def get_client(timeout: int = 60) -> docker.DockerClient:
    global _client
    if _client is not None:
        return _client
    last: Exception | None = None
    try:
        c = docker.from_env(timeout=timeout)
        c.ping()
        _client = c
        return c
    except Exception as exc:  # fall through to explicit endpoints
        last = exc
    for url in _CANDIDATES:
        try:
            c = docker.DockerClient(base_url=url, timeout=timeout)
            c.ping()
            _client = c
            return c
        except Exception as exc:
            last = exc
    raise docker.errors.DockerException(f"could not connect to any Docker endpoint: {last}")
