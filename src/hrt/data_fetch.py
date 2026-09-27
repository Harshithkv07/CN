"""Download the threat-intelligence corpora used by the RAG knowledge base."""

from __future__ import annotations

import httpx

from hrt.config import Settings

MITRE_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def _download(url: str, dest, label: str) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    print(f"[fetch] {label}: {url}")
    with httpx.stream("GET", url, timeout=120, follow_redirects=True) as r:
        r.raise_for_status()
        with open(dest, "wb") as fh:
            for chunk in r.iter_bytes(1 << 16):
                fh.write(chunk)
    print(f"[fetch] saved {dest} ({dest.stat().st_size / 1e6:.1f} MB)")


def fetch_mitre(settings: Settings) -> None:
    if settings.mitre_stix.exists():
        print(f"[fetch] MITRE STIX already present ({settings.mitre_stix.stat().st_size / 1e6:.1f} MB)")
        return
    _download(MITRE_URL, settings.mitre_stix, "MITRE ATT&CK Enterprise STIX")


def fetch_kev(settings: Settings) -> None:
    try:
        _download(KEV_URL, settings.kev_json, "CISA Known Exploited Vulnerabilities")
    except httpx.HTTPError as exc:
        print(f"[fetch] KEV download failed ({exc}); CVE collection will be skipped")
