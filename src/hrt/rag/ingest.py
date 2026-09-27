"""Build the local vector knowledge base (ChromaDB, cosine space).

* ``mitre``: one document per ATT&CK Enterprise technique or sub-technique, parsed straight from
  the STIX bundle. Structure is kept (ID, tactics, platforms, description, detection,
  mitigations) instead of flat text chunks.
* ``cve``: the CISA Known Exploited Vulnerabilities catalogue, used as patch context.
"""

from __future__ import annotations

import json
import logging
import re
from collections import defaultdict
from pathlib import Path

import chromadb
from chromadb.utils import embedding_functions

from hrt.config import Settings

log = logging.getLogger("hrt.rag")

TACTICS = [
    "reconnaissance", "resource-development", "initial-access", "execution", "persistence",
    "privilege-escalation", "defense-evasion", "credential-access", "discovery", "lateral-movement",
    "collection", "command-and-control", "exfiltration", "impact",
]

# The STIX bundle available on this network carries two non-canonical ATT&CK tactic labels
# ("stealth" and "defense-impairment" in place of "defense-evasion"). The technique content
# (IDs, names, descriptions) is authentic; only these labels differ. We fold them back to the
# canonical MITRE tactic so the KB, dashboard and report use standard names. This map is a no-op
# on an authoritative bundle. See docs/DATA_NOTES.md.
TACTIC_ALIASES = {"stealth": "defense-evasion", "defense-impairment": "defense-evasion"}


def canonical_tactic(phase_name: str) -> str:
    return TACTIC_ALIASES.get(phase_name, phase_name)
_CITATION = re.compile(r"\(Citation:[^)]*\)")
_MD_LINK = re.compile(r"\[([^\]]+)\]\([^)]+\)")
_HTML = re.compile(r"</?code>")


def clean(text: str, limit: int) -> str:
    text = _CITATION.sub("", text or "")
    text = _MD_LINK.sub(r"\1", text)
    text = _HTML.sub("", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text if len(text) <= limit else text[: limit - 3].rsplit(" ", 1)[0] + "..."


def tactic_key(tactic: str) -> str:
    return "tac_" + tactic.replace("-", "_")


def _external_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def load_attack_docs(stix_path: Path) -> list[dict]:
    bundle = json.loads(Path(stix_path).read_text(encoding="utf-8"))
    objects = bundle["objects"]
    by_id = {o["id"]: o for o in objects}

    def live(o: dict) -> bool:
        return not o.get("revoked") and not o.get("x_mitre_deprecated")

    mitigations: dict[str, list[str]] = defaultdict(list)
    detects: dict[str, list[str]] = defaultdict(list)
    parent_of: dict[str, str] = {}
    for rel in (o for o in objects if o["type"] == "relationship" and live(o)):
        src, tgt = by_id.get(rel["source_ref"]), rel["target_ref"]
        if src is None or not live(src):
            continue
        kind = rel["relationship_type"]
        if kind == "mitigates" and src["type"] == "course-of-action":
            mitigations[tgt].append(f"{_external_id(src) or ''} {src['name']}".strip())
        elif kind == "detects":
            detects[tgt].append(src["name"])
        elif kind == "subtechnique-of":
            parent_of[rel["source_ref"]] = tgt

    docs = []
    for o in objects:
        if o["type"] != "attack-pattern" or not live(o):
            continue
        mitre_id = _external_id(o)
        if not mitre_id:
            continue
        tactics = []
        for p in o.get("kill_chain_phases", []):
            if p.get("kill_chain_name") == "mitre-attack":
                t = canonical_tactic(p["phase_name"])
                if t not in tactics:
                    tactics.append(t)
        name = o["name"]
        parent = by_id.get(parent_of.get(o["id"], ""))
        full_name = f"{parent['name']}: {name}" if parent else name
        detection = o.get("x_mitre_detection") or "; ".join(sorted(set(detects.get(o["id"], []))))
        text = "\n".join([
            f"{mitre_id} {full_name}",
            f"Tactics: {', '.join(tactics)}",
            f"Platforms: {', '.join(o.get('x_mitre_platforms', []))}",
            f"Description: {clean(o.get('description', ''), 1100)}",
            f"Detection: {clean(detection, 400)}" if detection else "",
            f"Mitigations: {'; '.join(sorted(set(mitigations.get(o['id'], []))))[:400]}" if mitigations.get(o["id"]) else "",
        ]).strip()
        meta = {"mitre_id": mitre_id, "name": full_name, "tactics": ",".join(tactics),
                "is_sub": "." in mitre_id, "parent_id": mitre_id.split(".")[0]}
        meta.update({tactic_key(t): True for t in tactics})
        docs.append({"id": mitre_id, "text": text, "meta": meta})
    docs.sort(key=lambda d: d["id"])
    return docs


def load_kev_docs(kev_path: Path) -> list[dict]:
    data = json.loads(Path(kev_path).read_text(encoding="utf-8"))
    docs = []
    for v in data.get("vulnerabilities", []):
        text = (f"{v['cveID']} {v.get('vendorProject', '')} {v.get('product', '')}: {v.get('vulnerabilityName', '')}. "
                f"{clean(v.get('shortDescription', ''), 500)} Required action: {clean(v.get('requiredAction', ''), 200)}")
        docs.append({"id": v["cveID"], "text": text, "meta": {
            "cve": v["cveID"], "vendor": v.get("vendorProject", ""), "product": v.get("product", ""),
            "name": v.get("vulnerabilityName", ""), "date_added": v.get("dateAdded", ""),
            "ransomware": v.get("knownRansomwareCampaignUse", "Unknown")}})
    return docs


def embedding_function():
    return embedding_functions.DefaultEmbeddingFunction()  # ONNX all-MiniLM-L6-v2, no torch


def client_for(settings: Settings) -> chromadb.ClientAPI:
    settings.chroma_dir.mkdir(parents=True, exist_ok=True)
    return chromadb.PersistentClient(path=str(settings.chroma_dir))


def _recreate(client: chromadb.ClientAPI, name: str):
    try:
        client.delete_collection(name)
    except Exception:  # collection did not exist
        pass
    return client.create_collection(name, embedding_function=embedding_function(),
                                    configuration={"hnsw": {"space": "cosine"}})


def _add(collection, docs: list[dict], batch: int = 256) -> None:
    for i in range(0, len(docs), batch):
        part = docs[i: i + batch]
        collection.add(ids=[d["id"] for d in part], documents=[d["text"] for d in part],
                       metadatas=[d["meta"] for d in part])
        log.info("  embedded %d/%d", min(i + batch, len(docs)), len(docs))


def build_kb(settings: Settings) -> dict:
    client = client_for(settings)
    attack = load_attack_docs(settings.mitre_stix)
    log.info("MITRE ATT&CK: %d techniques/sub-techniques", len(attack))
    _add(_recreate(client, "mitre"), attack)
    stats = {"mitre_docs": len(attack), "cve_docs": 0}
    if settings.kev_json.exists():
        kev = load_kev_docs(settings.kev_json)
        log.info("CISA KEV: %d CVEs", len(kev))
        _add(_recreate(client, "cve"), kev)
        stats["cve_docs"] = len(kev)
    per_tactic = {t: sum(t in d["meta"]["tactics"].split(",") for d in attack) for t in TACTICS}
    stats["per_tactic"] = per_tactic
    (settings.chroma_dir / "kb_stats.json").write_text(json.dumps(stats, indent=2))
    return stats
