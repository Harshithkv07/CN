"""Hierarchical retrieval over the ATT&CK vector store.

Level 1 (deterministic): Tier-1 rule hits select candidate tactics.
Level 2 (semantic): cosine-similarity search restricted to techniques in those tactics.
The search-space reduction is measured per query and reported (it isn't assumed).
"""

from __future__ import annotations

import time
from functools import lru_cache

from hrt.config import Settings
from hrt.models import Alert, RetrievalTrace, RetrievedDoc
from hrt.rag.ingest import client_for, embedding_function, tactic_key
from hrt.rag.query import behaviour_query, candidate_tactics, cve_query


def tactic_filter(tactics: list[str]) -> dict | None:
    if not tactics:
        return None
    clauses = [{tactic_key(t): True} for t in tactics]
    return clauses[0] if len(clauses) == 1 else {"$or": clauses}


class Retriever:
    def __init__(self, settings: Settings):
        client = client_for(settings)
        ef = embedding_function()
        self.mitre = client.get_collection("mitre", embedding_function=ef)
        try:
            self.cve = client.get_collection("cve", embedding_function=ef)
        except Exception:
            self.cve = None
        self.total = self.mitre.count()
        meta = self.mitre.get(include=["metadatas"])
        self.catalog = {m["mitre_id"]: m for m in meta["metadatas"]}
        self._candidates = lru_cache(maxsize=64)(self._count_candidates)

    def known(self, mitre_id: str) -> bool:
        return mitre_id in self.catalog

    def name_of(self, mitre_id: str) -> str:
        return self.catalog.get(mitre_id, {}).get("name", "")

    def _count_candidates(self, tactics: tuple[str, ...]) -> int:
        where = tactic_filter(list(tactics))
        if where is None:
            return self.total
        return len(self.mitre.get(where=where, include=[])["ids"])

    def search(self, query: str, tactics: list[str], top_k: int) -> tuple[list[RetrievedDoc], list[str]]:
        res = self.mitre.query(query_texts=[query], n_results=top_k, where=tactic_filter(tactics),
                               include=["metadatas", "documents", "distances"])
        docs, texts = [], []
        for meta, text, dist in zip(res["metadatas"][0], res["documents"][0], res["distances"][0]):
            docs.append(RetrievedDoc(mitre_id=meta["mitre_id"], name=meta["name"],
                                     tactics=meta["tactics"].split(","), score=round(1.0 - dist, 4)))
            texts.append(text)
        return docs, texts

    def retrieve(self, alert: Alert, top_k: int = 5, hierarchical: bool = True) -> tuple[RetrievalTrace, list[str]]:
        t0 = time.perf_counter()
        query = behaviour_query(alert)
        tactics = candidate_tactics(alert) if hierarchical else []
        docs, texts = self.search(query, tactics, top_k)
        candidates = self._candidates(tuple(tactics))
        cves: list[dict[str, str]] = []
        if self.cve is not None:
            r = self.cve.query(query_texts=[cve_query(alert)], n_results=2, include=["metadatas", "documents"])
            for meta, text in zip(r["metadatas"][0], r["documents"][0]):
                cves.append({"cve": meta["cve"], "product": f"{meta['vendor']} {meta['product']}", "text": text[:300]})
        trace = RetrievalTrace(
            query=query, candidate_tactics=tactics, candidates=candidates, total_docs=self.total,
            search_space_reduction=round(1 - candidates / self.total, 4) if self.total else 0.0,
            docs=docs, cves=cves, seconds=round(time.perf_counter() - t0, 3))
        return trace, texts
