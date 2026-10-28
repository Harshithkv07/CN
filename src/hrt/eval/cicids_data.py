"""Fetch CICIDS2018 flow data, normalise, stratified-sample, and keep only the small parquet.

The full "Processed Traffic Data" is ~1.3 GB and this build network delivers it at ~50 KB/s, so a
full download is infeasible here. Instead we stream each day's CSV in chunks and stop as soon as we
have gathered enough benign + attack flows (or hit a per-day byte cap). Documented in
docs/DATA_NOTES.md. On a fast link, raise the caps for the full dataset.
"""

from __future__ import annotations

import io
import logging
from collections import Counter
from pathlib import Path

import httpx
import pandas as pd

from hrt.config import Settings
from hrt.telemetry.cicids import normalise

log = logging.getLogger("hrt.eval.data")

BUCKET = "https://cse-cic-ids2018.s3.ca-central-1.amazonaws.com/Processed%20Traffic%20Data%20for%20ML%20Algorithms"
DAYS = {
    "wed-14-02": "Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv",   # FTP/SSH brute force
    "thu-15-02": "Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv",    # DoS GoldenEye / Slowloris
    "fri-16-02": "Friday-16-02-2018_TrafficForML_CICFlowMeter.csv",      # DoS Hulk / SlowHTTP
    "wed-21-02": "Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv",   # DDoS LOIC-UDP / HOIC
    "fri-02-03": "Friday-02-03-2018_TrafficForML_CICFlowMeter.csv",      # Bot
    "wed-28-02": "Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv",   # Infiltration
    "thu-01-03": "Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv",    # Infiltration
    "thu-22-02": "Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv",    # Brute Force -Web / -XSS, SQL Injection
    "fri-23-02": "Friday-23-02-2018_TrafficForML_CICFlowMeter.csv",      # Brute Force -Web / -XSS, SQL Injection
}
HARD_PARQUET = "cicids_hard.parquet"
# classes that the original 4-attack sample lacks: C2, post-exploitation, and web attacks whose flows look
# a lot like normal browsing, so the Tier-1 rules rarely fire for them
HARD_LABELS = ["Bot", "Infilteration", "DoS attacks-GoldenEye", "DoS attacks-Slowloris", "DoS attacks-SlowHTTPTest"]
SAMPLE_PARQUET = "cicids_sample.parquet"


def _file_size(url: str) -> int:
    r = httpx.head(url, timeout=30, follow_redirects=True)
    r.raise_for_status()
    return int(r.headers.get("content-length", 0))


def _fetch_header(url: str) -> str:
    r = httpx.get(url, headers={"Range": "bytes=0-4095"}, timeout=30, follow_redirects=True)
    return r.text.split("\n", 1)[0]


def _stream_until_enough(url: str, benign_target: int, attack_target: int, byte_cap: int,
                         chunk_mb: int = 4, start_byte: int = 0, header: str | None = None) -> pd.DataFrame:
    """Stream the CSV from `start_byte` (via HTTP Range, which skips earlier bytes without
    downloading them), parsing chunk-by-chunk, stopping once we have enough of each class."""
    carry = b""
    got_benign = got_attack = 0
    frames: list[pd.DataFrame] = []
    downloaded = 0
    first_block = True
    headers = {"Range": f"bytes={start_byte}-"} if start_byte else None
    with httpx.stream("GET", url, timeout=120, follow_redirects=True, headers=headers) as r:
        r.raise_for_status()
        for raw in r.iter_bytes(chunk_mb << 20):
            downloaded += len(raw)
            buf = carry + raw
            nl = buf.rfind(b"\n")
            if nl == -1:
                carry = buf
                continue
            block, carry = buf[: nl + 1], buf[nl + 1:]
            text = block.decode("utf-8", errors="replace")
            if first_block:
                first_block = False
                if header is None:                       # reading from byte 0: first line is the header
                    header, _, text = text.partition("\n")
                else:                                    # started mid-file: drop the partial first record
                    text = text.partition("\n")[2]
            if not text.strip():
                continue
            try:
                df = pd.read_csv(io.StringIO(header + "\n" + text), low_memory=False)
                norm = normalise(df)
            except Exception:
                continue
            if norm.empty:
                continue
            mal = norm["label"] != "Benign"
            frames.append(norm)
            got_attack += int(mal.sum())
            got_benign += int((~mal).sum())
            if (got_attack >= attack_target and got_benign >= benign_target) or downloaded >= byte_cap:
                break
    if not frames:
        return pd.DataFrame()
    out = pd.concat(frames, ignore_index=True)
    log.info("  streamed %.0f MB -> %d flows (%d attack, %d benign)", downloaded / 1e6, len(out), got_attack, got_benign)
    return out


# Targeted slices (day, start_fraction, cap_MB) located by probing where each attack/benign zone
# sits in the time-ordered files. Range seeks skip earlier bytes for free, so total download is
# only the sum of caps (~60 MB), not the full 1.3 GB. Tune caps up on a fast link.
SLICE_PLAN: list[tuple[str, float, int]] = [
    ("wed-14-02", 0.30, 16),   # FTP + SSH brute force
    ("wed-14-02", 0.62, 8),    # benign zone of the same day
    ("fri-16-02", 0.30, 16),   # DoS Hulk + SlowHTTPTest (well mixed with benign here)
    ("wed-21-02", 0.30, 14),   # DDoS HOIC
    ("wed-21-02", 0.62, 8),    # benign zone
]


def _clean_labels(df: pd.DataFrame) -> pd.DataFrame:
    from hrt.eval.labels import CIC_LABELS

    return df[df["label"].isin(CIC_LABELS)].reset_index(drop=True)


def _sample_group(df: pd.DataFrame, benign_cap: int, attack_cap: int, seed: int) -> pd.DataFrame:
    parts = []
    for label, grp in df.groupby("label"):
        cap = benign_cap if label == "Benign" else attack_cap
        parts.append(grp.sample(min(len(grp), cap), random_state=seed) if len(grp) > cap else grp)
    return pd.concat(parts, ignore_index=True)


def build_sample(settings: Settings, benign_cap: int = 15000, attack_per_class: int = 5000,
                 seed: int = 42, plan: list[tuple[str, float, int]] | None = None) -> Path:
    settings.cicids_dir.mkdir(parents=True, exist_ok=True)
    out = settings.cicids_dir / SAMPLE_PARQUET
    plan = plan or SLICE_PLAN
    sizes: dict[str, int] = {}
    headers: dict[str, str] = {}
    frames = []
    for day, frac, cap_mb in plan:
        url = f"{BUCKET}/{DAYS[day]}"
        try:
            if day not in sizes:
                sizes[day] = _file_size(url)
                headers[day] = _fetch_header(url)
            start = int(sizes[day] * frac)
            log.info("slice %s @%.0f%% (from %d MB, cap %d MB)", day, frac * 100, start // (1 << 20), cap_mb)
            df = _stream_until_enough(url, benign_target=10**9, attack_target=10**9,
                                      byte_cap=cap_mb << 20, start_byte=start, header=headers[day])
            if not df.empty:
                df["day"] = day
                frames.append(_clean_labels(df))
        except Exception as exc:
            log.warning("slice %s @%.2f failed: %s", day, frac, exc)
    if not frames:
        raise SystemExit("no CICIDS slices could be fetched (check network access to the AWS bucket)")
    combined = _clean_labels(pd.concat(frames, ignore_index=True)).drop_duplicates()
    sample = _sample_group(combined, benign_cap, attack_per_class, seed)
    sample.to_parquet(out, index=False)
    log.info("wrote %s (%d rows) class counts: %s", out, len(sample), dict(Counter(sample["label"])))
    return out


def load_sample(settings: Settings) -> pd.DataFrame:
    out = settings.cicids_dir / SAMPLE_PARQUET
    if not out.exists():
        raise SystemExit(f"{out} not found; run the triage evaluation which builds it, or call build_sample()")
    return pd.read_parquet(out)


# TEST-NET-2 addresses for synthesised agent incidents (documented as synthetic in the report)
SYNTH_ATTACKER = {
    "brute_force": "198.51.100.11", "dos": "198.51.100.21", "ddos": "198.51.100.31",
    "botnet": "198.51.100.41", "web_attack": "198.51.100.51", "recon": "198.51.100.61",
    "infiltration": "198.51.100.71",
}


# The day files are *not* time-ordered (rows are shuffled), so attack rows are spread through each file in
# proportion to how common they are. Rare classes (SQL injection, XSS: under 100 rows per file) would need most of
# the file; the classes below are common enough that one slice per file yields hundreds of rows.
HARD_PLAN: list[tuple[str, float, int]] = [
    ("fri-02-03", 0.50, 8),    # Bot (C2)
    ("thu-01-03", 0.45, 8),    # Infiltration (post-exploitation); this file is mostly attack rows
    ("wed-28-02", 0.40, 6),    # Infiltration
    ("thu-15-02", 0.30, 10),   # DoS GoldenEye and Slowloris
    ("fri-16-02", 0.55, 8),    # DoS SlowHTTPTest
]


def build_hard_sample(settings: Settings, per_class: int = 600, benign_cap: int = 3000, seed: int = 42,
                      plan: list[tuple[str, float, int]] | None = None) -> Path:
    """Stream one slice per planned day file and write ``cicids_hard.parquet``."""
    out = settings.cicids_dir / HARD_PARQUET
    settings.cicids_dir.mkdir(parents=True, exist_ok=True)
    frames = []
    for day, frac, cap_mb in plan or HARD_PLAN:
        url = f"{BUCKET}/{DAYS[day]}"
        try:
            size, header = _file_size(url), None
            header = _fetch_header(url)
            log.info("hard slice %s @%.0f%% (cap %d MB)", day, frac * 100, cap_mb)
            df = _stream_until_enough(url, 10**9, 10**9, byte_cap=cap_mb << 20, start_byte=int(size * frac), header=header)
            if not df.empty:
                df["day"] = day
                frames.append(_clean_labels(df))
                log.info("  labels: %s", dict(Counter(df["label"])))
        except Exception as exc:
            log.warning("slice %s failed: %s", day, exc)
    if not frames:
        raise SystemExit("no CICIDS slices could be fetched")
    combined = _clean_labels(pd.concat(frames, ignore_index=True)).drop_duplicates()
    sample = _sample_group(combined, benign_cap, per_class, seed)
    sample.to_parquet(out, index=False)
    log.info("wrote %s (%d rows) class counts: %s", out, len(sample), dict(Counter(sample["label"])))
    return out


def load_hard_sample(settings: Settings) -> pd.DataFrame:
    out = settings.cicids_dir / HARD_PARQUET
    if not out.exists():
        raise SystemExit(f"{out} not found; run `hrt fetch-hard`")
    return pd.read_parquet(out)
