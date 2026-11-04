"""
Layer 2: VirusTotal API v3 enrichment with local caching and backoff.
"""
import os
import time
import sqlite3
import requests
from typing import Dict, Any, List

VT_BASE = "https://www.virustotal.com/api/v3"
CACHE_DB = "data/vt_cache.sqlite"
RATE_LIMIT_SECONDS = 15  # free tier: 4 req/min -> 15s spacing

def _api_key() -> str:
    key = os.environ.get("VIRUSTOTAL_API_KEY") or _streamlit_secret("VIRUSTOTAL_API_KEY")
    if not key:
        raise RuntimeError("VIRUSTOTAL_API_KEY not set")
    return key

def _streamlit_secret(key: str):
    try:
        import streamlit as st
        return st.secrets.get(key)
    except Exception:
        return None

def _init_cache():
    os.makedirs("data", exist_ok=True)
    conn = sqlite3.connect(CACHE_DB)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS vt_cache (
            ioc TEXT PRIMARY KEY,
            ioc_type TEXT,
            malicious INTEGER,
            suspicious INTEGER,
            undetected INTEGER,
            harmless INTEGER,
            fetched_at REAL
        )
    """)
    conn.commit()
    return conn

def _cache_get(conn, ioc: str):
    row = conn.execute(
        "SELECT malicious, suspicious, undetected, harmless FROM vt_cache WHERE ioc=?",
        (ioc,),
    ).fetchone()
    return row

def _cache_put(conn, ioc: str, ioc_type: str, stats: Dict[str, int]):
    conn.execute(
        "INSERT OR REPLACE INTO vt_cache VALUES (?, ?, ?, ?, ?, ?, ?)",
        (ioc, ioc_type, stats["malicious"], stats["suspicious"],
         stats["undetected"], stats["harmless"], time.time()),
    )
    conn.commit()

def _endpoint(ioc: str) -> str:
    if _looks_like_ip(ioc):
        return f"{VT_BASE}/ip_addresses/{ioc}"
    if _looks_like_hash(ioc):
        return f"{VT_BASE}/files/{ioc}"
    return f"{VT_BASE}/domains/{ioc}"

def _looks_like_ip(s: str) -> bool:
    parts = s.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)

def _looks_like_hash(s: str) -> bool:
    return len(s) in (32, 40, 64) and all(c in "0123456789abcdefABCDEF" for c in s)

def enrich(ioc: str) -> Dict[str, Any]:
    ioc = ioc.strip()
    conn = _init_cache()
    cached = _cache_get(conn, ioc)
    if cached:
        return {"ioc": ioc, "cached": True,
                "malicious": cached[0], "suspicious": cached[1],
                "undetected": cached[2], "harmless": cached[3]}

    headers = {"x-apikey": _api_key()}
    url = _endpoint(ioc)
    for attempt in range(4):
        resp = requests.get(url, headers=headers, timeout=30)
        if resp.status_code == 200:
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            result = {
                "ioc": ioc,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
                "harmless": stats.get("harmless", 0),
            }
            _cache_put(conn, ioc, "unknown", result)
            time.sleep(RATE_LIMIT_SECONDS)
            return result
        if resp.status_code == 429:
            time.sleep(RATE_LIMIT_SECONDS * (2 ** attempt))
            continue
        return {"ioc": ioc, "error": f"HTTP {resp.status_code}"}
    return {"ioc": ioc, "error": "rate_limited"}

def precision_for_iocs(iocs: List[str]) -> Dict[str, Any]:
    """Return precision = malicious/total for a list of IOCs."""
    total = 0
    malicious = 0
    details = []
    for ioc in iocs:
        r = enrich(ioc)
        details.append(r)
        if "error" not in r:
            total += 1
            if r.get("malicious", 0) >= 1:
                malicious += 1
    return {
        "total": total,
        "malicious": malicious,
        "precision": (malicious / total) if total else 0.0,
        "details": details,
    }