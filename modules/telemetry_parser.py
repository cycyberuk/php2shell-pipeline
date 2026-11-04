"""
Layer 1a: Deterministic evidence extraction.
Converts raw log lines into structured artifacts before any LLM invocation.
"""
import re
import json
from datetime import datetime
from typing import List, Dict, Any

PATTERNS = {
    # --- Existing PHP2Shell indicators ---
    "multipart_boundary": re.compile(r"boundary=([A-Za-z0-9_\-]{8,70})"),
    "upload_progress": re.compile(r"PHP_SESSION_UPLOAD_PROGRESS"),
    "phpsessid": re.compile(r"PHPSESSID=([A-Za-z0-9]{20,64})"),
    "oom_event": re.compile(r"(Allowed memory size of \d+ bytes exhausted|Out of memory)", re.I),
    "segfault": re.compile(r"(segfault|signal 11|SIGSEGV)", re.I),
    "worker_crash": re.compile(r"(exited on signal|child \d+ exited)", re.I),
    "shell_spawn": re.compile(r"(/bin/sh|/bin/bash|cmd\.exe|powershell)", re.I),
    "outbound": re.compile(r"(wget|curl|nc |ncat|/dev/tcp/)", re.I),
    "fatal_backtrace": re.compile(r"(Fatal error.*backtrace|fatal_error_backtraces)", re.I),

    # --- New context indicators (needed for attribution) ---
    "php_version": re.compile(r"PHP\s+(\d+\.\d+\.\d+)"),
    "server_api": re.compile(r"Server API:\s*([A-Za-z0-9/_\-]+)"),
    "upload_progress_enabled": re.compile(r"session\.upload_progress\.enabled\s*=\s*(On|Off)", re.I),
    "memory_limit": re.compile(r"memory_limit\s*=\s*(-?\d+[KMG]?)", re.I),
    "fpm_worker": re.compile(r"(php-fpm|fpm/fastcgi|pm\.max_requests)", re.I),
    "mod_php": re.compile(r"(mod_php|apache2handler)", re.I),
}

def _extract_timestamp(line: str) -> str:
    m = re.search(r"\[([^\]]+)\]", line)
    if m:
        return m.group(1)
    return datetime.utcnow().isoformat() + "Z"

def _classify(line: str) -> List[Dict[str, Any]]:
    artifacts = []
    ts = _extract_timestamp(line)
    for artifact_type, pattern in PATTERNS.items():
        for match in pattern.finditer(line):
            # If the pattern has a group, use group(1); otherwise group(0)
            if match.lastindex and match.lastindex >= 1:
                raw = match.group(0)
                value = match.group(1)
            else:
                raw = match.group(0)
                value = raw.strip()

            # Confidence: high for explicit config/version, lower for behavioral hints
            high_conf = {
                "upload_progress", "oom_event", "fatal_backtrace",
                "php_version", "server_api", "upload_progress_enabled",
                "memory_limit", "fpm_worker", "mod_php",
            }
            confidence = 1.0 if artifact_type in high_conf else 0.8

            artifacts.append({
                "source": "log",
                "timestamp": ts,
                "artifact_type": artifact_type,
                "raw_value": raw,
                "normalized_value": value,
                "confidence": confidence,
            })
    return artifacts

def parse_logs(log_text: str) -> List[Dict[str, Any]]:
    artifacts: List[Dict[str, Any]] = []
    for line in log_text.splitlines():
        if not line.strip():
            continue
        artifacts.extend(_classify(line))

    # Deduplicate on (artifact_type, normalized_value, timestamp)
    seen = set()
    unique = []
    for a in artifacts:
        key = (a["artifact_type"], a["normalized_value"], a["timestamp"])
        if key not in seen:
            seen.add(key)
            unique.append(a)
    return unique

def summarize_artifacts(artifacts: List[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for a in artifacts:
        counts[a["artifact_type"]] = counts.get(a["artifact_type"], 0) + 1
    return counts

if __name__ == "__main__":
    sample = open("data/sample_logs/cve_2026_109619_sample.log").read()
    arts = parse_logs(sample)
    print(json.dumps(arts, indent=2))
    print("Summary:", summarize_artifacts(arts))