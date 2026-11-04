"""
Layer 3: Policy-gated containment.
Actions are gated by evidence thresholds AND intelligence confidence AND benchmark validation.
"""
from typing import Dict, Any, List

# Benchmark table from the paper (Table 2 / Table 6)
BENCHMARK = {
    "disable_upload_progress": {"cve_618": 0.0, "cve_619": 0.72, "cost": "none"},
    "disable_fatal_backtrace": {"cve_618": 0.0, "cve_619": 0.60, "cost": "none"},
    "worker_isolation":        {"cve_618": 0.45, "cve_619": 0.89, "cost": "high"},
    "waf_multipart_block":     {"cve_618": 0.38, "cve_619": 0.41, "cost": "medium"},
    "patch_php":               {"cve_618": 1.0,  "cve_619": 1.0,  "cost": "maintenance"},
}

def gate(explanation: Dict[str, Any], intelligence: Dict[str, Any],
         min_confidence: float = 0.7) -> Dict[str, Any]:
    attribution = explanation.get("cve_attribution")
    conf = explanation.get("confidence", 0.0)
    intel_precision = intelligence.get("precision", 0.0)

    evidence_ok = attribution in ("CVE-2026-109618", "CVE-2026-109619", "both")
    confidence_ok = conf >= min_confidence
    intelligence_ok = intel_precision >= 0.5 or intel_precision == 0.0  # 0 = not run

    allowed_actions: List[str] = []
    if evidence_ok and confidence_ok:
        if attribution in ("CVE-2026-109619", "both"):
            allowed_actions.extend(["disable_upload_progress", "disable_fatal_backtrace", "worker_isolation"])
        if attribution in ("CVE-2026-109618", "both"):
            allowed_actions.extend(["worker_isolation", "waf_multipart_block"])
    # Patch is always allowed if evidence is credible
    if evidence_ok:
        allowed_actions.append("patch_php")

    return {
        "evidence_ok": evidence_ok,
        "confidence_ok": confidence_ok,
        "intelligence_ok": intelligence_ok,
        "allowed_actions": allowed_actions,
        "benchmark": {a: BENCHMARK[a] for a in allowed_actions if a in BENCHMARK},
        "rationale": _rationale(evidence_ok, confidence_ok, intelligence_ok, attribution),
    }

def _rationale(ev, cf, intel, attr) -> str:
    parts = []
    parts.append("evidence threshold met" if ev else "evidence threshold NOT met")
    parts.append("confidence threshold met" if cf else "confidence threshold NOT met")
    parts.append("intelligence confidence met" if intel else "intelligence confidence NOT met")
    return f"Attribution={attr}; " + "; ".join(parts)