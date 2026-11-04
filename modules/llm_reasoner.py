"""
Layer 1b: Evidence-grounded LLM reasoning via DeepSeek.
The LLM sees ONLY extracted artifacts; post-generation validation rejects
claims without a traceable artifact citation.
"""
import json
import os
from typing import List, Dict, Any
from openai import OpenAI

SYSTEM_PROMPT = """You are a PHP2Shell detection analyst. You may only reason over the
structured artifacts provided. Do NOT invent indicators.

You have explicit knowledge of the following facts:

CVE-2026-109618 (OOM corruption):
- Trigger: out-of-memory event during multipart request processing
- Affected versions: PHP 5.4.0 through 8.5.11
- Fixed in: PHP 8.5.12, 8.4.27, 8.3.36, 8.2.35
- Key artifacts: oom_event, multipart_boundary, segfault, worker_crash

CVE-2026-109619 (stale global state UAF):
- Trigger: session upload progress OR fatal error backtrace, on same worker across two requests
- Affected versions: PHP 5.4.0 through 8.5.11
- Fixed in: PHP 8.5.12, 8.4.27, 8.3.36, 8.2.35
- Key artifacts: upload_progress, upload_progress_enabled=On, phpsessid, server_api (FPM or mod_php), oom_event, outbound, shell_spawn

Attribution rules:
1. If php_version is present and is LESS THAN the fixed version for its branch AND
   at least two key artifacts for a CVE are present, attribute that CVE.
2. If php_version is present and is EQUAL TO OR GREATER THAN the fixed version,
   attribute "insufficient_evidence" with explanation "patched version".
3. If php_version is absent, attribute "insufficient_evidence".
4. If both CVE artifact sets are present and version is vulnerable, attribute "both".
5. Always cite the artifact indices that support the attribution.

Return STRICT JSON with keys:
- cve_attribution: "CVE-2026-109618" | "CVE-2026-109619" | "both" | "insufficient_evidence"
- confidence: float 0..1
- evidence_citations: list of artifact indices (integers)
- explanation: string referencing the version comparison
- recommended_action: string
"""

def get_client() -> OpenAI:
    api_key = os.environ.get("DEEPSEEK_API_KEY") or _streamlit_secret("DEEPSEEK_API_KEY")
    if not api_key:
        raise RuntimeError("DEEPSEEK_API_KEY not set")
    return OpenAI(api_key=api_key, base_url="https://api.deepseek.com")

def _streamlit_secret(key: str):
    try:
        import streamlit as st
        return st.secrets.get(key)
    except Exception:
        return None

def reason(artifacts: List[Dict[str, Any]], temperature: float = 0.3) -> Dict[str, Any]:
    if not artifacts:
        return {
            "cve_attribution": "insufficient_evidence",
            "confidence": 0.0,
            "evidence_citations": [],
            "explanation": "No artifacts extracted from telemetry.",
            "recommended_action": "Collect additional telemetry.",
        }

    client = get_client()
    payload = [
        {"index": i, "type": a["artifact_type"], "value": a["normalized_value"], "ts": a["timestamp"]}
        for i, a in enumerate(artifacts)
    ]

    resp = client.chat.completions.create(
        model="deepseek-chat",
        temperature=temperature,
        response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": "Artifacts:\n" + json.dumps(payload, indent=2)},
        ],
    )
    content = resp.choices[0].message.content
    try:
        parsed = json.loads(content)
    except json.JSONDecodeError:
        return {
            "cve_attribution": "insufficient_evidence",
            "confidence": 0.0,
            "evidence_citations": [],
            "explanation": "LLM returned non-JSON; manual review required.",
            "recommended_action": "Escalate to human analyst.",
        }
    return validate_explanation(parsed, artifacts)

def validate_explanation(parsed: Dict[str, Any], artifacts: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Reject citations that don't map to real artifact indices."""
    valid_indices = {i for i in range(len(artifacts))}
    cited = [i for i in parsed.get("evidence_citations", []) if i in valid_indices]
    parsed["evidence_citations"] = cited
    if parsed.get("cve_attribution") not in ("insufficient_evidence",) and not cited:
        parsed["cve_attribution"] = "insufficient_evidence"
        parsed["confidence"] = min(parsed.get("confidence", 0.0), 0.2)
        parsed["explanation"] = "Attribution rejected: no valid evidence citations."
    return parsed