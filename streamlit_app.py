import streamlit as st
import pandas as pd
import plotly.express as px

from modules.telemetry_parser import parse_logs, summarize_artifacts
from modules.llm_reasoner import reason
from modules.vt_enricher import precision_for_iocs
from modules.containment_engine import gate

st.set_page_config(page_title="PHP2Shell Detection-to-Defense Pipeline", layout="wide")
st.title("PHP2Shell Detection-to-Defense Pipeline")
st.caption("Layer 1: DeepSeek explainability · Layer 2: VirusTotal fusion · Layer 3: Policy-gated containment")

tab1, tab2, tab3 = st.tabs(["1. Telemetry & Explanation", "2. Intelligence Enrichment", "3. Containment Recommendation"])

# ---------- Tab 1 ----------
with tab1:
    st.subheader("Paste PHP/Apache/WAF log lines")
    log_text = st.text_area("Log input", height=220, placeholder="Paste log lines here...")
    if st.button("Extract & Explain", key="btn_t1"):
        artifacts = parse_logs(log_text)
        st.write("**Extracted artifacts**")
        st.dataframe(pd.DataFrame(artifacts), use_container_width=True)
        st.write("**Artifact summary**")
        st.json(summarize_artifacts(artifacts))

        if artifacts:
            with st.spinner("DeepSeek reasoning..."):
                explanation = reason(artifacts)
            st.session_state["explanation"] = explanation
            st.session_state["artifacts"] = artifacts
            st.write("**Validated explanation**")
            st.json(explanation)
        else:
            st.warning("No artifacts extracted. Check log format.")

# ---------- Tab 2 ----------
with tab2:
    st.subheader("Advisory IOC enrichment via VirusTotal")
    ioc_text = st.text_area("IOCs (one per line: IP / domain / hash)", height=160)
    if st.button("Enrich & Score", key="btn_t2"):
        iocs = [l.strip() for l in ioc_text.splitlines() if l.strip()]
        if not iocs:
            st.warning("No IOCs provided.")
        else:
            with st.spinner("Querying VirusTotal (rate-limited)..."):
                result = precision_for_iocs(iocs)
            st.session_state["intelligence"] = result
            st.write(f"**Precision:** {result['precision']:.2f}  ({result['malicious']}/{result['total']})")
            df = pd.DataFrame(result["details"])
            st.dataframe(df, use_container_width=True)
            if "malicious" in df.columns:
                fig = px.bar(df, x="ioc", y="malicious", title="Malicious detections per IOC")
                st.plotly_chart(fig, use_container_width=True)

# ---------- Tab 3 ----------
with tab3:
    st.subheader("Policy-gated containment recommendation")
    explanation = st.session_state.get("explanation")
    intelligence = st.session_state.get("intelligence", {"precision": 0.0})

    if not explanation:
        st.info("Run Tab 1 first to generate an explanation.")
    else:
        decision = gate(explanation, intelligence)
        st.write("**Gate evaluation**")
        st.json({k: decision[k] for k in ("evidence_ok", "confidence_ok", "intelligence_ok", "rationale")})

        st.write("**Allowed actions (benchmark-validated)**")
        if decision["allowed_actions"]:
            rows = [{"action": a, **decision["benchmark"].get(a, {})} for a in decision["allowed_actions"]]
            st.dataframe(pd.DataFrame(rows), use_container_width=True)
        else:
            st.warning("No actions passed the gate. Escalate to human analyst.")