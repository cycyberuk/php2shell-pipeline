# PHP2Shell Detection-to-Defense Pipeline

Three-layer pipeline for CVE-2026-109618 / CVE-2026-109619.

## Run locally
1. `python -m venv .venv && source .venv/bin/activate`
2. `pip install -r requirements.txt`
3. Create `.streamlit/secrets.toml` with `DEEPSEEK_API_KEY` and `VIRUSTOTAL_API_KEY`
4. `streamlit run streamlit_app.py`

## Deploy to Streamlit Community Cloud
1. Push to GitHub (without `.streamlit/secrets.toml`)
2. Create app at share.streamlit.io, entrypoint `streamlit_app.py`
3. Paste secrets into the app's Secrets field
4. Python 3.12 is selected automatically