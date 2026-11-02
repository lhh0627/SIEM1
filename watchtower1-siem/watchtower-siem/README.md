# Watchtower SIEM: analyst console for the AI-Assisted Tier-1 SOC Triage Assistant

    docker compose up --build        # UI + API: http://localhost:8000   syslog: udp/5514
    # no Docker:  pip install -r requirements.txt && uvicorn app:app --host 0.0.0.0 --port 8000

Set SIEM_API_KEY in docker-compose.yml (the UI asks for it once per session).

## Architecture
    Wazuh manager --(integratord, tools/custom-watchtower)--> POST /api/ingest   (Wazuh mapper, dedup by alert id)
    Triage service (AI team) --> GET /api/alerts, GET /api/alerts/{id}/context, POST /api/alerts/{id}/report
    Analyst --> Triage queue: approve / reject, label ground truth --> Evaluation tab / GET /api/eval

## Connect Wazuh
1. Copy tools/custom-watchtower to /var/ossec/integrations/ on the Wazuh manager; chmod 750; chown root:wazuh.
2. Add tools/ossec-snippet.xml to ossec.conf (set the host and api_key), restart wazuh-manager.
3. Backfill or replay stored alerts (safe to repeat): python tools/forward_alerts.py /var/ossec/logs/alerts/alerts.json --url http://HOST:8000 --key KEY
Check the integration against your Wazuh version's custom-integration docs.

## Try it without Wazuh
    python tools/forward_alerts.py tools/sample_alerts.ndjson
    python tools/triage_stub.py --once          # placeholder agent = Wazuh-level baseline
Open "Triage queue", click an alert, approve or reject, add labels (two labelers + "adjudicated" to resolve disputes), then open "Evaluation".

## Triage API contract (what the AI team implements)
POST /api/alerts/{id}/report  {verdict: true_positive|false_positive|escalate, technique, confidence, summary,
evidence:[{id,text}], recommended_action, model, latency_ms, cost_usd, valid, validator_notes}
See tools/triage_stub.py: llm_triage() is the placeholder to replace, validate() is the starting point for the validator.

## Notes
- WAZUH_DETECT=0 (default): Watchtower rules do not fire on Wazuh alerts, so Wazuh stays the only detector.
- Approving a report only writes an audit entry and a "simulated containment" record. Nothing touches a host.
- Baseline 1 maps Wazuh level to a verdict (>=10 true positive, 7-9 escalate, else false positive); change baseline() in app.py if your proposal defines it differently.
- The Evaluation tab covers accuracy, baseline accuracy, recall, validator pass rate, latency, cost, Cohen's kappa. The no-enrichment LLM baseline and the human-analyst timing study still need your own runs.
- Limits: SQLite (fine for lab scale), no SSO or enforced roles, no TLS (use a reverse proxy), the users screen is a demo.
