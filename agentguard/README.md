# AgentGuard

A local prototype of a runtime security layer for multi-agent workflows. Every protected action passes through one interceptor that combines role permissions, mandatory policies, task relevance, a trained action classifier, and an Isolation Forest signal. The three local agents exchange actual findings and generate a Markdown report without external services.

## Run locally

From the repository root:

```powershell
python -m pip install -r agentguard/requirements.txt
Set-Location agentguard
python -m streamlit run app.py
```

Open http://localhost:8501. Models are loaded from `agentguard/models/`; run `python train_models.py --force` from `agentguard/` to retrain them from the included reproducible synthetic dataset.

## Five acceptance demonstrations

1. **Normal task:** enter a research request and click **Start Task**. Confirm all three agents complete and the report exists in `agentguard/output/`.
2. **Unauthorized action:** click **Unauthorized access** in Demo Scenarios. Confirm the restricted dummy credential read is `BLOCK`, the protected callback was not executed, and the read counter did not increase.
3. **Evidence-backed incident:** click **Suspicious sequence**. The real interceptor records a local research read, a blocked restricted-file read, and a blocked untrusted-destination transfer attempt. Review the correlated incident, event evidence, decisions, model signals, and status controls.
4. **Genuine ML:** expand **ML Model Metrics & Architecture**. The displayed Random Forest metrics and confusion matrix are calculated from the held-out split. The high-frequency anomaly control displays the Isolation Forest result from a controlled action.
5. **Cross-agent analysis:** in the incident list, open the sequence incident and inspect the ordered events from ResearchAgent, AnalysisAgent, and ReportAgent. Acknowledge or resolve it to demonstrate the incident lifecycle.

The same panel also includes **Approval flow**, which creates an actual model-routed `ASK` and allows an authorized reviewer to approve/resume or reject it, and **Task failure**, which reads a deliberately missing but permitted file and reports a task failure without labeling it an attack.

## Architecture and data

- `agents.py`: deterministic Research, Analysis, and Report agents; every tool callback uses the interceptor.
- `risk_engine.py`: permissions, mandatory policy precedence, classifier/anomaly inference, ALLOW/ASK/BLOCK, and approval resolution.
- `sequence_engine.py`: SQLite action history, sequence correlation, and OPEN/ACKNOWLEDGED/RESOLVED incident records.
- `train_models.py`: reproducible 4,000-row synthetic dataset, split-before-fit Random Forest training, held-out metrics, and normal-only Isolation Forest training.
- `app.py`: Streamlit task, scenario, event, incident, and evaluation views.

SQLite logs are stored at `agentguard/output/agentguard_events.sqlite3`. Action and incident records survive app restarts. Pending approval callbacks are held in memory and expire when the app process stops. The restricted local resource contains dummy data only.

## Tests

From the repository root:

```powershell
python -m pytest agentguard/test_runtime.py -q
```

The tests cover real report creation, allowed and blocked execution, non-execution after BLOCK, trained model predictions, anomaly detection, mandatory-rule precedence, approval and rejection, cross-agent sequence evidence, incident status updates, and task failure handling.

## Limits

The model data is synthetic, so its metrics do not establish real-world detection accuracy. These deterministic Python agents are not LLM agents. AgentGuard protects only operations routed through its interceptor; arbitrary code and direct operating-system activity are outside this prototype's enforcement boundary.
