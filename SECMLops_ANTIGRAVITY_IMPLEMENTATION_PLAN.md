ib# SecMLOps — Antigravity Implementation Plan

## Mission

Improve the existing SecMLOps project in `~/secmlops` into a reliable, professional, graph-aware cyber-defense research prototype.

**Primary goals:**
1. Make the security agent investigate incident graph evidence, explain its decisions, compare response choices, and track response verification instead of simply mapping every alert to a fixed action.
2. Replace the current basic dashboard with a professional, cohesive Security Operations Center (SOC) interface while preserving the working Temporal Attack Graph and FastAPI backend.
3. Make the local WSL2/K3s demonstration simpler to start, diagnose, and repeat.
4. Add a small number of safe, repeatable attack-simulation scenarios and a benign baseline if the core agent and dashboard are stable.

Work on the existing project. Do not start a rewrite from scratch. Inspect first, implement incrementally, and verify every claim.

---

## 1. Mandatory working and safety rules

- Read the project documentation that exists, including `SECMLops_CURRENT_PROJECT_STATUS_AND_ROADMAP.md`, `SECMLops_PROJECT_SPEC.md`, and relevant README files.
- Inspect the actual repository structure, current branch, Git status, and code before editing. Preserve existing backups and Git history; do not delete or overwrite recovery points.
- Do not commit or push changes automatically. Keep changes reviewable and show the user what changed.
- Preserve the working Tetragon collector, live detector, Temporal Attack Graph, GNN model, context validator, risk engine, security agent, safety gate, and existing FastAPI endpoints unless inspection demonstrates a defect requiring a minimal change.
- Keep `SEC_MLOPS_DRY_RUN=1` throughout development and demo testing.
- **Never execute real pod isolation, delete workloads, change Kubernetes NetworkPolicies, or disrupt the cluster during this task.**
- Do not fabricate telemetry, incidents, graph nodes, model outputs, service-health states, agent explanations, or successful containment.
- Never expose unrestricted shell execution through dashboard buttons.
- Clearly distinguish each response stage: **detected**, **recommended**, **approved by safety gate**, **attempted**, **executed**, and **verified**.
- If a dependency or service is not deployed or unavailable, display its actual status instead of showing a false `ONLINE` label.
- Do not add a paid external LLM/API dependency. The agent must remain useful and testable if no external LLM is configured.
- Make small, reviewable changes and run relevant tests after each phase.

## 2. Existing project context to verify

The following has been reported from prior controlled tests. Treat it as a baseline to re-verify, not as proof that the current checkout/runtime still behaves the same way.

- The project runs in Ubuntu on WSL2 with a local K3s cluster and Tetragon.
- Tetragon policies have captured selected process execution, file-access, and network activity.
- `collector/tetragon_collector.py` normalizes Tetragon event records.
- `live_detection.py` consumes Tetragon events and has detected a controlled `MULTI_STAGE_ACTIVITY` scenario.
- `graph/temporal_graph.py` constructs a temporal attack graph.
- The dashboard graph issue was fixed and a graph with **7 nodes and 8 edges** was visibly shown for a controlled incident.
- `gnn/temporal_gnn.pt` reportedly produced a suspicious score near `0.9998` for the tested graph. This is an output for that input, not a calibrated real-world attack probability.
- Context validation, a risk engine, a security agent, and a safety gate exist.
- A controlled test reached CRITICAL severity and recommended `ISOLATE_POD`; real containment was not executed because the test was in dry-run mode.
- The dashboard backend is `dashboard/app.py`; the current frontend is `dashboard/index.html`.
- The graph renders, but the Security Response section has shown blank fields and some service-health indicators need attention.
- A previous investigation found Kafka and Neo4j were not deployed in the current WSL2 environment. Verify before making any claim about their current availability.
- The live detector currently tails Tetragon directly. Do not claim Kafka, Spark, or Neo4j are in the active detection path unless code and runtime verification prove that integration.

Start by checking the current code, running processes, and API responses.

---

## Phase A — Audit and stabilize the existing project

1. Inspect the repository, existing documentation, Git status, current branch, and recent changes.
2. Trace the current flow through:
   - Tetragon telemetry
   - `collector/tetragon_collector.py`
   - `live_detection.py`
   - temporal graph construction
   - GNN inference
   - context validation
   - risk assessment
   - security agent
   - safety gate
   - dashboard state storage
   - FastAPI endpoints
   - frontend rendering
3. Run the relevant existing tests before editing and record their results.
4. Classify important components as working, partial, broken, or unverified.
5. Check actual API contracts and responses, including `/api/graph`, `/api/threat`, `/api/state`, and health endpoints if present.
6. Find and fix the actual reason why Security Response fields are blank. Keep backend and frontend state structures aligned.
7. Ensure service-health labels only show `ONLINE` when genuine health checks succeed. Use appropriate states such as `OFFLINE`, `DEGRADED`, `UNKNOWN`, or `NOT CONFIGURED` where needed.
8. Investigate previous WSL/network-change failures using actual configuration and logs. Remove unnecessary hardcoded dynamic IP addresses. Prefer `localhost` for same-machine browser access and Kubernetes Service DNS for in-cluster communication when appropriate.
9. Report the audit findings and the smallest safe implementation plan before making broad changes.

## Phase B — Build a genuinely graph-aware security agent

Inspect the existing agent, graph, detector, GNN runtime, context validator, risk engine, and safety gate. Reuse current working code and data structures.

### Required behavior

#### 1. Investigate the incident graph

Use the graph and its underlying observed events to investigate:
- process and parent/child relationships
- file resources and access events
- network destinations and connections
- workload, pod, and namespace identity
- timestamps and event order
- related events immediately before and after the suspicious sequence

Preserve event IDs, timestamps, and provenance wherever available. Do not invent relationships to make the explanation look complete.

#### 2. Produce an evidence-grounded explanation

Generate a structured investigation result containing:
- **Observed facts:** directly supported by telemetry
- **Graph relationships:** observed edges or clearly marked inferred relationships
- **Interpretation:** why the sequence may be suspicious
- **Uncertainty / missing evidence:** what cannot be concluded from the available data
- **Supporting references:** relevant process names, event IDs, timestamps, paths, destinations, pod, and namespace where available

The explanation must be based on the actual incident state. Avoid generic text that simply restates the alert title.

#### 3. Keep analysis signals separate

Display and retain distinct fields for:
- GNN output
- context-validation result
- graph evidence
- rule-based risk score and severity
- agent recommendation
- safety-gate result

Do not call a GNN score a calibrated real-world attack probability unless calibration has actually been evaluated. Do not double-count correlated signals without a documented rationale.

#### 4. Compare response options

For each incident, consider only actions supported by the existing implementation and policy, such as:
- continue monitoring
- collect more evidence
- recommend restricting outbound network communication for a disposable test workload
- recommend isolating a test workload
- request human review / abstain

For each viable option, explain supporting evidence, expected benefit, operational risk, and uncertainty. Avoid claiming an action is implemented if it is only a proposed option.

#### 5. Support abstention

If the evidence is incomplete or contradictory, the target is protected, or the safety gate rejects the action, the agent must be able to recommend monitoring or human review instead of always recommending isolation.

#### 6. Enforce the safety gate

Every proposed response action must pass through the existing safety gate. Do not bypass protected-namespace restrictions or authorization checks. Do not introduce real enforcement during this task.

#### 7. Track the full response lifecycle

Represent and display these states separately:
- detection result
- agent recommendation
- safety-gate decision
- execution mode (dry-run or enforcement)
- execution status
- post-action verification status

For dry-run, show wording such as **“Recommended and approved; not executed (dry-run)”** when that matches the actual backend state. Do not label a recommendation as successful containment.

#### 8. Verify outcomes in a future safe test path

Prepare a clear verification interface for a later controlled test using real workload state and subsequent telemetry. During this task, do not execute real isolation or make disruptive cluster changes.

#### 9. Optional incident memory

Only if it can be done reliably within the existing architecture, store incident summaries/references, reviewed labels, agent decisions, and verified outcomes. Similar-incident retrieval may support the current investigation. Do not describe storage or retrieval as continuous model learning.

### Agent acceptance criteria

- A controlled suspicious incident produces an explanation tied to actual observed evidence.
- A benign or incomplete-evidence incident can result in monitoring/abstention rather than forced isolation.
- Graph evidence, GNN output, context validation, risk score, recommendation, safety-gate decision, and execution/verification states are distinct.
- Recommendations are not just a hardcoded “if threat then isolate” mapping.
- Dry-run clearly shows that actual enforcement did not happen.
- Tests cover complete evidence, missing/conflicting evidence, benign activity, protected targets, and safety-gate rejection.

Prioritize reliable graph querying and structured, explainable planning over building a superficial chatbot. If no external LLM is configured, the system must still function using structured evidence and documented deterministic logic.

---

## Phase C — Create a professional SOC dashboard

The current `dashboard/index.html` is functional but needs a more polished and maintainable UI. The goal is a professional application suitable for a cybersecurity project demonstration, not an oversized rewrite.

### Frontend architecture decision

Inspect the current frontend, API contracts, and project size first.

**Preferred option:** a small **Vite + React + TypeScript** frontend, while retaining FastAPI as the backend, if it can be migrated incrementally without breaking the working graph.

- Keep the Python backend and existing API contracts wherever practical.
- Put frontend code in a clearly named folder such as `frontend/`.
- Use reusable components and typed API models.
- Keep dependencies lean. Do not add Next.js, a complex state-management framework, or unrelated infrastructure.
- Configure development API access cleanly and document a reliable local production/demo build and serving approach.
- Add clear commands for install, development, production build, and demo startup.
- Do not replace or remove the old working frontend until the new frontend has passed build/API checks and the graph has been verified in a browser.
- If migrating will add more risk than value within the current project scope, explain why a smaller modular improvement to the current frontend is safer, then choose one approach. Do not maintain two competing frontends indefinitely.

### Visual design requirements

Create a cohesive dark cybersecurity operations interface:
- clear information hierarchy and readable typography
- consistent spacing, panel sizing, borders, restrained accent colors, severity colors, and meaningful icons
- clean laptop-sized/responsive layout with no clipped panels or overflowing graph
- real information density rather than decorative charts
- useful loading, empty, error, offline, and stale-data states
- subtle, responsive interactions with clear button feedback
- explicit labels for live telemetry versus controlled simulation data

Do not add made-up counts, charts, incident records, or health indicators just to make the dashboard look busy.

### Four primary views

#### 1. Overview
Show when supported by real backend state:
- actual K3s, Tetragon, and configured optional-service health
- active/recent incidents and severity
- latest telemetry or detection timestamp
- detection latency only if measured
- recent incident list with identity, time, affected target, severity, and lifecycle status
- clear distinctions among live, simulated/test, stale, and unavailable information

#### 2. Attack Graph
- Preserve the working Temporal Attack Graph.
- Render actual nodes and edges for the selected incident.
- Support node/edge selection and display event data, process, workload, timestamp, file path or network destination where available.
- Distinguish observed versus inferred relationships when supported by the data model.
- Show selected incident identity and a related event timeline.
- Handle loading, no incident, API failure, and stale state honestly.

#### 3. AI Agent / Investigation
- evidence-based incident summary
- graph findings and suspicious event sequence
- separate GNN result, context validation, risk score, and severity
- response options and rationale, including uncertainty and operational side effects
- chosen recommendation and safety-gate result
- execution mode and post-action verification
- clear dry-run wording when no containment was executed

#### 4. Simulation Lab
- controls only for safe scenarios that are actually implemented in the backend
- scenario ID, run status, and event timeline
- associated attack graph, detection/model results, agent recommendation, gate decision, and outcome-verification status
- benign baseline if it is feasible within the current scope
- run history only when it is persisted from real runs
- no arbitrary shell-command execution from the browser

### Dashboard acceptance criteria

- The existing Temporal Attack Graph still renders from real backend data.
- Security Response fields are populated from actual backend state.
- Optional services do not show false `ONLINE` status.
- No fabricated data is shown as live telemetry.
- Empty/loading/error/stale states are usable and understandable.
- The frontend builds successfully if Vite is chosen.
- The dashboard can be started with documented commands and visually verified in a browser.
- API tests verify real response payloads, not just HTTP 200 status.

---

## Phase D — Improve demo startup and runtime reliability

1. Add a preflight/status command that checks K3s node readiness, Tetragon health/events, detector status, dashboard health, and configured optional services.
2. If feasible, provide `scripts/start_demo.sh` and `scripts/status_demo.sh`.
3. The start script should check prerequisites, start only required services, wait for readiness, print useful errors/log locations, and display the dashboard URL.
4. Do not automatically start attack simulations or containment on startup.
5. Review whether persistent processes should be managed with systemd or an existing Kubernetes deployment/restart policy instead of unmanaged terminal sessions.
6. Ensure the detector and dashboard agree on the state-file path and schema, and avoid silent failures when state is unavailable.
7. Do not add Kafka, Spark, or Neo4j merely for visual appearance. Add or depend on them only if actually deployed, configured, and verified.
8. Document the WSL limitation honestly: processes inside WSL cannot keep Linux running if the entire WSL environment is stopped.
9. Keep logs accessible so failures after a network change can be diagnosed instead of guessed at.

---

## Phase E — Safe, repeatable simulation scenarios

Only proceed after the agent and dashboard core are stable. Use disposable test workloads and local/controlled endpoints only.

Prioritize:
1. Existing sensitive-file-access followed by network-connection scenario.
2. Suspicious process execution chain.
3. Repeated outbound requests to a controlled local test service to represent spam-like behavior without sending actual spam.
4. Benign baseline workload.
5. Cross-workload connection scenario only if the current cluster supports it safely and there is time to test it.

For every run, record actual scenario/incident IDs, timestamps, normalized events, graph, detection result, model output, agent recommendation, safety-gate decision, and response verification status.

Do not deploy real malware, run credential theft or persistence behavior, attack external systems, send real spam, or perform destructive actions. Remain in dry-run mode. A test should prove detection and recommendation separately from actual containment.

---

## Verification procedure

Run relevant checks incrementally. Start with repository status and current tests. At minimum, where these files exist:

```bash
cd ~/secmlops
git status --short
git diff --check
python -m py_compile live_detection.py dashboard/app.py graph/temporal_graph.py collector/tetragon_collector.py
```

Then:
- run the repository's relevant existing tests
- test the agent on suspicious, benign, incomplete-evidence, and protected-target cases
- check actual JSON responses from the graph, threat, state, and health endpoints that exist
- verify the graph uses real incident data
- if Vite is chosen, run its production build and any existing frontend tests
- open the dashboard in a browser and visually verify layout, graph, API-driven state, and response panel
- verify actual service health instead of trusting hardcoded values
- inspect the final diff for unintended changes
- confirm `SEC_MLOPS_DRY_RUN=1` remained enabled and no actual containment was executed

Do not say a test, build, visual check, or containment verification passed unless it was actually performed. If something could not be verified, state that explicitly.

---

## Required final report

When finished, report:

1. What was already working before the changes.
2. Which files were changed and why.
3. Agent behavior implemented versus still planned.
4. Whether the frontend remained HTML or migrated to Vite/React/TypeScript, and the reason for that choice.
5. Which dashboard views were implemented and visually verified.
6. Actual commands/tests/builds executed and their pass/fail outcomes.
7. Current WSL/K3s/Tetragon/service-health findings and remaining blockers.
8. What simulation scenarios were actually run and their real outcomes.
9. Minimal commands needed to start the demonstration.
10. Explicit confirmation that no real containment was executed.

## Execution order — follow this sequence

1. Inspect the repository and check the existing state.
2. Run current tests and identify the highest-priority real defects.
3. Fix Security Response state and service-health accuracy.
4. Improve the graph-aware agent and its tests.
5. Build the professional dashboard, choosing the smallest maintainable frontend approach.
6. Add startup/status reliability helpers.
7. Add safe simulation controls only after the core UI and agent are stable.
8. Run tests, inspect the final diff, and provide the required report.

**Begin with inspection and a concise audit. Diagnose before editing. Preserve the existing working graph. Implement in small, testable phases. Do not claim success without verification.**
