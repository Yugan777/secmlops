"""
Graph-aware security agent for SecMLOps.

The agent:
1. Investigates the incident graph to gather evidence.
2. Produces a structured, evidence-grounded explanation.
3. Compares response options with rationale.
4. Supports abstention when evidence is incomplete.
5. Tracks the full response lifecycle.

No external LLM dependency required. All reasoning is deterministic
and based on structured telemetry from the detection pipeline.
"""


class SecurityAgent:
    """
    Graph-aware constrained security-response agent.

    Accepted actions (enforced by the safety gate):
        NO_ACTION     — continue monitoring
        ISOLATE_POD   — apply network isolation to the target pod

    Additional recommendations the agent can express (not yet enforced
    by the current containment implementation):
        COLLECT_MORE_EVIDENCE  — gather more telemetry before deciding
        REQUEST_HUMAN_REVIEW   — insufficient confidence; escalate

    These are stored in the recommendation but map to NO_ACTION for
    the safety gate unless the gate is extended.
    """

    ALLOWED_ACTIONS = {"NO_ACTION", "ISOLATE_POD"}

    # Risk score thresholds
    ISOLATION_THRESHOLD = 61
    HIGH_THRESHOLD = 81

    # Minimum context score before recommending isolation
    MIN_CONTEXT_SCORE_FOR_ISOLATION = 0.5

    def analyze(self, detection, risk, graph_data=None):
        """
        Analyze a detection result and produce an enriched agent result.

        Parameters
        ----------
        detection : dict
            Normalized detection from TemporalDetector (and ContextValidator).
        risk : dict
            Risk assessment from RiskEngine.
        graph_data : dict or None
            Serialized graph from TemporalSecurityGraph.to_dict().
            Optional. When provided, graph evidence is included.

        Returns
        -------
        dict with keys:
            assessment, reasoning, graph_evidence, observed_facts,
            uncertainty, response_options, recommended_action, priority,
            risk_score, pod, namespace, execution_mode, lifecycle_state
        """

        score = risk.get("risk_score", 0)
        severity = risk.get("severity", "LOW")
        reasons = risk.get("reasons", [])
        context = detection.get("context") or {}
        gnn = detection.get("gnn") or {}

        # ------------------------------------------------------------------
        # 1. Gather graph evidence
        # ------------------------------------------------------------------
        observed_facts, graph_evidence, uncertainty = self._investigate_graph(
            detection, graph_data, context, gnn
        )

        # ------------------------------------------------------------------
        # 2. Determine priority / assessment
        # ------------------------------------------------------------------
        if score >= self.HIGH_THRESHOLD:
            priority = "CRITICAL"
            assessment = (
                "High-confidence multi-stage suspicious activity detected."
            )
        elif score >= self.ISOLATION_THRESHOLD:
            priority = "HIGH"
            assessment = "Suspicious activity requiring containment review."
        elif score >= 31:
            priority = "MEDIUM"
            assessment = "Potentially suspicious activity; additional context needed."
        else:
            priority = "LOW"
            assessment = "Low-risk activity; continue monitoring."

        # ------------------------------------------------------------------
        # 3. Build reasoning from risk reasons + context evidence
        # ------------------------------------------------------------------
        reasoning = list(reasons)
        context_evidence = context.get("evidence", [])
        for ev in context_evidence:
            if ev not in reasoning:
                reasoning.append(ev)

        # ------------------------------------------------------------------
        # 4. Compare response options
        # ------------------------------------------------------------------
        response_options = self._build_response_options(
            score, detection, context, gnn, graph_evidence
        )

        # ------------------------------------------------------------------
        # 5. Choose recommendation
        # ------------------------------------------------------------------
        recommended_action, lifecycle_state = self._choose_action(
            score, detection, context, graph_evidence
        )

        # ------------------------------------------------------------------
        # 6. Determine execution mode
        # ------------------------------------------------------------------
        import os
        dry_run = os.getenv("SEC_MLOPS_DRY_RUN", "1") == "1"
        execution_mode = "DRY_RUN" if dry_run else "ENFORCEMENT"

        return {
            # Core fields (backwards-compatible with existing dashboard)
            "assessment": assessment,
            "reasoning": reasoning,
            "recommended_action": recommended_action,
            "priority": priority,
            "risk_score": score,
            "severity": severity,
            "pod": detection.get("pod"),
            "namespace": detection.get("namespace"),

            # Evidence-based fields (Phase B additions)
            "observed_facts": observed_facts,
            "graph_evidence": graph_evidence,
            "uncertainty": uncertainty,
            "response_options": response_options,

            # Lifecycle tracking
            "lifecycle_state": lifecycle_state,
            "execution_mode": execution_mode,
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _investigate_graph(self, detection, graph_data, context, gnn):
        """
        Build observed_facts, graph_evidence, and uncertainty lists
        from the available detection data and optional graph.
        """

        observed_facts = []
        graph_evidence = []
        uncertainty = []

        # --- Process chain ---
        processes = detection.get("processes", [])
        process_chain = context.get("process_chain", [])

        if processes:
            binaries = [p.get("process") for p in processes if p.get("process")]
            observed_facts.append(
                f"Observed {len(processes)} process(es) in temporal chain: "
                + ", ".join(binaries)
            )
        elif process_chain:
            observed_facts.append(
                "Process chain from context: " + " → ".join(process_chain)
            )
        else:
            uncertainty.append("No process telemetry available.")

        # --- Process ancestry ---
        if context.get("process_ancestry"):
            graph_evidence.append(
                "Process ancestry links confirmed: child processes share "
                "exec_id with observed parent."
            )
        else:
            uncertainty.append(
                "Process ancestry not confirmed — exec_id chain incomplete."
            )

        # --- Same workload ---
        if context.get("same_workload"):
            pod = detection.get("pod")
            namespace = detection.get("namespace")
            observed_facts.append(
                f"All observed processes belong to the same workload: "
                f"{pod} (ns: {namespace})."
            )
        else:
            uncertainty.append(
                "Events span multiple workloads or workload identity is missing."
            )

        # --- File access ---
        file_path = detection.get("file")
        if file_path:
            observed_facts.append(f"Sensitive file accessed: {file_path}")
            if context.get("sensitive_resource"):
                graph_evidence.append(
                    f"Sensitive resource access confirmed by context validator: "
                    f"{file_path}"
                )
        else:
            uncertainty.append("No file access telemetry in this detection.")

        # --- Network activity ---
        dest_ip = detection.get("destination_ip")
        if dest_ip:
            observed_facts.append(f"Outbound network connection to: {dest_ip}")
            if context.get("network_followup"):
                graph_evidence.append(
                    f"Network activity follows sensitive-file access "
                    f"(destination: {dest_ip}) — consistent with data-exfil pattern."
                )
        else:
            uncertainty.append("No outbound network connection in this detection.")

        # --- Temporal proximity ---
        time_window = detection.get("time_window_seconds")
        if context.get("temporal_proximity") and time_window is not None:
            observed_facts.append(
                f"Events correlated within {time_window:.3f}s temporal window."
            )
        elif not context.get("temporal_proximity"):
            uncertainty.append(
                "Events are NOT within the configured temporal correlation window."
            )

        # --- Event sequence ---
        if context.get("sequence_consistent"):
            graph_evidence.append(
                "Event sequence consistent with multi-stage lateral movement: "
                "process execution → sensitive file read → network exfil."
            )
        else:
            uncertainty.append(
                "Event sequence is NOT consistent with expected attack pattern."
            )

        # --- GNN signal ---
        if gnn.get("available"):
            susp = gnn.get("suspicious_probability", 0.0)
            observed_facts.append(
                f"GNN model output: suspicious_probability={susp:.4f} "
                f"(this is model output for this specific graph, not a "
                f"calibrated real-world probability)."
            )
        else:
            uncertainty.append(
                "GNN model unavailable or produced no output for this incident."
            )

        # --- Graph topology (if serialized graph provided) ---
        if graph_data and isinstance(graph_data, dict):
            nodes = graph_data.get("nodes", [])
            edges = graph_data.get("edges", [])
            attack_chain = graph_data.get("attack_chain", [])

            if nodes:
                node_types = {}
                for n in nodes:
                    t = n.get("type", "unknown")
                    node_types[t] = node_types.get(t, 0) + 1

                graph_evidence.append(
                    f"Temporal attack graph: {len(nodes)} nodes "
                    f"({', '.join(f'{c} {t}' for t, c in node_types.items())}), "
                    f"{len(edges)} observed relationship(s)."
                )

            if attack_chain:
                chain_strs = [
                    f"{step[0]} --{step[1]}--> {step[2]}"
                    for step in attack_chain
                    if len(step) == 3
                ]
                if chain_strs:
                    graph_evidence.append(
                        "Attack chain from graph: " + "; ".join(chain_strs)
                    )

            if not nodes:
                uncertainty.append(
                    "Temporal attack graph is empty — no graph evidence available."
                )

        elif graph_data is None:
            uncertainty.append(
                "Temporal attack graph was not provided to the agent."
            )

        return observed_facts, graph_evidence, uncertainty

    def _build_response_options(self, score, detection, context, gnn, graph_evidence):
        """
        Return a list of response option dicts, each with:
            action, rationale, expected_benefit, operational_risk, uncertainty
        """

        options = []

        # --- Option 1: Continue Monitoring ---
        options.append({
            "action": "MONITOR",
            "maps_to": "NO_ACTION",
            "rationale": "Continue collecting telemetry without intervention.",
            "expected_benefit": "No operational disruption; gathers more evidence.",
            "operational_risk": "Attack may progress while monitoring.",
            "uncertainty": (
                "Appropriate when evidence is inconclusive or risk score is low."
            ),
        })

        # --- Option 2: Collect More Evidence ---
        if score < self.ISOLATION_THRESHOLD or not context.get("sequence_consistent"):
            options.append({
                "action": "COLLECT_MORE_EVIDENCE",
                "maps_to": "NO_ACTION",
                "rationale": (
                    "Risk score or evidence is insufficient to justify isolation. "
                    "Additional telemetry may confirm or rule out the threat."
                ),
                "expected_benefit": "Reduces false-positive containment.",
                "operational_risk": "Delay in containment if threat is real.",
                "uncertainty": (
                    "Sequence consistency or context score below threshold."
                ),
            })

        # --- Option 3: Isolate Pod ---
        if score >= self.ISOLATION_THRESHOLD:
            pod = detection.get("pod")
            namespace = detection.get("namespace")
            has_graph_evidence = len(graph_evidence) > 0
            has_file_and_network = (
                detection.get("file") and detection.get("destination_ip")
            )

            rationale_parts = [
                f"Risk score {score} meets or exceeds isolation threshold "
                f"({self.ISOLATION_THRESHOLD})."
            ]
            if has_file_and_network:
                rationale_parts.append(
                    "Both sensitive file access and outbound network connection observed."
                )
            if has_graph_evidence:
                rationale_parts.append(
                    "Graph evidence supports the multi-stage activity interpretation."
                )

            options.append({
                "action": "ISOLATE_POD",
                "maps_to": "ISOLATE_POD",
                "rationale": " ".join(rationale_parts),
                "expected_benefit": (
                    f"Stops lateral movement and potential exfiltration from "
                    f"pod {pod} (ns: {namespace})."
                ),
                "operational_risk": (
                    "Isolating a legitimate workload causes service disruption. "
                    "Verify the target is a disposable test workload."
                ),
                "uncertainty": (
                    "Containment is not executed in dry-run mode. "
                    "Post-action verification must be performed separately."
                ),
            })

        # --- Option 4: Request Human Review ---
        if (
            score < self.ISOLATION_THRESHOLD
            or not context.get("process_ancestry")
            or not context.get("same_workload")
        ):
            options.append({
                "action": "REQUEST_HUMAN_REVIEW",
                "maps_to": "NO_ACTION",
                "rationale": (
                    "Evidence is incomplete or conflicting. "
                    "Human review is recommended before automated containment."
                ),
                "expected_benefit": "Prevents erroneous automated containment.",
                "operational_risk": "Requires analyst availability.",
                "uncertainty": (
                    "Some context checks did not pass. "
                    "See uncertainty list for details."
                ),
            })

        return options

    def _choose_action(self, score, detection, context, graph_evidence):
        """
        Choose the recommended action and a lifecycle state label.

        Returns (recommended_action, lifecycle_state).
        """

        context_score = context.get("context_score", 0.0)
        same_workload = context.get("same_workload", False)
        process_ancestry = context.get("process_ancestry", False)

        # Abstain: evidence contradictory or workload identity missing
        if not same_workload and score < self.HIGH_THRESHOLD:
            return (
                "NO_ACTION",
                "ABSTAINED_MISSING_WORKLOAD_CONTEXT",
            )

        # Abstain: score below threshold
        if score < self.ISOLATION_THRESHOLD:
            return (
                "NO_ACTION",
                "MONITORING_INSUFFICIENT_SCORE",
            )

        # Abstain: context score too low despite high risk score
        if context_score < self.MIN_CONTEXT_SCORE_FOR_ISOLATION:
            return (
                "NO_ACTION",
                "MONITORING_LOW_CONTEXT_SCORE",
            )

        # Recommend isolation
        action = "ISOLATE_POD"
        if action not in self.ALLOWED_ACTIONS:
            action = "NO_ACTION"

        return (
            action,
            "RECOMMENDED",
        )


# ---------------------------------------------------------------------------
# Standalone demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":

    sample_detection = {
        "attack_type": "MULTI_STAGE_ACTIVITY",
        "file": "/tmp/secmlops-test/sensitive.txt",
        "destination_ip": "10.0.0.50",
        "time_window_seconds": 2.0,
        "pod": "telemetry-test",
        "namespace": "security-lab",
        "processes": [
            {"process": "/bin/sh"},
            {"process": "/bin/cat"},
            {"process": "/bin/wget"},
        ],
        "context": {
            "validated": True,
            "context_score": 1.0,
            "same_workload": True,
            "process_ancestry": True,
            "temporal_proximity": True,
            "sensitive_resource": True,
            "network_followup": True,
            "sequence_consistent": True,
            "process_chain": ["/bin/sh", "/bin/cat", "/bin/wget"],
            "evidence": [
                "Observed processes belong to the same workload",
                "Process ancestry links the observed activities",
            ],
        },
        "gnn": {
            "available": True,
            "benign_probability": 0.0002,
            "suspicious_probability": 0.9998,
            "prediction": 1,
        },
    }

    sample_risk = {
        "risk_score": 90,
        "severity": "CRITICAL",
        "reasons": [
            "Sensitive file access detected",
            "Outbound network connection detected",
            "Multi-stage activity detected",
            "Multiple processes involved in attack chain",
            "Events correlated within temporal window",
            "GNN suspiciousness contributed 20/20 points",
        ],
    }

    sample_graph = {
        "nodes": [
            {"id": "pod:security-lab:telemetry-test", "type": "pod"},
            {"id": "process:exec-sh", "type": "process"},
            {"id": "process:exec-cat", "type": "process"},
            {"id": "process:exec-wget", "type": "process"},
            {"id": "file:/tmp/secmlops-test/sensitive.txt", "type": "file"},
            {"id": "ip:10.0.0.50", "type": "network"},
        ],
        "edges": [
            {"source": "process:exec-sh", "target": "process:exec-cat", "label": "SPAWNED"},
            {"source": "process:exec-cat", "target": "file:/tmp/secmlops-test/sensitive.txt", "label": "READ"},
            {"source": "process:exec-wget", "target": "ip:10.0.0.50", "label": "CONNECTED_TO"},
        ],
        "attack_chain": [
            ["/bin/sh", "SPAWNED", "/bin/cat"],
            ["/bin/cat", "READ", "/tmp/secmlops-test/sensitive.txt"],
            ["/bin/wget", "CONNECTED_TO", "10.0.0.50"],
        ],
    }

    agent = SecurityAgent()
    result = agent.analyze(sample_detection, sample_risk, sample_graph)

    print("\n========== SECURITY AGENT (GRAPH-AWARE) ==========")
    print(f"Assessment        : {result['assessment']}")
    print(f"Risk Score        : {result['risk_score']}")
    print(f"Severity          : {result['severity']}")
    print(f"Priority          : {result['priority']}")
    print(f"Recommended Action: {result['recommended_action']}")
    print(f"Lifecycle State   : {result['lifecycle_state']}")
    print(f"Execution Mode    : {result['execution_mode']}")

    print("\nObserved Facts:")
    for fact in result["observed_facts"]:
        print(f"  [FACT] {fact}")

    print("\nGraph Evidence:")
    for ev in result["graph_evidence"]:
        print(f"  [GRAPH] {ev}")

    print("\nUncertainty:")
    for u in result["uncertainty"]:
        print(f"  [?] {u}")

    print("\nResponse Options:")
    for opt in result["response_options"]:
        print(f"  [{opt['action']}] {opt['rationale']}")

    print(f"\nPod       : {result['pod']}")
    print(f"Namespace : {result['namespace']}")
    print("==================================================")
