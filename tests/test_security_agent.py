"""Pytest tests for the graph-aware SecurityAgent (Phase B)."""
import os
from agent.security_agent import SecurityAgent


# -----------------------------------------------------------------------
# Fixtures
# -----------------------------------------------------------------------

SUSPICIOUS_DETECTION = {
    "attack_type": "MULTI_STAGE_ACTIVITY",
    "file": "/tmp/secmlops-test/sensitive.txt",
    "destination_ip": "10.0.0.50",
    "time_window_seconds": 2.0,
    "pod": "telemetry-test",
    "namespace": "security-lab",
    "processes": [
        {"process": "/bin/sh", "exec_id": "exec-sh"},
        {"process": "/bin/cat", "exec_id": "exec-cat"},
        {"process": "/bin/wget", "exec_id": "exec-wget"},
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
        "evidence": ["Observed processes belong to the same workload"],
    },
    "gnn": {
        "available": True,
        "benign_probability": 0.0002,
        "suspicious_probability": 0.9998,
        "prediction": 1,
    },
}

HIGH_RISK = {
    "risk_score": 100,
    "severity": "CRITICAL",
    "reasons": [
        "Sensitive file access detected",
        "Outbound network connection detected",
        "Multi-stage activity detected",
    ],
}

LOW_RISK = {
    "risk_score": 20,
    "severity": "LOW",
    "reasons": ["Low-level event"],
}

MISSING_EVIDENCE_DETECTION = {
    "attack_type": "PROCESS_EXEC",
    "pod": "unknown-pod",
    "namespace": "default",
    "processes": [],
    "context": {
        "validated": False,
        "context_score": 0.0,
        "same_workload": False,
        "process_ancestry": False,
        "temporal_proximity": False,
        "sensitive_resource": False,
        "network_followup": False,
        "sequence_consistent": False,
        "evidence": [],
    },
    "gnn": {"available": False},
}

SAMPLE_GRAPH = {
    "nodes": [
        {"id": "pod:security-lab:telemetry-test", "type": "pod"},
        {"id": "process:exec-sh", "type": "process"},
        {"id": "file:/tmp/sensitive.txt", "type": "file"},
        {"id": "ip:10.0.0.50", "type": "network"},
    ],
    "edges": [
        {"source": "process:exec-sh", "target": "file:/tmp/sensitive.txt", "label": "READ"},
        {"source": "process:exec-sh", "target": "ip:10.0.0.50", "label": "CONNECTED_TO"},
    ],
    "attack_chain": [
        ["/bin/sh", "READ", "/tmp/sensitive.txt"],
        ["/bin/sh", "CONNECTED_TO", "10.0.0.50"],
    ],
}


# -----------------------------------------------------------------------
# Tests: Suspicious / high-risk incident
# -----------------------------------------------------------------------

def test_suspicious_incident_recommends_isolate():
    agent = SecurityAgent()
    result = agent.analyze(SUSPICIOUS_DETECTION, HIGH_RISK, SAMPLE_GRAPH)
    assert result["recommended_action"] == "ISOLATE_POD"


def test_suspicious_incident_priority_critical():
    agent = SecurityAgent()
    result = agent.analyze(SUSPICIOUS_DETECTION, HIGH_RISK, SAMPLE_GRAPH)
    assert result["priority"] == "CRITICAL"


def test_suspicious_incident_has_observed_facts():
    agent = SecurityAgent()
    result = agent.analyze(SUSPICIOUS_DETECTION, HIGH_RISK, SAMPLE_GRAPH)
    assert len(result["observed_facts"]) > 0


def test_suspicious_incident_has_graph_evidence():
    agent = SecurityAgent()
    result = agent.analyze(SUSPICIOUS_DETECTION, HIGH_RISK, SAMPLE_GRAPH)
    assert len(result["graph_evidence"]) > 0


def test_suspicious_incident_no_uncertainty_for_complete_evidence():
    """With all context checks True, uncertainty list should be empty."""
    agent = SecurityAgent()
    result = agent.analyze(SUSPICIOUS_DETECTION, HIGH_RISK, SAMPLE_GRAPH)
    assert result["uncertainty"] == []


def test_suspicious_incident_lifecycle_state_recommended():
    agent = SecurityAgent()
    result = agent.analyze(SUSPICIOUS_DETECTION, HIGH_RISK, SAMPLE_GRAPH)
    assert result["lifecycle_state"] == "RECOMMENDED"


# -----------------------------------------------------------------------
# Tests: Benign / low-risk incident (abstention)
# -----------------------------------------------------------------------

def test_low_risk_does_not_recommend_isolation():
    agent = SecurityAgent()
    result = agent.analyze(SUSPICIOUS_DETECTION, LOW_RISK)
    assert result["recommended_action"] == "NO_ACTION"


def test_missing_evidence_abstains():
    agent = SecurityAgent()
    result = agent.analyze(MISSING_EVIDENCE_DETECTION, LOW_RISK)
    assert result["recommended_action"] == "NO_ACTION"


def test_missing_evidence_has_uncertainty():
    agent = SecurityAgent()
    result = agent.analyze(MISSING_EVIDENCE_DETECTION, LOW_RISK)
    assert len(result["uncertainty"]) > 0


# -----------------------------------------------------------------------
# Tests: Response options
# -----------------------------------------------------------------------

def test_response_options_include_monitor():
    agent = SecurityAgent()
    result = agent.analyze(SUSPICIOUS_DETECTION, HIGH_RISK, SAMPLE_GRAPH)
    actions = [opt["action"] for opt in result["response_options"]]
    assert "MONITOR" in actions


def test_response_options_include_isolate_for_high_risk():
    agent = SecurityAgent()
    result = agent.analyze(SUSPICIOUS_DETECTION, HIGH_RISK, SAMPLE_GRAPH)
    actions = [opt["action"] for opt in result["response_options"]]
    assert "ISOLATE_POD" in actions


def test_response_options_no_isolate_for_low_risk():
    agent = SecurityAgent()
    result = agent.analyze(SUSPICIOUS_DETECTION, LOW_RISK)
    actions = [opt["action"] for opt in result["response_options"]]
    assert "ISOLATE_POD" not in actions


# -----------------------------------------------------------------------
# Tests: Execution mode / lifecycle
# -----------------------------------------------------------------------

def test_dry_run_mode_default(monkeypatch):
    monkeypatch.delenv("SEC_MLOPS_DRY_RUN", raising=False)
    agent = SecurityAgent()
    result = agent.analyze(SUSPICIOUS_DETECTION, HIGH_RISK)
    assert result["execution_mode"] == "DRY_RUN"


def test_result_structure_has_required_keys():
    agent = SecurityAgent()
    result = agent.analyze(SUSPICIOUS_DETECTION, HIGH_RISK)
    required = [
        "assessment", "reasoning", "recommended_action", "priority",
        "risk_score", "severity", "pod", "namespace",
        "observed_facts", "graph_evidence", "uncertainty",
        "response_options", "lifecycle_state", "execution_mode",
    ]
    for key in required:
        assert key in result, f"Missing key: {key}"


# -----------------------------------------------------------------------
# Tests: Protected namespace (via safety gate interaction)
# -----------------------------------------------------------------------

def test_agent_safe_with_none_graph():
    """Agent must not crash when graph_data is None."""
    agent = SecurityAgent()
    result = agent.analyze(SUSPICIOUS_DETECTION, HIGH_RISK, graph_data=None)
    assert "recommended_action" in result
    assert "uncertainty" in result
