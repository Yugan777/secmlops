"""Unit tests for SecMLOps FastAPI Dashboard Backend (Phase C)."""
import json
import os
import pytest
from dashboard import app as dash_app


def test_default_state_structure():
    """Verify default_state contains all required schema keys."""
    state = dash_app.default_state()
    assert state["status"] == "MONITORING"
    assert "graph" in state
    assert state["graph"]["nodes"] == []
    assert state["graph"]["edges"] == []
    assert state["graph"]["has_incident"] is False
    assert "gnn" in state
    assert "context" in state
    assert "agent" in state
    assert "safety_gate" in state
    assert "containment" in state
    assert isinstance(state["events"], list)


def test_index_file_response():
    """Verify root endpoint returns the dashboard index.html."""
    res = dash_app.index()
    assert os.path.exists(res.path)
    assert res.path.endswith("index.html")


def test_api_state_no_file(tmp_path, monkeypatch):
    """When state file is missing, api_state returns default state."""
    missing_file = str(tmp_path / "nonexistent_state.json")
    monkeypatch.setattr(dash_app, "STATE_FILE", missing_file)

    state = dash_app.api_state()
    assert state["status"] == "MONITORING"
    assert state["attack_type"] is None
    assert state["risk_score"] is None


def test_api_state_with_data(tmp_path, monkeypatch):
    """When state file exists, api_state correctly loads and merges it."""
    test_file = tmp_path / "live_state.json"
    dummy_data = {
        "status": "CONTAINMENT_APPROVED",
        "attack_type": "MULTI_STAGE_ACTIVITY",
        "target": "telemetry-test",
        "risk_score": 100,
        "severity": "CRITICAL",
        "agent": {
            "recommended_action": "ISOLATE_POD",
            "priority": "CRITICAL",
        },
        "safety_gate": {
            "approved": True,
            "action": "ISOLATE_POD",
        },
    }
    test_file.write_text(json.dumps(dummy_data))
    monkeypatch.setattr(dash_app, "STATE_FILE", str(test_file))

    state = dash_app.api_state()
    assert state["status"] == "CONTAINMENT_APPROVED"
    assert state["attack_type"] == "MULTI_STAGE_ACTIVITY"
    assert state["risk_score"] == 100
    assert state["agent"]["recommended_action"] == "ISOLATE_POD"
    assert state["safety_gate"]["approved"] is True


def test_api_threat_payload(tmp_path, monkeypatch):
    """Verify /api/threat returns structured threat and response fields."""
    test_file = tmp_path / "live_state.json"
    dummy_data = {
        "status": "INCIDENT_DETECTED",
        "threat": {
            "attack_type": "MULTI_STAGE_ACTIVITY",
            "pod": "telemetry-test",
            "namespace": "security-lab",
            "file": "/tmp/sensitive.txt",
            "destination_ip": "10.0.0.50",
            "confidence": 0.95,
        },
        "risk": {
            "risk_score": 90,
            "severity": "HIGH",
        },
        "gnn": {
            "available": True,
            "suspicious_probability": 0.9998,
        },
        "agent": {
            "assessment": "High-confidence multi-stage activity.",
            "recommended_action": "ISOLATE_POD",
        },
        "safety_gate": {
            "approved": True,
        },
    }
    test_file.write_text(json.dumps(dummy_data))
    monkeypatch.setattr(dash_app, "STATE_FILE", str(test_file))

    threat = dash_app.api_threat()
    assert threat["status"] == "INCIDENT_DETECTED"
    assert threat["attack_type"] == "MULTI_STAGE_ACTIVITY"
    assert threat["target"] == "telemetry-test"
    assert threat["namespace"] == "security-lab"
    assert threat["file"] == "/tmp/sensitive.txt"
    assert threat["destination_ip"] == "10.0.0.50"
    assert threat["risk_score"] == 90
    assert threat["severity"] == "HIGH"
    assert threat["gnn"]["available"] is True
    assert threat["agent"]["recommended_action"] == "ISOLATE_POD"


def test_api_events_limit(tmp_path, monkeypatch):
    """Verify /api/events caps at the last 50 events."""
    test_file = tmp_path / "live_state.json"
    dummy_events = [{"id": i, "process": f"/bin/test{i}"} for i in range(70)]
    test_file.write_text(json.dumps({"events": dummy_events}))
    monkeypatch.setattr(dash_app, "STATE_FILE", str(test_file))

    res = dash_app.api_events()
    assert "events" in res
    assert len(res["events"]) == 50
    assert res["events"][-1]["id"] == 69
    assert res["events"][0]["id"] == 20


def test_api_graph_empty(tmp_path, monkeypatch):
    """Verify /api/graph returns empty graph when no incident."""
    test_file = tmp_path / "live_state.json"
    test_file.write_text(json.dumps({"status": "MONITORING", "events": []}))
    monkeypatch.setattr(dash_app, "STATE_FILE", str(test_file))

    graph = dash_app.api_graph()
    assert graph["has_incident"] is False
    assert graph["nodes"] == []
    assert graph["edges"] == []


def test_api_graph_from_prebuilt_state(tmp_path, monkeypatch):
    """Verify /api/graph returns pre-built graph if stored in state."""
    test_file = tmp_path / "live_state.json"
    stored_graph = {
        "nodes": [{"id": "pod:test", "type": "pod"}],
        "edges": [{"source": "pod:test", "target": "proc:1", "label": "RUNS"}],
        "attack_chain": [["pod:test", "RUNS", "proc:1"]],
    }
    dummy_data = {
        "status": "INCIDENT_DETECTED",
        "attack_type": "MULTI_STAGE_ACTIVITY",
        "graph": stored_graph,
    }
    test_file.write_text(json.dumps(dummy_data))
    monkeypatch.setattr(dash_app, "STATE_FILE", str(test_file))

    graph = dash_app.api_graph()
    assert graph["has_incident"] is True
    assert len(graph["nodes"]) == 1
    assert graph["nodes"][0]["id"] == "pod:test"
    assert len(graph["edges"]) == 1


def test_api_graph_build_from_threat(tmp_path, monkeypatch):
    """Verify /api/graph builds graph from threat structure when incident detected."""
    test_file = tmp_path / "live_state.json"
    dummy_data = {
        "status": "INCIDENT_DETECTED",
        "attack_type": "MULTI_STAGE_ACTIVITY",
        "threat": {
            "pod": "telemetry-test",
            "namespace": "security-lab",
            "file": "/tmp/secret.txt",
            "destination_ip": "10.0.0.50",
            "processes": [
                {"process": "/bin/cat", "exec_id": "exec-1"},
            ],
        },
    }
    test_file.write_text(json.dumps(dummy_data))
    monkeypatch.setattr(dash_app, "STATE_FILE", str(test_file))

    graph = dash_app.api_graph()
    assert graph["has_incident"] is True
    node_ids = [n["id"] for n in graph["nodes"]]
    assert "pod:security-lab:telemetry-test" in node_ids
    assert "file:/tmp/secret.txt" in node_ids
    assert "ip:10.0.0.50" in node_ids


def test_api_health_check(monkeypatch):
    """Verify /api/health accurately reports ONLINE / OFFLINE based on commands."""
    def fake_run(cmd):
        if "nodes" in cmd:
            return True
        if "tetragon" in cmd:
            return True
        return False  # kafka and neo4j are not deployed

    monkeypatch.setattr(dash_app, "run_command", fake_run)
    health = dash_app.api_health()
    assert health["k3s"] == "ONLINE"
    assert health["tetragon"] == "ONLINE"
    assert health["kafka"] == "NOT_CONFIGURED"
    assert health["neo4j"] == "NOT_CONFIGURED"


def test_api_simulate_multi_stage(tmp_path, monkeypatch):
    """Verify MULTI_STAGE scenario produces critical risk and recommended isolation."""
    test_file = tmp_path / "live_state.json"
    monkeypatch.setattr(dash_app, "STATE_FILE", str(test_file))

    req = dash_app.SimRequest(scenario="MULTI_STAGE")
    res = dash_app.api_simulate(req)

    assert res["scenario"] == "MULTI_STAGE"
    assert res["risk_score"] == 100
    assert res["severity"] == "CRITICAL"
    assert res["recommended_action"] == "ISOLATE_POD"
    assert res["gate_approved"] is True
    assert res["execution_mode"] == "DRY_RUN"

    # State file must be updated
    loaded = dash_app.api_state()
    assert loaded["attack_type"] == "MULTI_STAGE_ACTIVITY"
    assert loaded["status"] == "CONTAINMENT_APPROVED"


def test_api_simulate_proc_chain(tmp_path, monkeypatch):
    """Verify PROC_CHAIN scenario abstains from isolation due to incomplete evidence."""
    test_file = tmp_path / "live_state.json"
    monkeypatch.setattr(dash_app, "STATE_FILE", str(test_file))

    req = dash_app.SimRequest(scenario="PROC_CHAIN")
    res = dash_app.api_simulate(req)

    assert res["scenario"] == "PROC_CHAIN"
    assert res["risk_score"] == 45
    assert res["severity"] == "MEDIUM"
    assert res["recommended_action"] != "ISOLATE_POD"
    assert res["gate_approved"] is True


def test_api_simulate_benign(tmp_path, monkeypatch):
    """Verify BENIGN scenario produces low risk and NO_ACTION."""
    test_file = tmp_path / "live_state.json"
    monkeypatch.setattr(dash_app, "STATE_FILE", str(test_file))

    req = dash_app.SimRequest(scenario="BENIGN")
    res = dash_app.api_simulate(req)

    assert res["scenario"] == "BENIGN"
    assert res["risk_score"] == 10
    assert res["severity"] == "LOW"
    assert res["recommended_action"] == "NO_ACTION"
    assert res["gate_action"] == "NO_ACTION"


def test_api_simulate_gate_block(tmp_path, monkeypatch):
    """Verify GATE_BLOCK scenario triggers safety gate refusal on protected namespace."""
    test_file = tmp_path / "live_state.json"
    monkeypatch.setattr(dash_app, "STATE_FILE", str(test_file))

    req = dash_app.SimRequest(scenario="GATE_BLOCK")
    res = dash_app.api_simulate(req)

    assert res["scenario"] == "GATE_BLOCK"
    assert res["risk_score"] == 95
    assert res["severity"] == "CRITICAL"
    assert res["gate_approved"] is False
    assert res["gate_action"] == "NO_ACTION"
    assert "Protected namespace" in res["gate_reason"]


def test_api_simulate_reset(tmp_path, monkeypatch):
    """Verify RESET resets state to baseline MONITORING."""
    test_file = tmp_path / "live_state.json"
    monkeypatch.setattr(dash_app, "STATE_FILE", str(test_file))

    req = dash_app.SimRequest(scenario="RESET")
    res = dash_app.api_simulate(req)

    assert res["scenario"] == "RESET"
    assert res["status"] == "MONITORING"
    loaded = dash_app.api_state()
    assert loaded["status"] == "MONITORING"
    assert loaded["attack_type"] is None

