import json
import os
import subprocess
import sys

from datetime import datetime, timezone
from fastapi import FastAPI
from fastapi.responses import FileResponse
from pydantic import BaseModel

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.abspath(os.path.join(BASE_DIR, ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from graph.temporal_graph import TemporalSecurityGraph
from agent.security_agent import SecurityAgent
from policy.safety_gate import PolicySafetyGate

app = FastAPI(title="SecMLOps Dashboard")

STATE_FILE = os.environ.get(
    "SEC_MLOPS_STATE_FILE",
    os.path.join(BASE_DIR, "live_state.json")
)
INDEX_FILE = os.path.join(BASE_DIR, "index.html")


def default_state():
    return {
        "status": "MONITORING",
        "attack_type": None,
        "target": None,
        "risk_score": None,
        "severity": None,
        "gnn": {},
        "context": {},
        "agent": {},
        "safety_gate": {},
        "containment": {},
        "events": [],
        "graph": {
            "nodes": [],
            "edges": [],
            "attack_chain": [],
            "has_incident": False,
        },
        "updated_at": None,
    }


def load_state():
    try:
        if not os.path.exists(STATE_FILE):
            return default_state()

        with open(STATE_FILE, "r") as f:
            state = json.load(f)

        base = default_state()
        base.update(state)
        return base

    except Exception:
        return default_state()


def run_command(command):
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=5,
        )

        return result.returncode == 0

    except Exception:
        return False


@app.get("/")
def index():
    return FileResponse(INDEX_FILE)


@app.get("/api/state")
def api_state():
    return load_state()


@app.get("/api/events")
def api_events():
    state = load_state()
    return {
        "events": state.get("events", [])[-50:]
    }


@app.get("/api/threat")
def api_threat():
    state = load_state()

    threat = state.get("threat") or {}
    risk = state.get("risk") or {}

    attack_type = state.get("attack_type") or threat.get("attack_type")
    target = state.get("target") or threat.get("pod") or threat.get("workload")
    risk_score = state.get("risk_score") if state.get("risk_score") is not None else risk.get("risk_score")
    severity = state.get("severity") or risk.get("severity")

    return {
        "status": state.get("status"),
        "attack_type": attack_type,
        "target": target,
        "namespace": threat.get("namespace"),
        "file": threat.get("file"),
        "destination_ip": threat.get("destination_ip"),
        "confidence": threat.get("confidence"),
        "risk_score": risk_score,
        "severity": severity,
        "gnn": state.get("gnn", {}),
        "context": state.get("context", {}),
        "agent": state.get("agent", {}),
        "safety_gate": state.get("safety_gate", {}),
        "containment": state.get("containment", {}),
        "updated_at": state.get("updated_at"),
    }


@app.get("/api/health")
def api_health():

    k3s = run_command(
        "kubectl get nodes --no-headers 2>/dev/null | "
        "awk '$2 == \"Ready\" {found=1} END {exit !found}'"
    )

    tetragon = run_command(
        "kubectl get pods -n kube-system "
        "-l app.kubernetes.io/name=tetragon "
        "--no-headers 2>/dev/null | "
        "awk '$2 ~ /^2\\/2$/ && $3 == \"Running\" {found=1} "
        "END {exit !found}'"
    )

    kafka = run_command(
        "kubectl get pod -n secmlops kafka-controller-0 "
        "--no-headers 2>/dev/null | "
        "awk '$2 == \"1/1\" && $3 == \"Running\" {found=1} END {exit !found}'"
    )

    neo4j = run_command(
        "kubectl get pod -n graph neo4j-0 "
        "--no-headers 2>/dev/null | "
        "awk '$2 == \"1/1\" && $3 == \"Running\" {found=1} END {exit !found}'"
    )

    return {
        "k3s": "ONLINE" if k3s else "OFFLINE",
        "tetragon": "ONLINE" if tetragon else "OFFLINE",
        "kafka": "ONLINE" if kafka else "NOT_CONFIGURED",
        "neo4j": "ONLINE" if neo4j else "NOT_CONFIGURED",
    }


@app.get("/api/graph")
def api_graph():

    state = load_state()

    threat = state.get("threat") or {}
    risk = state.get("risk") or {}

    attack_type = state.get("attack_type") or threat.get("attack_type")
    target = state.get("target") or threat.get("pod") or threat.get("workload")
    risk_score = state.get("risk_score") if state.get("risk_score") is not None else risk.get("risk_score")
    severity = state.get("severity") or risk.get("severity")
    status = state.get("status", "MONITORING")

    # 1. Use pre-built graph if available in state and populated with nodes
    graph_data = state.get("graph")
    if isinstance(graph_data, dict) and graph_data.get("nodes"):
        return {
            "nodes": graph_data.get("nodes", []),
            "edges": graph_data.get("edges", []),
            "attack_chain": graph_data.get("attack_chain", []),
            "has_incident": True,
            "attack_type": attack_type,
            "target": target,
            "risk_score": risk_score,
            "severity": severity,
            "status": status,
            "updated_at": state.get("updated_at"),
        }

    # 2. If an incident was detected, generate graph using TemporalSecurityGraph
    if attack_type or threat.get("detected"):
        temp_graph = TemporalSecurityGraph(max_age_seconds=300)

        if threat and (threat.get("processes") or threat.get("file") or threat.get("destination_ip")):
            temp_graph.build_from_threat(threat)
        else:
            events = state.get("events", [])
            if events:
                temp_graph.build_from_events(events)

        exported = temp_graph.to_dict()
        if exported.get("nodes"):
            return {
                "nodes": exported.get("nodes", []),
                "edges": exported.get("edges", []),
                "attack_chain": exported.get("attack_chain", []),
                "has_incident": True,
                "attack_type": attack_type,
                "target": target,
                "risk_score": risk_score,
                "severity": severity,
                "status": status,
                "updated_at": state.get("updated_at"),
            }

    # 3. No incident: return empty graph state
    return {
        "nodes": [],
        "edges": [],
        "attack_chain": [],
        "has_incident": False,
        "status": status,
        "updated_at": state.get("updated_at"),
    }


def save_state(state):
    try:
        os.makedirs(os.path.dirname(os.path.abspath(STATE_FILE)), exist_ok=True)
        with open(STATE_FILE, "w") as f:
            json.dump(state, f, indent=2)
        return True
    except Exception:
        return False


class SimRequest(BaseModel):
    scenario: str


@app.post("/api/simulate")
def api_simulate(req: SimRequest):
    sc = req.scenario.upper()
    now_iso = datetime.now(timezone.utc).isoformat()
    agent = SecurityAgent()
    gate = PolicySafetyGate()

    if sc == "RESET":
        state = default_state()
        state["updated_at"] = now_iso
        save_state(state)
        return {
            "scenario": "RESET",
            "status": "MONITORING",
            "message": "Reset to baseline monitoring state",
        }

    if sc == "MULTI_STAGE":
        threat = {
            "attack_type": "MULTI_STAGE_ACTIVITY",
            "pod": "telemetry-test",
            "namespace": "security-lab",
            "file": "/tmp/secmlops-test/sensitive.txt",
            "destination_ip": "10.0.0.50",
            "time_window_seconds": 2.0,
            "processes": [
                {"process": "/bin/sh", "exec_id": "exec-sh-1", "timestamp": now_iso},
                {"process": "/bin/cat", "exec_id": "exec-cat-1", "timestamp": now_iso},
                {"process": "/bin/wget", "exec_id": "exec-wget-1", "timestamp": now_iso},
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
        risk = {
            "risk_score": 100,
            "severity": "CRITICAL",
            "reasons": [
                "Sensitive file access detected",
                "Outbound network connection detected",
                "Multi-stage activity detected",
            ],
        }
        temp_graph = TemporalSecurityGraph(max_age_seconds=300)
        temp_graph.build_from_threat(threat)
        graph_data = temp_graph.to_dict()

        agent_result = agent.analyze(threat, risk, graph_data=graph_data)
        gate_result = gate.evaluate(agent_result)

        new_state = {
            "status": "CONTAINMENT_APPROVED" if gate_result["approved"] else "SAFETY_GATE_BLOCKED",
            "attack_type": "MULTI_STAGE_ACTIVITY",
            "target": "telemetry-test",
            "threat": threat,
            "risk": risk,
            "risk_score": 100,
            "severity": "CRITICAL",
            "gnn": threat["gnn"],
            "context": threat["context"],
            "agent": agent_result,
            "safety_gate": gate_result,
            "containment": {
                "success": False,
                "action": "ISOLATE_POD",
                "status": "DRY_RUN",
                "message": "Recommended and approved; not executed (dry-run mode enabled).",
            },
            "graph": graph_data,
            "events": [
                {"event_type": "PROCESS_EXEC", "process": "/bin/sh", "pod": "telemetry-test", "timestamp": now_iso},
                {"event_type": "FILE_READ", "process": "/bin/cat", "file_path": "/tmp/secmlops-test/sensitive.txt", "pod": "telemetry-test", "timestamp": now_iso},
                {"event_type": "NETWORK_CONNECT", "process": "/bin/wget", "destination_ip": "10.0.0.50", "pod": "telemetry-test", "timestamp": now_iso},
            ],
            "updated_at": now_iso,
        }
        save_state(new_state)
        return {
            "scenario": "MULTI_STAGE",
            "status": new_state["status"],
            "attack_type": "MULTI_STAGE_ACTIVITY",
            "risk_score": 100,
            "severity": "CRITICAL",
            "recommended_action": agent_result["recommended_action"],
            "gate_approved": gate_result["approved"],
            "gate_action": gate_result["action"],
            "gate_reason": gate_result["reason"],
            "execution_mode": agent_result["execution_mode"],
            "lifecycle_state": agent_result["lifecycle_state"],
            "message": "Recommended and approved; not executed (dry-run mode enabled).",
        }

    elif sc == "PROC_CHAIN":
        threat = {
            "attack_type": "SUSPICIOUS_EXEC_CHAIN",
            "pod": "worker-agent",
            "namespace": "analytics",
            "processes": [
                {"process": "/bin/sh", "exec_id": "exec-sh-2", "timestamp": now_iso},
                {"process": "/usr/bin/python3", "exec_id": "exec-py-2", "timestamp": now_iso},
                {"process": "/bin/whoami", "exec_id": "exec-who-2", "timestamp": now_iso},
            ],
            "context": {
                "validated": False,
                "context_score": 0.4,
                "same_workload": True,
                "process_ancestry": True,
                "temporal_proximity": True,
                "sensitive_resource": False,
                "network_followup": False,
                "sequence_consistent": False,
                "evidence": ["Unusual binary execution chain in container"],
            },
            "gnn": {
                "available": True,
                "benign_probability": 0.45,
                "suspicious_probability": 0.55,
                "prediction": 0,
            },
        }
        risk = {
            "risk_score": 45,
            "severity": "MEDIUM",
            "reasons": ["Unusual process execution chain detected"],
        }
        temp_graph = TemporalSecurityGraph(max_age_seconds=300)
        temp_graph.build_from_threat(threat)
        graph_data = temp_graph.to_dict()

        agent_result = agent.analyze(threat, risk, graph_data=graph_data)
        gate_result = gate.evaluate(agent_result)

        new_state = {
            "status": "ANALYZING_RESPONSE",
            "attack_type": "SUSPICIOUS_EXEC_CHAIN",
            "target": "worker-agent",
            "threat": threat,
            "risk": risk,
            "risk_score": 45,
            "severity": "MEDIUM",
            "gnn": threat["gnn"],
            "context": threat["context"],
            "agent": agent_result,
            "safety_gate": gate_result,
            "containment": None,
            "graph": graph_data,
            "events": [
                {"event_type": "PROCESS_EXEC", "process": "/bin/sh", "pod": "worker-agent", "timestamp": now_iso},
                {"event_type": "PROCESS_EXEC", "process": "/usr/bin/python3", "pod": "worker-agent", "timestamp": now_iso},
                {"event_type": "PROCESS_EXEC", "process": "/bin/whoami", "pod": "worker-agent", "timestamp": now_iso},
            ],
            "updated_at": now_iso,
        }
        save_state(new_state)
        return {
            "scenario": "PROC_CHAIN",
            "status": "MONITORING",
            "attack_type": "SUSPICIOUS_EXEC_CHAIN",
            "risk_score": 45,
            "severity": "MEDIUM",
            "recommended_action": agent_result["recommended_action"],
            "gate_approved": gate_result["approved"],
            "gate_action": gate_result["action"],
            "gate_reason": gate_result["reason"],
            "execution_mode": agent_result["execution_mode"],
            "lifecycle_state": agent_result["lifecycle_state"],
            "message": "Abstained from isolation due to incomplete evidence (context score < 0.5).",
        }

    elif sc == "BENIGN":
        threat = {
            "attack_type": None,
            "pod": "app-backend",
            "namespace": "production",
            "processes": [
                {"process": "/usr/local/bin/node", "exec_id": "exec-node-1", "timestamp": now_iso},
            ],
            "context": {
                "validated": False,
                "context_score": 0.05,
                "same_workload": True,
                "process_ancestry": False,
                "temporal_proximity": False,
                "sensitive_resource": False,
                "network_followup": False,
                "sequence_consistent": False,
                "evidence": [],
            },
            "gnn": {
                "available": True,
                "benign_probability": 0.998,
                "suspicious_probability": 0.002,
                "prediction": 0,
            },
        }
        risk = {
            "risk_score": 10,
            "severity": "LOW",
            "reasons": ["Routine process execution"],
        }
        temp_graph = TemporalSecurityGraph(max_age_seconds=300)
        temp_graph.build_from_threat(threat)
        graph_data = temp_graph.to_dict()

        agent_result = agent.analyze(threat, risk, graph_data=graph_data)
        gate_result = gate.evaluate(agent_result)

        new_state = {
            "status": "MONITORING",
            "attack_type": None,
            "target": "app-backend",
            "threat": threat,
            "risk": risk,
            "risk_score": 10,
            "severity": "LOW",
            "gnn": threat["gnn"],
            "context": threat["context"],
            "agent": agent_result,
            "safety_gate": gate_result,
            "containment": None,
            "graph": {"nodes": [], "edges": [], "attack_chain": [], "has_incident": False},
            "events": [
                {"event_type": "PROCESS_EXEC", "process": "/usr/local/bin/node", "pod": "app-backend", "timestamp": now_iso},
            ],
            "updated_at": now_iso,
        }
        save_state(new_state)
        return {
            "scenario": "BENIGN",
            "status": "MONITORING",
            "attack_type": "BENIGN",
            "risk_score": 10,
            "severity": "LOW",
            "recommended_action": "NO_ACTION",
            "gate_approved": True,
            "gate_action": "NO_ACTION",
            "gate_reason": "Agent recommended no containment",
            "execution_mode": agent_result["execution_mode"],
            "lifecycle_state": "MONITORING",
            "message": "Routine workload verified benign. No false positives triggered.",
        }

    elif sc == "GATE_BLOCK":
        threat = {
            "attack_type": "MULTI_STAGE_ACTIVITY",
            "pod": "coredns-7cfb7bc9c7-zg8fn",
            "namespace": "kube-system",
            "file": "/etc/kubernetes/admin.conf",
            "destination_ip": "198.51.100.1",
            "time_window_seconds": 1.5,
            "processes": [
                {"process": "/bin/sh", "exec_id": "exec-sh-k8s", "timestamp": now_iso},
                {"process": "/bin/cat", "exec_id": "exec-cat-k8s", "timestamp": now_iso},
            ],
            "context": {
                "validated": True,
                "context_score": 0.9,
                "same_workload": True,
                "process_ancestry": True,
                "temporal_proximity": True,
                "sensitive_resource": True,
                "network_followup": False,
                "sequence_consistent": True,
                "evidence": ["Activity matches suspicious pattern in core infrastructure"],
            },
            "gnn": {
                "available": True,
                "benign_probability": 0.05,
                "suspicious_probability": 0.95,
                "prediction": 1,
            },
        }
        risk = {
            "risk_score": 95,
            "severity": "CRITICAL",
            "reasons": [
                "Sensitive cluster config access",
                "Suspicious process execution in system namespace",
            ],
        }
        temp_graph = TemporalSecurityGraph(max_age_seconds=300)
        temp_graph.build_from_threat(threat)
        graph_data = temp_graph.to_dict()

        agent_result = agent.analyze(threat, risk, graph_data=graph_data)
        gate_result = gate.evaluate(agent_result)

        new_state = {
            "status": "SAFETY_GATE",
            "attack_type": "MULTI_STAGE_ACTIVITY",
            "target": "coredns-7cfb7bc9c7-zg8fn",
            "threat": threat,
            "risk": risk,
            "risk_score": 95,
            "severity": "CRITICAL",
            "gnn": threat["gnn"],
            "context": threat["context"],
            "agent": agent_result,
            "safety_gate": gate_result,
            "containment": {
                "success": False,
                "action": "NO_ACTION",
                "status": "BLOCKED",
                "message": f"Containment rejected by safety gate: {gate_result['reason']}",
            },
            "graph": graph_data,
            "events": [
                {"event_type": "PROCESS_EXEC", "process": "/bin/sh", "pod": "coredns-7cfb7bc9c7-zg8fn", "timestamp": now_iso},
                {"event_type": "FILE_READ", "process": "/bin/cat", "file_path": "/etc/kubernetes/admin.conf", "pod": "coredns-7cfb7bc9c7-zg8fn", "timestamp": now_iso},
            ],
            "updated_at": now_iso,
        }
        save_state(new_state)
        return {
            "scenario": "GATE_BLOCK",
            "status": "SAFETY_GATE_BLOCKED",
            "attack_type": "MULTI_STAGE_ACTIVITY",
            "risk_score": 95,
            "severity": "CRITICAL",
            "recommended_action": agent_result["recommended_action"],
            "gate_approved": gate_result["approved"],
            "gate_action": gate_result["action"],
            "gate_reason": gate_result["reason"],
            "execution_mode": agent_result["execution_mode"],
            "lifecycle_state": "GATE_BLOCKED",
            "message": f"Isolation BLOCKED by Policy Safety Gate: {gate_result['reason']}",
        }

    return {
        "scenario": sc,
        "status": "UNKNOWN_SCENARIO",
        "message": f"Scenario {sc} not recognized. Choose MULTI_STAGE, PROC_CHAIN, BENIGN, or GATE_BLOCK.",
    }
