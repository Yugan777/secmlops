import json
import os
import subprocess
import sys

from fastapi import FastAPI
from fastapi.responses import FileResponse

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.abspath(os.path.join(BASE_DIR, ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from graph.temporal_graph import TemporalSecurityGraph

app = FastAPI(title="SecMLOps Dashboard")

STATE_FILE = os.path.join(BASE_DIR, "live_state.json")
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
        "awk '$2 == \"1/1\" && $3 == \"Running\" "
        "{exit 0} {exit 1}'"
    )

    neo4j = run_command(
        "kubectl get pod -n graph neo4j-0 "
        "--no-headers 2>/dev/null | "
        "awk '$2 == \"1/1\" && $3 == \"Running\" "
        "{exit 0} {exit 1}'"
    )

    return {
        "k3s": "ONLINE" if k3s else "OFFLINE",
        "tetragon": "ONLINE" if tetragon else "OFFLINE",
        "kafka": "ONLINE" if kafka else "OFFLINE",
        "neo4j": "ONLINE" if neo4j else "OFFLINE",
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
