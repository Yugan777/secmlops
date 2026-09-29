import json
import os
import subprocess

from fastapi import FastAPI
from fastapi.responses import FileResponse

app = FastAPI(title="SecMLOps Dashboard")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
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

    threat = state.get("threat", {})
    risk = state.get("risk", {})

    return {
        "status": state.get("status"),
        "attack_type": threat.get("attack_type"),
        "target": threat.get("pod"),
        "namespace": threat.get("namespace"),
        "file": threat.get("file"),
        "destination_ip": threat.get("destination_ip"),
        "confidence": threat.get("confidence"),
        "risk_score": risk.get("risk_score"),
        "severity": risk.get("severity"),
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

    attack_type = state.get("attack_type")
    target = state.get("target")

    # IMPORTANT:
    # Do NOT require status == THREAT_DETECTED.
    # The last detected incident remains visible while the
    # system returns to MONITORING.

    if not attack_type:
        return {
            "nodes": [],
            "edges": [],
            "has_incident": False,
        }

    events = state.get("events", [])

    nodes = []
    edges = []
    seen = set()

    def add_node(node_id, label, node_type):
        if node_id not in seen:
            nodes.append({
                "id": node_id,
                "label": label,
                "type": node_type,
            })
            seen.add(node_id)

    # Build the graph from the most recent security-relevant events.
    process_nodes = []
    file_nodes = []
    network_nodes = []

    for event in events:

        event_type = event.get("event_type", "")
        process = (
            event.get("process")
            or event.get("process_name")
            or event.get("binary")
        )

        file_path = (
            event.get("file")
            or event.get("file_path")
            or event.get("path")
        )

        destination = (
            event.get("destination_ip")
            or event.get("dst_ip")
            or event.get("remote_ip")
        )

        if process and event_type in (
            "PROCESS_EXEC",
            "PROCESS_EXIT",
            "FILE_READ",
            "FILE_WRITE",
            "NETWORK_CONNECT",
            "NETWORK_SEND",
        ):
            process_name = os.path.basename(str(process))
            process_id = f"process:{process_name}"

            add_node(
                process_id,
                process_name,
                "process",
            )

            if process_name not in process_nodes:
                process_nodes.append(process_name)

        if file_path and event_type in (
            "FILE_READ",
            "FILE_WRITE",
        ):
            file_name = os.path.basename(str(file_path))

            if file_name:
                file_id = f"file:{file_name}"

                add_node(
                    file_id,
                    file_name,
                    "file",
                )

                if file_name not in file_nodes:
                    file_nodes.append(file_name)

        if destination and event_type in (
            "NETWORK_CONNECT",
            "NETWORK_SEND",
        ):
            destination = str(destination)

            network_id = f"network:{destination}"

            add_node(
                network_id,
                destination,
                "network",
            )

            if destination not in network_nodes:
                network_nodes.append(destination)

    # If the event buffer no longer contains the original events,
    # retain the important threat target as a graph node.
    if target:
        target_text = str(target)

        if "/" in target_text:
            target_text = target_text.split("/")[-1]

        if target_text:
            add_node(
                "workload:" + target_text,
                target_text,
                "workload",
            )

    # Process → file relationships
    for process_name in process_nodes:
        process_id = f"process:{process_name}"

        for file_name in file_nodes:
            edges.append({
                "source": process_id,
                "target": f"file:{file_name}",
                "label": "FILE_ACTIVITY",
            })

    # Last process → network destination
    if process_nodes and network_nodes:
        last_process = process_nodes[-1]

        for destination in network_nodes:
            edges.append({
                "source": f"process:{last_process}",
                "target": f"network:{destination}",
                "label": "CONNECTS_TO",
            })

    # Process chain
    for i in range(len(process_nodes) - 1):
        edges.append({
            "source": f"process:{process_nodes[i]}",
            "target": f"process:{process_nodes[i + 1]}",
            "label": "FOLLOWS",
        })

    return {
        "nodes": nodes,
        "edges": edges,
        "has_incident": True,
        "attack_type": attack_type,
        "target": target,
        "risk_score": state.get("risk_score"),
        "severity": state.get("severity"),
        "status": state.get("status"),
        "updated_at": state.get("updated_at"),
    }
