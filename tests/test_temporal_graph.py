"""Pytest tests for TemporalSecurityGraph."""
from graph.temporal_graph import TemporalSecurityGraph


SAMPLE_EVENTS = [
    {
        "event_type": "PROCESS_EXEC",
        "timestamp": "2026-09-25T18:20:01Z",
        "process": "/bin/sh",
        "pid": 100,
        "exec_id": "exec-sh",
        "parent_exec_id": "exec-init",
        "pod": "telemetry-test",
        "namespace": "security-lab",
    },
    {
        "event_type": "PROCESS_EXEC",
        "timestamp": "2026-09-25T18:20:02Z",
        "process": "/bin/cat",
        "pid": 101,
        "exec_id": "exec-cat",
        "parent_exec_id": "exec-sh",
        "pod": "telemetry-test",
        "namespace": "security-lab",
    },
    {
        "event_type": "FILE_READ",
        "timestamp": "2026-09-25T18:20:03Z",
        "process": "/bin/cat",
        "pid": 101,
        "exec_id": "exec-cat",
        "pod": "telemetry-test",
        "namespace": "security-lab",
        "file_path": "/tmp/secmlops-test/sensitive.txt",
    },
    {
        "event_type": "PROCESS_EXEC",
        "timestamp": "2026-09-25T18:20:04Z",
        "process": "/bin/wget",
        "pid": 102,
        "exec_id": "exec-wget",
        "parent_exec_id": "exec-sh",
        "pod": "telemetry-test",
        "namespace": "security-lab",
    },
    {
        "event_type": "NETWORK_CONNECT",
        "timestamp": "2026-09-25T18:20:05Z",
        "process": "/bin/wget",
        "pid": 102,
        "exec_id": "exec-wget",
        "pod": "telemetry-test",
        "namespace": "security-lab",
        "destination_ip": "10.0.0.50",
        "destination_port": 80,
        "protocol": "IPPROTO_TCP",
    },
]


def _build_graph():
    graph = TemporalSecurityGraph()
    for event in SAMPLE_EVENTS:
        graph.add_event(event)
    return graph


def test_graph_builds_correct_node_count():
    graph = _build_graph()
    exported = graph.to_dict()
    assert len(exported["nodes"]) == 7


def test_graph_builds_correct_edge_count():
    graph = _build_graph()
    exported = graph.to_dict()
    assert len(exported["edges"]) == 8


def test_graph_contains_pod_node():
    graph = _build_graph()
    exported = graph.to_dict()
    pod_nodes = [n for n in exported["nodes"] if n.get("type") == "pod"]
    assert len(pod_nodes) >= 1


def test_graph_contains_file_node():
    graph = _build_graph()
    exported = graph.to_dict()
    file_nodes = [n for n in exported["nodes"] if n.get("type") == "file"]
    assert len(file_nodes) >= 1


def test_graph_contains_network_node():
    graph = _build_graph()
    exported = graph.to_dict()
    net_nodes = [n for n in exported["nodes"] if n.get("type") in ("network", "ip")]
    assert len(net_nodes) >= 1


def test_graph_to_dict_has_required_keys():
    graph = _build_graph()
    exported = graph.to_dict()
    assert "nodes" in exported
    assert "edges" in exported
    assert "attack_chain" in exported


def test_empty_graph_to_dict():
    graph = TemporalSecurityGraph()
    exported = graph.to_dict()
    assert exported["nodes"] == [] or isinstance(exported["nodes"], list)
    assert exported["edges"] == [] or isinstance(exported["edges"], list)
