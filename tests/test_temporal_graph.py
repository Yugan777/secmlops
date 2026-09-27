from graph.temporal_graph import TemporalSecurityGraph


graph = TemporalSecurityGraph()


events = [

    {
        "event_type": "PROCESS_EXEC",
        "timestamp": "2026-09-25T18:20:01Z",
        "process": "/bin/sh",
        "pid": 100,
        "exec_id": "exec-sh",
        "parent_exec_id": "exec-init",
        "pod": "telemetry-test",
        "namespace": "security-lab"
    },

    {
        "event_type": "PROCESS_EXEC",
        "timestamp": "2026-09-25T18:20:02Z",
        "process": "/bin/cat",
        "pid": 101,
        "exec_id": "exec-cat",
        "parent_exec_id": "exec-sh",
        "pod": "telemetry-test",
        "namespace": "security-lab"
    },

    {
        "event_type": "FILE_READ",
        "timestamp": "2026-09-25T18:20:03Z",
        "process": "/bin/cat",
        "pid": 101,
        "exec_id": "exec-cat",
        "pod": "telemetry-test",
        "namespace": "security-lab",
        "file_path": "/tmp/secmlops-test/sensitive.txt"
    },

    {
        "event_type": "PROCESS_EXEC",
        "timestamp": "2026-09-25T18:20:04Z",
        "process": "/bin/wget",
        "pid": 102,
        "exec_id": "exec-wget",
        "parent_exec_id": "exec-sh",
        "pod": "telemetry-test",
        "namespace": "security-lab"
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
        "protocol": "IPPROTO_TCP"
    }
]


for event in events:
    graph.add_event(event)


graph.print_graph()
