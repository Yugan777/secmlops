from detection.temporal_detector import TemporalDetector


events = [

    {
        "event_type": "PROCESS_EXEC",
        "timestamp": "2026-09-25T18:20:01Z",
        "process": "/bin/sh",
        "pid": 100,
        "exec_id": "exec-sh",
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
        "destination_port": 80
    }
]


detector = TemporalDetector(
    time_window_seconds=10
)

result = detector.detect(events)


print("\n========== DETECTION RESULT ==========")

if result:
    print("THREAT DETECTED")
    print(f"Attack Type : {result['attack_type']}")
    print(f"Confidence  : {result['confidence']}")
    print(f"Pod         : {result['pod']}")
    print(f"File        : {result['file']}")
    print(f"Destination : {result['destination_ip']}")
    print(
        f"Time Window : "
        f"{result['time_window_seconds']} seconds"
    )

    print("\nProcesses in temporal chain:")

    for process in result["processes"]:
        print(
            f"  {process['process']} "
            f"@ {process['timestamp']}"
        )

else:
    print("NO THREAT DETECTED")

print("======================================")
