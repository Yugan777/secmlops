from datetime import datetime


class TemporalDetector:
    def __init__(self, time_window_seconds=10):
        self.time_window_seconds = time_window_seconds

    def _parse_time(self, timestamp):
        return datetime.fromisoformat(timestamp.replace("Z", "+00:00"))

    def _get_process_ancestry(self, exec_id, process_map, parent_map):
        """
        Walk backwards through parent_exec_id relationships.
        Returns processes from oldest ancestor to the requested process.
        """
        ancestry = []
        current = exec_id
        visited = set()

        while current and current not in visited:
            visited.add(current)

            process = process_map.get(current)
            if not process:
                break

            ancestry.append(process)

            current = parent_map.get(current)

        ancestry.reverse()
        return ancestry

    def detect(self, events):
        """
        Detect:

            FILE_READ
                +
            NETWORK_CONNECT

        occurring within the configured time window
        inside the same pod.

        The resulting process chain includes:
        - ancestors of the file-read process
        - the file-read process
        - ancestors of the network process
        - the network process
        """

        if not events:
            return None

        events = sorted(
            events,
            key=lambda event: self._parse_time(event["timestamp"])
        )

        # ---------------------------------------------------------
        # Build process relationships
        # ---------------------------------------------------------

        process_map = {}
        parent_map = {}

        for event in events:
            if event.get("event_type") == "PROCESS_EXEC":
                exec_id = event.get("exec_id")

                if exec_id:
                    process_map[exec_id] = event

                    parent_exec_id = event.get("parent_exec_id")

                    if parent_exec_id:
                        parent_map[exec_id] = parent_exec_id

        # ---------------------------------------------------------
        # Find FILE_READ -> NETWORK_CONNECT
        # ---------------------------------------------------------

        file_reads = [
            event
            for event in events
            if event.get("event_type") == "FILE_READ"
        ]

        network_events = [
            event
            for event in events
            if event.get("event_type") == "NETWORK_CONNECT"
        ]

        for file_event in file_reads:

            file_time = self._parse_time(file_event["timestamp"])

            for network_event in network_events:

                network_time = self._parse_time(
                    network_event["timestamp"]
                )

                delta = (network_time - file_time).total_seconds()

                # Network event must occur after file access
                if delta < 0:
                    continue

                # Must happen inside temporal window
                if delta > self.time_window_seconds:
                    continue

                # Same pod
                if file_event.get("pod") != network_event.get("pod"):
                    continue

                # -------------------------------------------------
                # Identify processes
                # -------------------------------------------------

                file_exec_id = file_event.get("exec_id")
                network_exec_id = network_event.get("exec_id")

                file_process = process_map.get(file_exec_id)
                network_process = process_map.get(network_exec_id)

                # -------------------------------------------------
                # Build process chain
                # -------------------------------------------------

                chain = []

                # -------------------------------------------------
                # 1. Get ancestry of the file-read process
                # -------------------------------------------------

                if file_exec_id:
                    chain.extend(
                        self._get_process_ancestry(
                            file_exec_id,
                            process_map,
                            parent_map
                        )
                    )

                # -------------------------------------------------
                # 2. Get the process that performed FILE_READ
                # -------------------------------------------------

                if file_process:
                    chain.append(file_process)
                else:
                    # FILE_READ may exist without a corresponding
                    # PROCESS_EXEC event.
                    chain.append({
                        "event_type": "PROCESS_EXEC",
                        "timestamp": file_event["timestamp"],
                        "process": file_event.get(
                            "process",
                            "UNKNOWN"
                        ),
                        "binary": file_event.get(
                            "process",
                            "UNKNOWN"
                        ),
                        "pid": file_event.get("pid"),
                        "exec_id": file_exec_id,
                        "pod": file_event.get("pod"),
                        "namespace": file_event.get("namespace")
                    })

                # -------------------------------------------------
                # 3. Get ancestry of the network process
                # -------------------------------------------------

                if network_exec_id:
                    chain.extend(
                        self._get_process_ancestry(
                            network_exec_id,
                            process_map,
                            parent_map
                        )
                    )

                # -------------------------------------------------
                # 4. Add the network process
                # -------------------------------------------------

                if network_process:
                    chain.append(network_process)

                # -------------------------------------------------
                # 5. Remove duplicate processes
                # -------------------------------------------------

                unique_processes = {}

                for process in chain:
                    exec_id = process.get("exec_id")

                    if exec_id:
                        unique_processes[exec_id] = process
                    else:
                        unique_key = (
                            process.get("timestamp"),
                            process.get("process")
                        )

                        unique_processes[unique_key] = process

                chain = list(unique_processes.values())

                # -------------------------------------------------
                # 6. Sort chronologically
                # -------------------------------------------------

                chain.sort(
                    key=lambda event: self._parse_time(
                        event["timestamp"]
                    )
                )

                # -------------------------------------------------
                # Detection result
                # -------------------------------------------------

                return {
                    "detected": True,
                    "attack_type": "MULTI_STAGE_ACTIVITY",
                    "confidence": 0.8,
                    "pod": file_event.get("pod"),
                    "namespace": file_event.get("namespace"),
                    "file": file_event.get("file_path"),
                    "destination_ip": network_event.get(
                        "destination_ip"
                    ),
                    "time_window_seconds": delta,
                    "processes": chain
                }
        return None


def print_detection_result(result):
    """
    Pretty-print detection result.
    """

    print("\n========== DETECTION RESULT ==========")

    if not result:
        print("NO THREAT DETECTED")
        print("======================================")
        return

    print("THREAT DETECTED")
    print(f"Attack Type : {result['attack_type']}")
    print(f"Confidence  : {result['confidence']}")
    print(f"Pod         : {result['pod']}")
    print(f"File        : {result['file']}")
    print(f"Destination : {result['destination']}")
    print(f"Time Window : {result['time_window']} seconds")

    print("\nProcesses in temporal chain:")

    for process in result["process_chain"]:
        binary = process.get("binary", "UNKNOWN")
        timestamp = process.get("timestamp", "UNKNOWN")

        print(f"  {binary} @ {timestamp}")

    print("======================================")
