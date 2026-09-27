from datetime import datetime


class ContextValidator:
    """
    Context / provenance-aware validation layer.

    This layer does not replace the temporal detector.
    It evaluates how strongly the detected events are
    related to one another using:
        - workload context
        - process ancestry
        - temporal proximity
        - sensitive resource access
        - network follow-up
        - event sequence
    """

    def __init__(self, temporal_threshold=10.0):
        self.temporal_threshold = temporal_threshold

    def _parse_time(self, timestamp):
        return datetime.fromisoformat(
            timestamp.replace("Z", "+00:00")
        )

    def _get_process_names(self, processes):
        names = []

        for process in processes:
            name = (
                process.get("process")
                or process.get("binary")
                or "UNKNOWN"
            )

            if name not in names:
                names.append(name)

        return names

    def _check_process_ancestry(self, processes):
        """
        Determine whether the observed processes have
        parent/child relationships.

        Returns True when at least one child process points
        to another process present in the detection chain.
        """

        exec_ids = {
            process.get("exec_id")
            for process in processes
            if process.get("exec_id")
        }

        for process in processes:
            parent_exec_id = process.get("parent_exec_id")

            if parent_exec_id and parent_exec_id in exec_ids:
                return True

        return False

    def _check_same_workload(self, processes, detection):
        pod = detection.get("pod")
        namespace = detection.get("namespace")

        if not pod:
            return False

        for process in processes:
            if process.get("pod") != pod:
                return False

            if namespace and process.get("namespace") != namespace:
                return False

        return True

    def _check_temporal_proximity(self, detection):
        delta = detection.get("time_window_seconds")

        if delta is None:
            return False

        try:
            return float(delta) <= self.temporal_threshold
        except (TypeError, ValueError):
            return False

    def _check_sensitive_resource(self, detection):
        return bool(detection.get("file"))

    def _check_network_followup(self, detection):
        return bool(detection.get("destination_ip"))

    def _check_sequence(self, detection):
        """
        Validate the observed high-level sequence.

        Expected suspicious sequence:

            process activity
                 ↓
            sensitive file access
                 ↓
            network activity
        """

        processes = detection.get("processes", [])

        if not processes:
            return False

        has_file = bool(detection.get("file"))
        has_network = bool(detection.get("destination_ip"))
        has_multi_stage = (
            detection.get("attack_type") == "MULTI_STAGE_ACTIVITY"
        )

        return (
            has_multi_stage
            and len(processes) >= 2
            and has_file
            and has_network
        )

    def validate(self, detection):
        """
        Produce structured contextual/provenance evidence.
        """

        if not detection:
            return {
                "validated": False,
                "context_score": 0.0,
                "evidence": []
            }

        processes = detection.get("processes", [])

        same_workload = self._check_same_workload(
            processes,
            detection
        )

        process_ancestry = self._check_process_ancestry(
            processes
        )

        temporal_proximity = self._check_temporal_proximity(
            detection
        )

        sensitive_resource = self._check_sensitive_resource(
            detection
        )

        network_followup = self._check_network_followup(
            detection
        )

        sequence_consistent = self._check_sequence(
            detection
        )

        # ---------------------------------------------------------
        # Context score
        #
        # This is an experimental contextual-strength score,
        # NOT a probability and NOT a universal security standard.
        # ---------------------------------------------------------

        score = 0.0

        if same_workload:
            score += 0.20

        if process_ancestry:
            score += 0.20

        if temporal_proximity:
            score += 0.15

        if sensitive_resource:
            score += 0.15

        if network_followup:
            score += 0.15

        if sequence_consistent:
            score += 0.15

        score = round(min(score, 1.0), 2)

        # ---------------------------------------------------------
        # Evidence
        # ---------------------------------------------------------

        evidence = []

        if same_workload:
            evidence.append(
                "Observed processes belong to the same workload"
            )

        if process_ancestry:
            evidence.append(
                "Process ancestry links the observed activities"
            )

        if temporal_proximity:
            evidence.append(
                "Events occur within the temporal correlation window"
            )

        if sensitive_resource:
            evidence.append(
                "Sensitive resource access is present"
            )

        if network_followup:
            evidence.append(
                "Network activity follows the observed activity"
            )

        if sequence_consistent:
            evidence.append(
                "Observed event sequence is consistent with multi-stage activity"
            )

        process_names = self._get_process_names(processes)

        return {
            "validated": score >= 0.60,
            "context_score": score,

            "same_workload": same_workload,
            "process_ancestry": process_ancestry,
            "temporal_proximity": temporal_proximity,
            "sensitive_resource": sensitive_resource,
            "network_followup": network_followup,
            "sequence_consistent": sequence_consistent,

            "process_chain": process_names,
            "evidence": evidence
        }

