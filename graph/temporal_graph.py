import networkx as nx
from datetime import datetime, timezone


class TemporalSecurityGraph:

    def __init__(self, max_age_seconds=300):
        """
        Temporal security graph.

        Nodes:
        - Process
        - File
        - IP
        - Pod

        Edges:
        - RUNS
        - SPAWNED
        - READ
        - MODIFIED
        - CONNECTED_TO

        Only relationships inside max_age_seconds are retained.
        """

        self.graph = nx.MultiDiGraph()
        self.max_age_seconds = max_age_seconds

    def _parse_timestamp(self, timestamp):
        if not timestamp:
            return None

        return datetime.fromisoformat(
            timestamp.replace("Z", "+00:00")
        )

    def _add_node(self, node_id, node_type, **attributes):
        self.graph.add_node(
            node_id,
            node_type=node_type,
            **attributes
        )

    def _add_edge(
        self,
        source,
        target,
        relationship,
        timestamp,
        **attributes
    ):
        """
        Add a timestamped relationship.

        RUNS is structural, so duplicate RUNS edges are avoided.
        Other relationships remain event-based and may occur multiple times.
        """

        if relationship == "RUNS":

            existing = self.graph.get_edge_data(source, target, default={})

            for key, data in existing.items():
                if data.get("relationship") == "RUNS":
                    data["timestamp"] = timestamp
                    return

        self.graph.add_edge(
            source,
            target,
            relationship=relationship,
            timestamp=timestamp,
            **attributes
        )

    def _prune_old_edges(self, current_timestamp):
        """
        Remove relationships older than max_age_seconds.
        """

        current_time = self._parse_timestamp(current_timestamp)

        if current_time is None:
            return

        edges_to_remove = []

        for source, target, key, data in self.graph.edges(
            keys=True,
            data=True
        ):
            edge_timestamp = self._parse_timestamp(
                data.get("timestamp")
            )

            if edge_timestamp is None:
                continue

            age = (
                current_time - edge_timestamp
            ).total_seconds()

            if age > self.max_age_seconds:
                edges_to_remove.append(
                    (source, target, key)
                )

        for source, target, key in edges_to_remove:
            self.graph.remove_edge(
                source,
                target,
                key
            )

        self._remove_orphan_nodes()

    def _remove_orphan_nodes(self):
        """
        Remove nodes that no longer participate in any relationship.

        Pod nodes are retained because they represent the workload context.
        """

        nodes_to_remove = []

        for node, data in self.graph.nodes(data=True):

            if data.get("node_type") == "POD":
                continue

            if self.graph.degree(node) == 0:
                nodes_to_remove.append(node)

        for node in nodes_to_remove:
            self.graph.remove_node(node)

    def add_event(self, event):
        """
        Convert a normalized SecMLOps event into graph entities
        and relationships.
        """

        event_type = event.get("event_type")
        timestamp = event.get("timestamp")

        if not timestamp:
            return

        # Keep only recent temporal context.
        self._prune_old_edges(timestamp)

        process = event.get("process")
        pid = event.get("pid")
        exec_id = event.get("exec_id")

        pod = event.get("pod")
        namespace = event.get("namespace")

        # --------------------------------------------------
        # PROCESS NODE
        # --------------------------------------------------

        process_node = None

        if exec_id:

            process_node = f"process:{exec_id}"

            self._add_node(
                process_node,
                "PROCESS",
                binary=process,
                pid=pid,
                pod=pod,
                namespace=namespace
            )

        # --------------------------------------------------
        # POD NODE
        # --------------------------------------------------

        if pod and namespace:

            pod_node = f"pod:{namespace}:{pod}"

            self._add_node(
                pod_node,
                "POD",
                name=pod,
                namespace=namespace
            )

            if process_node:

                self._add_edge(
                    pod_node,
                    process_node,
                    "RUNS",
                    timestamp
                )

        # --------------------------------------------------
        # PROCESS EXECUTION
        # --------------------------------------------------

        if event_type == "PROCESS_EXEC":

            parent_exec_id = event.get("parent_exec_id")

            if parent_exec_id and exec_id:

                parent_node = f"process:{parent_exec_id}"

                self._add_node(
                    parent_node,
                    "PROCESS"
                )

                self._add_edge(
                    parent_node,
                    process_node,
                    "SPAWNED",
                    timestamp
                )

        # --------------------------------------------------
        # FILE ACCESS
        # --------------------------------------------------

        elif event_type in ("FILE_READ", "FILE_WRITE"):

            file_path = event.get("file_path")

            if file_path and process_node:

                file_node = f"file:{file_path}"

                self._add_node(
                    file_node,
                    "FILE",
                    path=file_path
                )

                relationship = (
                    "READ"
                    if event_type == "FILE_READ"
                    else "MODIFIED"
                )

                self._add_edge(
                    process_node,
                    file_node,
                    relationship,
                    timestamp
                )

        # --------------------------------------------------
        # NETWORK CONNECTION
        # --------------------------------------------------

        elif event_type == "NETWORK_CONNECT":

            destination_ip = event.get("destination_ip")

            if destination_ip and process_node:

                ip_node = f"ip:{destination_ip}"

                self._add_node(
                    ip_node,
                    "IP",
                    address=destination_ip
                )

                self._add_edge(
                    process_node,
                    ip_node,
                    "CONNECTED_TO",
                    timestamp,
                    destination_port=event.get(
                        "destination_port"
                    ),
                    protocol=event.get("protocol")
                )

    def print_graph(self):
        """
        Print a human-readable representation of the graph.
        """

        print("\n========== TEMPORAL SECURITY GRAPH ==========")

        print(
            f"Nodes : {self.graph.number_of_nodes()}"
        )

        print(
            f"Edges : {self.graph.number_of_edges()}"
        )

        print("\nNODES:")

        for node, data in self.graph.nodes(data=True):

            print(
                f"  {node} "
                f"[{data.get('node_type')}]"
            )

        print("\nRELATIONSHIPS:")

        for source, target, data in self.graph.edges(
            data=True
        ):

            print(
                f"  {source}"
                f" --{data.get('relationship')}--> "
                f"{target}"
                f" @ {data.get('timestamp')}"
            )

        print(
            "=============================================\n"
        )
    def get_attack_chain(self):
        """
        Return a readable attack chain using process metadata
        stored in the graph.
        """

        chain = []

        for source, target, data in self.graph.edges(data=True):

            relationship = data.get("relationship")

            # Ignore pod/process bookkeeping
            if relationship == "RUNS":
                continue

            source_data = self.graph.nodes.get(source, {})
            target_data = self.graph.nodes.get(target, {})

            # -----------------------------
            # SOURCE NAME
            # -----------------------------
            source_name = (
                source_data.get("binary")
                or source_data.get("process")
                or source_data.get("name")
            )

            if not source_name:
                if source.startswith("process:"):
                    source_name = "PROCESS"
                elif source.startswith("pod:"):
                    source_name = source.replace("pod:", "")
                else:
                    source_name = source

            # -----------------------------
            # TARGET NAME
            # -----------------------------
            target_name = (
                target_data.get("binary")
                or target_data.get("process")
                or target_data.get("name")
                or target_data.get("path")
                or target_data.get("address")
            )

            if not target_name:

                if target.startswith("file:"):
                    target_name = target.replace("file:", "")

                elif target.startswith("ip:"):
                    target_name = target.replace("ip:", "")

                elif target.startswith("process:"):
                    target_name = "PROCESS"

                else:
                    target_name = target

            item = (
                source_name,
                relationship,
                target_name
            )

            if item not in chain:
                chain.append(item)

        return chain

    def print_attack_chain(self):
        """
        Print a simplified human-readable attack chain.
        """

        print("\n========== ATTACK CHAIN ==========")

        chain = self.get_attack_chain()

        if not chain:
            print("  No attack-chain relationships available.")
        else:
            for source, relationship, target in chain:
                print(
                    f"  {source}"
                    f" --{relationship}--> "
                    f"{target}"
                )

        print("==================================\n")
