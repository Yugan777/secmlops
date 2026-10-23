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

        Avoid duplicate edges between the same source and target for the
        same relationship type when events are processed repeatedly.
        """

        existing = self.graph.get_edge_data(source, target, default={})

        for key, data in existing.items():
            if data.get("relationship") == relationship:
                if timestamp:
                    data["timestamp"] = timestamp
                data.update(attributes)
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
        elif process:
            process_node = f"process:{process}:{pid}" if pid else f"process:{process}"

        if process_node:
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

            if parent_exec_id and process_node:

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

        elif event_type in ("FILE_READ", "FILE_WRITE", "FILE_ACCESS"):

            file_path = event.get("file_path") or event.get("file")

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
                    if event_type == "FILE_WRITE"
                    else "ACCESSED"
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

        elif event_type in ("NETWORK_CONNECT", "NETWORK_SEND"):

            destination_ip = event.get("destination_ip") or event.get("dst_ip")

            if destination_ip and process_node:

                ip_node = f"ip:{destination_ip}"

                self._add_node(
                    ip_node,
                    "IP",
                    address=str(destination_ip)
                )

                relationship = (
                    "CONNECTED_TO"
                    if event_type == "NETWORK_CONNECT"
                    else "SENT_TO"
                )

                self._add_edge(
                    process_node,
                    ip_node,
                    relationship,
                    timestamp,
                    destination_port=event.get("destination_port") or event.get("dport"),
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

    def build_from_events(self, events):
        """
        Populate the graph from an iterable of normalized events.
        """
        if not events:
            return
        for event in events:
            self.add_event(event)

    def build_from_threat(self, threat):
        """
        Reconstruct graph relationships from a detected threat dictionary.
        Uses process ancestry, sensitive file access, and network connections.
        """
        if not threat or not isinstance(threat, dict):
            return

        pod = threat.get("pod")
        namespace = threat.get("namespace", "default")
        processes = threat.get("processes", [])

        for p in processes:
            self.add_event({
                "event_type": "PROCESS_EXEC",
                "timestamp": p.get("timestamp"),
                "process": p.get("process"),
                "pid": p.get("pid"),
                "exec_id": p.get("exec_id"),
                "parent_exec_id": p.get("parent_exec_id"),
                "pod": p.get("pod", pod),
                "namespace": p.get("namespace", namespace),
            })

        # Connect file access to the file reader process
        if threat.get("file"):
            file_proc = None
            for p in processes:
                proc_name = (p.get("process") or "").lower()
                if "cat" in proc_name or "grep" in proc_name:
                    file_proc = p
                    break
            if not file_proc and len(processes) > 1:
                file_proc = processes[1]
            elif not file_proc and processes:
                file_proc = processes[0]

            self.add_event({
                "event_type": "FILE_READ",
                "timestamp": processes[1].get("timestamp") if len(processes) > 1 else (processes[0].get("timestamp") if processes else None),
                "process": file_proc.get("process") if file_proc else "/bin/cat",
                "pid": file_proc.get("pid") if file_proc else None,
                "exec_id": file_proc.get("exec_id") if file_proc else None,
                "pod": pod,
                "namespace": namespace,
                "file_path": threat.get("file"),
            })

        # Connect network event to the network process
        if threat.get("destination_ip"):
            net_proc = None
            for p in processes:
                proc_name = (p.get("process") or "").lower()
                if "wget" in proc_name or "curl" in proc_name:
                    net_proc = p
                    break
            if not net_proc and processes:
                net_proc = processes[-1]

            self.add_event({
                "event_type": "NETWORK_CONNECT",
                "timestamp": processes[-1].get("timestamp") if processes else None,
                "process": net_proc.get("process") if net_proc else "/bin/wget",
                "pid": net_proc.get("pid") if net_proc else None,
                "exec_id": net_proc.get("exec_id") if net_proc else None,
                "pod": pod,
                "namespace": namespace,
                "destination_ip": threat.get("destination_ip"),
            })

    def to_dict(self):
        """
        Export graph representation to a clean dictionary structure
        suitable for JSON serialization and API / UI rendering.
        """
        import os

        nodes = []
        edges = []
        seen_nodes = set()

        def get_node_label(node_id, data):
            ntype = data.get("node_type", "")
            if ntype == "POD":
                return data.get("name") or node_id.split(":")[-1]
            elif ntype == "PROCESS":
                binary = data.get("binary") or data.get("process")
                if binary:
                    return os.path.basename(str(binary))
                parts = node_id.split(":")
                val = parts[-1] if len(parts) > 1 else node_id
                if val.startswith("exec-"):
                    return val.replace("exec-", "")
                if len(val) > 16 and "=" in val:
                    return "parent_process"
                return val
            elif ntype == "FILE":
                path = data.get("path")
                if path:
                    return os.path.basename(str(path))
                return node_id.replace("file:", "")
            elif ntype == "IP":
                return data.get("address") or node_id.replace("ip:", "")
            return node_id

        # Logical sequential order:
        # Pod -> Root Process -> Spawned Process(es) -> File(s) -> Network Destination(s)
        pod_nodes = []
        root_process_nodes = []
        child_process_nodes = []
        file_nodes = []
        network_nodes = []
        other_nodes = []

        spawned_targets = set()
        for s, t, d in self.graph.edges(data=True):
            if d.get("relationship") == "SPAWNED":
                spawned_targets.add(t)

        for node_id, data in self.graph.nodes(data=True):
            ntype = data.get("node_type", "").upper()
            if ntype == "POD":
                pod_nodes.append((node_id, data))
            elif ntype == "PROCESS":
                if node_id in spawned_targets:
                    child_process_nodes.append((node_id, data))
                else:
                    root_process_nodes.append((node_id, data))
            elif ntype == "FILE":
                file_nodes.append((node_id, data))
            elif ntype == "IP":
                network_nodes.append((node_id, data))
            else:
                other_nodes.append((node_id, data))

        ordered_nodes = (
            pod_nodes +
            root_process_nodes +
            child_process_nodes +
            file_nodes +
            network_nodes +
            other_nodes
        )

        for node_id, data in ordered_nodes:
            if node_id in seen_nodes:
                continue
            seen_nodes.add(node_id)
            label = get_node_label(node_id, data)
            ntype = data.get("node_type", "ENTITY").lower()
            if ntype == "ip":
                ntype = "network"

            node_dict = {
                "id": str(node_id),
                "label": label,
                "type": ntype,
            }
            if data.get("binary"):
                node_dict["binary"] = data.get("binary")
            if data.get("pid"):
                node_dict["pid"] = data.get("pid")
            if data.get("path"):
                node_dict["path"] = data.get("path")
            if data.get("address"):
                node_dict["address"] = data.get("address")
            if data.get("name"):
                node_dict["name"] = data.get("name")
            if data.get("namespace"):
                node_dict["namespace"] = data.get("namespace")

            nodes.append(node_dict)

        node_label_map = {n["id"]: n["label"] for n in nodes}

        for source, target, data in self.graph.edges(data=True):
            rel = data.get("relationship", "RELATED")
            edge_dict = {
                "source": str(source),
                "target": str(target),
                "source_label": node_label_map.get(source, str(source)),
                "target_label": node_label_map.get(target, str(target)),
                "label": rel,
                "relationship": rel,
            }
            if data.get("timestamp"):
                edge_dict["timestamp"] = data.get("timestamp")
            if data.get("destination_port"):
                edge_dict["destination_port"] = data.get("destination_port")
            if data.get("protocol"):
                edge_dict["protocol"] = data.get("protocol")

            edges.append(edge_dict)

        return {
            "nodes": nodes,
            "edges": edges,
            "attack_chain": self.get_attack_chain(),
            "has_incident": len(nodes) > 0,
        }
