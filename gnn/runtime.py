import torch
from torch_geometric.data import Data

from gnn.temporal_gnn import TemporalGNN


MODEL_PATH = "gnn/temporal_gnn.pt"


class GNNRuntime:

    def __init__(self):

        self.device = torch.device("cpu")

        self.model = TemporalGNN(
            input_dim=8,
            hidden_dim=32,
            output_dim=2
        ).to(self.device)

        self.model.load_state_dict(
            torch.load(
                MODEL_PATH,
                map_location=self.device
            )
        )

        self.model.eval()

    def _build_graph(self, detection):

        processes = detection.get("processes", [])

        nodes = []
        timestamps = []
        edges = []

        # --------------------------------------------------
        # Process nodes
        # --------------------------------------------------

        process_indices = {}

        for index, process in enumerate(processes):

            process_name = (
                process.get("process")
                or process.get("binary")
                or "UNKNOWN"
            )

            process_indices[process_name] = len(nodes)

            # Base process feature
            feature = [
                1,  # process
                0,  # file
                0,  # network
                0,  # secondary process
                0,  # sensitive
                0,  # external
                0,  # additional process
                0
            ]

            if index > 0:
                feature[3] = 1

            if index > 1:
                feature[6] = 1

            nodes.append(feature)

            timestamps.append(
                float(index)
            )

        # --------------------------------------------------
        # Connect process chain
        # --------------------------------------------------

        for index in range(len(processes) - 1):

            edges.append([
                index,
                index + 1
            ])

        # --------------------------------------------------
        # File node
        # --------------------------------------------------

        file_path = detection.get("file")

        if file_path:

            file_index = len(nodes)

            nodes.append([
                0,  # process
                1,  # file
                0,  # network
                0,
                1,  # sensitive resource
                0,
                0,
                0
            ])

            timestamps.append(
                float(len(processes))
            )

            if processes:

                edges.append([
                    max(0, len(processes) - 1),
                    file_index
                ])

        # --------------------------------------------------
        # Network node
        # --------------------------------------------------

        destination_ip = detection.get(
            "destination_ip"
        )

        if destination_ip:

            network_index = len(nodes)

            nodes.append([
                0,  # process
                0,
                1,  # network
                0,
                0,
                1,  # external
                0,
                0
            ])

            timestamps.append(
                float(len(processes) + 1)
            )

            if processes:

                edges.append([
                    len(processes) - 1,
                    network_index
                ])

        # --------------------------------------------------
        # Safety handling
        # --------------------------------------------------

        if not nodes:

            return None

        x = torch.tensor(
            nodes,
            dtype=torch.float
        )

        timestamps = torch.tensor(
            timestamps,
            dtype=torch.float
        )

        if edges:

            edge_index = torch.tensor(
                edges,
                dtype=torch.long
            ).t().contiguous()

        else:

            edge_index = torch.empty(
                (2, 0),
                dtype=torch.long
            )

        batch = torch.zeros(
            x.size(0),
            dtype=torch.long
        )

        return Data(
            x=x,
            edge_index=edge_index,
            timestamps=timestamps,
            batch=batch
        )

    def predict(self, detection):

        graph = self._build_graph(detection)

        if graph is None:

            return {
                "available": False,
                "suspicious_probability": 0.0,
                "prediction": 0
            }

        graph = graph.to(self.device)

        with torch.no_grad():

            logits = self.model(
                graph.x,
                graph.edge_index,
                graph.timestamps,
                graph.batch
            )

            probabilities = torch.softmax(
                logits,
                dim=1
            )

        benign_probability = (
            probabilities[0, 0].item()
        )

        suspicious_probability = (
            probabilities[0, 1].item()
        )

        prediction = int(
            suspicious_probability >= 0.5
        )

        return {
            "available": True,
            "benign_probability": round(
                benign_probability,
                4
            ),
            "suspicious_probability": round(
                suspicious_probability,
                4
            ),
            "prediction": prediction
        }
