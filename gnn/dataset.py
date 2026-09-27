import random
import torch
from torch_geometric.data import Data


def make_graph(benign=True):
    """
    Generate one synthetic security provenance graph.

    Labels:
        0 = benign
        1 = suspicious
    """

    nodes = []
    edges = []
    timestamps = []

    # ==================================================
    # BENIGN
    # ==================================================
    if benign:

        scenario = random.choice([
            "normal_file",
            "normal_network",
            "file_then_network",
            "multiple_processes"
        ])

        # ----------------------------------------------
        # Normal file access
        # ----------------------------------------------
        if scenario == "normal_file":

            nodes.append([1, 0, 0, 0, 0, 0, 0, 0])
            timestamps.append(0.0)

            nodes.append([0, 1, 0, 0, 0, 0, 0, 0])
            timestamps.append(random.uniform(0.2, 2.0))

            edges.append([0, 1])

        # ----------------------------------------------
        # Normal network activity
        # ----------------------------------------------
        elif scenario == "normal_network":

            nodes.append([1, 0, 0, 0, 0, 0, 0, 0])
            timestamps.append(0.0)

            nodes.append([0, 0, 1, 0, 0, 0, 0, 0])
            timestamps.append(random.uniform(0.5, 3.0))

            edges.append([0, 1])

        # ----------------------------------------------
        # BENIGN file + network
        #
        # Important hard negative:
        # file access followed by network activity
        # ----------------------------------------------
        elif scenario == "file_then_network":

            nodes.append([1, 0, 0, 0, 0, 0, 0, 0])
            timestamps.append(0.0)

            # Normal file
            nodes.append([0, 1, 0, 0, 0, 0, 0, 0])
            timestamps.append(random.uniform(0.2, 1.0))

            # Normal network destination
            nodes.append([0, 0, 1, 0, 0, 0, 0, 0])
            timestamps.append(random.uniform(1.5, 4.0))

            edges.append([0, 1])
            edges.append([0, 2])

        # ----------------------------------------------
        # Multiple benign processes
        # ----------------------------------------------
        elif scenario == "multiple_processes":

            nodes.append([1, 0, 0, 0, 0, 0, 0, 0])
            timestamps.append(0.0)

            nodes.append([1, 0, 0, 1, 0, 0, 0, 0])
            timestamps.append(random.uniform(0.1, 1.0))

            nodes.append([1, 0, 0, 1, 0, 0, 1, 0])
            timestamps.append(random.uniform(0.5, 2.0))

            edges.append([0, 1])
            edges.append([0, 2])

    # ==================================================
    # SUSPICIOUS
    # ==================================================
    else:

        scenario = random.choice([
            "sensitive_file_network",
            "multi_stage_attack",
            "privileged_chain"
        ])

        # ----------------------------------------------
        # Sensitive file → network
        # ----------------------------------------------
        if scenario == "sensitive_file_network":

            # Shell
            nodes.append([1, 0, 0, 0, 0, 0, 0, 0])
            timestamps.append(0.0)

            # Sensitive file
            nodes.append([0, 1, 0, 0, 1, 0, 0, 0])
            timestamps.append(random.uniform(0.2, 1.0))

            # External network
            nodes.append([0, 0, 1, 0, 0, 1, 0, 0])
            timestamps.append(random.uniform(1.0, 2.5))

            edges.append([0, 1])
            edges.append([0, 2])

        # ----------------------------------------------
        # Multi-stage attack
        # ----------------------------------------------
        elif scenario == "multi_stage_attack":

            nodes.append([1, 0, 0, 0, 0, 0, 0, 0])
            timestamps.append(0.0)

            nodes.append([1, 0, 0, 1, 0, 0, 0, 0])
            timestamps.append(random.uniform(0.1, 0.8))

            nodes.append([0, 1, 0, 0, 1, 0, 0, 0])
            timestamps.append(random.uniform(0.8, 1.8))

            nodes.append([0, 0, 1, 0, 0, 1, 0, 0])
            timestamps.append(random.uniform(1.8, 3.0))

            edges.append([0, 1])
            edges.append([1, 2])
            edges.append([1, 3])

        # ----------------------------------------------
        # Privileged process chain
        # ----------------------------------------------
        elif scenario == "privileged_chain":

            nodes.append([1, 0, 0, 0, 0, 0, 0, 0])
            timestamps.append(0.0)

            nodes.append([1, 0, 0, 1, 0, 0, 0, 0])
            timestamps.append(random.uniform(0.1, 0.7))

            nodes.append([0, 1, 0, 0, 1, 0, 0, 0])
            timestamps.append(random.uniform(0.7, 1.5))

            nodes.append([0, 0, 1, 0, 0, 1, 0, 0])
            timestamps.append(random.uniform(1.5, 2.5))

            edges.append([0, 1])
            edges.append([1, 2])
            edges.append([2, 3])

    x = torch.tensor(nodes, dtype=torch.float)

    edge_index = torch.tensor(
        edges,
        dtype=torch.long
    ).t().contiguous()

    timestamps = torch.tensor(
        timestamps,
        dtype=torch.float
    )

    y = torch.tensor(
        [1 if not benign else 0],
        dtype=torch.long
    )

    return Data(
        x=x,
        edge_index=edge_index,
        timestamps=timestamps,
        y=y
    )


def create_dataset(num_samples=500):

    dataset = []

    half = num_samples // 2

    for _ in range(half):
        dataset.append(
            make_graph(benign=True)
        )

    for _ in range(half):
        dataset.append(
            make_graph(benign=False)
        )

    random.shuffle(dataset)

    return dataset


if __name__ == "__main__":

    dataset = create_dataset(10)

    print(f"Dataset size: {len(dataset)}")

    for i, graph in enumerate(dataset[:5]):

        print(f"\nGraph {i}")
        print("Nodes:", graph.x.shape)
        print("Edges:", graph.edge_index.shape)
        print("Timestamps:", graph.timestamps)
        print("Label:", graph.y.item())
