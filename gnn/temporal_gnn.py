import torch
import torch.nn as nn
import torch.nn.functional as F

from torch_geometric.nn import GCNConv, global_mean_pool


class TemporalGNN(nn.Module):
    """
    Small CPU-friendly Temporal GNN prototype.

    Input:
        x            -> node features
        edge_index   -> graph connectivity
        timestamps   -> normalized temporal feature per node
        batch        -> graph ID for each node

    Output:
        graph-level logits for:
            0 = benign
            1 = suspicious
    """

    def __init__(
        self,
        input_dim=8,
        hidden_dim=32,
        output_dim=2,
    ):
        super().__init__()

        self.gcn1 = GCNConv(
            input_dim,
            hidden_dim
        )

        self.gcn2 = GCNConv(
            hidden_dim,
            hidden_dim
        )

        self.temporal_layer = nn.Linear(
            1,
            hidden_dim
        )

        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim, 16),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(16, output_dim)
        )

    def forward(
        self,
        x,
        edge_index,
        timestamps,
        batch,
    ):

        # ---------------------------------------------
        # GRAPH REPRESENTATION
        # ---------------------------------------------

        x = self.gcn1(
            x,
            edge_index
        )

        x = F.relu(x)

        x = self.gcn2(
            x,
            edge_index
        )

        x = F.relu(x)

        # ---------------------------------------------
        # TEMPORAL INFORMATION
        # ---------------------------------------------

        timestamps = timestamps.view(-1, 1)

        temporal_features = self.temporal_layer(
            timestamps
        )

        temporal_features = F.relu(
            temporal_features
        )

        # Combine graph + temporal information

        x = x + temporal_features

        # ---------------------------------------------
        # GRAPH-LEVEL REPRESENTATION
        # ---------------------------------------------

        graph_embedding = global_mean_pool(
            x,
            batch
        )

        # ---------------------------------------------
        # CLASSIFICATION
        # ---------------------------------------------

        logits = self.classifier(
            graph_embedding
        )

        return logits


if __name__ == "__main__":

    # Simple standalone sanity test

    x = torch.tensor([
        [1.0, 0, 0, 0, 0, 0, 0, 0],
        [0, 1.0, 0, 0, 0, 0, 0, 0],
        [0, 0, 1.0, 0, 0, 0, 0, 0],
    ])

    edge_index = torch.tensor([
        [0, 1, 2],
        [1, 2, 0],
    ], dtype=torch.long)

    timestamps = torch.tensor([
        0.0,
        0.5,
        1.0,
    ])

    batch = torch.zeros(
        x.size(0),
        dtype=torch.long
    )

    model = TemporalGNN(
        input_dim=8,
        hidden_dim=32,
        output_dim=2
    )

    output = model(
        x,
        edge_index,
        timestamps,
        batch
    )

    probabilities = torch.softmax(
        output,
        dim=1
    )

    print("Model:")
    print(model)

    print("\nLogits:")
    print(output)

    print("\nProbabilities:")
    print(probabilities)

    print("\nPredicted class:")
    print(torch.argmax(probabilities, dim=1))
