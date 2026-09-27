import random
import numpy as np
import torch

from torch_geometric.loader import DataLoader
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)

from dataset import create_dataset
from temporal_gnn import TemporalGNN


SEED = 123

random.seed(SEED)
np.random.seed(SEED)
torch.manual_seed(SEED)


# --------------------------------------------------
# Dataset
# --------------------------------------------------

dataset = create_dataset(500)

random.shuffle(dataset)

train_size = int(0.70 * len(dataset))
val_size = int(0.15 * len(dataset))

test_dataset = dataset[
    train_size + val_size:
]

test_loader = DataLoader(
    test_dataset,
    batch_size=32,
    shuffle=False
)


# --------------------------------------------------
# Load trained GNN
# --------------------------------------------------

device = torch.device("cpu")

model = TemporalGNN(
    input_dim=8,
    hidden_dim=32,
    output_dim=2
).to(device)

model.load_state_dict(
    torch.load(
        "gnn/temporal_gnn.pt",
        map_location=device
    )
)

model.eval()


# --------------------------------------------------
# Context validation
# --------------------------------------------------

def validate_context(graph):
    """
    Experimental contextual validation.

    The validator checks whether suspicious activity
    has a coherent temporal and graph relationship.

    This is NOT formal causal inference.
    """

    x = graph.x
    timestamps = graph.timestamps
    edge_index = graph.edge_index

    has_sensitive_file = False
    has_network = False
    process_count = 0

    for node in x:

        # process
        if node[0].item() == 1:
            process_count += 1

        # file + sensitive marker
        if (
            node[1].item() == 1
            and node[4].item() == 1
        ):
            has_sensitive_file = True

        # network + external marker
        if (
            node[2].item() == 1
            and node[5].item() == 1
        ):
            has_network = True

    # Temporal span
    if len(timestamps) > 1:
        temporal_span = (
            float(torch.max(timestamps))
            - float(torch.min(timestamps))
        )
    else:
        temporal_span = 0.0

    temporal_proximity = temporal_span <= 5.0

    # Graph connectivity
    graph_has_edges = edge_index.size(1) > 0

    # Context score
    score = 0.0

    if has_sensitive_file:
        score += 0.35

    if has_network:
        score += 0.25

    if process_count >= 2:
        score += 0.15

    if temporal_proximity:
        score += 0.15

    if graph_has_edges:
        score += 0.10

    score = min(score, 1.0)

    return score


# --------------------------------------------------
# Combined evaluation
# --------------------------------------------------

labels = []
predictions = []
gnn_predictions = []

for batch in test_loader:

    batch = batch.to(device)

    with torch.no_grad():

        logits = model(
            batch.x,
            batch.edge_index,
            batch.timestamps,
            batch.batch
        )

        probabilities = torch.softmax(
            logits,
            dim=1
        )

    gnn_pred = torch.argmax(
        probabilities,
        dim=1
    )

    # Individual graphs in the batch
    for i, graph_label in enumerate(batch.y):

        graph_probability = probabilities[i, 1].item()

        # Reconstruct individual graph
        node_mask = batch.batch == i

        graph = type(
            "Graph",
            (),
            {
                "x": batch.x[node_mask].cpu(),
                "timestamps": batch.timestamps[node_mask].cpu(),
                "edge_index": batch.edge_index.cpu()
            }
        )

        context_score = validate_context(graph)

        # Combined decision
        #
        # GNN must indicate suspicion AND
        # contextual evidence must be strong.
        combined_prediction = int(
            graph_probability >= 0.5
            and context_score >= 0.60
        )

        labels.append(
            graph_label.item()
        )

        predictions.append(
            combined_prediction
        )

        gnn_predictions.append(
            gnn_pred[i].item()
        )


# --------------------------------------------------
# Metrics
# --------------------------------------------------

accuracy = accuracy_score(
    labels,
    predictions
)

precision = precision_score(
    labels,
    predictions,
    zero_division=0
)

recall = recall_score(
    labels,
    predictions,
    zero_division=0
)

f1 = f1_score(
    labels,
    predictions,
    zero_division=0
)

cm = confusion_matrix(
    labels,
    predictions
)


# --------------------------------------------------
# Results
# --------------------------------------------------

print("\n================================")
print("GNN + CONTEXT VALIDATION")
print("================================")

print(f"Test samples : {len(labels)}")
print(f"Accuracy     : {accuracy:.4f}")
print(f"Precision    : {precision:.4f}")
print(f"Recall       : {recall:.4f}")
print(f"F1 Score     : {f1:.4f}")

print("\nConfusion Matrix:")
print(cm)

print("\nClass interpretation:")
print("0 = BENIGN")
print("1 = SUSPICIOUS")
