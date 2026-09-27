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


# --------------------------------------------------
# Reproducibility
# --------------------------------------------------

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
# Load trained model
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
# Inference
# --------------------------------------------------

predictions = []
labels = []
probabilities = []

with torch.no_grad():

    for batch in test_loader:

        batch = batch.to(device)

        logits = model(
            batch.x,
            batch.edge_index,
            batch.timestamps,
            batch.batch
        )

        probs = torch.softmax(
            logits,
            dim=1
        )

        predicted = torch.argmax(
            probs,
            dim=1
        )

        predictions.extend(
            predicted.cpu().numpy()
        )

        labels.extend(
            batch.y.cpu().numpy()
        )

        probabilities.extend(
            probs[:, 1].cpu().numpy()
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
print("SEC MLOPS GNN EVALUATION")
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

print("\nSample predictions:")

for i in range(min(10, len(labels))):

    print(
        f"Sample {i+1:02d} | "
        f"Actual={labels[i]} | "
        f"Predicted={predictions[i]} | "
        f"Suspicious Probability={probabilities[i]:.4f}"
    )
