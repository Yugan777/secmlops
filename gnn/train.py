import random
import numpy as np
import torch
import torch.nn.functional as F

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

SEED = 42

random.seed(SEED)
np.random.seed(SEED)
torch.manual_seed(SEED)


# --------------------------------------------------
# Configuration
# --------------------------------------------------

NUM_SAMPLES = 500
BATCH_SIZE = 32
EPOCHS = 50
LEARNING_RATE = 0.001


# --------------------------------------------------
# Dataset
# --------------------------------------------------

dataset = create_dataset(NUM_SAMPLES)

random.shuffle(dataset)

train_size = int(0.70 * len(dataset))
val_size = int(0.15 * len(dataset))

train_dataset = dataset[:train_size]
val_dataset = dataset[train_size:train_size + val_size]
test_dataset = dataset[train_size + val_size:]

print("Dataset:")
print(f"  Total      : {len(dataset)}")
print(f"  Training   : {len(train_dataset)}")
print(f"  Validation : {len(val_dataset)}")
print(f"  Test       : {len(test_dataset)}")


train_loader = DataLoader(
    train_dataset,
    batch_size=BATCH_SIZE,
    shuffle=True
)

val_loader = DataLoader(
    val_dataset,
    batch_size=BATCH_SIZE,
    shuffle=False
)

test_loader = DataLoader(
    test_dataset,
    batch_size=BATCH_SIZE,
    shuffle=False
)


# --------------------------------------------------
# Model
# --------------------------------------------------

device = torch.device("cpu")

model = TemporalGNN(
    input_dim=8,
    hidden_dim=32,
    output_dim=2
).to(device)

optimizer = torch.optim.Adam(
    model.parameters(),
    lr=LEARNING_RATE
)


# --------------------------------------------------
# Training
# --------------------------------------------------

def train():
    model.train()

    total_loss = 0.0

    for batch in train_loader:

        batch = batch.to(device)

        optimizer.zero_grad()

        output = model(
            batch.x,
            batch.edge_index,
            batch.timestamps,
            batch.batch
        )

        loss = F.cross_entropy(
            output,
            batch.y
        )

        loss.backward()

        optimizer.step()

        total_loss += loss.item()

    return total_loss / len(train_loader)


# --------------------------------------------------
# Validation
# --------------------------------------------------

def evaluate(loader):

    model.eval()

    predictions = []
    labels = []

    total_loss = 0.0

    with torch.no_grad():

        for batch in loader:

            batch = batch.to(device)

            output = model(
                batch.x,
                batch.edge_index,
                batch.timestamps,
                batch.batch
            )

            loss = F.cross_entropy(
                output,
                batch.y
            )

            total_loss += loss.item()

            predicted = torch.argmax(
                output,
                dim=1
            )

            predictions.extend(
                predicted.cpu().numpy()
            )

            labels.extend(
                batch.y.cpu().numpy()
            )

    accuracy = accuracy_score(labels, predictions)

    return (
        total_loss / len(loader),
        accuracy
    )


# --------------------------------------------------
# Training loop
# --------------------------------------------------

print("\nTraining Temporal GNN...\n")

for epoch in range(1, EPOCHS + 1):

    train_loss = train()

    val_loss, val_accuracy = evaluate(
        val_loader
    )

    if epoch == 1 or epoch % 5 == 0:

        print(
            f"Epoch {epoch:02d}/{EPOCHS} | "
            f"Train Loss: {train_loss:.4f} | "
            f"Val Loss: {val_loss:.4f} | "
            f"Val Accuracy: {val_accuracy:.4f}"
        )


# --------------------------------------------------
# Final evaluation
# --------------------------------------------------

model.eval()

predictions = []
labels = []

with torch.no_grad():

    for batch in test_loader:

        batch = batch.to(device)

        output = model(
            batch.x,
            batch.edge_index,
            batch.timestamps,
            batch.batch
        )

        predicted = torch.argmax(
            output,
            dim=1
        )

        predictions.extend(
            predicted.cpu().numpy()
        )

        labels.extend(
            batch.y.cpu().numpy()
        )


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

print("\n==============================")
print("Temporal GNN Test Results")
print("==============================")

print(f"Accuracy  : {accuracy:.4f}")
print(f"Precision : {precision:.4f}")
print(f"Recall    : {recall:.4f}")
print(f"F1 Score  : {f1:.4f}")

print("\nConfusion Matrix:")
print(cm)


# --------------------------------------------------
# Save model
# --------------------------------------------------

torch.save(
    model.state_dict(),
    "gnn/temporal_gnn.pt"
)

print("\nModel saved to:")
print("gnn/temporal_gnn.pt")
