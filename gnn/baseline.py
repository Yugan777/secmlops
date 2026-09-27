import random
import numpy as np

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)

from dataset import create_dataset


SEED = 123

random.seed(SEED)
np.random.seed(SEED)


# --------------------------------------------------
# Create evaluation dataset
# --------------------------------------------------

dataset = create_dataset(500)

random.shuffle(dataset)

train_size = int(0.70 * len(dataset))
val_size = int(0.15 * len(dataset))

test_dataset = dataset[
    train_size + val_size:
]


# --------------------------------------------------
# Simple rule-based detector
# --------------------------------------------------

def rule_detector(graph):

    has_file = False
    has_network = False

    for node in graph.x:

        # Feature index 1 = file
        if node[1].item() == 1:
            has_file = True

        # Feature index 2 = network
        if node[2].item() == 1:
            has_network = True

    # Simple baseline:
    # file + network = suspicious

    if has_file and has_network:
        return 1

    return 0


# --------------------------------------------------
# Evaluate
# --------------------------------------------------

labels = []
predictions = []

for graph in test_dataset:

    actual = graph.y.item()

    predicted = rule_detector(graph)

    labels.append(actual)
    predictions.append(predicted)


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
print("RULE-BASED BASELINE")
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
