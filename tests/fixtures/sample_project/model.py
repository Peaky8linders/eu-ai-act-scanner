"""Sample AI project fixture — intentionally mixed quality.

Used by tests to verify analyzer behaviour end-to-end.
"""

import logging

import torch
import torch.nn as nn

logger = logging.getLogger(__name__)


class SimpleClassifier(nn.Module):
    """A trivial classifier for fixture purposes."""

    def __init__(self, hidden: int = 128):
        super().__init__()
        self.fc1 = nn.Linear(768, hidden)
        self.fc2 = nn.Linear(hidden, 2)

    def forward(self, x):
        return self.fc2(torch.relu(self.fc1(x)))


def confidence_threshold(score: float, threshold: float = 0.7) -> bool:
    """Gate predictions below threshold for human review.

    Maps to Art. 14 human oversight obligation.
    """
    return score >= threshold


def human_review(prediction, context):
    """Hook for manual review of low-confidence predictions."""
    logger.info("human_review_requested", prediction=prediction, context=context)
    return {"status": "pending_review"}
