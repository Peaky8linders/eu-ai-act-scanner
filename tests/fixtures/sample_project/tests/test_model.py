"""Basic tests for the fixture model."""

import torch
from model import SimpleClassifier, confidence_threshold


def test_classifier_forward_shape():
    m = SimpleClassifier()
    x = torch.randn(4, 768)
    out = m(x)
    assert out.shape == (4, 2)


def test_confidence_threshold_blocks_low_scores():
    assert confidence_threshold(0.5) is False
    assert confidence_threshold(0.9) is True
