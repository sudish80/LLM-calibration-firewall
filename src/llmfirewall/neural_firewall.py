import logging
from typing import Optional

import torch
import torch.nn as nn
import torch.optim as optim

from llmfirewall.config import settings
from llmfirewall.vector_firewall import EnhancedVectorFirewall
from llmfirewall.schemas import ModerationResult

logger = logging.getLogger(__name__)


class SmartJudgeNN(nn.Module):
    def __init__(self, input_dim: int = 3):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(input_dim, 32),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(32, 16),
            nn.ReLU(),
            nn.Linear(16, 8),
            nn.ReLU(),
            nn.Linear(8, 1),
            nn.Sigmoid(),
        )
        self.apply(self._init_weights)

    @staticmethod
    def _init_weights(m: nn.Module):
        if isinstance(m, nn.Linear):
            nn.init.xavier_uniform_(m.weight)
            m.bias.data.fill_(0.01)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


class HybridNeuralFirewall(EnhancedVectorFirewall):
    def __init__(
        self,
        toxicity_threshold: Optional[float] = None,
        sentiment_threshold: Optional[float] = None,
        semantic_threshold: Optional[float] = None,
    ):
        super().__init__(toxicity_threshold, sentiment_threshold, semantic_threshold)
        self.smart_judge = SmartJudgeNN(input_dim=3)
        self.optimizer = optim.Adam(self.smart_judge.parameters(), lr=0.001)
        self.criterion = nn.BCELoss()
        logger.info("Neural judge initialized.")

    def get_neural_risk(self, semantic_score: float, toxicity_score: float, edu_score: float) -> float:
        self.smart_judge.eval()
        with torch.no_grad():
            features = torch.tensor([[semantic_score, toxicity_score, edu_score]], dtype=torch.float32)
            risk_prob = self.smart_judge(features).item()
        return risk_prob

    def moderate(self, text: str) -> ModerationResult:
        results = super().moderate(text)

        sem_score = results.semantic_similarity or 0.0
        tox_score = results.toxicity.score if results.toxicity else 0.0

        labels = results.intent.labels if results.intent else []
        scores = results.intent.scores if results.intent else []

        edu_score = scores[labels.index("educational")] if "educational" in labels else 0.0
        info_score = scores[labels.index("informative")] if "informative" in labels else 0.0

        neural_risk = self.get_neural_risk(sem_score, tox_score, edu_score)
        results.neural_risk_score = neural_risk

        is_edu_profile = edu_score > 0.4 or info_score > 0.4
        safety_keywords = ["protect", "secure", "prevent", "defense", "how to stop"]
        is_protective = any(k in text.lower() for k in safety_keywords)

        if neural_risk > settings.neural_hard_block_threshold:
            results.allowed = False
            results.reasons = [r for r in results.reasons if "Educational" not in r]
            if not any("Neural Judge Strict Block" in r for r in results.reasons):
                results.reasons.append(f"Neural Judge Strict Block (Risk: {neural_risk:.2f})")
            return results

        if (is_edu_profile or is_protective) and neural_risk < settings.neural_edu_override_threshold:
            results.allowed = True
            results.reasons = [r for r in results.reasons if "Semantic" not in r and "Neural" not in r]
            if "Educational Intent Override applied" not in results.reasons:
                results.reasons.append("Educational Intent Override applied")

        elif neural_risk > settings.neural_moderate_block_threshold:
            results.allowed = False
            if not any("Neural Judge" in r for r in results.reasons):
                results.reasons.append(f"Neural Judge block (Risk: {neural_risk:.2f})")

        return results
