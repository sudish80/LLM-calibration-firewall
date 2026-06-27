import logging

import gradio as gr

from llmfirewall import HybridNeuralFirewall
from llmfirewall.config import settings

logger = logging.getLogger(__name__)

_firewall: HybridNeuralFirewall | None = None


def get_firewall() -> HybridNeuralFirewall:
    global _firewall
    if _firewall is None:
        _firewall = HybridNeuralFirewall()
    return _firewall


def moderate_input(text: str) -> tuple[str, str, str]:
    result = get_firewall().moderate(text)
    status = "ALLOWED" if result.allowed else "BLOCKED"
    reasons = ", ".join(result.reasons) if result.reasons else "Clean input"
    risk = (
        f"Neural Risk: {result.neural_risk_score:.3f} | "
        f"Toxicity: {result.toxicity.score:.3f} | "
        f"Similarity: {result.semantic_similarity:.3f}"
    )
    return status, risk, reasons


def launch(share: bool = False, port: int | None = None) -> None:
    iface = gr.Interface(
        fn=moderate_input,
        inputs=gr.Textbox(label="User Input", placeholder="Enter text to test the firewall..."),
        outputs=[
            gr.Textbox(label="Decision"),
            gr.Textbox(label="Risk Metrics"),
            gr.Textbox(label="Detection Details"),
        ],
        title="Hybrid Neural LLM Firewall",
        description="Tiered Defense: Regex → Semantic (ChromaDB) → Neural Judge (PyTorch)",
        allow_flagging="never",
    )
    iface.launch(share=share, server_port=port or settings.server_port)
