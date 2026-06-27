import pytest

from llmfirewall import LLMFirewall, HybridNeuralFirewall


@pytest.fixture(scope="module")
def base_firewall():
    return LLMFirewall()


@pytest.fixture(scope="module")
def hybrid_firewall():
    return HybridNeuralFirewall()
