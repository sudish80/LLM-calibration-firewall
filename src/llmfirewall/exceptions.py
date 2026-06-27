class LLMFirewallError(Exception):
    pass


class ModelLoadError(LLMFirewallError):
    pass


class ConfigurationError(LLMFirewallError):
    pass


class ModerationError(LLMFirewallError):
    pass
