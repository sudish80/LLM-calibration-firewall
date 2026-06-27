import argparse
import shlex
from typing import Optional

from llmfirewall import HybridNeuralFirewall
from llmfirewall.schemas import ModerationResult

_firewall: Optional[HybridNeuralFirewall] = None


def get_firewall() -> HybridNeuralFirewall:
    global _firewall
    if _firewall is None:
        _firewall = HybridNeuralFirewall()
    return _firewall


def run_repl() -> None:
    print("LLM Firewall REPL. Type your input to moderate, or :help for commands.")
    print()
    while True:
        try:
            line = input(">>> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not line:
            continue
        if line.startswith(":"):
            _handle_command(line[1:])
            continue
        result = get_firewall().moderate(line)
        _print_result(result)


def _handle_command(cmd: str) -> None:
    parts = shlex.split(cmd)
    if not parts:
        return
    command = parts[0].lower()
    if command in ("help", "h", "?"):
        print("Commands:")
        print("  :help / :h            Show this help")
        print("  :quit / :q / :exit    Exit REPL")
        print("  :stats                Show firewall stats")
        print("  :model <name>         Check model health")
        print("  :config               Show current config")
        print()
    elif command in ("quit", "q", "exit"):
        raise EOFError
    elif command == "stats":
        fw = get_firewall()
        for name in ["toxicity", "intent", "sentiment"]:
            print(f"  {name}: {'HEALTHY' if fw.is_model_healthy(name) else 'DOWN'}")
    elif command == "model" and len(parts) > 1:
        fw = get_firewall()
        status = fw.is_model_healthy(parts[1])
        print(f"  {parts[1]}: {'HEALTHY' if status else 'DOWN'}")
    elif command == "config":
        from llmfirewall.config import settings
        print(f"  toxicity_threshold: {settings.toxicity_threshold}")
        print(f"  semantic_threshold: {settings.semantic_threshold}")
        print(f"  device: {settings.device}")
        print(f"  max_input_length: {settings.max_input_length}")
    else:
        print(f"Unknown command: :{command}")


def _print_result(result: ModerationResult) -> None:
    decision = "ALLOWED" if result.allowed else "BLOCKED"
    color = "\033[92m" if result.allowed else "\033[91m"
    reset = "\033[0m"
    print(f"  {color}{decision}{reset}")
    if result.reasons:
        for r in result.reasons:
            print(f"    reason: {r}")
    if result.toxicity:
        print(f"    toxicity: {result.toxicity.score:.4f}")
    if result.semantic_similarity is not None:
        print(f"    semantic: {result.semantic_similarity:.4f}")
    if result.neural_risk_score is not None:
        print(f"    neural:   {result.neural_risk_score:.4f}")
    if result.layer_contributions:
        print(f"    layers:   {', '.join(f'{lc.layer}={lc.score:.2f}' for lc in result.layer_contributions)}")
    print()


def run_batch(inputs: list[str], fmt: str = "text") -> None:
    fw = get_firewall()
    results = []
    for text in inputs:
        result = fw.moderate(text)
        results.append(result)

    if fmt == "json":
        import json
        print(json.dumps([r.model_dump() for r in results], indent=2))
    elif fmt == "csv":
        print("input,allowed,reasons,toxicity,neural_risk,semantic")
        for r in results:
            reasons = "; ".join(r.reasons)
            tox = round(r.toxicity.score, 4) if r.toxicity else ""
            nr = round(r.neural_risk_score, 4) if r.neural_risk_score is not None else ""
            sem = round(r.semantic_similarity, 4) if r.semantic_similarity is not None else ""
            print(f"{r.input!r},{r.allowed},{reasons!r},{tox},{nr},{sem}")
    else:
        for r in results:
            status = "ALLOWED" if r.allowed else "BLOCKED"
            reasons = "; ".join(r.reasons) if r.reasons else "-"
            print(f"[{status}] {r.input[:60]:<60} | {reasons}")
