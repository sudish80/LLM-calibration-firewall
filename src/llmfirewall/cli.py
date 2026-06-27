import argparse
import logging
import sys
from pathlib import Path

from llmfirewall import HybridNeuralFirewall, LLMFirewall
from llmfirewall.config import load_settings, settings
from llmfirewall.server import main as server_main

logger = logging.getLogger(__name__)


def moderate_cli(args: argparse.Namespace) -> None:
    firewall: LLMFirewall
    if args.neural:
        firewall = HybridNeuralFirewall()
    else:
        firewall = LLMFirewall()

    text = args.text or sys.stdin.read().strip()
    if not text:
        logger.error("No input text provided.")
        sys.exit(1)

    result = firewall.moderate(text)

    print(f"{'Decision:':<15} {'ALLOWED' if result.allowed else 'BLOCKED'}")
    if result.reasons:
        print(f"{'Reasons:':<15} {', '.join(result.reasons)}")
    if result.toxicity:
        print(f"{'Toxicity:':<15} {result.toxicity.score:.4f} ({result.toxicity.label})")
    if result.semantic_similarity is not None:
        print(f"{'Semantic:':<15} {result.semantic_similarity:.4f}")
    if result.neural_risk_score is not None:
        print(f"{'Neural Risk:':<15} {result.neural_risk_score:.4f}")


def train_cli(args: argparse.Namespace) -> None:
    from llmfirewall.train import TRAINING_EXAMPLES, EXTRA_HARD_CASES, train_neural_judge

    logger.info("Initializing HybridNeuralFirewall for training...")
    firewall = HybridNeuralFirewall()

    examples = list(TRAINING_EXAMPLES)
    if args.include_hard:
        examples.extend(EXTRA_HARD_CASES)
    if args.data:
        import csv
        path = Path(args.data)
        if not path.exists():
            logger.error("Data file not found: %s", args.data)
            sys.exit(1)
        with open(path) as f:
            reader = csv.reader(f)
            next(reader, None)
            for row in reader:
                if len(row) >= 2:
                    examples.append((row[0], int(row[1])))
        logger.info("Loaded %d examples from %s", len(examples) - len(TRAINING_EXAMPLES) - (len(EXTRA_HARD_CASES) if args.include_hard else 0), args.data)

    losses = train_neural_judge(
        firewall=firewall,
        examples=examples,
        epochs=args.epochs,
        lr=args.lr,
        loss_fn=args.loss,
        save_path=args.output,
    )
    logger.info("Training complete. Final loss: %.6f", losses[-1] if losses else 0)


def load_cli(args: argparse.Namespace) -> None:
    from llmfirewall.train import load_weights

    path = Path(args.weights)
    if not path.exists():
        logger.error("Weights file not found: %s", args.weights)
        sys.exit(1)
    firewall = HybridNeuralFirewall()
    load_weights(firewall, str(path))
    text = args.text or sys.stdin.read().strip()
    if not text:
        logger.error("No input text provided.")
        sys.exit(1)
    result = firewall.moderate(text)
    print(f"{'Decision:':<15} {'ALLOWED' if result.allowed else 'BLOCKED'}")
    if result.reasons:
        print(f"{'Reasons:':<15} {', '.join(result.reasons)}")
    if result.toxicity:
        print(f"{'Toxicity:':<15} {result.toxicity.score:.4f} ({result.toxicity.label})")
    if result.neural_risk_score is not None:
        print(f"{'Neural Risk:':<15} {result.neural_risk_score:.4f}")


def gradio_cli(args: argparse.Namespace) -> None:
    from llmfirewall.gradio_ui import launch

    launch(share=args.share, port=args.port)


def main() -> None:
    parser = argparse.ArgumentParser(description="LLM Firewall — content moderation for LLM inputs")
    parser.add_argument("--config", help="Path to YAML configuration file")

    sub = parser.add_subparsers(dest="command")

    moderate_parser = sub.add_parser("moderate", help="Moderate a single text input")
    moderate_parser.add_argument("text", nargs="?", help="Text to moderate (reads from stdin if omitted)")
    moderate_parser.add_argument("--neural", action="store_true", help="Use full HybridNeuralFirewall")

    train_parser = sub.add_parser("train", help="Train the Neural Judge")
    train_parser.add_argument("--epochs", type=int, default=2500, help="Number of training epochs")
    train_parser.add_argument("--lr", type=float, default=0.0005, help="Learning rate")
    train_parser.add_argument("--loss", choices=["mse", "bce"], default="mse", help="Loss function")
    train_parser.add_argument("--include-hard", action="store_true", help="Include hard negative examples")
    train_parser.add_argument("--data", help="CSV file with custom training examples (text,label)")
    train_parser.add_argument("--output", "-o", default=None, help="Path to save trained weights (.pt)")

    load_parser = sub.add_parser("load", help="Load trained weights and moderate")
    load_parser.add_argument("weights", help="Path to .pt weights file")
    load_parser.add_argument("text", nargs="?", help="Text to moderate (reads from stdin if omitted)")

    server_parser = sub.add_parser("server", help="Start the FastAPI moderation server")
    server_parser.add_argument("--host", help="Override server host")
    server_parser.add_argument("--port", type=int, help="Override server port")
    server_parser.add_argument("--workers", type=int, help="Number of worker processes")

    gradio_parser = sub.add_parser("gradio", help="Launch the Gradio web interface")
    gradio_parser.add_argument("--share", action="store_true", help="Create a public shareable link")
    gradio_parser.add_argument("--port", type=int, default=None, help="Port to run on")

    args = parser.parse_args()

    if args.config:
        load_settings(args.config)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    if args.command == "moderate":
        moderate_cli(args)
    elif args.command == "train":
        train_cli(args)
    elif args.command == "load":
        load_cli(args)
    elif args.command == "server":
        if args.host:
            settings.server_host = args.host
        if args.port:
            settings.server_port = args.port
        if args.workers:
            settings.server_workers = args.workers
        server_main()
    elif args.command == "gradio":
        gradio_cli(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
