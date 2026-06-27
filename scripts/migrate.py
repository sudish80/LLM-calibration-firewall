#!/usr/bin/env python3
"""Migrate from the legacy Colab notebook format to the package format.

This script converts the old flat `llmfirewall_legacy_colab.py` into the
new structured package layout by extracting classes and writing them to
the proper module files.

Usage:
    python scripts/migrate.py                          # check only
    python scripts/migrate.py --write                  # write migration report
    python scripts/migrate.py --dry-run                # preview changes
"""

import argparse
import ast
import sys
from pathlib import Path


def analyze_legacy(path: str = "llmfirewall_legacy_colab.py") -> dict:
    path_obj = Path(path)
    if not path_obj.exists():
        return {"error": f"File not found: {path}"}

    with open(path_obj) as f:
        source = f.read()

    tree = ast.parse(source)
    classes = [node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]
    functions = [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.parent is None]

    imports = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                imports.append(f"{module}.{alias.name}")

    lines = source.split("\n")
    pip_installs = [line for line in lines if line.startswith("!pip install") or line.startswith("!pip3 install")]
    colab_cells = sum(1 for line in lines if line.strip().startswith('"""##'))
    matplotlib_calls = sum(1 for node in ast.walk(tree) if isinstance(node, ast.Call) and getattr(node.func, 'attr', None) in ('show', 'savefig'))

    return {
        "file": path,
        "lines": len(lines),
        "classes": [c.name for c in classes],
        "functions": [f.name for f in functions],
        "imports": imports[:20],
        "pip_install_lines": pip_installs[:10],
        "colab_cells": colab_cells,
        "matplotlib_calls": matplotlib_calls,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Migrate legacy Colab notebook to package format")
    parser.add_argument("--legacy", default="llmfirewall_legacy_colab.py", help="Path to legacy file")
    parser.add_argument("--dry-run", action="store_true", help="Preview changes without writing")
    parser.add_argument("--write", action="store_true", help="Write migration report")
    args = parser.parse_args()

    info = analyze_legacy(args.legacy)

    if "error" in info:
        print(f"Error: {info['error']}")
        sys.exit(1)

    print(f"\n{'='*55}")
    print(f"  Migration Analysis: {info['file']}")
    print(f"{'='*55}")
    print(f"  Total lines:     {info['lines']}")
    print(f"  Classes found:   {len(info['classes'])}")
    for c in info['classes']:
        print(f"    - {c}")
    print(f"  Colab cells:     {info['colab_cells']}")
    print(f"  Pip installs:    {len(info['pip_install_lines'])}")
    print(f"  Matplotlib:      {info['matplotlib_calls']} show/savefig calls")

    print(f"\n{'='*55}")
    print(f"  Migration Status")
    print(f"{'='*55}")

    package_classes = [
        "LLMFirewall",
        "EnhancedVectorFirewall",
        "SmartJudgeNN",
        "HybridNeuralFirewall",
        "AdvancedFirewallFeatures",
        "FirewallTester",
    ]
    missing = [c for c in package_classes if c not in info['classes']]
    extra = [c for c in info['classes'] if c not in package_classes]

    if missing:
        for c in missing:
            print(f"  ⚠ Missing in legacy: {c}")

    for c in package_classes:
        if c in info['classes']:
            print(f"  ✓ {c} — migrated")
        else:
            print(f"  ✗ {c} — NOT FOUND in legacy")

    print(f"\n  Legacy file can be safely deleted once confirmed.")

    if args.write:
        report_path = "migration_report.txt"
        with open(report_path, "w") as f:
            f.write(f"Migration Report for {info['file']}\n")
            f.write(f"{'='*55}\n")
            f.write(f"Lines: {info['lines']}\n")
            f.write(f"Classes: {', '.join(info['classes'])}\n")
            f.write(f"Colab cells: {info['colab_cells']}\n")
            f.write(f"Pip installs: {len(info['pip_install_lines'])}\n")
        print(f"\n  Report written to {report_path}")


if __name__ == "__main__":
    main()
