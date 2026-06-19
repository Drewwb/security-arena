"""Arena CLI.

    python -m arena list                       list corpus samples
    python -m arena validate                   validate every manifest
    python -m arena run --adapter NAME         run a scanner over the corpus
    python -m arena score --adapter NAME       score the latest run for NAME
    python -m arena adapters                    list discovered adapters
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .adapters import available_adapters
from .runner import latest_results, run
from .scorer import format_report, score
from .schema import iter_samples, load_taxonomy, validate_sample


def _parse_config(items: list[str] | None) -> dict[str, str]:
    config: dict[str, str] = {}
    for item in items or []:
        if "=" not in item:
            raise SystemExit(f"--config expects key=value, got '{item}'")
        key, value = item.split("=", 1)
        config[key] = value
    return config


def cmd_list(args) -> int:
    samples = iter_samples(args.ecosystem)
    for s in samples:
        kind = "MAL " if s.malicious else "benign"
        print(f"{s.id:<34} {s.ecosystem:<5} {kind} {s.technique}")
    print(f"\n{len(samples)} sample(s)")
    return 0


def cmd_validate(args) -> int:
    taxonomy = load_taxonomy()
    samples = iter_samples()
    total_errors = 0
    for s in samples:
        errors = validate_sample(s, taxonomy)
        if errors:
            total_errors += len(errors)
            print(f"FAIL {s.id}")
            for e in errors:
                print(f"     - {e}")
    if total_errors == 0:
        print(f"OK - {len(samples)} sample(s) valid")
        return 0
    print(f"\n{total_errors} error(s) across the corpus")
    return 1


def cmd_adapters(args) -> int:
    for name, cls in sorted(available_adapters().items()):
        try:
            ready = cls().available()
        except Exception:
            ready = False
        mark = "ready" if ready else "needs config/tool"
        print(f"{name:<14} {mark:<18} {cls.__module__}")
    return 0


def cmd_run(args) -> int:
    config = _parse_config(args.config)
    out = run(args.adapter, config=config, ecosystem=args.ecosystem)
    print(f"\nResults written to {out.relative_to(Path.cwd()) if out.is_relative_to(Path.cwd()) else out}")
    return 0


def cmd_score(args) -> int:
    if args.results:
        results_file = Path(args.results)
    else:
        results_file = latest_results(args.adapter)
        if results_file is None:
            raise SystemExit(f"no results found for adapter '{args.adapter}'. Run it first.")
    report = score(results_file)
    print(format_report(report))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="arena", description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_list = sub.add_parser("list", help="list corpus samples")
    p_list.add_argument("--ecosystem", choices=["npm", "pypi"])
    p_list.set_defaults(func=cmd_list)

    p_val = sub.add_parser("validate", help="validate manifests")
    p_val.set_defaults(func=cmd_validate)

    p_ad = sub.add_parser("adapters", help="list discovered adapters")
    p_ad.set_defaults(func=cmd_adapters)

    p_run = sub.add_parser("run", help="run a scanner over the corpus")
    p_run.add_argument("--adapter", required=True)
    p_run.add_argument("--config", action="append", help="key=value (repeatable)")
    p_run.add_argument("--ecosystem", choices=["npm", "pypi"])
    p_run.set_defaults(func=cmd_run)

    p_score = sub.add_parser("score", help="score a run")
    p_score.add_argument("--adapter", required=True)
    p_score.add_argument("--results", help="explicit results file (default: latest)")
    p_score.set_defaults(func=cmd_score)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
