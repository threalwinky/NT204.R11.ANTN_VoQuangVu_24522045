import argparse
import json
import sys
from datetime import datetime
from math import isfinite
from pathlib import Path

from modules.capture import CaptureError, capture_live, read_pcap
from modules.engine import (
    DetectionEventGenerator,
    RuleEvaluationEngine,
    RuleLoader,
    RuleParser,
    RuleRepository,
)
from modules.logger import JSONLLogger
from modules.preprocessor import apply_processing_policy


OUTPUT_DIR = Path("files/output")


def print_event(event) -> None:
    record = event if isinstance(event, dict) else event.to_dict()
    print(json.dumps(record, ensure_ascii=False))


def parse_disabled_rule(value: str) -> tuple[str, int]:
    path, separator, line = value.rpartition(":")

    if (
        not separator
        or not path
        or not line.isascii()
        or not line.isdecimal()
        or int(line) < 1
    ):
        raise ValueError(
            "--disable-rule must use FILE:LINE with a positive line number"
        )

    return path, int(line)


def load_rule_engine(
    rule_paths: list[str],
    disabled_files: list[str] | None = None,
    disabled_rules: list[tuple[str, int]] | None = None,
) -> RuleEvaluationEngine:

    loader = RuleLoader(
        disabled_files=disabled_files or [],
        disabled_rules=disabled_rules or [],
    )

    loaded = loader.load(rule_paths)

    for warning in loaded.warnings:
        print(
            f"[RULE WARNING] {warning.path}: {warning.reason}",
            file=sys.stderr,
        )

    parser = RuleParser()
    repository = RuleRepository()

    invalid_count = 0
    unsupported_count = 0
    rejected_count = 0

    for result in parser.parse_many(loaded.rules):
        location = (
            f"{result.source.path}:"
            f"{result.source.line_number}"
        )

        if result.status != "valid":
            if result.status == "invalid":
                invalid_count += 1
            else:
                unsupported_count += 1

            print(
                f"[RULE {result.status.upper()}] "
                f"{location}: {result.reason}",
                file=sys.stderr,
            )
            continue

        if result.rule is None:
            rejected_count += 1
            print(
                f"[RULE WARNING] {location}: missing parsed rule",
                file=sys.stderr,
            )
            continue

        try:
            repository.add(result.rule)

        except ValueError as error:
            rejected_count += 1
            print(
                f"[RULE WARNING] {location}: {error}",
                file=sys.stderr,
            )

    print(
        "[RULE LOADER] "
        f"loaded={len(repository)} "
        f"invalid={invalid_count} "
        f"unsupported={unsupported_count} "
        f"rejected={rejected_count} "
        f"file_warnings={len(loaded.warnings)}",
        file=sys.stderr,
    )

    if len(repository) == 0:
        print(
            "[RULE WARNING] No active valid Snort rules loaded",
            file=sys.stderr,
        )

    return RuleEvaluationEngine(repository)


def run_capture(
    args,
    emit,
    detection_engine: RuleEvaluationEngine | None = None,
    detections_only: bool = False,
) -> None:
    tcp_timeout = getattr(args, "tcp_timeout", 300.0)
    udp_timeout = getattr(args, "udp_timeout", 60.0)

    generator = (
        DetectionEventGenerator()
        if detection_engine is not None
        else None
    )

    def handle(event) -> None:
        apply_processing_policy(
            event,
            skip_partial=args.skip_partial,
            skip_invalid=args.skip_invalid,
            skip_unknown=args.skip_unknown,
        )

        if event.processing_action == "skip":
            return

        if not detections_only:
            emit(event)

        if detection_engine is None:
            return

        result = detection_engine.evaluate(event)

        for detection in generator.generate(result):
            emit(detection.to_dict())

    flow_emit = emit if not detections_only else None

    if args.interface:
        print(f"Sniffing on {args.interface}...")

        capture_live(
            interface=args.interface,
            on_event=handle,
            on_flow_expired=flow_emit,
            tcp_timeout=tcp_timeout,
            udp_timeout=udp_timeout,
        )

    else:
        print(f"Reading from {args.pcap}...")

        for event in read_pcap(
            args.pcap,
            on_flow_expired=flow_emit,
            tcp_timeout=tcp_timeout,
            udp_timeout=udp_timeout,
            on_flow_finalized=(
                flow_emit
                if getattr(args, "emit_flow_summaries", False)
                else None
            ),
        ):
            handle(event)


def main():
    parser = argparse.ArgumentParser()

    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument(
        "--interface",
        help="Network interface for live capture",
    )

    group.add_argument(
        "--pcap",
        help="PCAP file to parse",
    )

    parser.add_argument(
        "--output",
        choices=("live", "file"),
        default="live",
        help="live: print events to stdout (default), "
             "file: write events to files/output/event_<datetime>.jsonl",
    )

    parser.add_argument(
        "--skip-unknown",
        action="store_true",
        help="skip events with UNKNOWN status",
    )

    parser.add_argument(
        "--skip-partial",
        action="store_true",
        help="skip events with partial preprocessing status",
    )

    parser.add_argument(
        "--skip-invalid",
        action="store_true",
        help="skip events with invalid preprocessing status",
    )

    parser.add_argument(
        "--tcp-timeout",
        type=float,
        default=300.0,
        help="TCP idle timeout in seconds",
    )

    parser.add_argument(
        "--udp-timeout",
        type=float,
        default=60.0,
        help="UDP idle timeout in seconds",
    )

    parser.add_argument(
        "--emit-flow-summaries",
        action="store_true",
        help="Export remaining flow summaries at the end of a PCAP",
    )

    # BT3 - Snort Core Engine
    parser.add_argument(
        "--rules",
        nargs="+",
        action="append",
        metavar="FILE",
        help="Load one or more Snort .rules files",
    )

    parser.add_argument(
        "--disable-rule-file",
        action="append",
        default=[],
        metavar="FILE",
        help="Disable a Snort rule file",
    )

    parser.add_argument(
        "--disable-rule",
        action="append",
        default=[],
        metavar="FILE:LINE",
        help="Disable an individual rule by file and line number",
    )

    parser.add_argument(
        "--detections-only",
        action="store_true",
        help="Emit only detection events; requires --rules",
    )

    args = parser.parse_args()

    for name in ("tcp_timeout", "udp_timeout"):
        value = getattr(args, name)

        if not isfinite(value) or value <= 0:
            option = name.replace("_", "-")
            parser.error(
                f"--{option} must be a positive finite number"
            )

    if args.interface and args.emit_flow_summaries:
        parser.error("--emit-flow-summaries requires --pcap")

    if args.detections_only and args.emit_flow_summaries:
        parser.error(
            "--detections-only cannot be combined with "
            "--emit-flow-summaries"
        )

    if not args.rules and (
        args.detections_only
        or args.disable_rule_file
        or args.disable_rule
    ):
        parser.error(
            "--detections-only and rule disabling options "
            "require --rules"
        )

    detection_engine = None

    if args.rules:
        rule_paths = [
            path
            for group_paths in args.rules
            for path in group_paths
        ]

        try:
            disabled_rules = [
                parse_disabled_rule(value)
                for value in args.disable_rule
            ]

        except ValueError as error:
            parser.error(str(error))

        detection_engine = load_rule_engine(
            rule_paths=rule_paths,
            disabled_files=args.disable_rule_file,
            disabled_rules=disabled_rules,
        )

    try:
        if args.output == "file":
            output_path = (
                OUTPUT_DIR
                / f"event_{datetime.now():%Y%m%d_%H%M%S}.jsonl"
            )

            with JSONLLogger(output_path) as logger:
                print(f"Writing events to {output_path}")

                run_capture(
                    args,
                    logger.write,
                    detection_engine=detection_engine,
                    detections_only=args.detections_only,
                )

        else:
            run_capture(
                args,
                print_event,
                detection_engine=detection_engine,
                detections_only=args.detections_only,
            )

    except CaptureError as error:
        print(
            f"{parser.prog}: error: {error}",
            file=sys.stderr,
        )

        raise SystemExit(1)

    if detection_engine is not None:
        print(
            "[RULE STATS] "
            + json.dumps(detection_engine.get_stats()),
            file=sys.stderr,
        )


if __name__ == "__main__":
    main()
