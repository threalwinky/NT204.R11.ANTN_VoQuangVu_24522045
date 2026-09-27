import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

from modules.capture import CaptureError, capture_live, read_pcap
from modules.logger import JSONLLogger

OUTPUT_DIR = Path("files/output")


def print_event(event) -> None:
    print(
        json.dumps(
            event.to_dict(),
            ensure_ascii=False,
        )
    )


def run_capture(args, emit) -> None:
    if args.interface:
        print(f"Sniffing on {args.interface}...")

        capture_live(
            interface=args.interface,
            on_event=emit,
        )

    else:
        print(f"Reading from {args.pcap}...")

        for event in read_pcap(args.pcap):
            emit(event)


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

    args = parser.parse_args()

    try:
        if args.output == "file":
            output_path = OUTPUT_DIR / f"event_{datetime.now():%Y%m%d_%H%M%S}.jsonl"

            with JSONLLogger(output_path) as logger:
                print(f"Writing events to {output_path}")

                run_capture(args, logger.write)

        else:
            run_capture(args, print_event)

    except CaptureError as error:
        print(
            f"{parser.prog}: error: {error}",
            file=sys.stderr,
        )

        raise SystemExit(1)


if __name__ == "__main__":
    main()
