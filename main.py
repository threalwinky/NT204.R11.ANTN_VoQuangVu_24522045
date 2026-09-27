import argparse
import json
from contextlib import ExitStack
from datetime import datetime
from pathlib import Path

from modules.capture import capture_live, read_pcap
from modules.logger import JSONLLogger

OUTPUT_DIR = Path("files/output")


def print_event(event) -> None:
    print(
        json.dumps(
            event.to_dict(),
            ensure_ascii=False,
        )
    )


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
        choices=["live", "file"],
        default="live",
        help="live: print events to stdout (default), "
             "file: write events to files/output/event_<datetime>.jsonl",
    )

    args = parser.parse_args()

    with ExitStack() as stack:
        if args.output == "file":
            output_path = OUTPUT_DIR / f"event_{datetime.now():%Y%m%d_%H%M%S}.jsonl"
            emit = stack.enter_context(JSONLLogger(output_path)).write
            print(f"Writing events to {output_path}")
        else:
            emit = print_event

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


if __name__ == "__main__":
    main()