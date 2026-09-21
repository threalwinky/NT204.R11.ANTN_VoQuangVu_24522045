import argparse
import json

from main.capture import capture_live, read_pcap
from main.logger import JSONLLogger


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
        default="events.jsonl",
        help="JSONL output file",
    )

    args = parser.parse_args()

    with JSONLLogger(args.output) as logger:

        def handle_event(event):
            logger.write(event)
            print_event(event)

        if args.interface:
            print(f"Sniffing on {args.interface}...")
            print(f"Writing events to {args.output}")

            capture_live(
                interface=args.interface,
                on_event=handle_event,
            )

        elif args.pcap:
            print(f"Reading from {args.pcap}...")
            print(f"Writing events to {args.output}")

            for event in read_pcap(args.pcap):
                handle_event(event)


if __name__ == "__main__":
    main()