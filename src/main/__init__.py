import argparse
from main.capture import capture_live, read_pcap


def print_event(event) -> None:
    print(event.to_dict())


def main():
    parser = argparse.ArgumentParser()

    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument("--interface")
    group.add_argument("--pcap")

    args = parser.parse_args()

    if args.interface:
        print(f"Sniffing on {args.interface}...")

        capture_live(
            interface=args.interface,
            on_event=print_event,
        )

    elif args.pcap:
        print(f"Reading from {args.pcap}...")

        for event in read_pcap(args.pcap):
            print_event(event)


if __name__ == "__main__":
    main()