import argparse
from scapy.all import sniff
from main.capture import read_pcap


def main():
    parser = argparse.ArgumentParser()

    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument("--interface")
    group.add_argument("--pcap")

    args = parser.parse_args()

    if args.interface:
        print(f"Sniffing on {args.interface}...")

        sniff(
            iface=args.interface,
            prn=lambda pkt: print(pkt.summary()),
            store=0,
        )

    elif args.pcap:
        print(f"Reading from {args.pcap}...")

        for event in read_pcap(args.pcap):
            print(event.to_dict())


if __name__ == "__main__":
    main()