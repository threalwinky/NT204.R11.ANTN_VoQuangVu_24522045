import argparse
from scapy.all import sniff, rdpcap

def main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--interface")
    group.add_argument("--pcap")
    args = parser.parse_args()

    if args.interface:
        print(f"Sniffing on {args.interface}...")
        sniff(iface=args.interface, prn=lambda pkt: print(pkt.summary()), store=0)
    elif args.pcap:
        print(f"Reading from {args.pcap}...")
        for pkt in rdpcap(args.pcap):
            print(pkt.summary())

if __name__ == "__main__":
    main()