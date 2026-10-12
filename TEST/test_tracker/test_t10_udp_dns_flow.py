from pathlib import Path
from tempfile import TemporaryDirectory

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.utils import wrpcap

from modules.capture import read_pcap
from modules.core import parse_packet
from modules.tracker import FlowTracker


CLIENT = "192.168.1.10"
SERVER = "8.8.8.8"
DOMAIN = "ExAmPlE.COM."


def make_query(client_port=53000, dns_id=100):
    return (
        IP(src=CLIENT, dst=SERVER)
        / UDP(sport=client_port, dport=53)
        / DNS(
            id=dns_id,
            qr=0,
            qd=DNSQR(qname=DOMAIN, qtype="A"),
        )
    )


def make_response(client_port=53000, dns_id=100):
    return (
        IP(src=SERVER, dst=CLIENT)
        / UDP(sport=53, dport=client_port)
        / DNS(
            id=dns_id,
            qr=1,
            aa=1,
            qd=DNSQR(qname=DOMAIN, qtype="A"),
            an=DNSRR(
                rrname=DOMAIN,
                type="A",
                ttl=60,
                rdata="93.184.216.34",
            ),
            ancount=1,
        )
    )


def observe(tracker, packets):
    return [
        parse_packet(packet, index, tracker=tracker)
        for index, packet in enumerate(packets, start=1)
    ]


def test_t10_dns_query_response_same_flow():
    tracker = FlowTracker()

    events = observe(tracker, [
        make_query(),
        make_response(),
    ])

    assert len(events) == 2
    assert events[0].flow_id == events[1].flow_id
    assert events[0].flow_id == "flow-000001"

    assert [event.flow_direction for event in events] == [
        "forward",
        "backward",
    ]

    assert all(
        event.transport_protocol == "UDP"
        for event in events
    )
    assert all(
        event.application_protocol == "DNS"
        for event in events
    )
    assert all(event.tcp_state is None for event in events)
    assert all(event.preprocess_status == "valid" for event in events)
    assert len(tracker.flows) == 1


def test_t10_dns_query_response_content():
    tracker = FlowTracker()

    query, response = observe(tracker, [
        make_query(),
        make_response(),
    ])

    query_data = query.application_data
    response_data = response.application_data

    assert query_data["type"] == "query"
    assert query_data["domain"] == "ExAmPlE.COM"
    assert query_data["normalized_domain"] == "example.com"
    assert query_data["query_type"] == "A"

    assert response_data["type"] == "response"
    assert response_data["answer"]["name"] == "ExAmPlE.COM"
    assert response_data["answer"]["normalized_name"] == "example.com"
    assert response_data["answer"]["record_type"] == "A"
    assert response_data["answer"]["data"] == "93.184.216.34"


def test_t10_multiple_dns_packets_same_flow():
    tracker = FlowTracker()

    events = observe(tracker, [
        make_query(dns_id=100),
        make_response(dns_id=100),
        make_query(dns_id=101),
        make_response(dns_id=101),
    ])

    assert len({event.flow_id for event in events}) == 1
    assert len(tracker.flows) == 1

    assert [event.flow_direction for event in events] == [
        "forward",
        "backward",
        "forward",
        "backward",
    ]


def test_t10_different_udp_client_ports():
    tracker = FlowTracker()

    events = observe(tracker, [
        make_query(client_port=53000),
        make_query(client_port=53001),
        make_response(client_port=53000),
        make_response(client_port=53001),
    ])

    assert events[0].flow_id == events[2].flow_id
    assert events[1].flow_id == events[3].flow_id
    assert events[0].flow_id != events[1].flow_id
    assert len(tracker.flows) == 2


def test_t10_response_first_defines_direction():
    tracker = FlowTracker()

    events = observe(tracker, [
        make_response(),
        make_query(),
    ])

    assert events[0].flow_id == events[1].flow_id
    assert events[0].flow_direction == "forward"
    assert events[1].flow_direction == "backward"

    flow = next(iter(tracker.flows.values()))

    assert flow.initiator == (SERVER, 53)
    assert flow.responder == (CLIENT, 53000)
    assert flow.protocol == "UDP"


def test_t10_udp_without_dns():
    tracker = FlowTracker()

    packets = [
        IP(src=CLIENT, dst=SERVER)
        / UDP(sport=51000, dport=9999),

        IP(src=SERVER, dst=CLIENT)
        / UDP(sport=9999, dport=51000),
    ]

    events = observe(tracker, packets)

    assert events[0].flow_id == events[1].flow_id
    assert events[0].flow_direction == "forward"
    assert events[1].flow_direction == "backward"

    assert all(event.tcp_state is None for event in events)
    assert all(event.application_protocol is None for event in events)
    assert all(event.preprocess_status == "partial" for event in events)
    assert len(tracker.flows) == 1


def test_t10_dns_response_without_answer():
    tracker = FlowTracker()

    packet = (
        IP(src=SERVER, dst=CLIENT)
        / UDP(sport=53, dport=53000)
        / DNS(
            id=100,
            qr=1,
            qd=DNSQR(qname=DOMAIN),
            ancount=0,
        )
    )

    event = parse_packet(packet, 1, tracker=tracker)

    assert event.status == "OK"
    assert event.application_protocol == "DNS"
    assert event.preprocess_status == "partial"
    assert "missing_application_type" in event.reason
    assert event.flow_id is not None
    assert event.tcp_state is None
    assert len(tracker.flows) == 1


def test_t10_tcp_udp_separate_flows():
    tracker = FlowTracker()

    tcp_packet = (
        IP(src=CLIENT, dst=SERVER)
        / TCP(sport=53000, dport=53, flags="S")
    )

    events = observe(tracker, [
        make_query(),
        tcp_packet,
        make_response(),
    ])

    assert events[0].flow_id == events[2].flow_id
    assert events[0].flow_id != events[1].flow_id
    assert events[0].tcp_state is None
    assert events[1].tcp_state == "NEW"
    assert len(tracker.flows) == 2


def test_t10_dns_pcap():
    packets = [
        make_query(client_port=53000),
        make_response(client_port=53000),
        make_query(client_port=53001),
        make_response(client_port=53001),
    ]

    with TemporaryDirectory() as directory:
        path = Path(directory) / "t10_dns_flow.pcap"
        wrpcap(str(path), packets)
        events = list(read_pcap(path))

    assert len(events) == 4
    assert [event.packet_id for event in events] == [1, 2, 3, 4]

    assert events[0].flow_id == events[1].flow_id
    assert events[2].flow_id == events[3].flow_id
    assert events[0].flow_id != events[2].flow_id

    assert [event.flow_direction for event in events] == [
        "forward",
        "backward",
        "forward",
        "backward",
    ]

    assert all(event.tcp_state is None for event in events)
    assert all(event.application_protocol == "DNS" for event in events)
    assert events[0].to_dict()["flow_id"] == events[1].flow_id
