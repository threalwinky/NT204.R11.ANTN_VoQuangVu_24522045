from collections.abc import Callable
from itertools import count
from threading import Event, RLock, Thread
from time import monotonic

from scapy.all import sniff
from scapy.error import Scapy_Exception
from scapy.interfaces import resolve_iface

from ..core import parse_packet
from ..models import NormalizedIDSEvent
from ..tracker import FlowTracker
from .errors import CaptureError


def capture_live(
    interface: str,
    on_event: Callable[[NormalizedIDSEvent], None],
    on_flow_expired: Callable[[dict[str, object]], None] | None = None,
    tcp_timeout: float = 300.0,
    udp_timeout: float = 60.0,
) -> None:
    
    try:
        iface = resolve_iface(interface)
    except ValueError as error:
        raise CaptureError(f"interface {interface!r} not found") from error

    packet_ids = count(start=1)
    tracker = FlowTracker(
        tcp_timeout=tcp_timeout,
        udp_timeout=udp_timeout,
        on_flow_expired=on_flow_expired,
    )

    tracker_lock = RLock()
    stop_expiration = Event()
    check_interval = min(
        0.5,
        tracker.tcp_timeout / 2,
        tracker.udp_timeout / 2,
    )

    last_packet_timestamp = None
    last_packet_monotonic = None

    def handle_packet(packet) -> None:
        nonlocal last_packet_timestamp, last_packet_monotonic

        with tracker_lock:
            packet_id = next(packet_ids)

            event = parse_packet(
                packet,
                packet_id=packet_id,
                tracker=tracker,
            )

            if event.flow_id is not None:
                last_packet_timestamp = float(event.timestamp)
                last_packet_monotonic = monotonic()

            on_event(event)

    def expire_on_idle() -> None:
        while not stop_expiration.wait(check_interval):
            with tracker_lock:
                if last_packet_timestamp is None:
                    continue

                elapsed = monotonic() - last_packet_monotonic
                now = last_packet_timestamp + elapsed
                tracker.expire_flows(now)

    expiration_thread = Thread(
        target=expire_on_idle,
        name="ids-live-flow-expiration",
        daemon=True,
    )

    expiration_thread.start()

    try:
        sniff(
            iface=iface,
            prn=handle_packet,
            store=False,
        )
    except (OSError, Scapy_Exception) as error:
        raise CaptureError(f"cannot capture on {interface!r}: {error}") from error
    finally:
        stop_expiration.set()
        expiration_thread.join()
