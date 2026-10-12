import re
from ipaddress import IPv4Address
from urllib.parse import urlsplit

from ..models import NormalizedIDSEvent


def _normalize_protocol(value, names):
    if not isinstance(value, str):
        return value

    name = value.strip().upper()
    return names.get(name, name)


def _normalize_ipv4(value):
    if not isinstance(value, str):
        return value

    value = value.strip()

    try:
        return str(IPv4Address(value))
    except ValueError:
        return value


def _normalize_domain(value):
    return value.strip().rstrip(".").lower()


def normalize_event(
    event: NormalizedIDSEvent,
) -> NormalizedIDSEvent:

    event.network_protocol = _normalize_protocol(
        event.network_protocol,
        {"IPV4": "IPv4", "IPV6": "IPv6"},
    )

    event.transport_protocol = _normalize_protocol(
        event.transport_protocol,
        {"TCP": "TCP", "UDP": "UDP"},
    )

    event.application_protocol = _normalize_protocol(
        event.application_protocol,
        {"HTTP": "HTTP", "DNS": "DNS", "SMTP": "SMTP"},
    )

    if event.network_protocol == "IPv4":
        event.src_ip = _normalize_ipv4(event.src_ip)
        event.dst_ip = _normalize_ipv4(event.dst_ip)

    if type(event.timestamp) is int:
        event.timestamp = float(event.timestamp)

    data = event.application_data

    if not isinstance(data, dict):
        return event

    if event.application_protocol == "DNS":
        domain = data.get("domain")

        if isinstance(domain, str):
            data["normalized_domain"] = _normalize_domain(domain)

        answer = data.get("answer")

        if isinstance(answer, dict):
            name = answer.get("name")

            if isinstance(name, str):
                answer["normalized_name"] = _normalize_domain(name)

    if event.application_protocol == "HTTP":
        headers = data.get("headers")

        if isinstance(headers, dict):
            data["normalized_headers"] = {
                name.strip().lower(): value
                for name, value in headers.items()
                if isinstance(name, str)
            }

        uri = data.get("uri")

        if isinstance(uri, str):
            normalized_uri = re.sub(
                r"%[0-9a-fA-F]{2}",
                lambda match: match.group(0).upper(),
                uri,
            )

            data["normalized_uri"] = normalized_uri

            try:
                data["normalized_path"] = urlsplit(
                    normalized_uri
                ).path
            except ValueError:
                data["normalized_path"] = None

    return event
