from urllib.parse import unquote

from ..models import NormalizedIDSEvent


def decode_http_uri(
    event: NormalizedIDSEvent,
) -> NormalizedIDSEvent:

    if event.application_protocol != "HTTP":
        return event

    data = event.application_data

    if data.get("type") != "request":
        return event

    raw_uri = data.get("uri")

    if not isinstance(raw_uri, str):
        return event

    try:
        decoded_uri = unquote(
            raw_uri,
            encoding="utf-8",
            errors="strict",
        )
        data["decode_status"] = "OK"

    except UnicodeDecodeError:
        decoded_uri = unquote(
            raw_uri,
            encoding="utf-8",
            errors="replace",
        )
        data["decode_status"] = "PARTIAL"

    data["decoded_uri"] = decoded_uri

    return event
