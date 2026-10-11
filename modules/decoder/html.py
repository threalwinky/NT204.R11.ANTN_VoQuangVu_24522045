from html import unescape

from ..models import NormalizedIDSEvent


def decode_html_entities(
    event: NormalizedIDSEvent,
    max_chars: int = 1000000,
) -> NormalizedIDSEvent:

    if event.application_protocol != "HTTP":
        return event

    data = event.application_data

    if data.get("type") not in ("request", "response"):
        return event

    headers = data.get("headers", {})
    content_type = ""

    if isinstance(headers, dict):
        for name, value in headers.items():
            if isinstance(name, str) and name.lower() == "content-type":
                if isinstance(value, str):
                    content_type = value.split(";", 1)[0].strip().lower()
                break

    if content_type not in ("", "text/html", "application/xhtml+xml"):
        return event

    body = data.get("body")

    if not isinstance(body, str) or not body:
        return event

    if len(body) > max_chars:
        data["html_decode_status"] = "SKIPPED"
        data["html_decode_reason"] = "Body exceeds character limit"
        return event

    data["decoded_body"] = unescape(body)
    data["html_decode_status"] = "OK"

    return event
