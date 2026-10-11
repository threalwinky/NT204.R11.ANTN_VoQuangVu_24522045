from urllib.parse import parse_qsl

from ..models import NormalizedIDSEvent


def decode_http_form(
    event: NormalizedIDSEvent,
    max_fields: int = 1000,
) -> NormalizedIDSEvent:

    if event.application_protocol != "HTTP":
        return event

    data = event.application_data

    if data.get("type") != "request":
        return event

    headers = data.get("headers")

    if not isinstance(headers, dict):
        return event

    content_type = ""

    for name, value in headers.items():
        if isinstance(name, str) and name.lower() == "content-type":
            if isinstance(value, str):
                content_type = value
            break

    media_type = content_type.split(";", 1)[0].strip().lower()

    if media_type != "application/x-www-form-urlencoded":
        return event

    raw_body = data.get("body")

    if not isinstance(raw_body, str):
        return event

    try:
        fields = parse_qsl(
            raw_body,
            keep_blank_values=True,
            encoding="utf-8",
            errors="strict",
            max_num_fields=max_fields,
        )
        decode_status = "OK"

    except UnicodeDecodeError:
        fields = parse_qsl(
            raw_body,
            keep_blank_values=True,
            encoding="utf-8",
            errors="replace",
            max_num_fields=max_fields,
        )
        decode_status = "PARTIAL"

    except ValueError as error:
        data["form_decode_status"] = "ERROR"
        data["form_decode_error"] = str(error)
        return event

    data["decoded_form"] = [
        {"name": name, "value": value}
        for name, value in fields
    ]
    data["form_decode_status"] = decode_status

    return event
