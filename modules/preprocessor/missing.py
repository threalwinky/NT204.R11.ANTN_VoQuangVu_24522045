from copy import deepcopy

from ..models import NormalizedIDSEvent


SCHEMAS = {
    ("HTTP", "request"): {
        "defaults": {
            "method": None,
            "uri": None,
            "version": None,
            "headers": {},
            "body": None,
            "normalized_headers": {},
            "normalized_uri": None,
            "normalized_path": None,
        },
        "required": ("method", "uri", "version"),
    },
    ("HTTP", "response"): {
        "defaults": {
            "version": None,
            "status_code": None,
            "reason": None,
            "headers": {},
            "body": None,
            "normalized_headers": {},
        },
        "required": ("version", "status_code"),
    },
    ("DNS", "query"): {
        "defaults": {
            "domain": None,
            "query_type": None,
            "query_type_code": None,
            "normalized_domain": None,
        },
        "required": ("domain",),
    },
    ("DNS", "response"): {
        "defaults": {
            "answer": None,
        },
        "required": ("answer",),
    },
    ("SMTP", "command"): {
        "defaults": {
            "command": None,
            "argument": None,
            "mime_parts": [],
        },
        "required": ("command",),
    },
    ("SMTP", "response"): {
        "defaults": {
            "status_code": None,
            "message": None,
            "mime_parts": [],
        },
        "required": ("status_code",),
    },
}


def handle_missing_fields(
    event: NormalizedIDSEvent,
) -> NormalizedIDSEvent:

    data = event.application_data

    if not isinstance(data, dict):
        return event

    protocol = event.application_protocol
    event_type = data.get("type")
    schema = SCHEMAS.get((protocol, event_type))

    missing = []

    if schema is None:
        if protocol in ("HTTP", "DNS", "SMTP"):
            if event_type is None:
                if not (
                    protocol == "SMTP"
                    and data.get("mime_parts")
                ):
                    missing.append("missing_application_type")
            else:
                missing.append("unsupported_application_data_type")
    else:
        required = schema["required"]

        for name in required:
            if data.get(name) is None:
                missing.append(f"missing_{name}")

        for name, default in schema["defaults"].items():
            if name not in data:
                data[name] = deepcopy(default)

    if missing:
        if event.preprocess_status == "valid":
            event.preprocess_status = "partial"

        reasons = event.reason.split("; ") if event.reason else []

        for reason in missing:
            if reason not in reasons:
                reasons.append(reason)

        event.reason = "; ".join(reasons)

    return event


def apply_processing_policy(
    event: NormalizedIDSEvent,
    skip_partial: bool = False,
    skip_invalid: bool = False,
    skip_unknown: bool = False,
) -> NormalizedIDSEvent:

    should_skip = (
        (skip_partial and event.preprocess_status == "partial")
        or (skip_invalid and event.preprocess_status == "invalid")
        or (skip_unknown and event.status == "UNKNOWN")
    )

    event.processing_action = "skip" if should_skip else "emit"

    return event
