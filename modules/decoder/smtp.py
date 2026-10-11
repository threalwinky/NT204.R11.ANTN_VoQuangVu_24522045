from base64 import b64decode
from binascii import Error
from email import policy
from email.parser import BytesParser
from quopri import decodestring

from scapy.packet import Packet, Raw

from ..models import NormalizedIDSEvent


def decode_smtp_mime(
    packet: Packet,
    event: NormalizedIDSEvent,
    max_message_bytes: int = 1048576,
) -> NormalizedIDSEvent:

    if event.application_protocol != "SMTP":
        return event

    if not packet.haslayer(Raw):
        return event

    payload = bytes(packet[Raw].load)
    data = event.application_data

    if len(payload) > max_message_bytes:
        data["mime_decode_status"] = "SKIPPED"
        data["mime_decode_error"] = "Message exceeds size limit"
        return event

    if payload.endswith(b"\r\n.\r\n"):
        payload = payload[:-5]

    message = BytesParser(policy=policy.compat32).parsebytes(payload)
    decoded_parts = []

    for part in message.walk():
        if part.is_multipart():
            continue

        encoding = str(
            part.get("Content-Transfer-Encoding", "")
        ).strip().lower()

        if encoding not in ("base64", "quoted-printable"):
            continue

        raw_body = part.get_payload(decode=False)

        if not isinstance(raw_body, str):
            continue

        result = {
            "content_type": part.get_content_type(),
            "encoding": encoding,
            "charset": part.get_content_charset() or "utf-8",
        }

        try:
            encoded_bytes = raw_body.encode(
                "ascii", errors="surrogateescape"
            )

            if encoding == "base64":
                decoded_bytes = b64decode(
                    b"".join(encoded_bytes.split()),
                    validate=True,
                )
            else:
                decoded_bytes = decodestring(encoded_bytes)

            try:
                decoded_body = decoded_bytes.decode(result["charset"])
                result["decode_status"] = "OK"
            except (UnicodeError, LookupError):
                decoded_body = decoded_bytes.decode(
                    "utf-8", errors="replace"
                )
                result["decode_status"] = "PARTIAL"

            result["decoded_body"] = decoded_body

        except (Error, ValueError, UnicodeEncodeError) as error:
            result["decode_status"] = "ERROR"
            result["error"] = str(error)

        decoded_parts.append(result)

    if not decoded_parts:
        return event

    data["mime_parts"] = decoded_parts

    statuses = [
        part["decode_status"] for part in decoded_parts
    ]

    if all(status == "ERROR" for status in statuses):
        data["mime_decode_status"] = "ERROR"
    elif any(status != "OK" for status in statuses):
        data["mime_decode_status"] = "PARTIAL"
    else:
        data["mime_decode_status"] = "OK"

    if len(decoded_parts) == 1:
        decoded_body = decoded_parts[0].get("decoded_body")
        if decoded_body is not None:
            data["mime_decoded_body"] = decoded_body

    return event
