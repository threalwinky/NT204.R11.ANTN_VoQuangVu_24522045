# Core Engine

Core Engine thực hiện Snort rule matching cho hệ thống IDS.

## Input

- Normalized IDS Event từ Preprocessor.
- Flow context từ Flow Tracker.

Core Engine không đọc trực tiếp raw packet từ Scapy.

## Modules

- loader.py: Nạp Snort rules từ file.
- parser.py: Parse và validate Snort rules.
- repository.py: Lưu trữ và index rules.
- matcher.py: So khớp rule với event và flow context.
- evaluator.py: Đánh giá candidate rules.
- detection.py: Sinh Detection Events.

## Pipeline

Normalized Event + Flow Context
    -> Rule Evaluation Engine
    -> Rule Repository / Indexer
    -> Rule Matching Engine
    -> Detection Event

## Status

Core Engine package initialized.
Rule matching functionality is not implemented yet.
