"""Stage 2b: sub-10ms deterministic fleet screening.

Latency is bounded by design: signatures are pre-compiled, patterns are linear
(no nested quantifiers), and only the first _SCAN_WINDOW characters are scanned.
Anything larger than 2 KB is flagged by the size rule regardless.
"""
import re
import time

from app.config import settings
from app.schemas.models import FleetRecord, FleetStatus

_SCAN_WINDOW = 8192

# (flag name, compiled pattern). Matching is case-insensitive.
# NOTE: the bare SELECT rule is intentionally literal (per spec) and will flag any
# payload containing the word "select". Tune it if your devices legitimately use it.
_SIGNATURES: tuple = tuple(
    (name, re.compile(pattern, re.IGNORECASE))
    for name, pattern in (
        ("SQLI_DROP_TABLE", r"\bdrop\s+table\b"),
        ("SQLI_SELECT", r"\bselect\b"),
        ("SQLI_TAUTOLOGY", r"['\"]\s*or\s*['\"]?\d+['\"]?\s*=\s*['\"]?\d+"),
        ("CMD_EXEC", r"\bexec\b"),
        ("CMD_CHAINING", r";\s*(?:rm|wget|curl|nc|ncat|bash|sh|chmod|python)\b"),
        ("CMD_SUBSTITUTION", r"\$\([^)]*\)|`[^`]*`"),
        ("CMD_PIPE_TO_SHELL", r"\|\s*(?:ba)?sh\b"),
    )
)


def evaluate_fleet(record: FleetRecord) -> FleetRecord:
    """Annotate `record` in place with status + flags and return it.

    * request_rate_hz > 100          -> DOS
    * payload > 2048 bytes OR a SQLi/command-injection signature
                                      -> MALICIOUS_PAYLOAD (takes priority over DOS)
    """
    started = time.perf_counter()
    dos_flags: list[str] = []
    payload_flags: list[str] = []

    if record.request_rate_hz > settings.dos_threshold_hz:
        dos_flags.append(f"DOS_RATE({record.request_rate_hz:.0f}Hz>{settings.dos_threshold_hz:g}Hz)")

    size = record.payload_size_bytes or 0
    if size > settings.max_payload_bytes:
        payload_flags.append(f"OVERSIZED_PAYLOAD({size}B>{settings.max_payload_bytes}B)")

    window = record.payload[:_SCAN_WINDOW]
    if window:
        for name, pattern in _SIGNATURES:
            if pattern.search(window):
                payload_flags.append(name)

    record.flags = payload_flags + dos_flags
    if payload_flags:
        record.status = FleetStatus.MALICIOUS_PAYLOAD
    elif dos_flags:
        record.status = FleetStatus.DOS
    else:
        record.status = FleetStatus.NORMAL
    record.sentinel_latency_ms = round((time.perf_counter() - started) * 1000, 4)
    return record