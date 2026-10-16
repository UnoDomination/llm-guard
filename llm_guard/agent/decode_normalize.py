from __future__ import annotations

import base64
import binascii
import re

from llm_guard.util import get_logger

LOGGER = get_logger()

# Zero-width / invisible format characters commonly used to hide payloads.
_ZERO_WIDTH_RE = re.compile(
    r"[\u200b\u200c\u200d\u2060\ufeff\u180e\u200e\u200f\u202a-\u202e\u2066-\u2069]"
)

# Base64 blobs (padded or unpadded), prefer longer candidates to reduce noise.
_BASE64_RE = re.compile(
    r"(?:[A-Za-z0-9+/]{24,}={0,2}|[A-Za-z0-9\-_]{24,}={0,2})"
)

# Hex-encoded payloads (even length, reasonably long).
_HEX_RE = re.compile(r"(?:0x)?([0-9a-fA-F]{32,})")

_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r"ignore\s+(all\s+)?(previous|prior|above|original)\s+"
        r"(instructions?|prompts?|context|rules?|goals?)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(reveal|leak|print|show|dump)\s+(the\s+)?(system\s+)?prompt",
        re.IGNORECASE,
    ),
    re.compile(
        r"(system\s+override|override\s+(the\s+)?system\s+(prompt|instructions?)|"
        r"new\s+system\s+(prompt|instructions?))",
        re.IGNORECASE,
    ),
    re.compile(
        r"disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|rules?)",
        re.IGNORECASE,
    ),
    re.compile(
        r"you\s+are\s+now\s+(in\s+)?(developer|DAN|jailbreak)\s+mode",
        re.IGNORECASE,
    ),
]


def strip_zero_width(text: str) -> str:
    """Remove zero-width and bidi override characters."""
    return _ZERO_WIDTH_RE.sub("", text)


def _looks_like_injection(text: str) -> bool:
    return any(p.search(text) for p in _INJECTION_PATTERNS)


def _try_decode_base64(blob: str) -> str | None:
    # Pure hex strings are handled by the hex decoder to avoid false base64 hits.
    if re.fullmatch(r"(?:0x)?[0-9a-fA-F]+", blob):
        return None

    padded = blob + "=" * (-len(blob) % 4)
    decoders = (
        lambda s: base64.b64decode(s, validate=False),
        base64.urlsafe_b64decode,
    )
    for decoder in decoders:
        try:
            raw = decoder(padded)
            # Prefer printable / utf-8 text payloads.
            decoded = raw.decode("utf-8")
            if decoded.isprintable() or "\n" in decoded or "\t" in decoded:
                return decoded
        except (binascii.Error, UnicodeDecodeError, ValueError, TypeError):
            continue
    return None


def _try_decode_hex(blob: str) -> str | None:
    hex_str = blob[2:] if blob.lower().startswith("0x") else blob
    if len(hex_str) % 2 != 0:
        return None
    try:
        raw = bytes.fromhex(hex_str)
        return raw.decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None


class DecodeNormalize:
    """
    Detect encoded (base64/hex) ignore-previous / system-prompt leak instructions.

    Also strips zero-width characters. When decoded content looks like injection,
    the prompt is marked invalid; with ``redact=True`` the encoded blob is replaced.
    """

    def __init__(self, *, redact: bool = False, decode: bool = True) -> None:
        self._redact = redact
        self._decode = decode

    def scan(self, prompt: str) -> tuple[str, bool, float]:
        if not prompt:
            return prompt, True, -1.0

        sanitized = strip_zero_width(prompt)
        zero_width_stripped = sanitized != prompt

        if not self._decode:
            if zero_width_stripped:
                LOGGER.debug("Stripped zero-width characters")
            return sanitized, True, -1.0 if not zero_width_stripped else 0.0

        found_injection = False
        blobs_to_redact: list[str] = []

        for match in _BASE64_RE.finditer(sanitized):
            blob = match.group(0)
            decoded = _try_decode_base64(blob)
            if decoded and _looks_like_injection(decoded):
                LOGGER.warning(
                    "Base64 payload decodes to injection",
                    preview=decoded[:120],
                )
                found_injection = True
                blobs_to_redact.append(blob)

        for match in _HEX_RE.finditer(sanitized):
            blob = match.group(0)
            decoded = _try_decode_hex(blob)
            if decoded and _looks_like_injection(decoded):
                LOGGER.warning(
                    "Hex payload decodes to injection",
                    preview=decoded[:120],
                )
                found_injection = True
                blobs_to_redact.append(blob)

        if found_injection:
            if self._redact:
                for blob in blobs_to_redact:
                    sanitized = sanitized.replace(blob, "[REDACTED]")
                LOGGER.debug("Redacted encoded injection payloads")
            return sanitized, False, 1.0

        if zero_width_stripped:
            LOGGER.debug("Stripped zero-width characters")
            return sanitized, True, 0.0

        LOGGER.debug("No encoded injection payloads found")
        return sanitized, True, -1.0
