"""Safe, local QR decoding from static image bytes (decode ≠ open).

Module responsibility:
    Turn in-memory image bytes into QR payload *strings*. Nothing else.

Key invariants:
    * Input is bytes already in memory — never a path, URL, or remote image.
    * Decoding returns text only; payloads are never opened, fetched,
      resolved, executed, or passed to a browser. Callers treat them as
      untrusted strings.
    * Only raster formats (PNG, JPEG, GIF, BMP, WEBP) are accepted; the first
      frame is used. Byte size and pixel count are capped before pixel data is
      loaded, and Pillow decompression-bomb warnings are treated as errors.
    * Optional dependency: ``pip install .[qr]`` (Pillow + zxing-cpp). When
      unavailable, ``default_qr_decoder()`` returns ``None`` and callers
      report ``decoder_unavailable`` instead of guessing.

Side effects:
    None (CPU-only image decoding in memory).
"""

from __future__ import annotations

import io
import warnings
from collections.abc import Callable

try:
    import zxingcpp
    from PIL import Image, UnidentifiedImageError
except ImportError:  # optional dependency group "qr"
    zxingcpp = None  # type: ignore[assignment]
    Image = None  # type: ignore[assignment]
    UnidentifiedImageError = OSError  # type: ignore[assignment,misc]

QrDecoder = Callable[[bytes], list[str]]

MAX_DECODE_BYTES = 5 * 1024 * 1024
MAX_PIXELS = 16_000_000
MIN_SIDE_PX = 21
MAX_PAYLOADS_PER_IMAGE = 5
ALLOWED_FORMATS = ("PNG", "JPEG", "GIF", "BMP", "WEBP")


class QrDecodeError(ValueError):
    """Image could not be decoded safely; ``reason`` is ``too_large`` or ``invalid_image``."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def decoder_available() -> bool:
    """Return True when the optional Pillow + zxing-cpp stack is importable."""
    return zxingcpp is not None and Image is not None


def zxing_qr_decoder(data: bytes) -> list[str]:
    """Decode QR payload strings from raster image bytes.

    Raises:
        QrDecodeError: bytes exceed limits or are not a supported image.
        RuntimeError: optional dependencies are not installed.
    """
    if zxingcpp is None or Image is None:
        raise RuntimeError("QR decoding requires the optional 'qr' extra (Pillow, zxing-cpp)")
    if len(data) > MAX_DECODE_BYTES:
        raise QrDecodeError("too_large")
    with warnings.catch_warnings():
        warnings.simplefilter("error", Image.DecompressionBombWarning)
        try:
            with Image.open(io.BytesIO(data), formats=list(ALLOWED_FORMATS)) as img:
                width, height = img.size
                if width * height > MAX_PIXELS:
                    raise QrDecodeError("too_large")
                if width < MIN_SIDE_PX or height < MIN_SIDE_PX:
                    return []
                img.seek(0)
                gray = img.convert("L")
        except QrDecodeError:
            raise
        except (
            UnidentifiedImageError,
            Image.DecompressionBombError,
            Image.DecompressionBombWarning,
            OSError,
            ValueError,
            EOFError,
            SyntaxError,
        ) as exc:
            raise QrDecodeError("invalid_image") from exc
    results = zxingcpp.read_barcodes(
        gray, formats=zxingcpp.BarcodeFormats(zxingcpp.BarcodeFormat.QRCode)
    )
    return [r.text for r in results if r.text][:MAX_PAYLOADS_PER_IMAGE]


def default_qr_decoder() -> QrDecoder | None:
    """Return the built-in decoder, or ``None`` when the optional stack is missing."""
    return zxing_qr_decoder if decoder_available() else None


__all__ = [
    "ALLOWED_FORMATS",
    "MAX_DECODE_BYTES",
    "MAX_PIXELS",
    "QrDecodeError",
    "QrDecoder",
    "decoder_available",
    "default_qr_decoder",
    "zxing_qr_decoder",
]
