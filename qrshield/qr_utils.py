"""QR image decoding and QR image generation helpers."""

from __future__ import annotations

from io import BytesIO

import cv2
import numpy as np
import qrcode
from PIL import Image, ImageOps

MAX_IMAGE_BYTES = 10 * 1024 * 1024
MAX_IMAGE_PIXELS = 25_000_000


def decode_qr_image(image_bytes: bytes) -> list[str]:
    """Decode one or more QR codes from an uploaded image safely."""
    if not image_bytes:
        raise ValueError("The uploaded image is empty.")
    if len(image_bytes) > MAX_IMAGE_BYTES:
        raise ValueError("Please upload an image smaller than 10 MB.")

    try:
        with Image.open(BytesIO(image_bytes)) as source:
            width, height = source.size
            if width * height > MAX_IMAGE_PIXELS:
                raise ValueError("This image is too large to process. Please use an image under 25 megapixels.")
            image = ImageOps.exif_transpose(source).convert("RGB")
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError("This image could not be read. Try a clear PNG or JPG file.") from exc

    # Keep detection responsive for very large camera images.
    if max(image.size) > 2400:
        ratio = 2400 / max(image.size)
        new_size = (max(1, int(image.width * ratio)), max(1, int(image.height * ratio)))
        image = image.resize(new_size, Image.Resampling.LANCZOS)

    rgb = np.asarray(image)
    bgr = cv2.cvtColor(rgb, cv2.COLOR_RGB2BGR)
    gray = cv2.cvtColor(bgr, cv2.COLOR_BGR2GRAY)
    detector = cv2.QRCodeDetector()
    found: list[str] = []

    # OpenCV versions differ; try multi-code detection first where available.
    try:
        if hasattr(detector, "detectAndDecodeMulti"):
            result = detector.detectAndDecodeMulti(gray)
            if result and len(result) >= 2 and result[0]:
                found.extend(value.strip() for value in result[1] if value and value.strip())
    except cv2.error:
        pass

    if not found:
        try:
            decoded, _points, _straight = detector.detectAndDecode(gray)
            if decoded and decoded.strip():
                found.append(decoded.strip())
        except cv2.error:
            pass

    # Remove duplicate text if the detector reports the same code twice.
    return list(dict.fromkeys(found))


def generate_qr_png(payload: str) -> bytes:
    """Generate a downloadable PNG for safe testing and demonstration."""
    if not payload or not payload.strip():
        raise ValueError("Enter some text or a URL before generating a QR code.")
    if len(payload) > 2000:
        raise ValueError("Please use a payload under 2,000 characters for QR generation.")

    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=4,
    )
    qr.add_data(payload.strip())
    qr.make(fit=True)
    image = qr.make_image(fill_color="#07111f", back_color="white").convert("RGB")
    buffer = BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()
