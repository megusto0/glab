from __future__ import annotations

import io
import math
import random
from typing import Dict, Iterable, List, Tuple

from PIL import Image


def bsc_channel(data: bytes, ber: float, seed: int | None = None) -> bytes:
    """Simulate a binary symmetric channel with the given bit error rate."""
    if ber <= 0 or not data:
        return data
    rng = random.Random(seed)
    mutated = bytearray()
    for byte in data:
        value = byte
        for bit in range(8):
            if rng.random() < ber:
                value ^= 1 << bit
        mutated.append(value)
    return bytes(mutated)


def repetition3_encode(data: bytes) -> bytes:
    """Encode payload by repeating each byte three times (with implicit interleaving)."""
    length = len(data)
    if length == 0:
        return b""
    encoded = bytearray(length * 3)
    for index, value in enumerate(data):
        encoded[index] = value
        encoded[index + length] = value
        encoded[index + 2 * length] = value
    return bytes(encoded)


def repetition3_decode(data: bytes) -> bytes:
    """Decode repetition-3 payload using majority voting per bit."""
    if len(data) % 3 != 0:
        raise ValueError("Repetition-3 payload length mismatch")
    chunk_size = len(data) // 3
    part_a = data[:chunk_size]
    part_b = data[chunk_size : 2 * chunk_size]
    part_c = data[2 * chunk_size :]
    output = bytearray(chunk_size)
    for idx in range(chunk_size):
        a = part_a[idx]
        b = part_b[idx]
        c = part_c[idx]
        value = 0
        for bit in range(8):
            votes = ((a >> bit) & 1) + ((b >> bit) & 1) + ((c >> bit) & 1)
            if votes >= 2:
                value |= 1 << bit
        output[idx] = value
    return bytes(output)


def bytes_to_gray_png(data: bytes, width: int = 256) -> bytes:
    """Convert arbitrary bytes into a grayscale PNG for visualisation."""
    width = max(16, width)
    if not data:
        data = b"\x00"
    height = math.ceil(len(data) / width)
    padded = data + b"\x00" * (width * height - len(data))
    image = Image.frombytes("L", (width, height), padded)
    png_buffer = io.BytesIO()
    image.save(png_buffer, format="PNG")
    return png_buffer.getvalue()


def bit_error_statistics(original: bytes, corrupted: bytes) -> Dict[str, float]:
    """Return bit-error statistics between two payloads."""
    max_len = max(len(original), len(corrupted))
    if max_len == 0:
        return {"bit_errors": 0, "total_bits": 0, "ber_actual": 0.0}
    total_bits = max_len * 8
    bit_errors = 0
    min_len = min(len(original), len(corrupted))
    for idx in range(min_len):
        bit_errors += (original[idx] ^ corrupted[idx]).bit_count()
    if len(original) != len(corrupted):
        bit_errors += (abs(len(original) - len(corrupted)) * 8)
    ber = bit_errors / total_bits
    return {"bit_errors": bit_errors, "total_bits": total_bits, "ber_actual": ber}


__all__ = [
    "bsc_channel",
    "repetition3_encode",
    "repetition3_decode",
    "bytes_to_gray_png",
    "bit_error_statistics",
]
