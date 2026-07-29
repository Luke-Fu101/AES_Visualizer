"""The four AES round operations: SubBytes, ShiftRows, MixColumns, AddRoundKey.

The state is a 16-byte sequence in column-major order: byte
index c*4 + r is row r, column c.
"""

from constants import INV_SBOX, SBOX


def sub_bytes(state: bytes) -> bytes:
    """Replace each byte of the state with its S-box lookup."""
    return bytes(SBOX[b] for b in state)


def inv_sub_bytes(state: bytes) -> bytes:
    """Replace each byte of the state with its inverse S-box lookup."""
    return bytes(INV_SBOX[b] for b in state)


def shift_rows(state: bytes) -> bytes:
    """Cyclically shift row r left by r bytes (row 0 unchanged)."""
    result = bytearray(16)
    for r in range(4):
        for c in range(4):
            result[c * 4 + r] = state[((c + r) % 4) * 4 + r]
    return bytes(result)


def inv_shift_rows(state: bytes) -> bytes:
    """Cyclically shift row r right by r bytes (inverse of shift_rows)."""
    result = bytearray(16)
    for r in range(4):
        for c in range(4):
            result[c * 4 + r] = state[((c - r) % 4) * 4 + r]
    return bytes(result)


def _xtime(b: int) -> int:
    """Multiply a byte by 2 in GF(2^8), reducing mod the AES field polynomial."""
    b <<= 1
    if b & 0x100:
        b ^= 0x11B
    return b & 0xFF


def _mix_single_column(col: bytes) -> bytes:
    a0, a1, a2, a3 = col
    r0 = _xtime(a0) ^ (_xtime(a1) ^ a1) ^ a2 ^ a3
    r1 = a0 ^ _xtime(a1) ^ (_xtime(a2) ^ a2) ^ a3
    r2 = a0 ^ a1 ^ _xtime(a2) ^ (_xtime(a3) ^ a3)
    r3 = (_xtime(a0) ^ a0) ^ a1 ^ a2 ^ _xtime(a3)
    return bytes([r0, r1, r2, r3])


def mix_columns(state: bytes) -> bytes:
    """Multiply each column by the fixed AES MixColumns matrix over GF(2^8)."""
    result = bytearray(16)
    for c in range(4):
        result[c * 4 : c * 4 + 4] = _mix_single_column(state[c * 4 : c * 4 + 4])
    return bytes(result)


def _gf_multiply(a: int, b: int) -> int:
    """Multiply two bytes in GF(2^8) (Russian peasant multiplication).

    InvMixColumns' coefficients (0x0E, 0x0B, 0x0D, 0x09) are too large to
    build cheaply from _xtime alone the way MixColumns' 2s and 3s are, so
    this covers the general case.
    """
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        high_bit = a & 0x80
        a = (a << 1) & 0xFF
        if high_bit:
            a ^= 0x1B
        b >>= 1
    return result


def _inv_mix_single_column(col: bytes) -> bytes:
    a0, a1, a2, a3 = col
    r0 = _gf_multiply(a0, 0x0E) ^ _gf_multiply(a1, 0x0B) ^ _gf_multiply(a2, 0x0D) ^ _gf_multiply(a3, 0x09)
    r1 = _gf_multiply(a0, 0x09) ^ _gf_multiply(a1, 0x0E) ^ _gf_multiply(a2, 0x0B) ^ _gf_multiply(a3, 0x0D)
    r2 = _gf_multiply(a0, 0x0D) ^ _gf_multiply(a1, 0x09) ^ _gf_multiply(a2, 0x0E) ^ _gf_multiply(a3, 0x0B)
    r3 = _gf_multiply(a0, 0x0B) ^ _gf_multiply(a1, 0x0D) ^ _gf_multiply(a2, 0x09) ^ _gf_multiply(a3, 0x0E)
    return bytes([r0, r1, r2, r3])


def inv_mix_columns(state: bytes) -> bytes:
    """Multiply each column by the fixed AES InvMixColumns matrix over GF(2^8)."""
    result = bytearray(16)
    for c in range(4):
        result[c * 4 : c * 4 + 4] = _inv_mix_single_column(state[c * 4 : c * 4 + 4])
    return bytes(result)


def add_round_key(state: bytes, round_key: bytes) -> bytes:
    """XOR the state with the round key."""
    return bytes(s ^ k for s, k in zip(state, round_key))
