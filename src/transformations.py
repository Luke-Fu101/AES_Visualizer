"""The four AES round operations: SubBytes, ShiftRows, MixColumns, AddRoundKey.

The state is a 16-byte sequence in column-major order: byte
index c*4 + r is row r, column c.
"""

from constants import SBOX


def sub_bytes(state: bytes) -> bytes:
    """Replace each byte of the state with its S-box lookup."""
    return bytes(SBOX[b] for b in state)


def shift_rows(state: bytes) -> bytes:
    """Cyclically shift row r left by r bytes (row 0 unchanged)."""
    result = bytearray(16)
    for r in range(4):
        for c in range(4):
            result[c * 4 + r] = state[((c + r) % 4) * 4 + r]
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


def add_round_key(state: bytes, round_key: bytes) -> bytes:
    """XOR the state with the round key."""
    return bytes(s ^ k for s, k in zip(state, round_key))
