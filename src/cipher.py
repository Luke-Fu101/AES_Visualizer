"""Orchestrates a full AES encrypt/decrypt by running the round operations in order.

"""

from key_schedule import key_expansion
from transformations import add_round_key, mix_columns, shift_rows, sub_bytes


def encrypt_block(plaintext: bytes, key: bytes) -> bytes:
    """Encrypt a single 16-byte block under the given key."""
    round_keys = key_expansion(key)
    nr = len(round_keys) - 1

    state = add_round_key(plaintext, round_keys[0])

    for round_num in range(1, nr):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[round_num])

    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[nr])

    return state
