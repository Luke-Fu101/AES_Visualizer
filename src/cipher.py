"""Orchestrates a full AES encrypt/decrypt by running the round operations in order.

"""

from key_schedule import key_expansion
from transformations import add_round_key, mix_columns, shift_rows, sub_bytes
from trace import CipherTrace, RoundRecord


def encrypt_block(plaintext: bytes, key: bytes) -> CipherTrace:
    """Encrypt a single 16-byte block under the given key, recording each round."""
    round_keys = key_expansion(key)
    nr = len(round_keys) - 1

    result = CipherTrace(plaintext=plaintext, key=key)

    state_before = plaintext
    state = add_round_key(plaintext, round_keys[0])
    result.rounds.append(RoundRecord(0, round_keys[0], state_before, state))

    for round_num in range(1, nr):
        state_before = state
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[round_num])
        result.rounds.append(RoundRecord(round_num, round_keys[round_num], state_before, state))

    state_before = state
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[nr])
    result.rounds.append(RoundRecord(nr, round_keys[nr], state_before, state))

    result.ciphertext = state
    return result
