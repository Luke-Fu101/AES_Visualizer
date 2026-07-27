"""Orchestrates a full AES encrypt/decrypt by running the round operations in order.

"""

from key_schedule import key_expansion
from transformations import add_round_key, mix_columns, shift_rows, sub_bytes
from trace import CipherTrace, RoundRecord, StepRecord


def _apply(name, func, state, steps, *args):
    """Run one named step, recording its before/after state into steps."""
    before = state
    after = func(state, *args)
    steps.append(StepRecord(name, before, after))
    return after


def encrypt_block(plaintext: bytes, key: bytes) -> CipherTrace:
    """Encrypt a single 16-byte block under the given key, recording each round and step."""
    round_keys = key_expansion(key)
    nr = len(round_keys) - 1

    result = CipherTrace(plaintext=plaintext, key=key)

    round_before = plaintext
    steps = []
    state = _apply("AddRoundKey", add_round_key, plaintext, steps, round_keys[0])
    result.rounds.append(RoundRecord(0, round_keys[0], round_before, state, steps))

    for round_num in range(1, nr):
        round_before = state
        steps = []
        state = _apply("SubBytes", sub_bytes, state, steps)
        state = _apply("ShiftRows", shift_rows, state, steps)
        state = _apply("MixColumns", mix_columns, state, steps)
        state = _apply("AddRoundKey", add_round_key, state, steps, round_keys[round_num])
        result.rounds.append(RoundRecord(round_num, round_keys[round_num], round_before, state, steps))

    round_before = state
    steps = []
    state = _apply("SubBytes", sub_bytes, state, steps)
    state = _apply("ShiftRows", shift_rows, state, steps)
    state = _apply("AddRoundKey", add_round_key, state, steps, round_keys[nr])
    result.rounds.append(RoundRecord(nr, round_keys[nr], round_before, state, steps))

    result.ciphertext = state
    return result
