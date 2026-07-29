"""Orchestrates a full AES encrypt/decrypt by running the round operations in order.

"""

from key_schedule import key_expansion
from transformations import add_round_key, mix_columns, shift_rows, sub_bytes
from trace import CipherTrace, RoundRecord, StepRecord

BLOCK_SIZE = 16


def pad_pkcs7(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """Pad data with PKCS#7 up to the next multiple of block_size.

    If data is already a multiple of block_size (including empty), a full
    block of padding is added, so the padding is always unambiguous to
    strip back off later.
    """
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


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


def encrypt(plaintext: bytes, key: bytes) -> list[CipherTrace]:
    """Pad plaintext (PKCS#7) to a multiple of the block size, split it into
    16-byte blocks, and encrypt each block independently under the same key
    (ECB mode). Returns one CipherTrace per block."""
    padded = pad_pkcs7(plaintext)
    blocks = [padded[i : i + BLOCK_SIZE] for i in range(0, len(padded), BLOCK_SIZE)]
    return [encrypt_block(block, key) for block in blocks]
