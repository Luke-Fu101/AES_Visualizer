"""Orchestrates a full AES encrypt/decrypt by running the round operations in order.

"""

import os

from key_schedule import key_expansion
from transformations import (
    add_round_key,
    inv_mix_columns,
    inv_shift_rows,
    inv_sub_bytes,
    mix_columns,
    shift_rows,
    sub_bytes,
)
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


def unpad_pkcs7(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """Remove PKCS#7 padding added by pad_pkcs7, validating it first."""
    if not data or len(data) % block_size != 0:
        raise ValueError("Data is not a valid padded, block-aligned message")

    pad_len = data[-1]
    if pad_len == 0 or pad_len > block_size or data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid PKCS#7 padding")

    return data[:-pad_len]


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


def decrypt_block(ciphertext: bytes, key: bytes) -> CipherTrace:
    """Decrypt a single 16-byte block under the given key, recording each round and step.

    Undoes encrypt_block's rounds in reverse (round Nr first, round 0 last),
    applying each round's operations in the order that inverts how
    encrypt_block applied them.
    """
    round_keys = key_expansion(key)
    nr = len(round_keys) - 1

    result = CipherTrace(plaintext=b"", key=key, ciphertext=ciphertext)

    round_before = ciphertext
    steps = []
    state = _apply("AddRoundKey", add_round_key, ciphertext, steps, round_keys[nr])
    state = _apply("InvShiftRows", inv_shift_rows, state, steps)
    state = _apply("InvSubBytes", inv_sub_bytes, state, steps)
    result.rounds.append(RoundRecord(nr, round_keys[nr], round_before, state, steps))

    for round_num in range(nr - 1, 0, -1):
        round_before = state
        steps = []
        state = _apply("AddRoundKey", add_round_key, state, steps, round_keys[round_num])
        state = _apply("InvMixColumns", inv_mix_columns, state, steps)
        state = _apply("InvShiftRows", inv_shift_rows, state, steps)
        state = _apply("InvSubBytes", inv_sub_bytes, state, steps)
        result.rounds.append(RoundRecord(round_num, round_keys[round_num], round_before, state, steps))

    round_before = state
    steps = []
    state = _apply("AddRoundKey", add_round_key, state, steps, round_keys[0])
    result.rounds.append(RoundRecord(0, round_keys[0], round_before, state, steps))

    result.plaintext = state
    return result


def encrypt(plaintext: bytes, key: bytes, iv: bytes | None = None) -> tuple[bytes, list[CipherTrace]]:
    """Pad plaintext (PKCS#7), split it into 16-byte blocks, and encrypt them
    in CBC mode: each block is XORed with the previous ciphertext block (the
    first with the IV) before being run through encrypt_block. Generates a
    random IV if none is given. Returns (iv, one CipherTrace per block)."""
    if iv is None:
        iv = os.urandom(BLOCK_SIZE)

    padded = pad_pkcs7(plaintext)
    blocks = [padded[i : i + BLOCK_SIZE] for i in range(0, len(padded), BLOCK_SIZE)]

    traces = []
    previous_ciphertext = iv
    for block in blocks:
        chained_block = add_round_key(block, previous_ciphertext)
        trace = encrypt_block(chained_block, key)

        # Make the CBC chaining visible in the trace: round 0 starts from the
        # raw plaintext block, XORs it with the IV/previous ciphertext block,
        # and only then feeds the result into AddRoundKey.
        cbc_step = StepRecord("CBC XOR (chain with IV/previous ciphertext)", block, chained_block)
        trace.rounds[0].steps.insert(0, cbc_step)
        trace.rounds[0].state_before = block
        trace.plaintext = block

        traces.append(trace)
        previous_ciphertext = trace.ciphertext

    return iv, traces


def decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> tuple[bytes, list[CipherTrace]]:
    """Split ciphertext into 16-byte blocks and decrypt them in CBC mode: each
    block is run through decrypt_block, then XORed with the previous
    ciphertext block (the first with the IV) to undo the chaining, and the
    PKCS#7 padding is stripped from the final result. Returns (plaintext,
    one CipherTrace per block)."""
    blocks = [ciphertext[i : i + BLOCK_SIZE] for i in range(0, len(ciphertext), BLOCK_SIZE)]

    traces = []
    plaintext_blocks = []
    previous_ciphertext = iv
    for block in blocks:
        trace = decrypt_block(block, key)
        raw_plaintext_block = add_round_key(trace.plaintext, previous_ciphertext)

        # Make the CBC un-chaining visible in the trace: after the last
        # round's AddRoundKey, XOR with the IV/previous ciphertext block to
        # recover the actual plaintext byte-for-byte.
        cbc_step = StepRecord(
            "CBC XOR (un-chain with IV/previous ciphertext)", trace.plaintext, raw_plaintext_block
        )
        trace.rounds[-1].steps.append(cbc_step)
        trace.rounds[-1].state_after = raw_plaintext_block
        trace.plaintext = raw_plaintext_block

        traces.append(trace)
        plaintext_blocks.append(raw_plaintext_block)
        previous_ciphertext = block

    plaintext = unpad_pkcs7(b"".join(plaintext_blocks))
    return plaintext, traces
