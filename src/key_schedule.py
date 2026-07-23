"""Expands the cipher key into the per-round keys used by AddRoundKey.

Takes the original key and produces one round key per round of encryption.
"""

from constants import KEY_SCHEDULE_PARAMS, NB, RCON, SBOX


def rot_word(word: bytes) -> bytes:
    """Rotate a 4-byte word left by one byte: [a0,a1,a2,a3] -> [a1,a2,a3,a0]."""
    return word[1:] + word[:1]


def sub_word(word: bytes) -> bytes:
    """Apply the S-box to each byte of a 4-byte word."""
    return bytes(SBOX[b] for b in word)


def key_expansion(key: bytes) -> list[bytes]:
    """Expand a 128/192/256-bit key into a list of 16-byte round keys.

    Returns Nr + 1 round keys, where Nr is the round count for the given
    key size (10/12/14). Round key 0 is used for the initial AddRoundKey.
    """
    params = KEY_SCHEDULE_PARAMS.get(len(key) * 8)
    if params is None:
        raise ValueError(f"Unsupported key length: {len(key)} bytes")
    nk, nr = params["nk"], params["nr"]

    words = [key[4 * i : 4 * i + 4] for i in range(nk)]

    total_words = NB * (nr + 1)
    for i in range(nk, total_words):
        temp = words[i - 1]
        if i % nk == 0:
            temp = sub_word(rot_word(temp))
            temp = bytes([temp[0] ^ RCON[i // nk]]) + temp[1:]
        elif nk > 6 and i % nk == 4:
            temp = sub_word(temp)
        words.append(bytes(a ^ b for a, b in zip(words[i - nk], temp)))

    return [b"".join(words[NB * r : NB * r + NB]) for r in range(nr + 1)]
