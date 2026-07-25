"""Data structures that record each round and each step within a round.

Round-level detail only for now; per-step (cycle) detail within a round is
added later.
"""

from dataclasses import dataclass, field


@dataclass
class RoundRecord:
    """One full round: its number, the round key used, and the state before/after."""

    round_number: int
    round_key: bytes
    state_before: bytes
    state_after: bytes


@dataclass
class CipherTrace:
    """The full round-by-round record of one encryption, for the visualizer."""

    plaintext: bytes
    key: bytes
    ciphertext: bytes = b""
    rounds: list[RoundRecord] = field(default_factory=list)
