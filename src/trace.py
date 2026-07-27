"""Data structures that record each round and each step within a round."""

from dataclasses import dataclass, field


@dataclass
class StepRecord:
    """One individual step within a round, e.g. SubBytes or AddRoundKey."""

    name: str
    state_before: bytes
    state_after: bytes


@dataclass
class RoundRecord:
    """One full round: its number, the round key used, the state before/after,
    and the individual steps taken to get there."""

    round_number: int
    round_key: bytes
    state_before: bytes
    state_after: bytes
    steps: list[StepRecord] = field(default_factory=list)


@dataclass
class CipherTrace:
    """The full round-by-round record of one encryption, for the visualizer."""

    plaintext: bytes
    key: bytes
    ciphertext: bytes = b""
    rounds: list[RoundRecord] = field(default_factory=list)
