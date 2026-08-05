# AES Visualizer

A desktop app for watching AES encryption and decryption happen step by step:
every round, and every operation within a round (SubBytes, ShiftRows,
MixColumns, AddRoundKey, and the CBC chaining step), rendered as a live 4x4
byte grid you can navigate block by block, round by round, step by step.

## Features

- **AES-128, AES-192, and AES-256**, selectable per key generated.
- **CBC mode** with a randomly generated IV per encryption, PKCS#7 padding for
  messages of any length (not just exactly 16 bytes).
- **Full round/step tracing** for both encryption and decryption - every
  intermediate state is recorded, not just the final ciphertext/plaintext.
- **Block-by-block navigation** for multi-block messages, on top of
  round-by-round and step-by-step navigation within each block.
- Plaintext entered as literal text (UTF-8 encoded), keys generated
  cryptographically at random (never hand-typed, to keep the demo honest
  about how AES keys are actually produced).

## Tech stack

- **Python 3.10+** - the entire AES implementation (key schedule, the four
  round transformations and their inverses, CBC chaining, padding) is
  written from scratch against FIPS-197 and NIST SP 800-38A, with no
  cryptography libraries involved.
- **[customtkinter](https://github.com/TomSchimansky/CustomTkinter)** for the
  GUI, built on top of Tkinter (Python's standard GUI toolkit).

## Project structure

Everything lives flat in `src/`, split by responsibility rather than by
folder, to keep coupling between modules simple and explicit:

| File | Responsibility |
|---|---|
| `constants.py` | Fixed AES spec data: S-box, inverse S-box, round constants (Rcon). |
| `key_schedule.py` | Expands the cipher key into one round key per round. |
| `transformations.py` | The four AES round operations (SubBytes, ShiftRows, MixColumns, AddRoundKey) and their inverses. |
| `cipher.py` | Orchestrates full encryption/decryption: key schedule + transformations + CBC chaining + PKCS#7 padding, recording every step into a trace. |
| `trace.py` | Data structures (`CipherTrace`, `RoundRecord`, `StepRecord`) that record round- and step-level state for the visualizer. |
| `gui.py` | The customtkinter interface: reads a trace and renders it. Contains no AES logic itself. |
| `main.py` | Entry point - launches the GUI. |

## Getting started

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 src/main.py
```

## Usage

1. Pick a key size (128/192/256-bit) and click **Generate Random Key**.
2. Type a plaintext message (any length - it's padded automatically).
3. Click **Encrypt** to see the IV and ciphertext, and step through every
   round and operation that produced them via the navigators.
4. Click **Decrypt** to reverse the last encryption and recover the original
   plaintext, stepping through the inverse operations the same way.

## How it works

AES encrypts data in fixed 16-byte blocks. A message longer than one block is
padded (PKCS#7) and split into multiple blocks, chained together in CBC mode
so identical plaintext blocks don't produce identical ciphertext. Each block
goes through:

1. An initial `AddRoundKey` (round 0).
2. A number of main rounds (9/11/13 for AES-128/192/256) of `SubBytes` ->
   `ShiftRows` -> `MixColumns` -> `AddRoundKey`.
3. A final, shortened round with the same three operations minus
   `MixColumns`.

Decryption runs the same structure in reverse, using the inverse of each
operation and the round keys in reverse order.

## Known limitations

- Decryption only works on ciphertext produced by the app's own last
  encryption in the current session - there's no way to paste in arbitrary
  external ciphertext/IV pairs yet.
- No automated test suite; correctness has been checked against published
  FIPS-197 and NIST SP 800-38A test vectors during development instead.

## License

[MIT](LICENSE)
