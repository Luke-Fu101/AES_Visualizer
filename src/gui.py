"""customtkinter interface for stepping through rounds and steps of an AES trace.

Reads a trace produced by cipher.py and renders it; contains no AES logic itself.
"""

import os

import customtkinter as ctk

from trace import CipherTrace

ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

DEFAULT_KEY_SIZE_BYTES = 16  # AES-128


class AESVisualizerApp(ctk.CTk):
    """Main window: holds the current trace and which round/step is displayed."""

    def __init__(self):
        super().__init__()

        self.title("AES Visualizer")
        self.geometry("900x600")

        # Algorithm state
        self.key: bytes = b""
        self.plaintext: bytes = b""
        self.trace: CipherTrace | None = None
        self.current_round_index: int = 0
        self.current_step_index: int = 0

        self._build_key_generator()

    def _build_key_generator(self) -> None:
        """Top-of-window box: shows the current key in hex, with a button to
        generate a new random one."""
        frame = ctk.CTkFrame(self)
        frame.pack(fill="x", padx=10, pady=10)

        self.key_entry = ctk.CTkEntry(frame, placeholder_text="Key (hex)")
        self.key_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))

        generate_button = ctk.CTkButton(
            frame, text="Generate Random Key", command=self._generate_random_key
        )
        generate_button.pack(side="left")

    def _generate_random_key(self) -> None:
        """Generate a cryptographically random key and show it in the key entry."""
        self.key = os.urandom(DEFAULT_KEY_SIZE_BYTES)
        self.key_entry.delete(0, "end")
        self.key_entry.insert(0, self.key.hex())
