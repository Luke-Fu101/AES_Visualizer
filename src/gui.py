"""customtkinter interface for stepping through rounds and steps of an AES trace.

Reads a trace produced by cipher.py and renders it; contains no AES logic itself.
"""

import os

import customtkinter as ctk

from trace import CipherTrace

ctk.set_appearance_mode("dark")

DEFAULT_KEY_SIZE_BYTES = 16  # AES-128

# Shared black/gray/green palette - every widget going forward should draw
# its colors from here rather than customtkinter's built-in theme colors.
COLOR_BG = "#0a0a0a"       # window background
COLOR_PANEL = "#1a1a1a"    # frame/panel background
COLOR_BORDER = "#333333"   # borders and dividers
COLOR_GREEN = "#39ff14"    # primary text/accent
COLOR_GREEN_DIM = "#1f7a0a"  # hover/pressed state


class AESVisualizerApp(ctk.CTk):
    """Main window: holds the current trace and which round/step is displayed."""

    def __init__(self):
        super().__init__()

        self.title("AES Visualizer")
        self.geometry("900x600")
        self.configure(fg_color=COLOR_BG)

        # Algorithm state
        self.key: bytes = b""
        self.plaintext: bytes = b""
        self.trace: CipherTrace | None = None
        self.current_round_index: int = 0
        self.current_step_index: int = 0

        self._build_title()
        self._build_key_generator()

    def _build_title(self) -> None:
        """App title"""
        title = ctk.CTkLabel(
            self,
            text="AES Visualizer",
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color=COLOR_GREEN,
            fg_color="transparent",
        )
        title.pack(fill="x", padx=10, pady=(10, 0))

    def _build_key_generator(self) -> None:
        """Top-of-window box: shows the current key in hex, with a button to
        generate a new random one."""
        frame = ctk.CTkFrame(
            self, fg_color=COLOR_PANEL, border_color=COLOR_BORDER, border_width=1
        )
        frame.pack(fill="x", padx=10, pady=10)

        self.key_entry = ctk.CTkEntry(
            frame,
            placeholder_text="Key (hex)",
            fg_color=COLOR_BG,
            text_color=COLOR_GREEN,
            border_color=COLOR_BORDER,
        )
        self.key_entry.pack(side="left", fill="x", expand=True, padx=10, pady=10)

        generate_button = ctk.CTkButton(
            frame,
            text="Generate Random Key",
            command=self._generate_random_key,
            fg_color=COLOR_PANEL,
            hover_color=COLOR_GREEN_DIM,
            text_color=COLOR_GREEN,
            border_color=COLOR_GREEN,
            border_width=1,
        )
        generate_button.pack(side="left", padx=(0, 10), pady=10)

    def _generate_random_key(self) -> None:
        """Generate a cryptographically random key and show it in the key entry."""
        self.key = os.urandom(DEFAULT_KEY_SIZE_BYTES)
        self.key_entry.delete(0, "end")
        self.key_entry.insert(0, self.key.hex())
