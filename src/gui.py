"""customtkinter interface for stepping through rounds and steps of an AES trace.

Reads a trace produced by cipher.py and renders it; contains no AES logic itself.
"""

import os
import tkinter as tk

import customtkinter as ctk

from cipher import BLOCK_SIZE, encrypt
from constants import KEY_SCHEDULE_PARAMS
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
        self._build_plaintext_input()
        self._build_encrypt_action()
        self._build_state_grid()
        self._build_navigation()
        self._refresh_display()

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

        self.key_var = tk.StringVar()
        self.key_entry = ctk.CTkEntry(
            frame,
            placeholder_text="Generate a key ->",
            textvariable=self.key_var,
            state="readonly",
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
        self.key_var.set(self.key.hex())

    def _build_plaintext_input(self) -> None:
        """Box for entering the plaintext message as literal text (UTF-8 encoded
        to bytes). Shorter than one block gets PKCS#7-padded up to 16 bytes by
        _run_encryption."""
        frame = ctk.CTkFrame(
            self, fg_color=COLOR_PANEL, border_color=COLOR_BORDER, border_width=1
        )
        frame.pack(fill="x", padx=10, pady=(0, 10))

        self.plaintext_entry = ctk.CTkEntry(
            frame,
            placeholder_text="Plaintext message (up to 16 bytes)",
            fg_color=COLOR_BG,
            text_color=COLOR_GREEN,
            border_color=COLOR_BORDER,
        )
        self.plaintext_entry.pack(fill="x", expand=True, padx=10, pady=10)

    def _build_encrypt_action(self) -> None:
        """Encrypt button plus a status/output label showing the result or any error."""
        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.pack(fill="x", padx=10, pady=(0, 10))

        encrypt_button = ctk.CTkButton(
            frame,
            text="Encrypt",
            command=self._run_encryption,
            fg_color=COLOR_PANEL,
            hover_color=COLOR_GREEN_DIM,
            text_color=COLOR_GREEN,
            border_color=COLOR_GREEN,
            border_width=1,
        )
        encrypt_button.pack(side="left", padx=(0, 10))

        self.status_label = ctk.CTkLabel(frame, text="", text_color=COLOR_GREEN)
        self.status_label.pack(side="left")

    def _run_encryption(self) -> None:
        """Read key/plaintext from the entries, pad the plaintext if needed, run encrypt, store the trace."""
        try:
            key = bytes.fromhex(self.key_entry.get().strip())
            plaintext = bytes.fromhex(self.plaintext_entry.get().strip())
        except ValueError:
            self.status_label.configure(text="Invalid hex in key or plaintext.")
            return

        if len(plaintext) > BLOCK_SIZE:
            self.status_label.configure(text=f"Plaintext must be at most {BLOCK_SIZE} bytes.")
            return

        if len(key) * 8 not in KEY_SCHEDULE_PARAMS:
            self.status_label.configure(text="Key must be 16, 24, or 32 bytes (128/192/256-bit).")
            return

        self.key = key
        self.plaintext = plaintext
        self.trace = encrypt(plaintext, key)
        self.current_round_index = 0
        self.current_step_index = 0
        self.status_label.configure(text=f"Ciphertext: {self.trace.ciphertext.hex()}")
        self._refresh_display()

    def _build_state_grid(self) -> None:
        """4x4 grid showing the state bytes (in hex) for the current step."""
        frame = ctk.CTkFrame(
            self, fg_color=COLOR_PANEL, border_color=COLOR_BORDER, border_width=1
        )
        frame.pack(padx=10, pady=(0, 10))

        self.grid_labels = {}
        for r in range(4):
            for c in range(4):
                label = ctk.CTkLabel(
                    frame,
                    text="--",
                    width=50,
                    height=50,
                    fg_color=COLOR_BG,
                    text_color=COLOR_GREEN,
                    font=ctk.CTkFont(family="Courier", size=16),
                )
                label.grid(row=r, column=c, padx=4, pady=4)
                self.grid_labels[(r, c)] = label

    def _build_navigation(self) -> None:
        """Prev/Next controls plus a label naming the current round and step."""
        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.pack(fill="x", padx=10, pady=(0, 10))

        prev_button = ctk.CTkButton(
            frame,
            text="◀ Prev",
            command=self._go_to_previous_step,
            fg_color=COLOR_PANEL,
            hover_color=COLOR_GREEN_DIM,
            text_color=COLOR_GREEN,
            border_color=COLOR_GREEN,
            border_width=1,
        )
        prev_button.pack(side="left")

        self.nav_label = ctk.CTkLabel(frame, text="No trace yet", text_color=COLOR_GREEN)
        self.nav_label.pack(side="left", expand=True)

        next_button = ctk.CTkButton(
            frame,
            text="Next ▶",
            command=self._go_to_next_step,
            fg_color=COLOR_PANEL,
            hover_color=COLOR_GREEN_DIM,
            text_color=COLOR_GREEN,
            border_color=COLOR_GREEN,
            border_width=1,
        )
        next_button.pack(side="right")

    def _go_to_next_step(self) -> None:
        """Advance to the next step, moving into the next round if needed."""
        if self.trace is None:
            return

        current_round = self.trace.rounds[self.current_round_index]
        if self.current_step_index + 1 < len(current_round.steps):
            self.current_step_index += 1
        elif self.current_round_index + 1 < len(self.trace.rounds):
            self.current_round_index += 1
            self.current_step_index = 0

        self._refresh_display()

    def _go_to_previous_step(self) -> None:
        """Go back to the previous step, moving into the previous round if needed."""
        if self.trace is None:
            return

        if self.current_step_index > 0:
            self.current_step_index -= 1
        elif self.current_round_index > 0:
            self.current_round_index -= 1
            self.current_step_index = len(self.trace.rounds[self.current_round_index].steps) - 1

        self._refresh_display()

    def _refresh_display(self) -> None:
        """Redraw the nav label and state grid for the current round/step."""
        if self.trace is None:
            self.nav_label.configure(text="No trace yet")
            for label in self.grid_labels.values():
                label.configure(text="--")
            return

        round_record = self.trace.rounds[self.current_round_index]
        step_record = round_record.steps[self.current_step_index]
        final_round_number = len(self.trace.rounds) - 1

        self.nav_label.configure(
            text=(
                f"Round {round_record.round_number}/{final_round_number}  —  "
                f"{step_record.name}  "
                f"(step {self.current_step_index + 1}/{len(round_record.steps)})"
            )
        )

        state = step_record.state_after
        for r in range(4):
            for c in range(4):
                self.grid_labels[(r, c)].configure(text=f"{state[c * 4 + r]:02X}")
