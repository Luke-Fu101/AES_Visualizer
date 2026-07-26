"""customtkinter interface for stepping through rounds and steps of an AES trace.

Reads a trace produced by cipher.py and renders it; contains no AES logic itself.
"""

import customtkinter as ctk

from trace import CipherTrace

ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")


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
