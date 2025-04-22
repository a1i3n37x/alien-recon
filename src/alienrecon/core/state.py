from collections.abc import Callable
from .models import Phase, Target


class ReconState:
    """
    Deterministic finite‑state machine driving the CLI conversation.
    """

    def __init__(self) -> None:
        self.phase: Phase = Phase.AWAIT_TARGET
        self.target: Target | None = None

    # ------------- public API -------------

    def set_target(self, host: str) -> None:
        self.target = Target(host)
        self.phase  = Phase.AWAIT_NMAP_OK

    def confirm(self) -> Phase:
        match self.phase:
            case Phase.AWAIT_NMAP_OK:
                self.phase = Phase.RUNNING_NMAP
            case Phase.AWAIT_GOB_OK:
                self.phase = Phase.RUNNING_GOB
            case _:
                raise ValueError("Nothing to confirm right now")
        return self.phase

    def next_after_scan(self, next_phase: Phase) -> None:
        """Call when a scanner finishes."""
        self.phase = next_phase

