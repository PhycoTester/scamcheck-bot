import time
from typing import Dict


class Cooldown:
    """
    Simple per-key cooldown with:
    - monotonic clock (immune to system time changes)
    - periodic pruning (bounded memory)
    """

    def __init__(self, seconds: int, prune_every_seconds: int = 60):
        self.seconds = max(0, int(seconds))
        self._last: Dict[str, float] = {}
        self._last_prune = 0.0
        self._prune_every = max(10, int(prune_every_seconds))

    def _prune(self) -> None:
        if self.seconds <= 0:
            # cooldown disabled -> no pruning required
            return

        now = time.monotonic()
        if now - self._last_prune < self._prune_every:
            return
        self._last_prune = now

        # Keep only recent keys (10 cooldown windows)
        cutoff = now - (self.seconds * 10)
        stale = [k for k, t in self._last.items() if t < cutoff]
        for k in stale:
            self._last.pop(k, None)

    def hit(self, key: str) -> bool:
        """
        Returns True if allowed now, False if still in cooldown.
        """
        now = time.monotonic()
        last = self._last.get(key, 0.0)
        if self.seconds > 0 and (now - last) < self.seconds:
            return False

        self._last[key] = now
        self._prune()
        return True
