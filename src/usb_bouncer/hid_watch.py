"""Keystroke-timing injection detector.

Records when keys go down, never which keys. The event callback reads two
things from each event: its timestamp and its autorepeat flag. It does not
read the key code field, and a test fails if that constant ever appears in
this package. See THREAT_MODEL.md section 7.
"""

import importlib
import queue
import threading
from collections import deque
from collections.abc import Callable
from itertools import pairwise
from statistics import median
from typing import Any


class BurstDetector:
    """Flag a run of keystrokes whose median gap is below a human threshold.

    Holds the last `window` timestamps and nothing else. The median means a
    couple of fast pairs inside normal typing do not trip it: more than half
    the gaps in the window have to be fast.
    """

    def __init__(self, window: int = 10, threshold_s: float = 0.040) -> None:
        if window < 3:
            raise ValueError("window must be at least 3 keystrokes")
        self.threshold_s = threshold_s
        self._times: deque[float] = deque(maxlen=window)

    def add(self, timestamp: float) -> float | None:
        """Record one key-down. Return the median gap in seconds if it is a burst."""
        self._times.append(timestamp)
        if len(self._times) < (self._times.maxlen or 0):
            return None
        gap = median(b - a for a, b in pairwise(self._times))
        if gap >= self.threshold_s:
            return None
        self._times.clear()  # one alert per window, not one per keystroke
        return gap


def start() -> Callable[[], list[float]]:
    """Install a listen-only key-down tap. Return drain(), which hands back the
    key-down timestamps (seconds) collected since it was last called.

    The tap runs on its own thread and its callback only queues a number.
    macOS switches off a tap that is slow to answer and drops keystrokes
    until it is switched back on, so the callback must never wait on a poll,
    a log write or a notification.

    Raises ImportError without pyobjc (install usb-bouncer[hid]) and
    RuntimeError when macOS refuses the tap.
    """
    q: Any = importlib.import_module("Quartz")
    stamps: queue.SimpleQueue[float] = queue.SimpleQueue()

    def callback(_proxy, event_type, event, _refcon):
        if event_type == q.kCGEventKeyDown:
            # a held key repeats at about 33 ms, under the threshold, so repeats are skipped
            if not q.CGEventGetIntegerValueField(event, q.kCGKeyboardEventAutorepeat):
                # the event's own timestamp (nanoseconds), not the time this callback ran
                stamps.put(q.CGEventGetTimestamp(event) / 1e9)
        elif event_type in (q.kCGEventTapDisabledByTimeout, q.kCGEventTapDisabledByUserInput):
            q.CGEventTapEnable(tap, True)
        return event

    tap = q.CGEventTapCreate(
        q.kCGSessionEventTap,
        q.kCGHeadInsertEventTap,
        q.kCGEventTapOptionListenOnly,  # cannot modify, drop or inject events
        q.CGEventMaskBit(q.kCGEventKeyDown),
        callback,
        None,
    )
    if tap is None:
        raise RuntimeError(
            "macOS refused the keyboard event tap. Allow this terminal under System Settings > "
            "Privacy & Security > Input Monitoring (Accessibility on older macOS), then rerun."
        )

    def run_tap() -> None:
        source = q.CFMachPortCreateRunLoopSource(None, tap, 0)
        q.CFRunLoopAddSource(q.CFRunLoopGetCurrent(), source, q.kCFRunLoopCommonModes)
        q.CGEventTapEnable(tap, True)
        q.CFRunLoopRun()

    threading.Thread(target=run_tap, name="usb-bouncer-hid-tap", daemon=True).start()

    def drain() -> list[float]:
        out = []
        while not stamps.empty():
            out.append(stamps.get())
        return out

    return drain
