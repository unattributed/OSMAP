"""Private mutation operation deadline; no configuration, RPC or activation.

Every future authentication, SQL/hash and containment phase must share the same
instance. Adapter integration below covers SQL/hash only, not a qualified full
workflow. The separate maximum does not change existing authentication or crypto
process profiles. Native measurement and outer process-group cleanup remain
required before enabling a mutation worker.
"""
import math
import time

from authoritative_password import Refused


class OperationBudget:
    MAXIMUM_SECONDS = 60.0

    def __init__(self, expires_at, *, maximum_seconds=MAXIMUM_SECONDS,
                 monotonic=time.monotonic, wall=time.time):
        if (type(expires_at) is not int or expires_at <= 0
                or type(maximum_seconds) not in (int, float)
                or not math.isfinite(maximum_seconds)
                or not 0 < maximum_seconds <= self.MAXIMUM_SECONDS):
            raise Refused('mutation deadline unavailable')
        self._monotonic = monotonic
        self._wall = wall
        self._expires = expires_at
        self._last_mono = self._sample(monotonic())
        self._last_wall = self._sample(wall())
        self._deadline = self._last_mono + maximum_seconds
        self.remaining()

    @staticmethod
    def _sample(value):
        if (type(value) not in (int, float) or not math.isfinite(value)
                or value < 0):
            raise Refused('mutation clock unavailable')
        return value

    def remaining(self):
        mono = self._sample(self._monotonic())
        wall = self._sample(self._wall())
        if mono < self._last_mono or wall < self._last_wall:
            raise Refused('mutation clock changed')
        self._last_mono = mono
        self._last_wall = wall
        remaining = min(self._deadline - mono, self._expires - wall)
        if remaining <= 0:
            raise Refused('mutation deadline expired')
        return remaining

    def cap_seconds(self, phase_limit):
        if (type(phase_limit) not in (int, float)
                or not math.isfinite(phase_limit) or phase_limit <= 0
                or phase_limit > self.MAXIMUM_SECONDS):
            raise Refused('mutation phase deadline unavailable')
        return min(phase_limit, self.remaining())
