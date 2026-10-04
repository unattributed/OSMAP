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
        self._owned_group = None
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


    @classmethod
    def from_original_deadline(cls, expires_at, *, received_mono, received_millis,
                               sent_millis, deadline_millis, monotonic=time.monotonic,
                               wall_millis):
        # The authenticated envelope consumer captures receipt before parsing.
        # Parsing/authentication time is deducted rather than starting a new cap.
        if (type(expires_at) is not int or expires_at <= 0 or
                any(type(v) is not int or v <= 0 for v in
                    (received_millis, sent_millis, deadline_millis)) or
                not 0 < deadline_millis - sent_millis <= 60000 or
                not sent_millis <= received_millis < deadline_millis or
                deadline_millis > expires_at * 1000):
            raise Refused('mutation original deadline unavailable')
        value = cls.__new__(cls)
        value._owned_group = None
        value._monotonic = monotonic
        value._wall = lambda: wall_millis() / 1000
        value._expires = min(expires_at, deadline_millis / 1000)
        value._last_mono = cls._sample(received_mono)
        value._last_wall = received_millis / 1000
        value._deadline = received_mono + (deadline_millis - received_millis) / 1000
        value.remaining()
        return value

    def attach_owned_process_group(self):
        # Called only by the supervised private worker entry. A browser/wire
        # boolean cannot enable group inheritance or choose any process ID.
        import os
        if self._owned_group is not None or os.getpid() != os.getpgrp() or os.getpid() <= 1:
            raise Refused('mutation process group unavailable')
        self.remaining()
        self._owned_group = os.getpid()

    def inherited_group(self):
        import os
        if self._owned_group is None:
            return False
        if os.getpgrp() != self._owned_group:
            raise Refused('mutation process group changed')
        self.remaining()
        return True
