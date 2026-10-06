"""Source-only bridge for an already consumed, authenticated step-up action.

No wire decoder or browser route imports this module. The future private worker
must authenticate the complete frame and its peer before constructing an action.
Its independently qualified authorize_action dependency must verify every sealed
binding, replay/deadline and current stored-session authority. A request boolean,
public constructor or database receipt cannot establish that authority.

The original fresh TOTP has already been consumed by Rust. This entry rechecks
the current primary credential under the durable account lock without replaying
that factor. Native transport, session containment and whole-operation deadline
remain separate required qualifications; this module enables none of them.
"""
from dataclasses import dataclass
import time
import unicodedata

from account_epoch import PasswordCoordinator, valid_epoch
from authoritative_password import Refused


@dataclass(frozen=True, repr=False)
class PreparedAction:
    account: str
    epoch: int
    intent_reference: str
    session_id: str
    request_id: str
    source: str
    issued: int
    expires: int
    current: str
    new: str
    confirmation: str


class PreparedPasswordCoordinator:
    def __init__(self, store, adapter, authorize_action, verify_current,
                 verify_changed, containment_ready, finish_containment,
                 clock=lambda: int(time.time()), invalidate_changed_auth=None, *, pending_confirmation=None,
                 release_containment=None):
        self.store = store
        self.adapter = adapter
        self.authorize_action = authorize_action
        self.verify_current = verify_current
        self.verify_changed = verify_changed
        self.containment_ready = containment_ready
        self.finish_containment = finish_containment
        self.clock = clock
        self.invalidate_changed_auth = invalidate_changed_auth
        self.pending_confirmation = pending_confirmation
        # Trusted source builder owns this descriptor lifetime; no wire field.
        self.release_containment = release_containment

    @staticmethod
    def _bounded(value):
        return (isinstance(value, str) and 0 < len(value) <= 256
                and all(32 <= ord(c) < 127 for c in value))

    def _validate(self, action, now):
        if type(action) is not PreparedAction:
            raise Refused('prepared action unavailable')
        self.adapter._account(action.account)
        self.adapter.validate_new(action.current, action.new, action.confirmation)
        try:
            current_valid = (0 < len(action.current.encode('utf-8')) <= 1024
                             and not any(unicodedata.category(c) == 'Cc'
                                         for c in action.current))
        except UnicodeEncodeError:
            current_valid = False
        if (not valid_epoch(action.epoch)
                or not current_valid
                or not self.store._reference(action.intent_reference)
                or not all(self._bounded(v) for v in
                           (action.session_id, action.request_id, action.source))
                or type(action.issued) is not int or action.issued <= 0
                or type(action.expires) is not int
                or action.expires != action.issued + 300
                or type(now) is not int or now < action.issued
                or now >= action.expires):
            raise Refused('prepared action unavailable')

    def change(self, action):
        began = self.clock()
        self._validate(action, began)

        def fresh():
            now = self.clock()
            self._validate(action, now)
            return now >= began

        def authorize():
            now = self.clock()
            self._validate(action, now)
            return (now >= began
                    and self.authorize_action(action, now) is True
                    and self.verify_current(action.account, action.current) is True)

        # The legacy entry keeps its own fresh-factor dependency. This private
        # shared transaction uses only the authenticated consumed action path.
        transaction = PasswordCoordinator(
            self.store, self.adapter, None, self.verify_changed,
            self.containment_ready, self.finish_containment,
            self.invalidate_changed_auth)
        return transaction._change(
            action.account, action.epoch, action.intent_reference,
            action.current, action.new, action.confirmation, began,
            authorize, fresh,
            None if self.pending_confirmation is None else
            lambda: self.pending_confirmation(action))
