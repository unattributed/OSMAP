"""Fixed admin/fixture configuration binding, never request-selected authority.

This pure renderer neither installs configuration nor qualifies the listener.
Root must custody the resulting file and current same-master/private endpoint.
The existing native primary command, kernel peer gates and original lock remain.
"""
import hashlib
from pathlib import Path

from authoritative_password import Refused

_TEMPLATE_SHA256 = "7464efc86a068191790a76af3340256864df9e82dbc30176015e8a40304a51f4"
_SOCKET_NAME = b"osmap-account-auth-client"
_SERVICE = b"osmap-primary-auth"


def add_private_primary_auth(config):
    """Append the sole fixed private auth service; preserve all input bytes.

    No account, purpose, service, endpoint, executable or setting is supplied
    separately by a caller. Existing private listeners must first be removed
    by the reviewed root configuration change, never silently reassigned here.
    This does not parse or approve arbitrary Dovecot configuration.
    """
    if (type(config) is not bytes or not 1 <= len(config) <= 16384
            or b"\x00" in config or b"!include" in config
            or config.count(b"service auth {\n") != 1
            or config.count(b"service auth-worker {\n") != 1
            or _SOCKET_NAME in config or _SERVICE in config):
        raise Refused("private primary configuration unavailable")
    raw = Path(__file__).with_name("dovecot-private-primary.conf").read_bytes()
    if (hashlib.sha256(raw).hexdigest() != _TEMPLATE_SHA256
            or len(config) + 1 + len(raw) > 16384):
        raise Refused("private primary template unavailable")
    return config + b"\n" + raw
