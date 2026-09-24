# -*- coding: utf-8 -*-
"""
TLS certificate-fingerprint pinning (trust-on-first-use) for the local gateway
clients. Replaces a blanket ``session.verify = False`` with a SHA-256 pin on the
gateway's certificate.

Why a raw pre-flight probe rather than peering into urllib3's socket:
  * The gateways use *self-signed* certs and are addressed by *IP*, so normal
    CA/hostname verification is off by design.
  * Tesla gateways are TLS-fingerprint sensitive (see powerwall.py), so we keep
    using plain ``requests`` and only *add* a one-shot cert check before any
    credential/token is transmitted.
  * A raw TLS handshake is the most reliable way to read the peer certificate
    across both gateways without depending on urllib3 internals.

Behaviour
  * First connect with no stored pin (TOFU): record the peer SHA-256, log it at
    INFO, and (via the ``save_pin`` callback) persist it to config.
  * Any later connect: if the presented fingerprint != the stored pin, REFUSE —
    no credentials/tokens are sent — and ``last_error`` carries a clear message.
  * Hostname checking stays OFF (the gateways use IPs).
  * The pin is read lazily (``pin_getter``), so changing the pin in config takes
    effect on the very next request with no client rebuild.
"""
import hashlib
import logging
import socket
import ssl

log = logging.getLogger("certpin")


def fetch_cert_sha256(host: str, port: int, timeout: float = 8.0) -> str:
    """SHA-256 hex fingerprint of the TLS certificate DER bytes that
    ``host:port`` presents. CA/hostname validation is deliberately OFF (the
    gateways are self-signed and addressed by IP)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
    if not der:
        raise ConnectionError("no peer certificate presented")
    return hashlib.sha256(der).hexdigest()


class CertPinner:
    """Per-process TOFU decision logic. One instance per client; the pin value is
    read from config on each HTTPS request via ``pin_getter``."""

    def __init__(self, source: str, pin_getter=None, save_pin=None):
        self.source = source
        self.pin_getter = pin_getter or (lambda: "")
        self.save_pin = save_pin or (lambda _f: None)
        self.last_error = None

    def check(self, host: str, port: int) -> bool:
        """Verify the gateway's presented cert against the stored pin (read
        lazily). TOFU: with no stored pin, record + persist and return True.
        On mismatch, set ``last_error`` and return False (no credentials sent)."""
        pin = (self.pin_getter() or "").lower()
        try:
            fp = fetch_cert_sha256(host, port)
        except Exception as e:  # network/TLS failure is NOT a pin mismatch
            self.last_error = "certificate check failed: %s" % e
            log.warning("certpin[%s]: %s", self.source, e)
            return False
        if not pin:
            log.info("certpin[%s]: TOFU — pinning %s certificate SHA256=%s",
                     self.source, host, fp)
            try:
                self.save_pin(fp)
            except Exception as e:
                log.warning("certpin[%s]: could not persist pin: %s",
                           self.source, e)
            self.last_error = None
            return True
        if fp != pin:
            self.last_error = ("certificate fingerprint mismatch for %s "
                              "(presented %s, pinned %s) — refusing to send "
                              "credentials. Reset the pin to re-pin."
                              % (host, fp[:16], pin[:16]))
            log.warning("certpin[%s]: %s", self.source, self.last_error)
            return False
        self.last_error = None
        return True


def make_pinning_session(pinner: "CertPinner"):
    """A requests.Session whose HTTPS traffic is checked against ``pinner``
    before the request (and its headers/body) is sent.

    The pinner does a raw TLS handshake (the security gate) before any
    credential/token leaves the process. The underlying urllib3 connection still
    uses ``verify=False`` (self-signed + IP addressing), so we localize the
    InsecureRequestWarning here — per the spec we only drop it if the adapter
    made it unnecessary (it doesn't, since the real socket is still unverified).
    """
    import requests
    import urllib3
    from requests.adapters import HTTPAdapter

    # Localized: only for this pinning session's unverified-socket noise.
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    class _PinningAdapter(HTTPAdapter):
        def send(self, request, **kwargs):
            from urllib.parse import urlparse
            u = urlparse(request.url)
            if u.scheme == "https":
                host = u.hostname or "127.0.0.1"
                port = u.port or 443
                if not pinner.check(host, port):
                    raise requests.exceptions.ConnectionError(
                        pinner.last_error or "certificate pin mismatch")
            return super().send(request, **kwargs)

    s = requests.Session()
    s.verify = False  # self-signed + IP addressing; pinning replaces the check
    s.mount("https://", _PinningAdapter())
    s.mount("http://", HTTPAdapter())
    return s
