# -*- coding: utf-8 -*-
"""
TLS certificate-fingerprint pinning (trust-on-first-use) for the local gateway
clients. Replaces a blanket ``session.verify = False`` with a SHA-256 pin on
the gateway certificate.

Item 5 — same-connection pinning. The old design did a raw pre-flight probe
connection (``CertPinner.check``) and then let urllib3 open a *second*,
unverified connection for the real request — a MITM could answer the probe
with the gateway real certificate and still intercept the request. The pin
is therefore enforced by urllib3 own ``assert_fingerprint`` on the SAME
connection that carries the request: a fingerprint mismatch aborts the TLS
handshake before any request bytes (and therefore before any credentials or
tokens) leave the process.

How it works
  * The session HTTPS adapter mounts pools with ``cert_reqs=CERT_NONE``,
    ``assert_hostname=False`` and ``assert_fingerprint=<pin>``. With
    ``assert_fingerprint`` set, urllib3 checks the peer certificate SHA-256
    during the handshake of the request own connection (no CA chain, no
    hostname — the gateways are self-signed and addressed by IP).
  * ``requests`` would otherwise clobber the pool TLS parameters per
    request (``HTTPAdapter.cert_verify`` and the per-request ``cert_reqs``
    derived from the session ``verify``), so the adapter disables that path
    and the session is pinned to ``verify=False``.
  * TOFU: when config holds no pin yet, the FIRST request does one raw probe
    (the only extra connection the design makes) to record and persist the
    fingerprint (via ``save_pin``); the pool is then (re)created pinned to
    it. Every later request is verified on the connection itself — no probe.
  * If the presented certificate ever differs from the stored pin, the
    handshake is refused at the TLS layer (``Fingerprints did not match``);
    nothing is sent. Reset the pin in config to re-pin (e.g. after a gateway
    firmware update that rotates the certificate).
  * The pin is read lazily (``pin_getter``), so changing the pin in config
    takes effect on the very next request with no client rebuild; the pools
    are transparently (re)pinned when the stored pin changes.

Network/TLS failures during the TOFU probe are NOT treated as a pin mismatch
(the gateway may simply be down); they surface as a connection error and the
next request retries the probe.
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
    """Per-process TOFU decision logic. One instance per client; the pin value
    is read from config on demand via ``pin_getter``.

    ``check()`` performs the one raw probe used for TOFU (recording a pin on
    first sight) and for explicit mismatch detection; the ongoing enforcement
    happens on the request own connection via ``assert_fingerprint``
    (see ``make_pinning_session``), not through a per-request probe."""

    def __init__(self, source: str, pin_getter=None, save_pin=None):
        self.source = source
        self.pin_getter = pin_getter or (lambda: "")
        self.save_pin = save_pin or (lambda _f: None)
        self.last_error = None

    def check(self, host: str, port: int) -> bool:
        """One raw probe of the gateway presented cert against the stored
        pin (read lazily). TOFU: with no stored pin, record + persist and
        return True. On mismatch, set ``last_error`` and return False (no
        credentials sent). Network/TLS failure is not a mismatch."""
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
    """A requests.Session whose HTTPS traffic is verified, on the SAME
    connection, against the gateway certificate fingerprint.

    Enforcement is urllib3 ``assert_fingerprint`` (the pools are created
    with ``cert_reqs=CERT_NONE``, ``assert_hostname=False`` and the current
    pin), so a mismatch aborts the handshake before any request bytes are
    sent. No per-request probe: only a first-time TOFU does one raw probe.
    """
    import requests
    import urllib3
    from requests.adapters import HTTPAdapter

    # Localized: only for this pinning session unverified-socket noise.
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    class _PinningAdapter(HTTPAdapter):
        def __init__(self, **kw):
            super().__init__(**kw)
            self._pool_pin = None  # fp the current pools are pinned to

        def cert_verify(self, conn, url, verify, cert):
            # Item 5: the per-request CA-bundle block in HTTPAdapter rewrites
            # conn.cert_reqs back to CERT_REQUIRED when the request verify is
            # truthy — it would silently override the pool CERT_NONE/pinning.
            # Fingerprint pinning replaces chain verification entirely, so
            # skip it.
            pass

        def init_poolmanager(self, connections, maxsize, block=False,
                            **pool_kwargs):
            pin = (pinner.pin_getter() or "").lower()
            pool_kwargs["cert_reqs"] = "CERT_NONE"
            pool_kwargs["assert_hostname"] = False
            pool_kwargs["assert_fingerprint"] = pin or None
            super().init_poolmanager(connections, maxsize, block,
                                    **pool_kwargs)
            self._pool_pin = pin or None

        def send(self, request, **kwargs):
            from urllib.parse import urlparse
            u = urlparse(request.url)
            if u.scheme == "https":
                host = u.hostname or "127.0.0.1"
                port = u.port or 443
                pin = (pinner.pin_getter() or "").lower()
                if not pin:
                    # TOFU: the ONE raw probe (the only extra connection the
                    # design makes) records + persists the fingerprint.
                    if not pinner.check(host, port):
                        raise requests.exceptions.ConnectionError(
                            pinner.last_error or "certificate pinning failed")
                    pin = (pinner.pin_getter() or "").lower()
                if pin != (self._pool_pin or "").lower():
                    # (Re)pin: the stored pin changed (or was just recorded),
                    # so rebuild the pools pinned to it.
                    self.poolmanager.connection_pool_kw[
                        "assert_fingerprint"] = pin or None
                    self.poolmanager.clear()
                    self._pool_pin = pin or None
                # No probe here: the pin is enforced by urllib3 on the
                # connection this very request uses.
            return super().send(request, **kwargs)

    s = requests.Session()
    s.verify = False  # self-signed + IP addressing; pinning replaces the check
    # Item: trust_env=False so REQUESTS_CA_BUNDLE / CURL_CA_BUNDLE /
    # HTTPS_PROXY (and friends) can't override verify=False or tunnel the
    # gateway traffic through an env-configured proxy. The pin is the only
    # TLS authority for this session; the environment must not add one.
    s.trust_env = False
    s.mount("https://", _PinningAdapter())
    s.mount("http://", HTTPAdapter())
    return s
