"""Automatische Wiederholung bei vorübergehenden Netzwerkfehlern (iCloud, Tailscale).

Hintergrund: Am 03.11.2026 brachen Kalender-Aufrufe mit
`Connection aborted. OSError(90, 'Message too long')` ab und liefen kurz darauf
wieder. Solche Aussetzer fängt diese Datei ab, indem sie den Aufruf nach einer
kurzen Pause erneut versucht. Echte Fehler (falsches Passwort, Mail nicht
gefunden, falsche Eingaben) werden NICHT wiederholt.
"""
from __future__ import annotations

import asyncio
import imaplib
import logging
from typing import Awaitable, Callable, TypeVar

log = logging.getLogger("icloud_mcp.retry")

T = TypeVar("T")

# Pausen zwischen den Versuchen in Sekunden: 4 Versuche über rund 12 s.
# Am 07.11.2026 schlugen drei Versuche innerhalb von 4 s fehl, kurz danach lief
# derselbe Aufruf wieder; die längere letzte Pause überbrückt solche Aussetzer.
DELAYS = (1.0, 3.0, 8.0)


def _optional_transient() -> tuple[type[BaseException], ...]:
    """Verbindungsfehler der HTTP-Bibliotheken, die caldav je nach Version nutzt."""
    found: list[type[BaseException]] = []
    for module, names in (
        ("requests.exceptions", ("ConnectionError", "Timeout", "ChunkedEncodingError")),
        ("niquests.exceptions", ("ConnectionError", "Timeout", "ChunkedEncodingError")),
        ("httpx", ("TransportError",)),
    ):
        try:
            mod = __import__(module, fromlist=list(names))
        except ImportError:
            continue
        found.extend(getattr(mod, n) for n in names if hasattr(mod, n))
    return tuple(found)


TRANSIENT: tuple[type[BaseException], ...] = (
    OSError,               # Socket-Fehler, z. B. Errno 90 „Message too long“, Timeouts, SSL
    imaplib.IMAP4.abort,   # IMAP-Verbindung abgerissen
    EOFError,
) + _optional_transient()

# Diese OSError-Unterklassen sind keine Netzwerk-Aussetzer.
NOT_TRANSIENT: tuple[type[BaseException], ...] = (FileNotFoundError, PermissionError)


def is_transient(exc: BaseException) -> bool:
    return isinstance(exc, TRANSIENT) and not isinstance(exc, NOT_TRANSIENT)


async def with_retry(
    call: Callable[[], Awaitable[T]],
    name: str,
    retry: bool = True,
    delays: tuple[float, ...] = DELAYS,
    sleep: Callable[[float], Awaitable[object]] = asyncio.sleep,
) -> T:
    """Führt `call` aus und wiederholt ihn bei vorübergehenden Fehlern."""
    waits = delays if retry else ()
    for attempt, wait in enumerate((*waits, None), start=1):
        try:
            return await call()
        except Exception as exc:
            if wait is None or not is_transient(exc):
                raise
            log.warning("%s: Versuch %d fehlgeschlagen (%s: %s), neuer Versuch in %.0f s",
                        name, attempt, type(exc).__name__, exc, wait)
            await sleep(wait)
    raise AssertionError("unerreichbar")
