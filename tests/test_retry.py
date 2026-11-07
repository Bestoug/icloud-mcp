import asyncio
import imaplib

import pytest

from icloud_mcp.retry import is_transient, with_retry


def _flaky(errors):
    """Liefert eine Funktion, die erst die Fehler wirft und dann „ok“ zurückgibt."""
    calls = {"n": 0}

    async def call():
        calls["n"] += 1
        if errors:
            raise errors.pop(0)
        return "ok"

    return call, calls


async def _no_sleep(_):
    return None


def run(coro):
    return asyncio.run(coro)


def test_message_too_long_is_retried():
    call, calls = _flaky([OSError(90, "Message too long")])
    assert run(with_retry(call, "test", sleep=_no_sleep)) == "ok"
    assert calls["n"] == 2


def test_imap_abort_is_retried():
    call, calls = _flaky([imaplib.IMAP4.abort("socket error"), TimeoutError()])
    assert run(with_retry(call, "test", sleep=_no_sleep)) == "ok"
    assert calls["n"] == 3


def test_gives_up_after_four_attempts():
    call, calls = _flaky([OSError(90, "x")] * 4)
    with pytest.raises(OSError):
        run(with_retry(call, "test", sleep=_no_sleep))
    assert calls["n"] == 4


def test_real_errors_are_not_retried():
    call, calls = _flaky([ValueError("Mail nicht gefunden")])
    with pytest.raises(ValueError):
        run(with_retry(call, "test", sleep=_no_sleep))
    assert calls["n"] == 1


def test_login_error_is_not_retried():
    assert not is_transient(imaplib.IMAP4.error("AUTHENTICATIONFAILED"))
    assert not is_transient(PermissionError())


def test_no_retry_for_writes():
    call, calls = _flaky([OSError(90, "x")])
    with pytest.raises(OSError):
        run(with_retry(call, "test", retry=False, sleep=_no_sleep))
    assert calls["n"] == 1
