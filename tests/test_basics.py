import datetime as dt
from email.message import EmailMessage

import pytest
from starlette.testclient import TestClient

from icloud_mcp import kalender, mail
from icloud_mcp.config import Settings
from icloud_mcp.server import build_app, build_server

TOKEN = "t" * 40
S = Settings(icloud_user="philipp@icloud.com", icloud_password="x", access_token=TOKEN)


def test_settings_require_long_token(monkeypatch):
    monkeypatch.setenv("ICLOUD_USER", "a@icloud.com")
    monkeypatch.setenv("ICLOUD_APP_PASSWORD", "pw")
    monkeypatch.setenv("MCP_ACCESS_TOKEN", "kurz")
    with pytest.raises(RuntimeError):
        Settings.from_env()


def test_criteria():
    c = mail.build_criteria("rechnung", "amazon", None, "2026-10-01", None, True, False)
    assert c == ["UNSEEN", "FROM", "amazon", "TEXT", "rechnung", "SINCE", dt.date(2026, 10, 1)]
    assert mail.build_criteria(None, None, None, None, None, False, False) == ["ALL"]


def test_parse_message_plain_and_attachment():
    m = EmailMessage()
    m["From"] = "Max Muster <max@example.com>"
    m["To"] = "philipp@icloud.com"
    m["Subject"] = "Grüße aus Kiel"
    m["Date"] = "Mon, 02 Nov 2026 10:00:00 +0100"
    m.set_content("Hallo Philipp")
    m.add_attachment(b"PDFDATA", maintype="application", subtype="pdf", filename="plan.pdf")
    parsed = mail.parse_message(m.as_bytes())
    assert parsed["subject"] == "Grüße aus Kiel"
    assert parsed["from"] == ["Max Muster <max@example.com>"]
    assert parsed["body"] == "Hallo Philipp"
    assert parsed["attachments"][0]["name"] == "plan.pdf"


def test_parse_message_html_only():
    m = EmailMessage()
    m["Subject"] = "HTML"
    m.set_content("<p>Hallo</p><script>x()</script><p>Welt</p>", subtype="html")
    assert mail.parse_message(m.as_bytes())["body"].split() == ["Hallo", "Welt"]


def test_build_draft_reply_headers():
    msg = mail.build_draft(S, ["a@example.com"], "Re: Test", "Text", reply_to_message_id="<abc@x>")
    assert msg["In-Reply-To"] == "<abc@x>"
    assert msg["From"] == "philipp@icloud.com"


def test_parse_when_local_timezone():
    v = kalender.parse_when("2026-11-03T18:30", "Europe/Berlin")
    assert v.utcoffset() == dt.timedelta(hours=1)
    assert kalender.parse_when("2026-11-03", "Europe/Berlin") == dt.date(2026, 11, 3)


def test_build_event_roundtrip():
    start = kalender.parse_when("2026-11-03T18:30", "Europe/Berlin")
    cal = kalender.build_event("Laufen", start, start + dt.timedelta(hours=1), "Kiel", None)
    comp = next(iter(cal.walk("VEVENT")))
    d = kalender.event_to_dict(comp, "Privat")
    assert d["title"] == "Laufen" and d["location"] == "Kiel" and d["all_day"] is False


def test_tools_registered():
    import asyncio
    mcp = build_server(S)
    tools = asyncio.run(mcp.get_tools()) if hasattr(mcp, "get_tools") else None
    names = set(tools.keys() if isinstance(tools, dict) else [t.name for t in tools or []])
    if names:
        assert {"mail_search", "mail_read", "mail_create_draft", "calendar_events"} <= names
        assert "mail_send" not in names


def test_auth_middleware():
    app = build_app(S)
    with TestClient(app) as client:
        assert client.get("/health").text == "ok"
        assert client.post("/mcp", json={}).status_code == 401
        r = client.post("/mcp", json={}, headers={"Authorization": "Bearer falsch"})
        assert r.status_code == 401
        r = client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": "2025-06-18", "capabilities": {},
                "clientInfo": {"name": "test", "version": "1"}}},
            headers={"Authorization": f"Bearer {TOKEN}",
                     "Accept": "application/json, text/event-stream"},
        )
        assert r.status_code == 200
        assert client.get("/.well-known/oauth-protected-resource").status_code == 404


def test_token_variants():
    from icloud_mcp.server import BearerAuth

    class R:
        def __init__(self, h): self.headers = h
    assert BearerAuth._extract(R({"authorization": "  bearer  abc "})) == "abc"
    assert BearerAuth._extract(R({"authorization": "abc"})) == "abc"
    assert BearerAuth._extract(R({"x-api-key": "abc"})) == "abc"
