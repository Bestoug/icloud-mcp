"""iCloud Mail über IMAP: suchen, lesen, verschieben, markieren, Entwürfe ablegen.

Bewusst ohne Versandfunktion: Claude legt nur Entwürfe an, abschicken macht Philipp.
"""
from __future__ import annotations

import datetime as dt
import email
import email.policy
from contextlib import contextmanager
from email.message import EmailMessage
from email.utils import format_datetime, getaddresses, make_msgid, parsedate_to_datetime
from typing import Iterator

from imapclient import IMAPClient

from . import schutz
from .config import Settings

MAX_BODY_CHARS = 20000


@contextmanager
def connect(s: Settings) -> Iterator[IMAPClient]:
    client = IMAPClient(s.imap_host, port=s.imap_port, ssl=True, timeout=30)
    try:
        client.login(s.icloud_user, s.icloud_password)
        yield client
    finally:
        try:
            client.logout()
        except Exception:
            pass


def _decode(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    return str(email.header.make_header(email.header.decode_header(value)))


def _addresses(value: str) -> list[str]:
    return [f"{n} <{a}>" if n else a for n, a in getaddresses([value]) if a]


def _text_body(msg: email.message.Message) -> tuple[str, int]:
    """Bevorzugt text/plain; fällt auf den sichtbaren Text des HTML zurück.

    Gibt zusätzlich die Anzahl versteckter HTML-Zeichen zurück, die weggelassen wurden.
    """
    plain, html = None, None
    for part in msg.walk() if msg.is_multipart() else [msg]:
        if part.get_content_disposition() == "attachment":
            continue
        ctype = part.get_content_type()
        try:
            content = part.get_content()
        except Exception:
            payload = part.get_payload(decode=True) or b""
            content = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
        if ctype == "text/plain" and plain is None:
            plain = content
        elif ctype == "text/html" and html is None:
            html = content
    if plain:
        return plain.strip(), 0
    if html:
        return schutz.html_zu_text(html)
    return "", 0


def _attachments(msg: email.message.Message) -> list[dict]:
    out = []
    for part in msg.walk():
        if part.get_content_disposition() == "attachment":
            out.append({
                "name": _decode(part.get_filename()),
                "type": part.get_content_type(),
                "size_bytes": len(part.get_payload(decode=True) or b""),
            })
    return out


def parse_message(raw: bytes) -> dict:
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    date = msg.get("Date")
    try:
        date_iso = parsedate_to_datetime(date).isoformat() if date else None
    except (TypeError, ValueError):
        date_iso = date
    body, versteckt = _text_body(msg)
    body, unsichtbar = schutz.unsichtbares_entfernen(body)
    subject_roh = _decode(msg.get("Subject"))
    subject = schutz.feld(subject_roh)
    unsichtbar += len(subject_roh) - len(subject)
    truncated = len(body) > MAX_BODY_CHARS
    body = body[:MAX_BODY_CHARS]
    verdacht = schutz.verdacht(subject, body)
    return {
        "hinweis": schutz.HINWEIS,
        "sicherheit": {
            "verdacht_auf_prompt_injection": verdacht,
            "versteckter_html_text_entfernt_zeichen": versteckt,
            "unsichtbare_zeichen_entfernt": unsichtbar,
        },
        "subject": subject,
        "from": _addresses(str(msg.get("From", ""))),
        "to": _addresses(str(msg.get("To", ""))),
        "cc": _addresses(str(msg.get("Cc", ""))),
        "date": date_iso,
        "message_id": str(msg.get("Message-ID", "")),
        "body": schutz.einpacken(body),
        "body_truncated": truncated,
        "attachments": _attachments(msg),
    }


def build_criteria(query: str | None, sender: str | None, subject: str | None,
                   since: str | None, before: str | None, unread_only: bool,
                   flagged_only: bool) -> list:
    criteria: list = []
    if unread_only:
        criteria.append("UNSEEN")
    if flagged_only:
        criteria.append("FLAGGED")
    if sender:
        criteria += ["FROM", sender]
    if subject:
        criteria += ["SUBJECT", subject]
    if query:
        criteria += ["TEXT", query]
    if since:
        criteria += ["SINCE", dt.date.fromisoformat(since[:10])]
    if before:
        criteria += ["BEFORE", dt.date.fromisoformat(before[:10])]
    return criteria or ["ALL"]


def list_folders(s: Settings) -> list[dict]:
    with connect(s) as c:
        result = []
        for flags, _delim, name in c.list_folders():
            if b"\\Noselect" in flags:
                continue
            status = c.folder_status(name, ["MESSAGES", "UNSEEN"])
            result.append({
                "name": name,
                "messages": status.get(b"MESSAGES", 0),
                "unread": status.get(b"UNSEEN", 0),
            })
        return result


def search(s: Settings, folder: str, criteria: list, limit: int) -> list[dict]:
    with connect(s) as c:
        c.select_folder(folder, readonly=True)
        uids = c.search(criteria, charset="UTF-8")
        uids = sorted(uids, reverse=True)[: max(1, min(limit, 100))]
        if not uids:
            return []
        data = c.fetch(uids, ["ENVELOPE", "FLAGS", "RFC822.SIZE"])
        out = []
        for uid in uids:
            item = data.get(uid)
            if not item:
                continue
            env = item[b"ENVELOPE"]
            sender = ""
            if env.from_:
                a = env.from_[0]
                addr = f"{_decode(a.mailbox)}@{_decode(a.host)}"
                sender = f"{_decode(a.name)} <{addr}>" if a.name else addr
            flags = [f.decode() if isinstance(f, bytes) else str(f) for f in item[b"FLAGS"]]
            out.append({
                "uid": uid,
                "folder": folder,
                "date": env.date.isoformat() if env.date else None,
                "from": sender,
                "subject": schutz.feld(_decode(env.subject)),
                "unread": "\\Seen" not in flags,
                "flagged": "\\Flagged" in flags,
                "size_bytes": item.get(b"RFC822.SIZE"),
            })
        return out


def read(s: Settings, folder: str, uid: int, mark_as_read: bool) -> dict:
    with connect(s) as c:
        c.select_folder(folder, readonly=not mark_as_read)
        data = c.fetch([uid], ["BODY.PEEK[]", "FLAGS"])
        if uid not in data:
            raise ValueError(f"Keine Mail mit UID {uid} in {folder}")
        result = parse_message(data[uid][b"BODY[]"])
        if mark_as_read:
            c.add_flags([uid], [b"\\Seen"])
        result.update({"uid": uid, "folder": folder})
        return result


PAPIERKORB = {"trash", "deleted messages", "gelöschte objekte", "papierkorb", "deleted items", "bin"}


def ist_papierkorb(name: str) -> bool:
    return name.strip().strip("/").split("/")[-1].lower() in PAPIERKORB


def move(s: Settings, folder: str, uids: list[int], target: str) -> dict:
    if ist_papierkorb(target) and not s.trash_erlaubt:
        raise PermissionError(
            "Verschieben in den Papierkorb ist gesperrt (Schutz davor, dass Warnmails "
            "versteckt werden). Erlaubt sind z. B. Junk und Archive. Freischalten nur über "
            "die Umgebungsvariable MAIL_TRASH_ERLAUBT=1 auf dem Server.")
    with connect(s) as c:
        if not c.folder_exists(target):
            raise ValueError(f"Zielordner {target!r} gibt es nicht")
        c.select_folder(folder)
        if c.has_capability("MOVE"):
            c.move(uids, target)
        else:
            c.copy(uids, target)
            c.delete_messages(uids)
            c.expunge(uids)
        return {"moved": uids, "from": folder, "to": target}


def set_flags(s: Settings, folder: str, uids: list[int], read: bool | None,
              flagged: bool | None) -> dict:
    with connect(s) as c:
        c.select_folder(folder)
        if read is True:
            c.add_flags(uids, [b"\\Seen"])
        elif read is False:
            c.remove_flags(uids, [b"\\Seen"])
        if flagged is True:
            c.add_flags(uids, [b"\\Flagged"])
        elif flagged is False:
            c.remove_flags(uids, [b"\\Flagged"])
        return {"updated": uids, "folder": folder, "read": read, "flagged": flagged}


def build_draft(s: Settings, to: list[str], subject: str, body: str,
                cc: list[str] | None = None, reply_to_message_id: str | None = None,
                now: dt.datetime | None = None) -> EmailMessage:
    msg = EmailMessage()
    msg["From"] = s.icloud_user
    msg["To"] = ", ".join(to)
    if cc:
        msg["Cc"] = ", ".join(cc)
    msg["Subject"] = subject
    msg["Date"] = format_datetime(now or dt.datetime.now(dt.timezone.utc))
    msg["Message-ID"] = make_msgid(domain=s.icloud_user.split("@")[-1])
    if reply_to_message_id:
        msg["In-Reply-To"] = reply_to_message_id
        msg["References"] = reply_to_message_id
    msg.set_content(body)
    return msg


def create_draft(s: Settings, msg: EmailMessage) -> dict:
    with connect(s) as c:
        c.append(s.drafts_folder, msg.as_bytes(), flags=[b"\\Draft", b"\\Seen"])
        return {"saved_to": s.drafts_folder, "subject": msg["Subject"], "to": msg["To"]}
