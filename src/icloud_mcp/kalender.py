"""Apple Kalender über CalDAV: Kalender auflisten, Termine lesen, anlegen und ändern."""
from __future__ import annotations

import datetime as dt
import uuid
from zoneinfo import ZoneInfo

import caldav
from icalendar import Calendar, Event

from .config import Settings


def parse_when(value: str, tz: str, all_day: bool = False) -> dt.date | dt.datetime:
    """ISO-Datum oder -Zeit; ohne Zeitzone gilt die lokale Zeitzone."""
    if all_day or (len(value) == 10 and value[4] == "-"):
        return dt.date.fromisoformat(value[:10])
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=ZoneInfo(tz))
    return parsed


def _client(s: Settings) -> caldav.DAVClient:
    return caldav.DAVClient(url=s.caldav_url, username=s.icloud_user, password=s.icloud_password)


def _calendars(s: Settings):
    return _client(s).principal().calendars()


def _find_calendar(s: Settings, name: str | None):
    cals = _calendars(s)
    if not cals:
        raise ValueError("Keine Kalender gefunden")
    if not name:
        return cals[0]
    for c in cals:
        if (c.name or "").strip().lower() == name.strip().lower():
            return c
    raise ValueError(f"Kalender {name!r} nicht gefunden. Vorhanden: {[c.name for c in cals]}")


def _iso(value) -> str | None:
    if value is None:
        return None
    v = value.dt if hasattr(value, "dt") else value
    return v.isoformat()


def event_to_dict(component, calendar_name: str) -> dict:
    return {
        "uid": str(component.get("UID", "")),
        "calendar": calendar_name,
        "title": str(component.get("SUMMARY", "")),
        "start": _iso(component.get("DTSTART")),
        "end": _iso(component.get("DTEND")),
        "all_day": not isinstance(component.get("DTSTART").dt, dt.datetime)
        if component.get("DTSTART") else False,
        "location": str(component.get("LOCATION", "")) or None,
        "notes": str(component.get("DESCRIPTION", "")) or None,
        "recurring": component.get("RRULE") is not None,
    }


def _components(obj):
    cal = obj.icalendar_instance if hasattr(obj, "icalendar_instance") else Calendar.from_ical(obj.data)
    return [c for c in cal.walk("VEVENT")]


def list_calendars(s: Settings) -> list[dict]:
    return [{"name": c.name, "url": str(c.url)} for c in _calendars(s)]


def list_events(s: Settings, start: str, end: str, calendar: str | None) -> list[dict]:
    start_dt = parse_when(start, s.timezone)
    end_dt = parse_when(end, s.timezone)
    if isinstance(start_dt, dt.date) and not isinstance(start_dt, dt.datetime):
        start_dt = dt.datetime.combine(start_dt, dt.time.min, ZoneInfo(s.timezone))
    if isinstance(end_dt, dt.date) and not isinstance(end_dt, dt.datetime):
        end_dt = dt.datetime.combine(end_dt, dt.time.max, ZoneInfo(s.timezone))
    cals = [_find_calendar(s, calendar)] if calendar else _calendars(s)
    events = []
    for cal in cals:
        for obj in cal.search(start=start_dt, end=end_dt, event=True, expand=True):
            for comp in _components(obj):
                events.append(event_to_dict(comp, cal.name))
    events.sort(key=lambda e: e["start"] or "")
    return events


def build_event(title: str, start, end, location: str | None, notes: str | None,
                uid: str | None = None) -> Calendar:
    cal = Calendar()
    cal.add("prodid", "-//icloud-mcp//Claude//DE")
    cal.add("version", "2.0")
    ev = Event()
    ev.add("uid", uid or f"{uuid.uuid4()}@icloud-mcp")
    ev.add("summary", title)
    ev.add("dtstart", start)
    ev.add("dtend", end)
    ev.add("dtstamp", dt.datetime.now(dt.timezone.utc))
    if location:
        ev.add("location", location)
    if notes:
        ev.add("description", notes)
    cal.add_component(ev)
    return cal


def _save(cal_obj, ical: str):
    for method in ("save_event", "add_event"):
        fn = getattr(cal_obj, method, None)
        if fn:
            return fn(ical)
    raise RuntimeError("caldav-Bibliothek ohne save_event/add_event")


def create_event(s: Settings, calendar: str | None, title: str, start: str, end: str | None,
                 all_day: bool, location: str | None, notes: str | None) -> dict:
    target = _find_calendar(s, calendar)
    start_v = parse_when(start, s.timezone, all_day)
    if end:
        end_v = parse_when(end, s.timezone, all_day)
    elif all_day:
        end_v = start_v + dt.timedelta(days=1)
    else:
        end_v = start_v + dt.timedelta(hours=1)
    ical = build_event(title, start_v, end_v, location, notes)
    _save(target, ical.to_ical().decode())
    comp = next(iter(ical.walk("VEVENT")))
    return event_to_dict(comp, target.name)


def _event_by_uid(cal_obj, uid: str):
    for method in ("get_event_by_uid", "event_by_uid"):
        fn = getattr(cal_obj, method, None)
        if fn:
            return fn(uid)
    raise RuntimeError("caldav-Bibliothek ohne event_by_uid")


def update_event(s: Settings, uid: str, calendar: str | None, title: str | None,
                 start: str | None, end: str | None, location: str | None,
                 notes: str | None) -> dict:
    cals = [_find_calendar(s, calendar)] if calendar else _calendars(s)
    for cal in cals:
        try:
            obj = _event_by_uid(cal, uid)
        except Exception:
            continue
        ical = obj.icalendar_instance
        comp = next(iter(ical.walk("VEVENT")))
        if comp.get("RRULE") is not None and (start or end):
            raise ValueError("Wiederkehrende Termine: Zeiten bitte in der Kalender-App ändern")
        all_day = not isinstance(comp.get("DTSTART").dt, dt.datetime)
        replacements = {
            "SUMMARY": title,
            "DTSTART": parse_when(start, s.timezone, all_day) if start else None,
            "DTEND": parse_when(end, s.timezone, all_day) if end else None,
            "LOCATION": location,
            "DESCRIPTION": notes,
        }
        for key, value in replacements.items():
            if value is not None:
                comp.pop(key, None)
                comp.add(key.lower(), value)
        obj.icalendar_instance = ical
        obj.save()
        return event_to_dict(comp, cal.name)
    raise ValueError(f"Kein Termin mit UID {uid} gefunden")
