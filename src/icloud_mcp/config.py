"""Konfiguration aus Umgebungsvariablen. Geheimnisse kommen nie aus dem Code."""
from __future__ import annotations

import os
from dataclasses import dataclass


def _req(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"Umgebungsvariable {name} fehlt")
    return value


@dataclass(frozen=True)
class Settings:
    icloud_user: str          # iCloud-Mailadresse, z. B. name@icloud.com
    icloud_password: str      # app-spezifisches Passwort
    access_token: str         # geheimer Bearer-Token für Claude
    timezone: str = "Europe/Berlin"
    imap_host: str = "imap.mail.me.com"
    imap_port: int = 993
    caldav_url: str = "https://caldav.icloud.com"
    drafts_folder: str = "Drafts"
    trash_erlaubt: bool = False   # Verschieben in den Papierkorb erlauben (Standard: nein)
    host: str = "0.0.0.0"
    port: int = 8000

    @classmethod
    def from_env(cls) -> "Settings":
        token = _req("MCP_ACCESS_TOKEN")
        if len(token) < 32:
            raise RuntimeError("MCP_ACCESS_TOKEN muss mindestens 32 Zeichen lang sein")
        return cls(
            icloud_user=_req("ICLOUD_USER"),
            icloud_password=_req("ICLOUD_APP_PASSWORD"),
            access_token=token,
            timezone=os.environ.get("TZ", "Europe/Berlin"),
            drafts_folder=os.environ.get("DRAFTS_FOLDER", "Drafts"),
            trash_erlaubt=os.environ.get("MAIL_TRASH_ERLAUBT", "").strip().lower() in ("1", "true", "ja"),
            port=int(os.environ.get("PORT", "8000")),
        )
