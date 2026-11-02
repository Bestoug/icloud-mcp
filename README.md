# icloud-mcp

Kleiner MCP-Server, der Claude Zugriff auf **iCloud Mail** und den **Apple Kalender** gibt. Läuft als Docker-Container auf dem eigenen Server und wird in claude.ai als eigener Connector eingebunden.

## Was Claude damit kann
| Bereich | Werkzeuge |
|---|---|
| Mail | Ordner auflisten, Mails suchen, lesen, verschieben, als gelesen/markiert setzen, **Entwürfe** anlegen |
| Kalender | Kalender auflisten, Termine anzeigen, anlegen, ändern |

**Kein Versand:** Antworten landen nur als Entwurf. Kein endgültiges Löschen.

## Sicherheit
- Zugriff auf iCloud über ein **app-spezifisches Passwort** (jederzeit unter account.apple.com widerrufbar)
- Der Server nimmt nur Anfragen mit dem geheimen Token `MCP_ACCESS_TOKEN` an (Header `Authorization: Bearer …`)
- Alle Geheimnisse kommen ausschließlich aus Umgebungsvariablen, nie aus dem Code

## Umgebungsvariablen
| Variable | Bedeutung |
|---|---|
| `ICLOUD_USER` | iCloud-Mailadresse, z. B. `name@icloud.com` |
| `ICLOUD_APP_PASSWORD` | app-spezifisches Passwort |
| `MCP_ACCESS_TOKEN` | langer Zufallswert (mind. 32 Zeichen), z. B. `openssl rand -hex 32` |
| `TZ` | Zeitzone, Standard `Europe/Berlin` |
| `DRAFTS_FOLDER` | Entwürfe-Ordner, Standard `Drafts` |
| `PORT` | Port im Container, Standard `8000` |

## Image
`ghcr.io/bestoug/icloud-mcp:latest` wird bei jedem Push auf `main` getestet und gebaut.

## Endpunkte
- `/mcp`: MCP (Streamable HTTP), braucht den Token
- `/health`: Lebenszeichen ohne Token
