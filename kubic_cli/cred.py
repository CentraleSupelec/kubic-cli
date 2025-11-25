import requests
from typing import List, Dict, Optional
from .config import PW_PUSH_URL
from urllib.parse import urlsplit, urlunsplit
import shutil

# Stock interne
_CREDS: List[Dict] = []

def collect(
    service: str,
    login: str,
    secret: str,
    url: Optional[str] = None,
    note: str = "",
    link: Optional[str] = None,
):
    """Enregistre un credential pour affichage ultérieur.

    link : URL déjà prête (ex: UI Vault). Si absent et service != 'vault', un
    lien Password Pusher sera généré automatiquement.
    """
    _CREDS.append({
        "service": service,
        "login": login,
        "secret": secret,
        "url": url or "",
        "note": note,
        "link": link,
    })


def _push_secret(secret: str) -> Optional[str]:
    try:
        r = requests.post(PW_PUSH_URL, data={"password[payload]": secret}, timeout=10)
        if r.ok:
            resp = r.json()
            if "url_token" in resp:
                # Construire l'URL à partir du token et de l'host de PW_PUSH_URL
                parts = urlsplit(PW_PUSH_URL)
                # remplace le chemin par /p/<token>
                path = f"/p/{resp['url_token']}"
                return urlunsplit((parts.scheme, parts.netloc, path, "", ""))
            if "url" in resp:
                return resp["url"]
    except Exception:
        pass
    return None


def _short(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "…"


def flush():
    if not _CREDS:
        return

    # Push secrets et récupérer liens
    for cred in _CREDS:
        display_url = cred.get("link") or cred["url"]
        payload = (
            f"login: {cred['login']}\n"
            f"secret: {cred['secret']}\n"
            f"url: {display_url}\n"
        )
        cred["pwp"] = _push_secret(payload)

    # Affichage tableau
    term_width = shutil.get_terminal_size((120, 20)).columns
    # max lengths per column (fallback values)
    limits = {
        "service": 15,
        "login": 15,
        "secret": 22,
        "link": 45,
        "url": 45,
        "note": 20,
    }

    # Apply shorten for display and compute widths
    rows = []
    for cred in _CREDS:
        row = {
            "service": _short(cred["service"], limits["service"]),
            "login": _short(cred["login"], limits["login"]),
            "secret": _short(cred["secret"], limits["secret"]),
            "link": _short(cred["pwp"], limits["link"]),
            "url": _short(cred["url"], limits["url"]),
            "note": _short(cred["note"], limits["note"]),
        }
        for k, lim in limits.items():
            row[k] = _short(row[k], lim)
        rows.append(row)

    head = tuple(k.capitalize() for k in limits.keys())
    col_widths = [max(len(r[k]) for r in rows + [dict(zip(limits.keys(), head))]) + 2 for k in limits]
    total = sum(col_widths)
    if total > term_width:
        # Reduce link & url proportionally
        over = total - term_width
        idx = [list(limits.keys()).index("url"), list(limits.keys()).index("link")]
        for i in idx:
            reduce_by = min(over, col_widths[i] - 10)
            col_widths[i] -= reduce_by
            over -= reduce_by
            if over <= 0:
                break

    fmt = "".join([f"{{:<{w}}}" for w in col_widths])
    print("\n=== Credentials générés ===")
    print(fmt.format(*head))
    print("-" * sum(col_widths))
    for row in rows:
        print(fmt.format(row["service"], row["login"], row["secret"], row["link"], row["url"], row["note"]))

    # Vider et terminer
    _CREDS.clear()
