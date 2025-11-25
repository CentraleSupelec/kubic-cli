from urllib.parse import urljoin

import requests

__all__ = ["login", "set_password"]


def login(url: str, username: str, password: str, verify: bool = True) -> str:
    """Retourne un token JWT pour l'utilisateur donné."""
    if not url:
        raise ValueError("URL ArgoCD manquante")
    endpoint = urljoin(url.rstrip("/"), "/api/v1/session")
    r = requests.post(endpoint, json={"username": username, "password": password}, timeout=10, verify=verify)
    r.raise_for_status()
    return r.json()["token"]


def set_password(url: str, admin_token: str, account: str, new_password: str, verify: bool = True):
    """Modifie (ou initialise) le mot de passe d'un compte local Argo CD."""
    endpoint = urljoin(url.rstrip("/"), "/api/v1/account/password")
    headers = {"Authorization": f"Bearer {admin_token}"}
    payload = {"name": account, "currentPassword": "", "newPassword": new_password}
    r = requests.put(endpoint, json=payload, headers=headers, timeout=10, verify=verify)
    r.raise_for_status()
