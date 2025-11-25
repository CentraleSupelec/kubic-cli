import secrets
import string
import requests
import typer
from typing import List, Optional

from .cred import collect

__all__ = ["request", "provision"]


def request(method: str, url: str, token: str, json=None, verify: bool = True):
    headers = {"X-Vault-Token": token}
    r = requests.request(method, url, json=json, headers=headers, timeout=10, verify=verify)
    if not r.ok:
        raise RuntimeError(f"Vault {method} {url} -> {r.status_code}: {r.text}")
    return r.json() if r.text else {}


def provision(slug: str, envs: List[str], addr: str, token: str, verify: bool = True, devs: Optional[List[str]] = None):
    """Regroupe toute la logique Vault (policy, approle, kv, userpass)."""

    base = addr.rstrip("/") + "/v1"

    # Policy - Vérifier si elle existe avant de la recréer
    try:
        request("GET", f"{base}/sys/policies/acl/{slug}", token, verify=verify)
        typer.echo(f"[EXISTS] Vault policy {slug}")
    except RuntimeError:
        policy_hcl = (
            f"path \"kv/metadata/{slug}/*\" {{\n  capabilities = [\"list\", \"read\", \"delete\"]\n}}\n"
            f"path \"kv/data/{slug}/*\" {{\n  capabilities = [\"create\", \"update\", \"read\", \"delete\"]\n}}\n"
            f"path \"kv/delete/{slug}/*\" {{\n  capabilities = [\"update\"]\n}}\n"
            f"path \"kv/undelete/{slug}/*\" {{\n  capabilities = [\"update\"]\n}}\n"
            f"path \"kv/destroy/{slug}/*\" {{\n  capabilities = [\"update\"]\n}}\n"
        )
        request("PUT", f"{base}/sys/policies/acl/{slug}", token, json={"policy": policy_hcl}, verify=verify)
        typer.echo(f"[WRITE] Vault policy {slug}")

    # AppRole - Préserver les credentials existants
    try:
        request("GET", f"{base}/auth/approle/role/{slug}", token, verify=verify)
        typer.echo(f"[EXISTS] AppRole {slug}")
        
        # Vérifier si les credentials AVP existent déjà
        try:
            request("GET", f"{base}/kv/data/argocd/avp/{slug}", token, verify=verify)
            typer.echo(f"[EXISTS] AVP credentials kv/argocd/avp/{slug} (preserved)")
        except RuntimeError:
            # Seulement si pas d'AVP secrets, en créer de nouveaux
            role_id = request("GET", f"{base}/auth/approle/role/{slug}/role-id", token, verify=verify)["data"]["role_id"]
            secret_id = request("POST", f"{base}/auth/approle/role/{slug}/secret-id", token, json={}, verify=verify)["data"]["secret_id"]
            request("PUT", f"{base}/kv/data/argocd/avp/{slug}", token, json={"data": {"role_id": role_id, "secret_id": secret_id}}, verify=verify)
            typer.echo(f"[WRITE] AVP credentials kv/argocd/avp/{slug}")
            
    except RuntimeError:
        # Créer tout si rien n'existe
        request("POST", f"{base}/auth/approle/role/{slug}", token, json={"token_policies": [slug]}, verify=verify)
        typer.echo(f"[WRITE] AppRole {slug}")
        role_id = request("GET", f"{base}/auth/approle/role/{slug}/role-id", token, verify=verify)["data"]["role_id"]
        secret_id = request("POST", f"{base}/auth/approle/role/{slug}/secret-id", token, json={}, verify=verify)["data"]["secret_id"]
        request("PUT", f"{base}/kv/data/argocd/avp/{slug}", token, json={"data": {"role_id": role_id, "secret_id": secret_id}}, verify=verify)
        typer.echo(f"[WRITE] AVP credentials kv/argocd/avp/{slug}")

    # Dossiers shared/envs - Merger avec les environnements existants
    try:
        existing_paths = request("LIST", f"{base}/kv/metadata/{slug}", token, verify=verify)
        existing_envs = set(existing_paths.get("data", {}).get("keys", []))
        typer.echo(f"[INFO] Found existing environments: {sorted(existing_envs)}")
    except RuntimeError:
        existing_envs = set()
        typer.echo(f"[INFO] No existing environments found")

    all_envs = existing_envs | {"shared", *envs}
    for env in sorted(all_envs):
        try:
            request("GET", f"{base}/kv/data/{slug}/{env}", token, verify=verify)
            typer.echo(f"[EXISTS] kv data {slug}/{env}")
        except RuntimeError:
            request("PUT", f"{base}/kv/data/{slug}/{env}", token, json={"data": {}}, verify=verify)
            typer.echo(f"[WRITE] kv data {slug}/{env}")

    # Comptes userpass
    if devs:
        for dev in devs:
            try:
                existing = request("GET", f"{base}/auth/userpass/users/{dev}", token, verify=verify)
                policies = set(existing.get("data", {}).get("policies", []))
                if slug not in policies:
                    policies.add(slug)
                    request("POST", f"{base}/auth/userpass/users/{dev}", token, json={"policies": ",".join(sorted(policies))}, verify=verify)
                    typer.echo(f"[UPDATE] userpass {dev} (+ policy {slug})")
            except RuntimeError as e:
                if "404" in str(e):
                    pwd = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(20))
                    request("POST", f"{base}/auth/userpass/users/{dev}", token, json={"password": pwd, "policies": slug}, verify=verify)
                    typer.echo(f"[WRITE] userpass {dev} (policy {slug})")
                    collect("vault", dev, pwd, addr, note=f"policy {slug}", link=f"{addr.rstrip('/')}/ui/vault/secrets/kv/list/{slug}/")
                else:
                    raise
