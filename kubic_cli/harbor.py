import base64
import json
from urllib.parse import urlsplit

import requests
import typer

from . import vault
from .cred import collect
from .utils import gen_pwd

ROBOTS = {"gitlab-ci": ["pull", "push"], "k8s": ["pull"]}
PROJECT_ADMIN = 1


class Harbor:
    def __init__(self, url: str, user: str, password: str, verify: bool = True, dry_run: bool = False):
        self.url = url.rstrip("/")
        self.api = f"{self.url}/api/v2.0"
        self._auth = (user, password)
        self.verify = verify
        self.dry_run = dry_run
        self.pre = "[DRY-RUN] " if dry_run else ""

    def request(self, method: str, path: str, body=None, params=None):
        url = f"{self.api}/{path}"
        try:
            r = requests.request(method, url, json=body, params=params, auth=self._auth,
                                 headers={"X-Is-Resource-Name": "true"}, timeout=10, verify=self.verify)
        except requests.RequestException as e:
            raise RuntimeError(f"Harbor {method} {url} : {e.__class__.__name__}") from e
        if not r.ok:
            raise RuntimeError(f"Harbor {method} {url} -> {r.status_code}: {r.text}")
        return r.json() if r.text else None

    def get_or_none(self, path: str, params=None):
        try:
            return self.request("GET", path, params=params)
        except RuntimeError as e:
            if "-> 404" in str(e):
                return None
            raise


def ensure_project(client: Harbor, slug: str):
    project = client.get_or_none(f"projects/{slug}")
    if project is not None:
        typer.echo(f"[EXISTS] Harbor projet {slug}")
        return project
    typer.echo(f"{client.pre}[WRITE] Harbor projet {slug} (privé)")
    if client.dry_run:
        return None
    client.request("POST", "projects", body={"project_name": slug, "metadata": {"public": "false"}})
    return client.request("GET", f"projects/{slug}")


def create_robot(client: Harbor, slug: str, short: str, actions):
    if client.dry_run:
        typer.echo(f"{client.pre}[WRITE] Harbor robot {slug}+{short} (repository {'+'.join(actions)})")
        return None
    body = {"name": short, "duration": -1, "level": "project",
            "permissions": [{"kind": "project", "namespace": slug,
                             "access": [{"resource": "repository", "action": a} for a in actions]}]}
    created = client.request("POST", "robots", body=body)
    typer.echo(f"[WRITE] Harbor robot {created['name']} (repository {'+'.join(actions)})")
    collect("harbor", created["name"], created["secret"], client.url, note=f"projet {slug}, {'+'.join(actions)}",
            group=f"harbor:{slug}")
    return created


def existing_robots(client: Harbor, slug: str, project):
    if project is None:
        return {}
    params = {"q": f"Level=project,ProjectID={project['project_id']}", "page_size": 100}
    names = [r["name"] for r in client.request("GET", "robots", params=params) or []]
    return {short: name for short in ROBOTS for name in names if name.endswith(f"{slug}+{short}")}


def ensure_robots(client: Harbor, slug: str, project):
    existing = existing_robots(client, slug, project)
    created = {}
    for short, actions in ROBOTS.items():
        if short in existing:
            typer.echo(f"[EXISTS] Harbor robot {existing[short]}")
            continue
        created[short] = create_robot(client, slug, short, actions)
    return created


def ensure_user(client: Harbor, slug: str, login: str, email_domain: str):
    found = client.request("GET", "users", params={"q": f"username={login}"}) or []
    if any(u["username"] == login for u in found):
        typer.echo(f"[EXISTS] Harbor user {login}")
        return
    typer.echo(f"{client.pre}[WRITE] Harbor user {login} ({login}@{email_domain})")
    if client.dry_run:
        return
    pwd = gen_password()
    client.request("POST", "users", body={"username": login, "email": f"{login}@{email_domain}",
                                          "realname": login, "password": pwd})
    collect("harbor", login, pwd, client.url, note=f"projet {slug}", group=f"harbor:{slug}")


def is_member(client: Harbor, slug: str, login: str, project) -> bool:
    if project is None:
        return False
    members = client.request("GET", f"projects/{slug}/members", params={"entityname": login, "page_size": 100})
    return any(m["entity_name"] == login for m in members or [])


def ensure_member(client: Harbor, slug: str, login: str, project):
    existing = f"[EXISTS] Harbor membre {login} de {slug} (rôle inchangé)"
    if is_member(client, slug, login, project):
        typer.echo(existing)
        return
    if client.dry_run:
        typer.echo(f"{client.pre}[WRITE] Harbor membre {login} projectAdmin de {slug}")
        return
    try:
        client.request("POST", f"projects/{slug}/members",
                       body={"role_id": PROJECT_ADMIN, "member_user": {"username": login}})
    except RuntimeError as e:
        if "-> 409" not in str(e):
            raise
        typer.echo(existing)
        return
    typer.echo(f"[WRITE] Harbor membre {login} projectAdmin de {slug}")


def ensure_devs(client: Harbor, slug: str, devs, email_domain: str, project):
    for dev in devs:
        ensure_user(client, slug, dev, email_domain)
        ensure_member(client, slug, dev, project)


def provision(client: Harbor, slug: str, devs=(), email_domain: str = ""):
    project = ensure_project(client, slug)
    created = ensure_robots(client, slug, project)
    ensure_devs(client, slug, devs, email_domain, project)
    return created.get("k8s")


def provision_users(client: Harbor, slug: str, devs, email_domain: str):
    project = ensure_project(client, slug)
    ensure_devs(client, slug, devs, email_domain, project)


def gen_password() -> str:
    while True:
        pwd = gen_pwd(20)
        if any(c.isupper() for c in pwd) and any(c.islower() for c in pwd) and any(c.isdigit() for c in pwd):
            return pwd


def dockerconfigjson(registry_url: str, robot_name: str, secret: str) -> str:
    auth = base64.b64encode(f"{robot_name}:{secret}".encode()).decode()
    return json.dumps({"auths": {urlsplit(registry_url).netloc: {"auth": auth}}})


def publish_pull_secret(client: Harbor, slug: str, robot, vault_addr, vault_token):
    if client.dry_run:
        typer.echo(f"[DRY-RUN] Vault kv/{slug}/shared : dockerconfigjson écrit seulement si le robot k8s est créé")
        return
    if robot is None:
        typer.secho(f"[WARN] Robot k8s existant, secret inconnu : dockerconfigjson de kv/{slug}/shared non écrit",
                    fg=typer.colors.YELLOW)
        return
    if not vault_addr or not vault_token:
        typer.secho(f"[WARN] Vault non configuré ou ignoré : dockerconfigjson de kv/{slug}/shared non écrit",
                    fg=typer.colors.YELLOW)
        return
    url =f"{vault_addr.rstrip('/')}/v1/kv/data/{slug}/shared"
    current = vault.get_or_none("GET", url, vault_token) or {}
    values = dict(current.get("data", {}).get("data") or {})
    values["dockerconfigjson"] = dockerconfigjson(client.url, robot["name"], robot["secret"])
    vault.request("PUT", url, vault_token, json={"data": values})
    typer.echo(f"[WRITE] Vault kv/{slug}/shared : clé dockerconfigjson ({robot['name']})")
