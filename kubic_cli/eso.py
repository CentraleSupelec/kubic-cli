"""External Secrets (CMP-37): JSON key, Vault store file and Vault role/policy of an app env.

Git (apps/<app>/<env>.json, key "externalSecrets.paths") is the source of truth;
Vault is reconciled from it. Secret values are never read: existence checks use kv/metadata.
"""
import difflib
import json
import re
from pathlib import Path
from typing import Dict, List, Optional

import requests
import typer

from . import vault

__all__ = ["EsoError", "namespace", "list_envs", "read_paths", "set_paths", "drop_key", "store_content",
           "desired_policy", "policy_in_sync", "role_diff", "proposed_paths", "plan", "enable", "disable", "status"]

ESO_KEY = "externalSecrets"
SA_NAME = "external-secrets-vault"
# Namespace and SA of the ESO operator: never bound to an app role
OPERATOR_NS = "external-secrets"
OPERATOR_SA = "external-secrets"
TOKEN_TTL = 600
TOKEN_MAX_TTL = 1800

_PATH_RE = re.compile(r"^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$")
_AVP_RE = re.compile(r"<path:kv/data/([^#>\s]+)#([^#>|\s]+)")
_POLICY_BLOCK = re.compile(r'path\s+"([^"]+)"\s*\{\s*capabilities\s*=\s*\[([^\]]*)\]\s*\}')
_WS = re.compile(r"\s*")


class EsoError(Exception):
    pass


# ---------------------------------------------------------------------------
# GitOps files
# ---------------------------------------------------------------------------

def namespace(app: str, env: str) -> str:
    """Same rule as the ApplicationSet: <app>, or <app>-<env> when the file is not named <app>."""
    return app if app == env else f"{app}-{env}"


def list_envs(gitops_path: Path, app: str) -> List[str]:
    return sorted(p.name.split(".")[0] for p in (gitops_path / "apps" / app).glob("*.json"))


def json_file(gitops_path: Path, app: str, env: str) -> Path:
    return gitops_path / "apps" / app / f"{env}.json"


def store_file(gitops_path: Path, ns: str) -> Path:
    return gitops_path / "helm" / "argocd" / "templates" / "external-secrets" / f"{ns}.yaml"


def store_content(ns: str) -> str:
    return (f"# CMP-37: Vault store of namespace {ns} (helper in _helpers.tpl)\n"
            f'{{{{ include "argocd.vaultStore" (dict "ns" "{ns}" "root" $) }}}}\n')


def _members(text: str):
    """Spans of the top-level members: [(key, key_start, value_start, value_end)], closing brace index."""
    dec = json.JSONDecoder()
    i = _WS.match(text, 0).end()
    if text[i:i + 1] != "{":
        raise EsoError("le fichier JSON n'est pas un objet")
    i += 1
    out = []
    while True:
        i = _WS.match(text, i).end()
        if text[i] == "}":
            return out, i
        key_start = i
        key, i = json.decoder.scanstring(text, i + 1)
        i = _WS.match(text, i).end() + 1  # ':'
        value_start = _WS.match(text, i).end()
        _, i = dec.raw_decode(text, value_start)
        out.append((key, key_start, value_start, i))
        i = _WS.match(text, i).end()
        if text[i] == ",":
            i += 1


def read_paths(text: str) -> Optional[List[str]]:
    value = json.loads(text).get(ESO_KEY)
    if value is None:
        return None
    if not isinstance(value, dict) or not isinstance(value.get("paths"), list):
        raise EsoError(f'"{ESO_KEY}" doit être de la forme {{"paths": [...]}}')
    return value["paths"]


def set_paths(text: str, paths: List[str]) -> str:
    """Set the key in place, leaving the rest of the file byte-identical."""
    value = json.dumps({"paths": paths}, ensure_ascii=False)
    members, close = _members(text)
    for key, _, start, end in members:
        if key == ESO_KEY:
            return text[:start] + value + text[end:]
    if not members:
        return text[:close].rstrip() + f'\n  "{ESO_KEY}": {value}\n' + text[close:]
    first_start = members[0][1]
    indent = text[text.rfind("\n", 0, first_start) + 1:first_start]
    last_end = members[-1][3]
    return text[:last_end] + f',\n{indent}"{ESO_KEY}": {value}' + text[last_end:]


def drop_key(text: str) -> str:
    members, _ = _members(text)
    for idx, (key, key_start, _, end) in enumerate(members):
        if key != ESO_KEY:
            continue
        if idx > 0:
            return text[:members[idx - 1][3]] + text[end:]
        if len(members) > 1:
            return text[:key_start] + text[members[1][1]:]
        return text[:key_start] + text[end:].lstrip(" \t")
    return text


def avp_placeholders(gitops_path: Path, app: str, env: str) -> Dict[str, List[str]]:
    """AVP placeholders of the env values files (and in-repo chart): {path: [keys]}. Key names only."""
    data = json.loads(json_file(gitops_path, app, env).read_text())
    files = [gitops_path / "apps" / app / v for v in data.get("valuesFiles", [])]
    chart = gitops_path / "helm" / app
    if chart.is_dir():
        files += sorted(chart.rglob("*.yaml"))
    found: Dict[str, set] = {}
    for f in files:
        if f.is_file():
            for path, key in _AVP_RE.findall(f.read_text()):
                found.setdefault(path, set()).add(key)
    return {p: sorted(k) for p, k in sorted(found.items())}


def proposed_paths(gitops_path: Path, app: str, env: str):
    """(paths, source): JSON key, else AVP placeholders, else <app>/shared + <app>/<env>."""
    current = read_paths(json_file(gitops_path, app, env).read_text())
    if current is not None:
        return current, "json"
    avp = avp_placeholders(gitops_path, app, env)
    if avp:
        return list(avp), "avp"
    return [f"{app}/shared", f"{app}/{env}"], "default"


def check_target(app: str, env: str, paths: List[str]):
    ns = namespace(app, env)
    if ns == OPERATOR_NS:
        raise EsoError(f"namespace {ns} refusé : c'est celui de l'opérateur ESO")
    if not paths:
        raise EsoError("aucun chemin Vault")
    for p in paths:
        if not _PATH_RE.match(p) or p.startswith("kv/"):
            raise EsoError(f"chemin invalide {p!r} (chemin KV v2 sans kv/data/, sans joker)")
        # A team only reads its own tree
        if p != app and not p.startswith(f"{app}/"):
            raise EsoError(f"chemin {p} hors de l'arborescence {app}/")


# ---------------------------------------------------------------------------
# Vault
# ---------------------------------------------------------------------------

def desired_policy(paths: List[str]) -> str:
    return "".join(f'path "kv/data/{p}" {{\n  capabilities = ["read"]\n}}\n' for p in paths)


def _parse_policy(hcl: str) -> Optional[Dict[str, tuple]]:
    """{path: capabilities}, or None if the policy holds anything else than path blocks."""
    text = "\n".join(l for l in hcl.splitlines() if not l.strip().startswith("#"))
    if _POLICY_BLOCK.sub("", text).strip():
        return None
    return {p: tuple(sorted(c.strip().strip('"') for c in caps.split(",") if c.strip()))
            for p, caps in _POLICY_BLOCK.findall(text)}


def policy_in_sync(current: Optional[str], paths: List[str]) -> bool:
    return current is not None and _parse_policy(current) == _parse_policy(desired_policy(paths))


def desired_role(ns: str) -> dict:
    return {
        "bound_service_account_names": [SA_NAME],
        "bound_service_account_namespaces": [ns],
        "audience": "vault",
        "token_policies": [f"eso-{ns}"],
        "token_ttl": TOKEN_TTL,
        "token_max_ttl": TOKEN_MAX_TTL,
    }


def _norm(value):
    if isinstance(value, list):
        return sorted(str(v) for v in value)
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return value


def role_diff(current: Optional[dict], desired: dict) -> List[tuple]:
    """[(field, current, desired)] for the fields that differ."""
    current = current or {}
    return [(k, current.get(k), v) for k, v in desired.items() if _norm(current.get(k)) != _norm(v)]


def _refuse_operator(role: dict):
    if (OPERATOR_NS in role["bound_service_account_namespaces"]
            or OPERATOR_SA in role["bound_service_account_names"]):
        raise EsoError("rôle refusé : il cible le ServiceAccount de l'opérateur ESO")


def _vget(base: str, path: str, token: str, verify) -> Optional[dict]:
    try:
        return vault.request("GET", f"{base}/{path}", token, verify=verify)
    except RuntimeError as e:
        if "-> 404" in str(e):
            return None
        raise


class VaultCtx:
    def __init__(self, addr: str, token: str, verify=True):
        self.base = addr.rstrip("/") + "/v1"
        self.token = token
        self.verify = verify

    def get(self, path: str) -> Optional[dict]:
        return _vget(self.base, path, self.token, self.verify)

    def call(self, method: str, path: str, json=None):
        return vault.request(method, f"{self.base}/{path}", self.token, json=json, verify=self.verify)

    def policy(self, ns: str) -> Optional[str]:
        r = self.get(f"sys/policies/acl/eso-{ns}")
        return r["data"]["policy"] if r else None

    def role(self, ns: str) -> Optional[dict]:
        r = self.get(f"auth/kubernetes/role/eso-{ns}")
        return r["data"] if r else None

    def kv_exists(self, path: str) -> bool:
        # Metadata only: the secret value is never read
        return self.get(f"kv/metadata/{path}") is not None


def _show_vault_diff(ns: str, policy: Optional[str], role: Optional[dict], paths: List[str]):
    """Print the diff, return (policy_ok, role_diff)."""
    want = desired_policy(paths)
    policy_ok = policy_in_sync(policy, paths)
    if policy is None:
        typer.echo(f"[MISSING] Vault policy eso-{ns}, à créer :")
        typer.echo("".join(f"    + {l}\n" for l in want.splitlines()), nl=False)
    elif policy_ok:
        typer.echo(f"[EXISTS] Vault policy eso-{ns} (à jour)")
    else:
        typer.secho(f"[DRIFT] Vault policy eso-{ns} :", fg=typer.colors.YELLOW)
        for l in difflib.unified_diff(policy.splitlines(), want.splitlines(), "vault", "git", lineterm="", n=1):
            typer.echo(f"    {l}")
    desired = desired_role(ns)
    diff = role_diff(role, desired)
    if role is None:
        typer.echo(f"[MISSING] Vault role auth/kubernetes/role/eso-{ns}, à créer : {json.dumps(desired)}")
    elif not diff:
        typer.echo(f"[EXISTS] Vault role eso-{ns} (à jour)")
    else:
        typer.secho(f"[DRIFT] Vault role eso-{ns} :", fg=typer.colors.YELLOW)
        for field, cur, new in diff:
            typer.echo(f"    {field}: {cur!r} -> {new!r}")
    return policy_ok, diff


def reconcile_vault(ctx: VaultCtx, ns: str, paths: List[str], dry_run: bool = False, assume_yes: bool = False):
    desired = desired_role(ns)
    _refuse_operator(desired)
    policy, role = ctx.policy(ns), ctx.role(ns)
    policy_ok, diff = _show_vault_diff(ns, policy, role, paths)
    if policy_ok and not diff:
        return
    if dry_run:
        typer.echo(f"[DRY-RUN] Vault eso-{ns} non modifié")
        return
    if not assume_yes and not typer.confirm(f"Appliquer ces changements Vault pour eso-{ns} ?", default=False):
        raise EsoError("changements Vault annulés")
    if not policy_ok:
        ctx.call("PUT", f"sys/policies/acl/eso-{ns}", json={"policy": desired_policy(paths)})
        typer.echo(f"[{'WRITE' if policy is None else 'UPDATE'}] Vault policy eso-{ns}")
    if diff:
        ctx.call("POST", f"auth/kubernetes/role/eso-{ns}", json=desired)
        typer.echo(f"[{'WRITE' if role is None else 'UPDATE'}] Vault role eso-{ns}")


# ---------------------------------------------------------------------------
# Kubernetes (read-only)
# ---------------------------------------------------------------------------

class KubeCtx:
    def __init__(self, api_server: str, api_token: str, verify=True):
        self.api = api_server.rstrip("/")
        self.headers = {"Authorization": f"Bearer {api_token}"}
        self.verify = verify

    def get(self, path: str) -> Optional[dict]:
        r = requests.get(f"{self.api}{path}", headers=self.headers, timeout=10, verify=self.verify)
        if r.status_code == 404:
            return None
        r.raise_for_status()
        return r.json()

    def store_ready(self, ns: str) -> Optional[str]:
        css = self.get(f"/apis/external-secrets.io/v1/clustersecretstores/vault-{ns}")
        if css is None:
            return None
        cond = next((c for c in css.get("status", {}).get("conditions", []) if c.get("type") == "Ready"), {})
        return f"{cond.get('status', 'Unknown')} {cond.get('reason', '')}".strip()

    def external_secrets(self, ns: str) -> List[str]:
        r = self.get(f"/apis/external-secrets.io/v1/namespaces/{ns}/externalsecrets") or {}
        return [i["metadata"]["name"] for i in r.get("items", [])]


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def _require_env(gitops_path: Path, app: str, env: str) -> Path:
    jf = json_file(gitops_path, app, env)
    if not jf.exists():
        raise EsoError(f"{jf} introuvable")
    return jf


def _store_state(gitops_path: Path, ns: str) -> str:
    sf = store_file(gitops_path, ns)
    if not sf.exists():
        return "absent"
    return "à jour" if sf.read_text() == store_content(ns) else "différent"


def plan(gitops_path: Path, app: str, envs: List[str], ctx: Optional[VaultCtx] = None):
    for env in envs:
        _require_env(gitops_path, app, env)
        ns = namespace(app, env)
        typer.secho(f"\n== {app}/{env}.json (namespace {ns})", bold=True)
        paths, source = proposed_paths(gitops_path, app, env)
        label = {"json": "clé JSON", "avp": "proposés (placeholders AVP)", "default": "proposés (défaut)"}[source]
        typer.echo(f"[INFO] Chemins {label} : {', '.join(paths)}")
        for path, keys in avp_placeholders(gitops_path, app, env).items():
            typer.echo(f"[AVP] <path:kv/data/{path}#...> clés : {', '.join(keys)}")
        try:
            check_target(app, env, paths)
        except EsoError as e:
            typer.secho(f"[ERROR] {e}", fg=typer.colors.RED)
            continue
        typer.echo(f"[INFO] Store {store_file(gitops_path, ns).relative_to(gitops_path)} : {_store_state(gitops_path, ns)}")
        if ctx is None:
            typer.echo("[INFO] Pas de Vault (VAULT_ADDR/VAULT_TOKEN) : diff Vault non calculé")
            continue
        for p in paths:
            if ctx.kv_exists(p):
                typer.echo(f"[EXISTS] kv/metadata/{p}")
            else:
                typer.secho(f"[WARN] kv/metadata/{p} absent dans Vault", fg=typer.colors.YELLOW)
        _show_vault_diff(ns, ctx.policy(ns), ctx.role(ns), paths)


def enable(gitops_path: Path, app: str, env: str, paths: Optional[List[str]], ctx: Optional[VaultCtx] = None,
           dry_run: bool = False, assume_yes: bool = False):
    jf = _require_env(gitops_path, app, env)
    ns = namespace(app, env)
    if not paths:
        paths, source = proposed_paths(gitops_path, app, env)
        typer.echo(f"[INFO] Chemins ({source}) : {', '.join(paths)}")
    check_target(app, env, paths)
    prefix = "[DRY-RUN] " if dry_run else ""

    text = jf.read_text()
    new_text = set_paths(text, paths)
    if new_text == text:
        typer.echo(f"[EXISTS] {jf} {ESO_KEY}")
    else:
        if not dry_run:
            jf.write_text(new_text)
        typer.echo(f"{prefix}[{'UPDATE' if read_paths(text) is not None else 'WRITE'}] {jf} {ESO_KEY}")

    sf = store_file(gitops_path, ns)
    state = _store_state(gitops_path, ns)
    if state == "à jour":
        typer.echo(f"[EXISTS] {sf}")
    else:
        if not dry_run:
            sf.parent.mkdir(parents=True, exist_ok=True)
            sf.write_text(store_content(ns))
        typer.echo(f"{prefix}[{'WRITE' if state == 'absent' else 'UPDATE'}] {sf}")

    if ctx is None:
        typer.echo("[INFO] Pas de Vault (VAULT_ADDR/VAULT_TOKEN) : rôle/policy Vault non réconciliés")
    else:
        reconcile_vault(ctx, ns, paths, dry_run=dry_run, assume_yes=assume_yes)


def disable(gitops_path: Path, app: str, env: str, ctx: Optional[VaultCtx] = None, kube: Optional[KubeCtx] = None,
            force: bool = False, dry_run: bool = False, assume_yes: bool = False):
    jf = _require_env(gitops_path, app, env)
    ns = namespace(app, env)
    if ns == OPERATOR_NS:
        raise EsoError(f"namespace {ns} refusé : c'est celui de l'opérateur ESO")
    if kube is None:
        typer.secho(f"[WARN] Pas d'accès cluster : ExternalSecrets de {ns} non vérifiés", fg=typer.colors.YELLOW)
    else:
        try:
            names = kube.external_secrets(ns)
        except Exception as e:
            if not force:
                raise EsoError(f"impossible de lister les ExternalSecrets de {ns} ({e}), --force pour passer outre")
            names = []
        if names and not force:
            raise EsoError(f"ExternalSecrets encore présents dans {ns} : {', '.join(names)} (--force pour passer outre)")
    prefix = "[DRY-RUN] " if dry_run else ""

    text = jf.read_text()
    new_text = drop_key(text)
    if new_text != text:
        if not dry_run:
            jf.write_text(new_text)
        typer.echo(f"{prefix}[DELETE] {jf} {ESO_KEY}")
    sf = store_file(gitops_path, ns)
    if sf.exists():
        if not dry_run:
            sf.unlink()
        typer.echo(f"{prefix}[DELETE] {sf}")

    if ctx is None:
        typer.echo("[INFO] Pas de Vault (VAULT_ADDR/VAULT_TOKEN) : rôle/policy Vault conservés")
        return
    targets = [(f"auth/kubernetes/role/eso-{ns}", ctx.role(ns) is not None),
               (f"sys/policies/acl/eso-{ns}", ctx.policy(ns) is not None)]
    present = [t for t, ok in targets if ok]
    if not present:
        typer.echo(f"[INFO] Vault eso-{ns} déjà absent")
        return
    if dry_run:
        for t in present:
            typer.echo(f"[DRY-RUN] [DELETE] Vault {t}")
        return
    if not assume_yes and not typer.confirm(f"Supprimer {', '.join(present)} ?", default=False):
        raise EsoError("suppression Vault annulée")
    for t in present:
        ctx.call("DELETE", t)
        typer.echo(f"[DELETE] Vault {t}")


def status(gitops_path: Path, app: str, envs: List[str], ctx: Optional[VaultCtx] = None, kube: Optional[KubeCtx] = None):
    for env in envs:
        _require_env(gitops_path, app, env)
        ns = namespace(app, env)
        paths = read_paths(json_file(gitops_path, app, env).read_text())
        typer.secho(f"\n== {app}/{env} (namespace {ns})", bold=True)
        typer.echo(f"  JSON   : {', '.join(paths) if paths is not None else 'désactivé'}")
        typer.echo(f"  Store  : {_store_state(gitops_path, ns)}")
        if ctx is not None:
            policy, role = ctx.policy(ns), ctx.role(ns)
            if paths is None:
                vstate = "absent" if policy is None and role is None else "DRIFT (orphelin, ESO désactivé dans Git)"
            elif policy is None or role is None:
                vstate = "DRIFT (policy ou rôle absent)"
            else:
                vstate = "sync" if policy_in_sync(policy, paths) and not role_diff(role, desired_role(ns)) else "DRIFT"
            typer.echo(f"  Vault  : {vstate}")
        if kube is not None:
            try:
                ready = kube.store_ready(ns)
                typer.echo(f"  Cluster: ClusterSecretStore vault-{ns} {ready or 'absent'}")
            except Exception as e:
                typer.secho(f"  Cluster: erreur ({e})", fg=typer.colors.YELLOW)
