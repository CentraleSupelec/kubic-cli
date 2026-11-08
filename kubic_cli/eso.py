"""External Secrets: JSON key, Vault store file and Vault role/policy of an app env.

Git (apps/<app>/<env>.json, key "externalSecrets.paths") is the source of truth;
Vault is reconciled from it. Secret values are never read.
"""
import difflib
import json
import re
from pathlib import Path
from typing import Dict, List, Optional

import typer

from . import vault

__all__ = ["EsoError", "namespace", "read_paths", "set_key", "set_paths", "default_paths", "target_paths", "store_content",
           "store_in_sync", "desired_policy", "policy_in_sync", "role_diff", "reconcile_vault", "ensure"]

ESO_KEY = "externalSecrets"
SA_NAME = "external-secrets-vault"
# Namespace and SA of the ESO operator: never bound to an app role
OPERATOR_NS = "external-secrets"
OPERATOR_SA = "external-secrets"
TOKEN_TTL = 600
TOKEN_MAX_TTL = 1800

_PATH_RE = re.compile(r"^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$")
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


def json_file(gitops_path: Path, app: str, env: str) -> Path:
    return gitops_path / "apps" / app / f"{env}.json"


def store_file(gitops_path: Path, ns: str) -> Path:
    return gitops_path / "helm" / "argocd" / "templates" / "external-secrets" / f"{ns}.yaml"


def store_content(ns: str) -> str:
    return (f"# External Secrets: Vault store of namespace {ns} (helper in _helpers.tpl)\n"
            f'{{{{ include "argocd.vaultStore" (dict "ns" "{ns}" "root" $) }}}}\n')


def _code(text: str) -> List[str]:
    return [l.strip() for l in text.splitlines() if l.strip() and not l.lstrip().startswith("#")]


def store_in_sync(text: str, ns: str) -> bool:
    """Comments ignored: an older header does not make the store stale."""
    return _code(text) == _code(store_content(ns))


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


def set_key(text: str, key: str, value) -> str:
    """Set a top-level key in place, leaving the rest of the file byte-identical."""
    value = json.dumps(value, ensure_ascii=False)
    members, close = _members(text)
    for k, _, start, end in members:
        if k == key:
            return text[:start] + value + text[end:]
    if not members:
        return text[:close].rstrip() + f'\n  "{key}": {value}\n' + text[close:]
    first_start = members[0][1]
    indent = text[text.rfind("\n", 0, first_start) + 1:first_start]
    last_end = members[-1][3]
    return text[:last_end] + f',\n{indent}"{key}": {value}' + text[last_end:]


def set_paths(text: str, paths: List[str]) -> str:
    return set_key(text, ESO_KEY, {"paths": paths})


def default_paths(app: str, env: str) -> List[str]:
    return [f"{app}/shared", f"{app}/{env}"]


def check_target(app: str, env: str, paths: List[str]):
    ns = namespace(app, env)
    if ns == OPERATOR_NS:
        raise EsoError(f"namespace {ns} refusé : c'est celui de l'opérateur ESO")
    if not paths:
        raise EsoError("aucun chemin Vault")
    for p in paths:
        if not isinstance(p, str) or not _PATH_RE.match(p) or p.startswith("kv/"):
            raise EsoError(f"chemin invalide {p!r} (chemin KV v2 sans kv/data/, sans joker)")
        # A team only reads its own tree
        if p != app and not p.startswith(f"{app}/"):
            raise EsoError(f"chemin {p} hors de l'arborescence {app}/")


def target_paths(gitops_path: Path, app: str, env: str) -> List[str]:
    """Existing JSON key (never shrunk), else the defaults. Checked."""
    jf = json_file(gitops_path, app, env)
    paths = read_paths(jf.read_text()) if jf.exists() else None
    if paths is None:
        paths = default_paths(app, env)
    check_target(app, env, paths)
    return paths


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


class VaultCtx:
    def __init__(self, addr: str, token: str, verify=True):
        self.base = addr.rstrip("/") + "/v1"
        self.token = token
        self.verify = verify

    def get(self, path: str) -> Optional[dict]:
        try:
            return vault.request("GET", f"{self.base}/{path}", self.token, verify=self.verify)
        except RuntimeError as e:
            if "-> 404" in str(e):
                return None
            raise

    def call(self, method: str, path: str, json=None):
        return vault.request(method, f"{self.base}/{path}", self.token, json=json, verify=self.verify)

    def policy(self, ns: str) -> Optional[str]:
        r = self.get(f"sys/policies/acl/eso-{ns}")
        return r["data"]["policy"] if r else None

    def role(self, ns: str) -> Optional[dict]:
        r = self.get(f"auth/kubernetes/role/eso-{ns}")
        return r["data"] if r else None


def reconcile_vault(ctx: VaultCtx, ns: str, paths: List[str], dry_run: bool = False):
    """Diff then write policy/role eso-<ns>; only the drifted part is written."""
    desired = desired_role(ns)
    _refuse_operator(desired)
    prefix = "[DRY-RUN] " if dry_run else ""
    policy, role = ctx.policy(ns), ctx.role(ns)
    want = desired_policy(paths)

    if policy_in_sync(policy, paths):
        typer.echo(f"[EXISTS] Vault policy eso-{ns}")
    else:
        if policy is None:
            typer.echo("".join(f"    + {l}\n" for l in want.splitlines()), nl=False)
        else:
            for l in difflib.unified_diff(policy.splitlines(), want.splitlines(), "vault", "git", lineterm="", n=1):
                typer.echo(f"    {l}")
        if not dry_run:
            ctx.call("PUT", f"sys/policies/acl/eso-{ns}", json={"policy": want})
        typer.echo(f"{prefix}[{'WRITE' if policy is None else 'UPDATE'}] Vault policy eso-{ns}")

    diff = role_diff(role, desired)
    if not diff:
        typer.echo(f"[EXISTS] Vault role eso-{ns}")
    else:
        if role is not None:
            for field, cur, new in diff:
                typer.echo(f"    {field}: {cur!r} -> {new!r}")
        if not dry_run:
            ctx.call("POST", f"auth/kubernetes/role/eso-{ns}", json=desired)
        typer.echo(f"{prefix}[{'WRITE' if role is None else 'UPDATE'}] Vault role eso-{ns}")


# ---------------------------------------------------------------------------
# create-project step
# ---------------------------------------------------------------------------

def ensure(gitops_path: Path, app: str, env: str, ctx: Optional[VaultCtx], dry_run: bool = False):
    """JSON key (added only if absent), store file, then Vault eso-<ns>. Safe to re-run."""
    ns = namespace(app, env)
    paths = target_paths(gitops_path, app, env)
    prefix = "[DRY-RUN] " if dry_run else ""

    jf = json_file(gitops_path, app, env)
    # Absent only in dry-run: the JSON step then creates it with the key
    if jf.exists():
        text = jf.read_text()
        if read_paths(text) is not None:
            typer.echo(f"[EXISTS] {jf} {ESO_KEY}")
        else:
            if not dry_run:
                jf.write_text(set_paths(text, paths))
            typer.echo(f"{prefix}[WRITE] {jf} {ESO_KEY} : {', '.join(paths)}")

    sf = store_file(gitops_path, ns)
    existed = sf.exists()
    if existed and store_in_sync(sf.read_text(), ns):
        typer.echo(f"[EXISTS] {sf}")
    else:
        if not dry_run:
            sf.parent.mkdir(parents=True, exist_ok=True)
            sf.write_text(store_content(ns))
        typer.echo(f"{prefix}[{'UPDATE' if existed else 'WRITE'}] {sf}")

    if ctx is None:
        typer.echo(f"[INFO] Vault non configuré : rôle/policy eso-{ns} non réconciliés")
    else:
        reconcile_vault(ctx, ns, paths, dry_run=dry_run)
