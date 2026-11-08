"""Data files of the helm/argocd chart: plain YAML, one per entity, rendered by the chart helpers
(argocd.repository, argocd.vaultToken, argocd.k8sUser in templates/_helpers.tpl)."""
from pathlib import Path
from typing import List

import typer
import yaml

from .tpl import render_yaml

__all__ = ["CHART", "dump", "repository_data", "vault_token_data", "user_data", "data_file", "user_file", "user_files",
           "user_namespaces", "add_user_namespaces"]

CHART = Path("helm") / "argocd"
LEGACY_ACCOUNTS = CHART / "templates" / "k8s-accounts"


class _Dumper(yaml.SafeDumper):
    """Lists indented under their key."""
    def increase_indent(self, flow=False, indentless=False):
        return super().increase_indent(flow, False)


def dump(data: dict) -> str:
    """Stable output: keys in insertion order, block style."""
    return yaml.dump(data, Dumper=_Dumper, sort_keys=False, default_flow_style=False)


def repository_data(slug: str, repo_url: str, ssh_host: str) -> dict:
    data = {"name": slug, "url": repo_url}
    # The helper derives the host of a git@<host>:<path> url; any other form passes it
    if not repo_url.startswith(f"git@{ssh_host}:"):
        data["host"] = ssh_host
    return data


def vault_token_data(slug: str) -> dict:
    return {"name": slug}


def user_data(user: str, namespaces: List[str]) -> dict:
    return {"name": user, "namespaces": list(namespaces)} if namespaces else {"name": user}


def data_file(gitops_path: Path, data_dir: str, name: str, legacy: str) -> Path:
    """<chart>/<data_dir>/<name>.yaml, or the older full YAML file <chart>/templates/<legacy> when it exists."""
    old = gitops_path / CHART / "templates" / legacy
    return old if old.exists() else gitops_path / CHART / data_dir / f"{name}.yaml"


def user_file(gitops_path: Path, dev: str) -> Path:
    return data_file(gitops_path, "users", dev, f"k8s-accounts/user-{dev}.yaml")


def user_files(gitops_path: Path) -> dict:
    """{dev: path} of every account file, data or older full YAML."""
    files = {p.stem[len("user-"):]: p for p in (gitops_path / LEGACY_ACCOUNTS).glob("user-*.yaml")}
    files.update({p.stem: p for p in (gitops_path / CHART / "users").glob("*.yaml")})
    return files


def _is_data(path: Path) -> bool:
    return path.parent.name == "users"


def user_namespaces(path: Path) -> List[str]:
    """Namespaces of the admin RoleBindings of an account file."""
    if _is_data(path):
        return list((yaml.safe_load(path.read_text()) or {}).get("namespaces") or [])
    return [d["metadata"]["namespace"] for d in yaml.safe_load_all(path.read_text())
            if isinstance(d, dict) and d.get("kind") == "RoleBinding" and "namespace" in d.get("metadata", {})]


def add_user_namespaces(path: Path, user: str, namespaces: List[str]) -> List[str]:
    """Give <user> the admin RoleBinding of each namespace it lacks; returns the namespaces added.
    An older full YAML file gets RoleBinding documents appended."""
    current = user_namespaces(path)
    added = [ns for ns in namespaces if ns not in current]
    if not added:
        return added
    text = path.read_text()
    if _is_data(path):
        data = yaml.safe_load(text) or {"name": user}
        data["namespaces"] = current + added
        text = dump(data)
    else:
        text += "" if text.endswith("\n") else "\n"
        text += "".join("---\n" + render_yaml("k8s-rolebinding.yaml.j2", user=user, namespace=ns).rstrip("\n") + "\n"
                        for ns in added)
    path.write_text(text)
    typer.echo(f"[UPDATE] {path} : RoleBindings {added}")
    return added
