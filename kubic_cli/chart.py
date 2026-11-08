"""One-line files of the helm/argocd chart: each one calls a helper of templates/_helpers.tpl."""
import re
from pathlib import Path
from typing import List

import typer

from .tpl import render_yaml

__all__ = ["repository_content", "vault_token_content", "user_content", "user_namespaces", "add_user_namespaces"]

_USER = re.compile(r'(\{\{ include "argocd\.k8sUser" \(dict "name" "[^"]+")( "namespaces" \(list ([^)]*)\))?')


def _quoted(items) -> str:
    return " ".join(f'"{i}"' for i in items)


def repository_content(slug: str, repo_url: str, ssh_host: str) -> str:
    # The helper derives the host of a git@<host>:<path> url; any other form passes it
    host = "" if repo_url.startswith(f"git@{ssh_host}:") else f' "host" "{ssh_host}"'
    return (f"# Argo CD repository of {slug} (helper in _helpers.tpl)\n"
            f'{{{{ include "argocd.repository" (dict "name" "{slug}" "url" "{repo_url}"{host} "root" $) }}}}\n')


def vault_token_content(slug: str) -> str:
    return (f"# AVP credentials of {slug} (helper in _helpers.tpl)\n"
            f'{{{{ include "argocd.vaultToken" (dict "name" "{slug}" "root" $) }}}}\n')


def user_content(user: str, namespaces: List[str]) -> str:
    ns = f' "namespaces" (list {_quoted(namespaces)})' if namespaces else ""
    return (f"# Kubernetes account {user} (helper in _helpers.tpl)\n"
            f'{{{{ include "argocd.k8sUser" (dict "name" "{user}"{ns}) }}}}\n')


def user_namespaces(text: str) -> List[str]:
    """Namespaces of the admin RoleBindings of an account file, one-line or full YAML (older files)."""
    m = _USER.search(text)
    if m:
        return re.findall(r'"([^"]+)"', m.group(3) or "")
    docs = re.split(r"^---\s*$", text, flags=re.M)
    return [ns for d in docs if re.search(r"^kind: RoleBinding\s*$", d, re.M)
            for ns in re.findall(r"^  namespace: (\S+)", d, re.M)]


def add_user_namespaces(path: Path, user: str, namespaces: List[str]) -> List[str]:
    """Give <user> the admin RoleBinding of each namespace it lacks; returns the namespaces added.
    A full YAML file (older or custom account) gets RoleBinding documents appended."""
    text = path.read_text()
    current = user_namespaces(text)
    added = [ns for ns in namespaces if ns not in current]
    if not added:
        return added
    m = _USER.search(text)
    if m:
        text = text[:m.start()] + f'{m.group(1)} "namespaces" (list {_quoted(current + added)})' + text[m.end():]
    else:
        text += "" if text.endswith("\n") else "\n"
        text += "".join("---\n" + render_yaml("k8s-rolebinding.yaml.j2", user=user, namespace=ns).rstrip("\n") + "\n"
                        for ns in added)
    path.write_text(text)
    typer.echo(f"[UPDATE] {path} : RoleBindings {added}")
    return added
