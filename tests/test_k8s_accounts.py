"""k8s-accounts/user-<dev>.yaml carries no endless token; setup-devs issues time-limited TokenRequests."""
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from kubic_cli import cred
from kubic_cli import main as main_mod
from kubic_cli.main import app

TOKEN_SECRET = "kubernetes.io/service-account-token"
USER_FILE = "helm/argocd/templates/k8s-accounts/user-{}.yaml"


def _docs(text: str):
    return [d for d in yaml.safe_load_all(text) if d]


def _assert_sa_and_rolebindings_only(text: str, dev: str, namespaces):
    docs = _docs(text)
    assert TOKEN_SECRET not in text
    assert [d["kind"] for d in docs] == ["ServiceAccount"] + ["RoleBinding"] * len(namespaces)
    assert docs[0]["metadata"]["name"] == dev
    assert sorted(d["metadata"]["namespace"] for d in docs[1:]) == sorted(namespaces)


def _create(gitops_path: Path, *extra):
    return CliRunner().invoke(app, ["create-project", "demo", "--repo-url", "git@host:demo.git",
                                    "--envs", "dev,prod", "--devs", "alice", "--skip-vault",
                                    "--gitops-path", str(gitops_path), *extra])


def test_create_project_new_dev_has_no_token_secret(tmp_path: Path):
    res = _create(tmp_path)
    assert res.exit_code == 0, res.output
    _assert_sa_and_rolebindings_only((tmp_path / USER_FILE.format("alice")).read_text(),
                                     "alice", ["demo-dev", "demo-prod"])


def test_create_project_dry_run_new_dev_has_no_token_secret(tmp_path: Path, monkeypatch):
    planned = {}
    real = main_mod.smart_write

    def spy(path, content, *a, **kw):
        planned[Path(path).name] = content
        return real(path, content, *a, **kw)

    monkeypatch.setattr(main_mod, "smart_write", spy)
    res = _create(tmp_path, "--dry-run")
    assert res.exit_code == 0, res.output
    assert TOKEN_SECRET not in res.output
    assert not (tmp_path / USER_FILE.format("alice")).exists()
    _assert_sa_and_rolebindings_only(planned["user-alice.yaml"], "alice", ["demo-dev", "demo-prod"])


def test_add_dev_new_dev_has_no_token_secret(tmp_path: Path):
    assert _create(tmp_path).exit_code == 0
    res = CliRunner().invoke(app, ["add-dev", "demo", "--devs", "bob", "--skip-vault",
                                   "--gitops-path", str(tmp_path)], input="y\n")
    assert res.exit_code == 0, res.output
    _assert_sa_and_rolebindings_only((tmp_path / USER_FILE.format("bob")).read_text(),
                                     "bob", ["demo-dev", "demo-prod"])


class _Resp:
    ok = True
    status_code = 201

    def json(self):
        return {"status": {"token": "tok"}}


@pytest.fixture
def token_requests(tmp_path: Path, monkeypatch):
    assert _create(tmp_path).exit_code == 0
    calls = []

    def fake_post(url, json=None, **kw):
        calls.append((url, json))
        return _Resp()

    monkeypatch.setattr(main_mod.requests, "post", fake_post)
    monkeypatch.setattr(cred, "_push_secret", lambda *a, **kw: None)
    ca = tmp_path / "ca.crt"
    ca.write_text("CA")

    def run(*extra):
        calls.clear()
        res = CliRunner().invoke(app, ["setup-devs", "demo", "--devs", "alice", "--gitops-path", str(tmp_path),
                                       "--api-server", "https://k8s.test", "--api-token", "admin",
                                       "--cluster-ca", str(ca), *extra])
        return res, [body for url, body in calls if url.endswith("/serviceaccounts/alice/token")]

    return run


def test_setup_devs_token_request_defaults_to_3_months(token_requests):
    res, bodies = token_requests()
    assert res.exit_code == 0, res.output
    assert len(bodies) == 1
    assert bodies[0]["kind"] == "TokenRequest"
    assert bodies[0]["spec"]["expirationSeconds"] == 7776000


def test_setup_devs_custom_duration(token_requests):
    res, bodies = token_requests("--duration", "30d")
    assert res.exit_code == 0, res.output
    assert bodies[0]["spec"]["expirationSeconds"] == 30 * 86400


@pytest.mark.parametrize("bad", ["0", "0h", "", "abc"])
def test_setup_devs_refuses_endless_or_invalid_duration(token_requests, bad):
    res, bodies = token_requests("--duration", bad)
    assert res.exit_code != 0
    assert "--duration" in res.output
    assert bodies == []
