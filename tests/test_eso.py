import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from kubic_cli import eso, vault
from kubic_cli.main import app

ADDR = "https://vault.test"
POLICY = 'path "kv/data/demo/shared" {\n  capabilities = ["read"]\n}\npath "kv/data/demo/prod" {\n  capabilities = ["read"]\n}\n'
ROLE = {
    "bound_service_account_names": ["external-secrets-vault"],
    "bound_service_account_namespaces": ["demo-prod"],
    "audience": "vault",
    "token_policies": ["eso-demo-prod"],
    "token_ttl": 600,
    "token_max_ttl": 1800,
    "alias_name_source": "serviceaccount_uid",
}


class FakeResp:
    def __init__(self, status, body=None):
        self.status_code = status
        self.ok = status < 400
        self.text = json.dumps(body) if body is not None else ""

    def json(self):
        return json.loads(self.text)


class FakeVault:
    """Mock of the Vault REST API: {path: data}."""

    def __init__(self, data=None):
        self.data = dict(data or {})
        self.calls = []

    def __call__(self, method, url, json=None, headers=None, timeout=None, verify=None):
        path = url.split("/v1/", 1)[1]
        self.calls.append((method, path))
        if path.startswith("kv/data/"):
            raise AssertionError("secret values must never be read")
        if method == "GET":
            return FakeResp(200, {"data": self.data[path]}) if path in self.data else FakeResp(404, {"errors": []})
        if method in ("PUT", "POST"):
            self.data[path] = dict(json)
        elif method == "DELETE":
            self.data.pop(path, None)
        return FakeResp(204)

    @property
    def writes(self):
        return [c for c in self.calls if c[0] != "GET"]


@pytest.fixture
def gitops(tmp_path: Path) -> Path:
    d = tmp_path / "apps" / "demo"
    d.mkdir(parents=True)
    (d / "prod.json").write_text('{\n  "valuesFiles": ["base.yaml", "prod.yaml"],\n  "project": "demo"\n}\n\n')
    (d / "prod.yaml").write_text('db:\n  password: <path:kv/data/demo/prod#DB_PASSWORD>\n  user: <path:kv/data/demo/shared#DB_USER | base64encode>\n')
    return tmp_path


def _fake(monkeypatch, data=None):
    fake = FakeVault(data)
    monkeypatch.setattr(vault.requests, "request", fake)
    return fake


def _synced():
    return {
        "sys/policies/acl/eso-demo-prod": {"policy": POLICY},
        "auth/kubernetes/role/eso-demo-prod": ROLE,
        "kv/metadata/demo/shared": {},
        "kv/metadata/demo/prod": {},
    }


# ---------------------------------------------------------------------------
# JSON edition
# ---------------------------------------------------------------------------

def test_set_paths_keeps_rest_of_file_byte_identical():
    text = '{\n  "valuesFiles": ["base.yaml", "prod.yaml"],\n  "project": "demo"\n}\n\n'
    out = eso.set_paths(text, ["demo/shared"])
    assert out == '{\n  "valuesFiles": ["base.yaml", "prod.yaml"],\n  "project": "demo",\n  "externalSecrets": {"paths": ["demo/shared"]}\n}\n\n'
    assert eso.set_paths(out, ["demo/shared"]) == out
    assert eso.drop_key(out) == text


def test_set_paths_updates_existing_key_in_place():
    text = '{\n    "externalSecrets": {"paths": ["a"]},\n    "project": "demo"\n}\n'
    out = eso.set_paths(text, ["demo/shared", "demo/prod"])
    assert out == '{\n    "externalSecrets": {"paths": ["demo/shared", "demo/prod"]},\n    "project": "demo"\n}\n'
    assert eso.drop_key(out) == '{\n    "project": "demo"\n}\n'


def test_set_paths_ignores_nested_key_of_same_name():
    text = '{\n  "x": {"externalSecrets": 1}\n}\n'
    out = eso.set_paths(text, ["demo"])
    assert json.loads(out) == {"x": {"externalSecrets": 1}, "externalSecrets": {"paths": ["demo"]}}


def test_namespace_rule():
    assert eso.namespace("demo", "prod") == "demo-prod"
    assert eso.namespace("demo", "demo") == "demo"


# ---------------------------------------------------------------------------
# Proposals, refusals
# ---------------------------------------------------------------------------

def test_proposed_paths_from_avp(gitops):
    assert eso.avp_placeholders(gitops, "demo", "prod") == {"demo/prod": ["DB_PASSWORD"], "demo/shared": ["DB_USER"]}
    assert eso.proposed_paths(gitops, "demo", "prod") == (["demo/prod", "demo/shared"], "avp")


def test_proposed_paths_default(gitops):
    (gitops / "apps" / "demo" / "prod.yaml").write_text("replicas: 1\n")
    assert eso.proposed_paths(gitops, "demo", "prod") == (["demo/shared", "demo/prod"], "default")


@pytest.mark.parametrize("app,env,paths", [
    ("external-secrets", "external-secrets", ["external-secrets/x"]),
    ("demo", "prod", ["other/prod"]),
    ("demo", "prod", ["demo/*"]),
    ("demo", "prod", ["kv/data/demo/prod"]),
    ("demo", "prod", []),
])
def test_check_target_refusals(app, env, paths):
    with pytest.raises(eso.EsoError):
        eso.check_target(app, env, paths)


def test_operator_sa_refused(monkeypatch):
    fake = _fake(monkeypatch)
    monkeypatch.setattr(eso, "SA_NAME", "external-secrets")
    with pytest.raises(eso.EsoError):
        eso.reconcile_vault(eso.VaultCtx(ADDR, "t"), "demo-prod", ["demo/prod"], assume_yes=True)
    assert fake.writes == []


# ---------------------------------------------------------------------------
# Vault diff / idempotency
# ---------------------------------------------------------------------------

def test_policy_compare_is_semantic():
    reordered = '# hand-made\npath "kv/data/demo/prod" { capabilities = ["read"] }\npath "kv/data/demo/shared" {\n capabilities = ["read"]\n}'
    assert eso.policy_in_sync(reordered, ["demo/shared", "demo/prod"])
    assert not eso.policy_in_sync(POLICY + 'path "sys/*" { capabilities = ["sudo"] }\n', ["demo/shared", "demo/prod"])
    assert not eso.policy_in_sync(POLICY.replace('"read"', '"read", "list"', 1), ["demo/shared", "demo/prod"])
    assert not eso.policy_in_sync(POLICY + "# x\nfoo = 1\n", ["demo/shared", "demo/prod"])


def test_role_diff_ignores_extra_fields_and_order():
    assert eso.role_diff(ROLE, eso.desired_role("demo-prod")) == []
    drift = dict(ROLE, token_ttl=3600, bound_service_account_namespaces=["other"])
    assert {d[0] for d in eso.role_diff(drift, eso.desired_role("demo-prod"))} == {"token_ttl", "bound_service_account_namespaces"}


def test_enable_creates_everything_then_is_idempotent(gitops, monkeypatch):
    fake = _fake(monkeypatch)
    ctx = eso.VaultCtx(ADDR, "t")
    eso.enable(gitops, "demo", "prod", ["demo/shared", "demo/prod"], ctx, assume_yes=True)

    data = json.loads((gitops / "apps/demo/prod.json").read_text())
    assert data["externalSecrets"] == {"paths": ["demo/shared", "demo/prod"]}
    assert data["valuesFiles"] == ["base.yaml", "prod.yaml"]
    store = gitops / "helm/argocd/templates/external-secrets/demo-prod.yaml"
    assert store.read_text() == (
        "# CMP-37: Vault store of namespace demo-prod (helper in _helpers.tpl)\n"
        '{{ include "argocd.vaultStore" (dict "ns" "demo-prod" "root" $) }}\n'
    )
    assert fake.data["sys/policies/acl/eso-demo-prod"]["policy"] == POLICY
    assert fake.data["auth/kubernetes/role/eso-demo-prod"] == eso.desired_role("demo-prod")

    before = len(fake.writes)
    json_before = (gitops / "apps/demo/prod.json").read_text()
    eso.enable(gitops, "demo", "prod", None, ctx, assume_yes=True)
    assert len(fake.writes) == before
    assert (gitops / "apps/demo/prod.json").read_text() == json_before


def test_enable_updates_only_drifted_part(gitops, monkeypatch):
    data = _synced()
    data["auth/kubernetes/role/eso-demo-prod"] = dict(ROLE, token_ttl=3600)
    fake = _fake(monkeypatch, data)
    eso.enable(gitops, "demo", "prod", ["demo/shared", "demo/prod"], eso.VaultCtx(ADDR, "t"), assume_yes=True)
    assert fake.writes == [("POST", "auth/kubernetes/role/eso-demo-prod")]


def test_enable_dry_run_writes_nothing(gitops, monkeypatch):
    fake = _fake(monkeypatch)
    before = (gitops / "apps/demo/prod.json").read_text()
    eso.enable(gitops, "demo", "prod", ["demo/prod"], eso.VaultCtx(ADDR, "t"), dry_run=True)
    assert fake.writes == []
    assert (gitops / "apps/demo/prod.json").read_text() == before
    assert not (gitops / "helm").exists()


def test_enable_refusal_writes_nothing(gitops, monkeypatch):
    fake = _fake(monkeypatch)
    before = (gitops / "apps/demo/prod.json").read_text()
    with pytest.raises(eso.EsoError):
        eso.enable(gitops, "demo", "prod", ["other/prod"], eso.VaultCtx(ADDR, "t"), assume_yes=True)
    assert fake.calls == []
    assert (gitops / "apps/demo/prod.json").read_text() == before


def test_enable_vault_needs_confirmation(gitops, monkeypatch):
    fake = _fake(monkeypatch)
    monkeypatch.setattr(eso.typer, "confirm", lambda *a, **k: False)
    with pytest.raises(eso.EsoError):
        eso.enable(gitops, "demo", "prod", ["demo/prod"], eso.VaultCtx(ADDR, "t"))
    assert fake.writes == []


# ---------------------------------------------------------------------------
# CLI: plan / status / disable
# ---------------------------------------------------------------------------

def test_cli_plan_in_sync_is_read_only(gitops, monkeypatch):
    fake = _fake(monkeypatch, _synced())
    eso.enable(gitops, "demo", "prod", ["demo/shared", "demo/prod"], None)
    r = CliRunner().invoke(app, ["eso", "plan", "demo", "--gitops-path", str(gitops), "--vault-addr", ADDR, "--vault-token", "t"])
    assert r.exit_code == 0, r.output
    assert "[EXISTS] Vault policy eso-demo-prod (à jour)" in r.output
    assert "[EXISTS] Vault role eso-demo-prod (à jour)" in r.output
    assert "à jour" in r.output and "[AVP]" in r.output
    assert fake.writes == []
    assert ("GET", "kv/metadata/demo/prod") in fake.calls


def test_cli_plan_shows_diff(gitops, monkeypatch):
    _fake(monkeypatch)
    r = CliRunner().invoke(app, ["eso", "plan", "demo", "--env", "prod", "--gitops-path", str(gitops), "--vault-addr", ADDR, "--vault-token", "t"])
    assert r.exit_code == 0, r.output
    assert "[MISSING] Vault policy eso-demo-prod" in r.output
    assert '+ path "kv/data/demo/prod" {' in r.output


def test_cli_status(gitops, monkeypatch):
    _fake(monkeypatch, _synced())
    eso.enable(gitops, "demo", "prod", ["demo/shared", "demo/prod"], None)
    r = CliRunner().invoke(app, ["eso", "status", "demo", "--gitops-path", str(gitops), "--vault-addr", ADDR, "--vault-token", "t"])
    assert r.exit_code == 0, r.output
    assert "Vault  : sync" in r.output


class FakeKube:
    def __init__(self, names):
        self.names = names

    def external_secrets(self, ns):
        if isinstance(self.names, Exception):
            raise self.names
        return self.names


def test_disable_refuses_with_external_secrets(gitops, monkeypatch):
    fake = _fake(monkeypatch, _synced())
    eso.enable(gitops, "demo", "prod", ["demo/shared", "demo/prod"], None)
    for kube in (FakeKube(["db-eso"]), FakeKube(RuntimeError("403"))):
        with pytest.raises(eso.EsoError):
            eso.disable(gitops, "demo", "prod", eso.VaultCtx(ADDR, "t"), kube, assume_yes=True)
    assert fake.writes == []
    assert "externalSecrets" in (gitops / "apps/demo/prod.json").read_text()


def test_disable_dry_run_then_real(gitops, monkeypatch):
    fake = _fake(monkeypatch, _synced())
    original = (gitops / "apps/demo/prod.json").read_text()
    eso.enable(gitops, "demo", "prod", ["demo/shared", "demo/prod"], None)
    ctx = eso.VaultCtx(ADDR, "t")

    eso.disable(gitops, "demo", "prod", ctx, FakeKube([]), dry_run=True)
    assert fake.writes == []
    assert "externalSecrets" in (gitops / "apps/demo/prod.json").read_text()

    eso.disable(gitops, "demo", "prod", ctx, FakeKube(["x"]), force=True, assume_yes=True)
    assert (gitops / "apps/demo/prod.json").read_text() == original
    assert not (gitops / "helm/argocd/templates/external-secrets/demo-prod.yaml").exists()
    assert set(fake.writes) == {("DELETE", "auth/kubernetes/role/eso-demo-prod"), ("DELETE", "sys/policies/acl/eso-demo-prod")}


def test_create_project_with_eso(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(eso.vault.requests, "request", FakeVault())
    r = CliRunner().invoke(app, ["create-project", "demo", "--repo-url", "git@host:demo.git", "--envs", "prod",
                                 "--gitops-path", str(tmp_path), "--skip-vault", "--eso"])
    assert r.exit_code == 0, r.output
    data = json.loads((tmp_path / "apps/demo/prod.json").read_text())
    assert data["externalSecrets"] == {"paths": ["demo/shared", "demo/prod"]}
    assert (tmp_path / "helm/argocd/templates/external-secrets/demo-prod.yaml").exists()
