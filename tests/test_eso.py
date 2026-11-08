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
    """Mock of the Vault REST API: {path: data}. strict: any kv/data access fails, read or write
    (existence is checked on kv/metadata, so a read-only run never touches kv/data)."""

    def __init__(self, data=None, strict=True):
        self.data = dict(data or {})
        self.strict = strict
        self.calls = []

    def __call__(self, method, url, json=None, headers=None, timeout=None, verify=None):
        path = url.split("/v1/", 1)[1]
        self.calls.append((method, path))
        if path.startswith("kv/data/") and self.strict:
            raise AssertionError(f"secret value read: {method} {path}")
        if path.endswith("/role-id"):
            return FakeResp(200, {"data": {"role_id": "r"}})
        if path.endswith("/secret-id"):
            return FakeResp(200, {"data": {"secret_id": "s"}})
        if method in ("GET", "LIST"):
            return FakeResp(200, {"data": self.data[path]}) if path in self.data else FakeResp(404, {"errors": []})
        self.data[path] = dict(json)
        if path.startswith("kv/data/"):
            self.data["kv/metadata/" + path[len("kv/data/"):]] = {}
        return FakeResp(204)

    @property
    def writes(self):
        return [c for c in self.calls if c[0] not in ("GET", "LIST")]


@pytest.fixture
def gitops(tmp_path: Path) -> Path:
    d = tmp_path / "apps" / "demo"
    d.mkdir(parents=True)
    (d / "prod.json").write_text('{\n  "valuesFiles": ["base.yaml", "prod.yaml"],\n  "project": "demo"\n}\n\n')
    return tmp_path


def _fake(monkeypatch, data=None, strict=True):
    fake = FakeVault(data, strict)
    monkeypatch.setattr(vault.requests, "request", fake)
    return fake


def _synced():
    return {
        "sys/policies/acl/eso-demo-prod": {"policy": POLICY},
        "auth/kubernetes/role/eso-demo-prod": ROLE,
    }


def _create(gitops_path, *extra):
    return CliRunner().invoke(app, ["create-project", "demo", "--repo-url", "git@host:demo.git", "--envs", "prod",
                                    "--gitops-path", str(gitops_path), *extra])


VAULT_OPTS = ["--vault-addr", ADDR, "--vault-token", "t"]
STORE = "helm/argocd/templates/external-secrets/demo-prod.yaml"


# ---------------------------------------------------------------------------
# JSON edition
# ---------------------------------------------------------------------------

def test_set_paths_keeps_rest_of_file_byte_identical():
    text = '{\n  "valuesFiles": ["base.yaml", "prod.yaml"],\n  "project": "demo"\n}\n\n'
    out = eso.set_paths(text, ["demo/shared"])
    assert out == '{\n  "valuesFiles": ["base.yaml", "prod.yaml"],\n  "project": "demo",\n  "externalSecrets": {"paths": ["demo/shared"]}\n}\n\n'
    assert eso.set_paths(out, ["demo/shared"]) == out


def test_set_paths_updates_existing_key_in_place():
    text = '{\n    "externalSecrets": {"paths": ["a"]},\n    "project": "demo"\n}\n'
    out = eso.set_paths(text, ["demo/shared", "demo/prod"])
    assert out == '{\n    "externalSecrets": {"paths": ["demo/shared", "demo/prod"]},\n    "project": "demo"\n}\n'


def test_set_paths_ignores_nested_key_of_same_name():
    text = '{\n  "x": {"externalSecrets": 1}\n}\n'
    out = eso.set_paths(text, ["demo"])
    assert json.loads(out) == {"x": {"externalSecrets": 1}, "externalSecrets": {"paths": ["demo"]}}


def test_namespace_rule():
    assert eso.namespace("demo", "prod") == "demo-prod"
    assert eso.namespace("demo", "demo") == "demo"


def test_target_paths_default_then_existing_key_kept(gitops):
    assert eso.target_paths(gitops, "demo", "prod") == ["demo/shared", "demo/prod"]
    assert eso.target_paths(gitops, "demo", "staging") == ["demo/shared", "demo/staging"]
    jf = gitops / "apps/demo/prod.json"
    jf.write_text(eso.set_paths(jf.read_text(), ["demo/prod", "demo/prod-db", "demo/shared"]))
    assert eso.target_paths(gitops, "demo", "prod") == ["demo/prod", "demo/prod-db", "demo/shared"]


def test_store_compare_ignores_comments():
    old = '# older header\n{{ include "argocd.vaultStore" (dict "ns" "demo-prod" "root" $) }}\n'
    assert eso.store_in_sync(old, "demo-prod")
    assert eso.store_in_sync(eso.store_content("demo-prod"), "demo-prod")
    assert not eso.store_in_sync(old, "demo-preprod")


# ---------------------------------------------------------------------------
# Refusals
# ---------------------------------------------------------------------------

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
        eso.reconcile_vault(eso.VaultCtx(ADDR, "t"), "demo-prod", ["demo/prod"])
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


def test_ensure_creates_everything_then_is_idempotent(gitops, monkeypatch):
    fake = _fake(monkeypatch)
    ctx = eso.VaultCtx(ADDR, "t")
    eso.ensure(gitops, "demo", "prod", ctx)

    data = json.loads((gitops / "apps/demo/prod.json").read_text())
    assert data["externalSecrets"] == {"paths": ["demo/shared", "demo/prod"]}
    assert data["valuesFiles"] == ["base.yaml", "prod.yaml"]
    assert (gitops / STORE).read_text() == (
        "# External Secrets: Vault store of namespace demo-prod (helper in _helpers.tpl)\n"
        '{{ include "argocd.vaultStore" (dict "ns" "demo-prod" "root" $) }}\n'
    )
    assert fake.data["sys/policies/acl/eso-demo-prod"]["policy"] == POLICY
    assert fake.data["auth/kubernetes/role/eso-demo-prod"] == eso.desired_role("demo-prod")

    before = len(fake.writes)
    json_before = (gitops / "apps/demo/prod.json").read_text()
    eso.ensure(gitops, "demo", "prod", ctx)
    assert len(fake.writes) == before
    assert (gitops / "apps/demo/prod.json").read_text() == json_before


def test_ensure_updates_only_drifted_part(gitops, monkeypatch):
    data = _synced()
    data["auth/kubernetes/role/eso-demo-prod"] = dict(ROLE, token_ttl=3600)
    fake = _fake(monkeypatch, data)
    eso.ensure(gitops, "demo", "prod", eso.VaultCtx(ADDR, "t"))
    assert fake.writes == [("POST", "auth/kubernetes/role/eso-demo-prod")]


def test_ensure_never_shrinks_existing_key(gitops, monkeypatch):
    jf = gitops / "apps/demo/prod.json"
    jf.write_text(eso.set_paths(jf.read_text(), ["demo/prod", "demo/prod-db"]))
    before = jf.read_text()
    fake = _fake(monkeypatch)
    eso.ensure(gitops, "demo", "prod", eso.VaultCtx(ADDR, "t"))
    assert jf.read_text() == before
    assert fake.data["sys/policies/acl/eso-demo-prod"]["policy"] == eso.desired_policy(["demo/prod", "demo/prod-db"])


def test_ensure_keeps_store_with_older_header(gitops, monkeypatch):
    store = gitops / STORE
    store.parent.mkdir(parents=True)
    old = '# older header\n{{ include "argocd.vaultStore" (dict "ns" "demo-prod" "root" $) }}\n'
    store.write_text(old)
    _fake(monkeypatch, _synced())
    eso.ensure(gitops, "demo", "prod", None)
    assert store.read_text() == old


def test_ensure_dry_run_writes_nothing(gitops, monkeypatch):
    fake = _fake(monkeypatch)
    before = (gitops / "apps/demo/prod.json").read_text()
    eso.ensure(gitops, "demo", "prod", eso.VaultCtx(ADDR, "t"), dry_run=True)
    assert fake.writes == []
    assert (gitops / "apps/demo/prod.json").read_text() == before
    assert not (gitops / "helm").exists()


# ---------------------------------------------------------------------------
# create-project: ESO by default, safe to re-run
# ---------------------------------------------------------------------------

def test_create_project_enables_eso_by_default(tmp_path: Path, monkeypatch):
    fake = _fake(monkeypatch, strict=False)
    r = _create(tmp_path, *VAULT_OPTS)
    assert r.exit_code == 0, r.output
    data = json.loads((tmp_path / "apps/demo/prod.json").read_text())
    assert data["externalSecrets"] == {"paths": ["demo/shared", "demo/prod"]}
    assert data["valuesFiles"] == ["base.yaml", "prod.yaml"]
    assert (tmp_path / STORE).read_text() == eso.store_content("demo-prod")
    assert fake.data["sys/policies/acl/eso-demo-prod"]["policy"] == POLICY
    assert fake.data["auth/kubernetes/role/eso-demo-prod"] == eso.desired_role("demo-prod")

    # Second run: nothing written, in Git or in Vault
    files = {p: p.read_text() for p in tmp_path.rglob("*") if p.is_file()}
    writes = len(fake.writes)
    r = _create(tmp_path, *VAULT_OPTS)
    assert r.exit_code == 0, r.output
    assert len(fake.writes) == writes
    assert {p: p.read_text() for p in tmp_path.rglob("*") if p.is_file()} == files
    assert "[WRITE]" not in r.output and "[UPDATE]" not in r.output


def test_create_project_migrates_existing_app(gitops, monkeypatch):
    fake = _fake(monkeypatch, {"sys/policies/acl/demo": {}, "auth/approle/role/demo": {}, "kv/metadata/argocd/avp/demo": {},
                               "kv/metadata/demo": {"keys": ["prod", "shared"]},
                               "kv/metadata/demo/prod": {}, "kv/metadata/demo/shared": {}}, strict=True)
    jf = gitops / "apps/demo/prod.json"
    original = jf.read_text()
    r = _create(gitops, *VAULT_OPTS)
    assert r.exit_code == 0, r.output
    # Only the key is added; valuesFiles and the rest stay byte-identical
    assert jf.read_text() == eso.set_paths(original, ["demo/shared", "demo/prod"])
    assert "[SKIP]" in r.output
    assert {p for _, p in fake.writes} == {"sys/policies/acl/eso-demo-prod", "auth/kubernetes/role/eso-demo-prod"}


def test_create_project_dry_run_writes_nothing(tmp_path: Path, monkeypatch):
    fake = _fake(monkeypatch, strict=True)
    r = _create(tmp_path, *VAULT_OPTS, "--devs", "alice", "--dry-run")
    assert r.exit_code == 0, r.output
    assert fake.writes == []
    assert not any(tmp_path.rglob("*"))
    assert "[DRY-RUN] [WRITE] Vault policy eso-demo-prod" in r.output
    assert "AppRole demo" not in r.output.replace("Mode ESO : AppRole demo", "")


def test_create_project_dry_run_on_synced_project(tmp_path: Path, monkeypatch):
    fake = _fake(monkeypatch, strict=False)
    assert _create(tmp_path, *VAULT_OPTS).exit_code == 0
    fake.strict = True
    writes = len(fake.writes)
    r = _create(tmp_path, *VAULT_OPTS, "--dry-run")
    assert r.exit_code == 0, r.output
    assert len(fake.writes) == writes
    assert "[DRY-RUN]" not in r.output.replace("Dry-run", "")


def test_create_project_refuses_before_writing(gitops, monkeypatch):
    fake = _fake(monkeypatch)
    jf = gitops / "apps/demo/prod.json"
    jf.write_text(eso.set_paths(jf.read_text(), ["other/prod"]))
    r = _create(gitops, *VAULT_OPTS)
    assert r.exit_code == 1
    assert fake.calls == []
    assert not (gitops / "helm").exists()


def test_create_project_refuses_operator_namespace(tmp_path: Path, monkeypatch):
    fake = _fake(monkeypatch)
    r = CliRunner().invoke(app, ["create-project", "external-secrets", "--repo-url", "git@host:x.git",
                                 "--envs", "external-secrets", "--gitops-path", str(tmp_path), *VAULT_OPTS])
    assert r.exit_code == 1
    assert fake.calls == [] and not any(tmp_path.rglob("*"))


# ---------------------------------------------------------------------------
# --eso (default) / --avp
# ---------------------------------------------------------------------------

TOKEN_FILE = "helm/argocd/templates/vault/vault-token-demo.yaml"
AVP_PATHS = ("auth/approle/", "kv/data/argocd/avp/", "kv/metadata/argocd/avp/")


def _files(root: Path):
    return {p: p.read_text() for p in root.rglob("*") if p.is_file()}


def test_eso_new_project_has_no_avp_piece(tmp_path: Path, monkeypatch):
    fake = _fake(monkeypatch, strict=False)
    r = _create(tmp_path, *VAULT_OPTS, "--eso")
    assert r.exit_code == 0, r.output
    data = json.loads((tmp_path / "apps/demo/prod.json").read_text())
    assert "vaultCredentials" not in data
    assert data["externalSecrets"] == {"paths": ["demo/shared", "demo/prod"]}
    assert not (tmp_path / TOKEN_FILE).exists()
    assert not [c for c in fake.calls if c[1].startswith(AVP_PATHS)]
    assert (tmp_path / STORE).exists()
    assert "auth/kubernetes/role/eso-demo-prod" in fake.data


def test_avp_new_project_is_old_model_without_eso(tmp_path: Path, monkeypatch):
    fake = _fake(monkeypatch, strict=False)
    r = _create(tmp_path, *VAULT_OPTS, "--avp")
    assert r.exit_code == 0, r.output
    jf = tmp_path / "apps/demo/prod.json"
    assert json.loads(jf.read_text()) == {
        "valuesFiles": ["base.yaml", "prod.yaml"], "externalRepoURL": "git@host:demo.git",
        "vaultCredentials": "vault-token-demo", "project": "demo", "_generated_by": "kubic-cli"}
    assert (tmp_path / TOKEN_FILE).exists()
    assert {"auth/approle/role/demo", "kv/data/argocd/avp/demo"} <= {p for _, p in fake.writes}
    assert not (tmp_path / "helm/argocd/templates/external-secrets").exists()
    assert not [c for c in fake.calls if "eso-" in c[1]]


def test_eso_rerun_on_avp_project_keeps_avp(tmp_path: Path, monkeypatch):
    fake = _fake(monkeypatch, strict=False)
    assert _create(tmp_path, *VAULT_OPTS, "--avp").exit_code == 0
    token_file = (tmp_path / TOKEN_FILE).read_text()
    avp_state = {k: v for k, v in fake.data.items() if k.startswith(AVP_PATHS)}
    n = len(fake.calls)
    r = _create(tmp_path, *VAULT_OPTS)
    assert r.exit_code == 0, r.output
    data = json.loads((tmp_path / "apps/demo/prod.json").read_text())
    assert data["vaultCredentials"] == "vault-token-demo"
    assert data["externalSecrets"] == {"paths": ["demo/shared", "demo/prod"]}
    assert (tmp_path / TOKEN_FILE).read_text() == token_file
    assert {k: v for k, v in fake.data.items() if k.startswith(AVP_PATHS)} == avp_state
    assert not [c for c in fake.calls[n:] if c[1].startswith(AVP_PATHS) or c[0] == "DELETE"]


def test_avp_rerun_on_eso_project_keeps_eso(tmp_path: Path, monkeypatch):
    fake = _fake(monkeypatch, strict=False)
    assert _create(tmp_path, *VAULT_OPTS).exit_code == 0
    store = (tmp_path / STORE).read_text()
    eso_state = {k: v for k, v in fake.data.items() if "eso-" in k}
    n = len(fake.calls)
    r = _create(tmp_path, *VAULT_OPTS, "--avp")
    assert r.exit_code == 0, r.output
    jf = tmp_path / "apps/demo/prod.json"
    data = json.loads(jf.read_text())
    assert data["externalSecrets"] == {"paths": ["demo/shared", "demo/prod"]}
    assert data["vaultCredentials"] == "vault-token-demo"
    assert (tmp_path / STORE).read_text() == store
    assert {k: v for k, v in fake.data.items() if "eso-" in k} == eso_state
    assert not [c for c in fake.calls[n:] if "eso-" in c[1] or c[0] == "DELETE"]
    assert (tmp_path / TOKEN_FILE).exists()
    # Third run: nothing more to add
    files = _files(tmp_path)
    assert _create(tmp_path, *VAULT_OPTS, "--avp").exit_code == 0
    assert _files(tmp_path) == files


def _add_env(gitops_path, *extra):
    return CliRunner().invoke(app, ["add-environment", "demo", "--envs", "preprod",
                                    "--gitops-path", str(gitops_path), *VAULT_OPTS, *extra])


@pytest.mark.parametrize("flag", ["--eso", "--avp"])
def test_add_environment_follows_mode(tmp_path: Path, monkeypatch, flag):
    fake = _fake(monkeypatch, strict=False)
    assert _create(tmp_path, *VAULT_OPTS, flag).exit_code == 0
    n = len(fake.calls)
    r = _add_env(tmp_path, flag)
    assert r.exit_code == 0, r.output
    data = json.loads((tmp_path / "apps/demo/preprod.json").read_text())
    store = tmp_path / "helm/argocd/templates/external-secrets/demo-preprod.yaml"
    if flag == "--eso":
        assert "vaultCredentials" not in data and data["externalSecrets"]["paths"] == ["demo/shared", "demo/preprod"]
        assert store.exists() and "auth/kubernetes/role/eso-demo-preprod" in fake.data
        assert not [c for c in fake.calls[n:] if c[1].startswith(AVP_PATHS)]
    else:
        assert data["vaultCredentials"] == "vault-token-demo" and "externalSecrets" not in data
        assert not store.exists() and not [c for c in fake.calls[n:] if "eso-" in c[1]]


def test_add_environment_eso_warns_on_avp_project(tmp_path: Path, monkeypatch):
    _fake(monkeypatch, strict=False)
    assert _create(tmp_path, *VAULT_OPTS, "--avp").exit_code == 0
    r = _add_env(tmp_path, "--eso")  # explicit: the default follows the project mode
    assert r.exit_code == 0, r.output
    assert "[WARN] Projet existant en AVP" in r.output


@pytest.mark.parametrize("flag", ["--eso", "--avp"])
def test_add_environment_default_follows_project_mode(tmp_path: Path, monkeypatch, flag):
    """No --eso/--avp: a new environment keeps the secret model of the project."""
    fake = _fake(monkeypatch, strict=False)
    assert _create(tmp_path, *VAULT_OPTS, flag).exit_code == 0
    n = len(fake.calls)
    r = _add_env(tmp_path)
    assert r.exit_code == 0, r.output
    assert "[INFO] Mode détecté" in r.output and "[WARN] Projet existant" not in r.output
    data = json.loads((tmp_path / "apps/demo/preprod.json").read_text())
    if flag == "--eso":
        assert "vaultCredentials" not in data and "externalSecrets" in data
        assert not [c for c in fake.calls[n:] if c[1].startswith(AVP_PATHS)]
    else:
        assert data["vaultCredentials"] == "vault-token-demo" and "externalSecrets" not in data
        assert not [c for c in fake.calls[n:] if "eso-" in c[1]]


def _add_dev(gitops_path):
    return CliRunner().invoke(app, ["add-dev", "demo", "--devs", "charlie", "--gitops-path", str(gitops_path), *VAULT_OPTS],
                              input="y\n")


@pytest.mark.parametrize("flag", ["--eso", "--avp"])
def test_add_dev_follows_project_mode(tmp_path: Path, monkeypatch, flag):
    """add-dev on an ESO project must not provision the AppRole / kv/argocd/avp of the AVP model."""
    fake = _fake(monkeypatch, strict=False)
    assert _create(tmp_path, *VAULT_OPTS, flag).exit_code == 0
    n = len(fake.calls)
    r = _add_dev(tmp_path)
    assert r.exit_code == 0, r.output
    assert ("POST", "auth/userpass/users/charlie") in fake.calls[n:]
    avp_calls = [c for c in fake.calls[n:] if c[1].startswith(AVP_PATHS)]
    if flag == "--eso":
        assert avp_calls == []
        assert "auth/approle/role/demo" not in fake.data
    else:
        assert avp_calls and not [c for c in avp_calls if c[0] not in ("GET", "LIST")]  # existing AVP only checked


# ---------------------------------------------------------------------------
# JSON edition: file shapes
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text", [
    '{}\n',
    '{ "a": 1 }',
    '{"valuesFiles": ["base.yaml"], "project": "x"}\n',
    '{"a": 1,\n  "b": 2\n}\n',
    '{\n\t"a": 1\n}\n',
])
def test_set_key_keeps_any_file_shape_parsable(text):
    out = eso.set_paths(text, ["x/shared"])
    data = json.loads(out)
    assert data["externalSecrets"] == {"paths": ["x/shared"]}
    assert {k: v for k, v in data.items() if k != "externalSecrets"} == json.loads(text)


def test_set_key_compact_file_gets_no_brace_in_indent():
    assert eso.set_paths('{ "a": 1 }', ["x"]) == '{ "a": 1,\n "externalSecrets": {"paths": ["x"]} }'
