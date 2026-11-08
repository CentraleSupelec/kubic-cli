import json

import pytest

from kubic_cli import eso, vault

ADDR = "https://vault.test"
SLUG = "demo"
# kv/metadata bodies: a live current version, a soft-deleted one, a destroyed one
LIVE = {"current_version": 1, "versions": {"1": {"deletion_time": "", "destroyed": False}}}
DELETED = {"current_version": 2, "versions": {"1": {"deletion_time": "", "destroyed": False},
                                              "2": {"deletion_time": "2026-01-01T00:00:00Z", "destroyed": False}}}
DESTROYED = {"current_version": 1, "versions": {"1": {"deletion_time": "", "destroyed": True}}}


class FakeResp:
    def __init__(self, status, body=None):
        self.status_code = status
        self.ok = status < 400
        self.text = json.dumps(body) if body is not None else ""

    def json(self):
        return json.loads(self.text)


class FakeVault:
    """Mock of the Vault REST API.

    `data`: {path: body} for paths that exist (GET/LIST -> 200).
    `fail`: {path: status} forces that exact path's GET/LIST to answer with that
    error status (403, 500, ...) instead of 200/404 -- simulates a Vault read
    failing for a reason other than "the object is absent".
    A path neither in `data` nor `fail` answers 404 (genuinely absent).
    """

    def __init__(self, data=None, fail=None):
        self.data = dict(data or {})
        self.fail = dict(fail or {})
        self.calls = []

    def __call__(self, method, url, json=None, headers=None, timeout=None, verify=None):
        path = url.split("/v1/", 1)[1]
        self.calls.append((method, path))
        if path in self.fail:
            return FakeResp(self.fail[path], {"errors": ["boom"]})
        if path.endswith("/role-id"):
            return FakeResp(200, {"data": {"role_id": "new-role-id"}})
        if path.endswith("/secret-id"):
            return FakeResp(200, {"data": {"secret_id": "new-secret-id"}})
        if method in ("GET", "LIST"):
            return FakeResp(200, {"data": self.data[path]}) if path in self.data else FakeResp(404, {"errors": []})
        self.data[path] = dict(json) if json else {}
        return FakeResp(204)

    @property
    def writes(self):
        return [(m, p) for m, p in self.calls if m not in ("GET", "LIST")]


def _fake(monkeypatch, data=None, fail=None):
    fake = FakeVault(data, fail)
    monkeypatch.setattr(vault.requests, "request", fake)
    return fake


def _full_existing_data(avp_role_id="existing-role-id", avp_secret_id="existing-secret-id"):
    """Every object vault.provision looks at already exists: a fully provisioned project."""
    return {
        f"sys/policies/acl/{SLUG}": {"policy": "path \"kv/data/demo/*\" {}"},
        f"auth/approle/role/{SLUG}": {"token_policies": [SLUG]},
        f"kv/data/argocd/avp/{SLUG}": {"role_id": avp_role_id, "secret_id": avp_secret_id},
        f"kv/metadata/argocd/avp/{SLUG}": LIVE,
        f"kv/metadata/{SLUG}": {"keys": ["shared", "prod"]},
        f"kv/data/{SLUG}/shared": {},
        f"kv/metadata/{SLUG}/shared": LIVE,
        f"kv/data/{SLUG}/prod": {},
        f"kv/metadata/{SLUG}/prod": LIVE,
    }


# ---------------------------------------------------------------------------
# 404 -> absent -> create (existing, intended behaviour)
# ---------------------------------------------------------------------------

def test_nothing_exists_creates_policy_approle_and_avp_credentials(monkeypatch):
    fake = _fake(monkeypatch)
    vault.provision(SLUG, ["prod"], ADDR, "t")

    writes = fake.writes
    assert ("PUT", f"sys/policies/acl/{SLUG}") in writes
    assert ("POST", f"auth/approle/role/{SLUG}") in writes
    assert ("PUT", f"kv/data/argocd/avp/{SLUG}") in writes
    assert ("PUT", f"kv/data/{SLUG}/shared") in writes
    assert ("PUT", f"kv/data/{SLUG}/prod") in writes


def test_userpass_absent_creates_user(monkeypatch):
    fake = _fake(monkeypatch, data=_full_existing_data())
    vault.provision(SLUG, ["prod"], ADDR, "t", devs=["alice"])
    assert ("POST", "auth/userpass/users/alice") in fake.writes


# ---------------------------------------------------------------------------
# existing -> no overwrite
# ---------------------------------------------------------------------------

def test_everything_exists_nothing_is_written(monkeypatch):
    fake = _fake(monkeypatch, data=_full_existing_data())
    vault.provision(SLUG, ["prod"], ADDR, "t")
    assert fake.writes == []


def test_approle_and_avp_exist_credentials_are_preserved(monkeypatch):
    """The core regression: AppRole already exists with its AVP credentials ->
    they must never be recreated/overwritten."""
    fake = _fake(monkeypatch, data=_full_existing_data(avp_role_id="keep-me", avp_secret_id="keep-me-too"))
    vault.provision(SLUG, ["prod"], ADDR, "t")
    assert fake.writes == []
    assert fake.data[f"kv/data/argocd/avp/{SLUG}"] == {"role_id": "keep-me", "secret_id": "keep-me-too"}


# ---------------------------------------------------------------------------
# 403 / 500 -> abort, no write at all (the fixed bug)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("status", [403, 500])
def test_policy_check_error_aborts_without_write(monkeypatch, status):
    fake = _fake(monkeypatch, fail={f"sys/policies/acl/{SLUG}": status})
    with pytest.raises(RuntimeError):
        vault.provision(SLUG, ["prod"], ADDR, "t")
    assert fake.writes == []


@pytest.mark.parametrize("status", [403, 500])
def test_approle_check_error_aborts_without_write(monkeypatch, status):
    # Policy already exists so the only pending check is the AppRole one that fails.
    data = {f"sys/policies/acl/{SLUG}": {"policy": "..."}}
    fake = _fake(monkeypatch, data=data, fail={f"auth/approle/role/{SLUG}": status})
    with pytest.raises(RuntimeError):
        vault.provision(SLUG, ["prod"], ADDR, "t")
    assert fake.writes == []


@pytest.mark.parametrize("status", [403, 500])
def test_avp_credentials_check_error_aborts_without_recreating_approle_or_credentials(monkeypatch, status):
    """AppRole exists (200) but the AVP credentials check itself errors out:
    must abort, never silently (re)create the AppRole or overwrite its credentials."""
    data = {
        f"sys/policies/acl/{SLUG}": {"policy": "..."},
        f"auth/approle/role/{SLUG}": {"token_policies": [SLUG]},
    }
    fake = _fake(monkeypatch, data=data, fail={f"kv/metadata/argocd/avp/{SLUG}": status})
    with pytest.raises(RuntimeError):
        vault.provision(SLUG, ["prod"], ADDR, "t")
    assert fake.writes == []


@pytest.mark.parametrize("status", [403, 500])
def test_kv_metadata_list_error_aborts_without_write(monkeypatch, status):
    data = {
        f"sys/policies/acl/{SLUG}": {"policy": "..."},
        f"auth/approle/role/{SLUG}": {"token_policies": [SLUG]},
        f"kv/data/argocd/avp/{SLUG}": {"role_id": "r", "secret_id": "s"},
        f"kv/metadata/argocd/avp/{SLUG}": LIVE,
    }
    fake = _fake(monkeypatch, data=data, fail={f"kv/metadata/{SLUG}": status})
    with pytest.raises(RuntimeError):
        vault.provision(SLUG, ["prod"], ADDR, "t")
    assert fake.writes == []


@pytest.mark.parametrize("status", [403, 500])
def test_kv_env_check_error_aborts_without_write(monkeypatch, status):
    data = {
        f"sys/policies/acl/{SLUG}": {"policy": "..."},
        f"auth/approle/role/{SLUG}": {"token_policies": [SLUG]},
        f"kv/data/argocd/avp/{SLUG}": {"role_id": "r", "secret_id": "s"},
        f"kv/metadata/argocd/avp/{SLUG}": LIVE,
    }
    # "prod" sorts before "shared", so it is checked (and fails) before any write happens
    fake = _fake(monkeypatch, data=data, fail={f"kv/metadata/{SLUG}/prod": status})
    with pytest.raises(RuntimeError):
        vault.provision(SLUG, ["prod"], ADDR, "t")
    assert fake.writes == []


@pytest.mark.parametrize("status", [403, 500])
def test_userpass_check_error_aborts_without_write(monkeypatch, status):
    fake = _fake(monkeypatch, data=_full_existing_data(), fail={"auth/userpass/users/alice": status})
    with pytest.raises(RuntimeError):
        vault.provision(SLUG, ["prod"], ADDR, "t", devs=["alice"])
    assert fake.writes == []


# ---------------------------------------------------------------------------
# KV existence: kv/metadata only, a deleted current version is absent
# ---------------------------------------------------------------------------

def test_kv_existence_never_reads_secret_values(monkeypatch):
    fake = _fake(monkeypatch, data=_full_existing_data())
    vault.provision(SLUG, ["prod"], ADDR, "t", devs=["alice"])
    assert not [c for c in fake.calls if c[1].startswith("kv/data/")]


@pytest.mark.parametrize("meta", [DELETED, DESTROYED])
def test_deleted_avp_credentials_are_recreated(monkeypatch, meta):
    data = dict(_full_existing_data(), **{f"kv/metadata/argocd/avp/{SLUG}": meta})
    fake = _fake(monkeypatch, data=data)
    vault.provision(SLUG, ["prod"], ADDR, "t")
    # A new secret-id of the existing AppRole, stored back; the AppRole itself is not recreated
    assert fake.writes == [("POST", f"auth/approle/role/{SLUG}/secret-id"), ("PUT", f"kv/data/argocd/avp/{SLUG}")]


def test_deleted_kv_env_is_recreated(monkeypatch):
    data = dict(_full_existing_data(), **{f"kv/metadata/{SLUG}/prod": DELETED})
    fake = _fake(monkeypatch, data=data)
    vault.provision(SLUG, ["prod"], ADDR, "t")
    assert fake.writes == [("PUT", f"kv/data/{SLUG}/prod")]


def test_dry_run_and_real_run_agree_on_existence(monkeypatch):
    """Same kv/metadata check in both modes: what the dry-run announces is what the run does."""
    data = dict(_full_existing_data(), **{f"kv/metadata/{SLUG}/prod": DELETED})
    dry = _fake(monkeypatch, data=data)
    vault.provision(SLUG, ["prod"], ADDR, "t", dry_run=True)
    assert dry.writes == []
    real = _fake(monkeypatch, data=data)
    vault.provision(SLUG, ["prod"], ADDR, "t")
    assert [c for c in dry.calls if c[0] in ("GET", "LIST")] == [c for c in real.calls if c[0] in ("GET", "LIST")]
    assert real.writes == [("PUT", f"kv/data/{SLUG}/prod")]


# ---------------------------------------------------------------------------
# Same rule in the ESO step (kubic_cli.eso.VaultCtx / reconcile_vault)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("status", [403, 500])
def test_eso_policy_check_error_aborts_without_write(monkeypatch, status):
    fake = _fake(monkeypatch, fail={"sys/policies/acl/eso-demo-prod": status})
    ctx = eso.VaultCtx(ADDR, "t")
    with pytest.raises(RuntimeError):
        eso.reconcile_vault(ctx, "demo-prod", ["demo/prod"])
    assert fake.writes == []


@pytest.mark.parametrize("status", [403, 500])
def test_eso_kubernetes_role_check_error_aborts_without_write(monkeypatch, status):
    data = {"sys/policies/acl/eso-demo-prod": {"policy": eso.desired_policy(["demo/prod"])}}
    fake = _fake(monkeypatch, data=data, fail={"auth/kubernetes/role/eso-demo-prod": status})
    ctx = eso.VaultCtx(ADDR, "t")
    with pytest.raises(RuntimeError):
        eso.reconcile_vault(ctx, "demo-prod", ["demo/prod"])
    assert fake.writes == []
