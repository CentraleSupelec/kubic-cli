from json import loads

import pytest
from typer.testing import CliRunner

from kubic_cli import cred, harbor
from kubic_cli.main import app
from tests.test_vault import FakeResp, FakeVault

URL = "https://registry.test"
SLUG = "demo"


class FakeHarbor:
    """Mock of the Harbor REST API /api/v2.0: projects, robots, users, project members.

    `fail`: {path: status} forces every call on that exact path to answer that error status,
    {(method, path): status} only the calls of that method.
    """

    def __init__(self, *, projects=(), robots=(), users=(), members=None, fail=None, prefix="robot$"):
        self.prefix = prefix
        self.projects = {name: {"project_id": i + 1, "name": name} for i, name in enumerate(projects)}
        self.robots = [{"name": f"{prefix}{ns}+{short}", "project_id": self.projects[ns]["project_id"]}
                       for ns, short in robots]
        self.users = [{"username": u} for u in users]
        self.members = {p: [{"entity_name": n, "role_id": r} for n, r in m] for p, m in (members or {}).items()}
        self.fail = dict(fail or {})
        self.calls = []

    def __call__(self, method, url, *, json=None, params=None, auth=None, headers=None, timeout=None, verify=None):
        path = url.split("/api/v2.0/", 1)[1]
        self.calls.append((method, path, params, json))
        status = self.fail.get((method, path), self.fail.get(path))
        if status:
            return FakeResp(status, {"errors": [{"message": "boom"}]})
        return getattr(self, f"_{method.lower()}")(path, params or {}, json)

    def _get(self, path, params, _body):
        parts = path.split("/")
        if parts[0] == "projects" and len(parts) == 2:
            project = self.projects.get(parts[1])
            return FakeResp(200, project) if project else FakeResp(404, {"errors": []})
        if parts[0] == "projects" and parts[2] == "members":
            found = [m for m in self.members.get(parts[1], []) if params.get("entityname", "") in m["entity_name"]]
            return FakeResp(200, found[:params.get("page_size", 10)])
        if path == "robots":
            pid = int(params["q"].split("ProjectID=")[1])
            return FakeResp(200, [r for r in self.robots if r["project_id"] == pid])
        if path == "users":
            login = params["q"].split("username=")[1]
            return FakeResp(200, [u for u in self.users if u["username"] == login])
        raise AssertionError(f"unexpected GET {path}")

    def _post(self, path, _params, body):
        if path == "projects":
            self.projects[body["project_name"]] = {"project_id": len(self.projects) + 1, "name": body["project_name"]}
            return FakeResp(201)
        if path == "robots":
            ns = body["permissions"][0]["namespace"]
            name = f"{self.prefix}{ns}+{body['name']}"
            self.robots.append({"name": name, "project_id": self.projects[ns]["project_id"]})
            return FakeResp(201, {"id": len(self.robots), "name": name, "secret": f"secret-{body['name']}"})
        if path == "users":
            self.users.append({"username": body["username"]})
            return FakeResp(201)
        if path.endswith("/members"):
            project = path.split("/")[1]
            entry = {"entity_name": body["member_user"]["username"], "role_id": body["role_id"]}
            self.members.setdefault(project, []).append(entry)
            return FakeResp(201)
        raise AssertionError(f"unexpected POST {path}")

    @property
    def writes(self):
        return [c for c in self.calls if c[0] != "GET"]


def _fake(monkeypatch, **state):
    fake = FakeHarbor(**state)
    monkeypatch.setattr(harbor.requests, "request", fake)
    return fake


@pytest.fixture(autouse=True, name="creds")
def creds_fixture():
    cred._CREDS.clear()
    yield cred._CREDS
    cred._CREDS.clear()


def _fakes(monkeypatch, vault_data=None, **state):
    fake_harbor, fake_vault = FakeHarbor(**state), FakeVault(vault_data)

    def route(method, url, **kwargs):
        return (fake_vault if "/v1/" in url else fake_harbor)(method, url, **kwargs)

    monkeypatch.setattr(harbor.requests, "request", route)
    return fake_harbor, fake_vault


def _client():
    return harbor.Harbor(URL, "admin", "admin-pass")


@pytest.mark.parametrize("status", [401, 403, 500])
def test_project_read_error_aborts_without_write(monkeypatch, status):
    fake = _fake(monkeypatch, fail={f"projects/{SLUG}": status})
    with pytest.raises(RuntimeError):
        harbor.provision(_client(), SLUG)
    assert fake.writes == []


def test_absent_project_is_created_private(monkeypatch):
    fake = _fake(monkeypatch)
    harbor.provision(_client(), SLUG)
    assert ("POST", "projects", None, {"project_name": SLUG, "metadata": {"public": "false"}}) in fake.writes


def test_existing_project_is_not_recreated(monkeypatch):
    fake = _fake(monkeypatch, projects=[SLUG])
    harbor.provision(_client(), SLUG)
    assert not [c for c in fake.writes if c[1] == "projects"]


def _robot_body(short, actions):
    return {"name": short, "duration": -1, "level": "project",
            "permissions": [{"kind": "project", "namespace": SLUG,
                             "access": [{"resource": "repository", "action": a} for a in actions]}]}


def test_robots_are_created_with_exact_permissions_and_no_expiry(monkeypatch):
    fake = _fake(monkeypatch)
    harbor.provision(_client(), SLUG)
    assert [c[3] for c in fake.writes if c[1] == "robots"] == [
        _robot_body("gitlab-ci", ["pull", "push"]),
        _robot_body("k8s", ["pull"]),
    ]


def test_robot_name_is_read_from_response_and_secret_collected(monkeypatch, creds):
    _fake(monkeypatch, prefix="bot_")
    harbor.provision(_client(), SLUG)
    assert [(c["service"], c["login"], c["secret"]) for c in creds] == [
        ("harbor", "bot_demo+gitlab-ci", "secret-gitlab-ci"),
        ("harbor", "bot_demo+k8s", "secret-k8s"),
    ]


def test_existing_robot_is_neither_rewritten_nor_collected(monkeypatch, creds):
    fake = _fake(monkeypatch, projects=[SLUG], robots=[(SLUG, "k8s")])
    harbor.provision(_client(), SLUG)
    assert [c[3]["name"] for c in fake.writes if c[1].startswith("robots")] == ["gitlab-ci"]
    assert [c["login"] for c in creds] == ["robot$demo+gitlab-ci"]


def test_generated_password_meets_harbor_policy():
    for _ in range(300):
        pwd = harbor.gen_password()
        assert len(pwd) >= 8
        assert any(c.isupper() for c in pwd) and any(c.islower() for c in pwd) and any(c.isdigit() for c in pwd)


def test_absent_dev_gets_user_with_conf_email_and_project_admin_membership(monkeypatch, creds):
    fake = _fake(monkeypatch, projects=[SLUG], robots=[(SLUG, "gitlab-ci"), (SLUG, "k8s")])
    harbor.provision(_client(), SLUG, devs=["jdoe"], email_domain="example.test")
    pwd = next(c["secret"] for c in creds if c["login"] == "jdoe")
    assert fake.writes == [
        ("POST", "users", None, {"username": "jdoe", "email": "jdoe@example.test", "realname": "jdoe", "password": pwd}),
        ("POST", f"projects/{SLUG}/members", None, {"role_id": 1, "member_user": {"username": "jdoe"}}),
    ]


def test_existing_user_keeps_password_and_gets_no_credential(monkeypatch, creds):
    fake = _fake(monkeypatch, projects=[SLUG], robots=[(SLUG, "gitlab-ci"), (SLUG, "k8s")], users=["jdoe"])
    harbor.provision(_client(), SLUG, devs=["jdoe"], email_domain="example.test")
    assert not [c for c in fake.writes if c[1] == "users"]
    assert creds == []


def test_existing_member_keeps_its_role(monkeypatch):
    fake = _fake(monkeypatch, projects=[SLUG], robots=[(SLUG, "gitlab-ci"), (SLUG, "k8s")], users=["jdoe"],
                 members={SLUG: [("jdoe", 3)]})
    harbor.provision(_client(), SLUG, devs=["jdoe"], email_domain="example.test")
    assert fake.writes == []
    assert fake.members[SLUG] == [{"entity_name": "jdoe", "role_id": 3}]


def test_users_only_provisioning_creates_missing_project_but_no_robot(monkeypatch):
    fake = _fake(monkeypatch)
    harbor.provision_users(_client(), SLUG, ["jdoe"], "example.test")
    assert [c[1] for c in fake.writes] == ["projects", "users", f"projects/{SLUG}/members"]
    assert not [c for c in fake.calls if c[1] == "robots"]


def test_dry_run_writes_nothing_and_collects_nothing(monkeypatch, creds):
    fake = _fake(monkeypatch)
    harbor.provision(harbor.Harbor(URL, "admin", "admin-pass", dry_run=True), SLUG, devs=["jdoe"], email_domain="example.test")
    assert fake.writes == []
    assert creds == []


VAULT = "https://vault.test"
SHARED = f"kv/data/{SLUG}/shared"


def test_new_k8s_robot_is_merged_as_dockerconfigjson_into_shared(monkeypatch):
    _, fake_vault = _fakes(monkeypatch, vault_data={SHARED: {"data": {"DB_URL": "postgres://db.test/demo"},
                                                             "metadata": {"version": 2}}})
    client = _client()
    robot = harbor.provision(client, SLUG)
    harbor.publish_pull_secret(client, SLUG, robot, VAULT, "t")
    written = fake_vault.data[SHARED]["data"]
    assert written["DB_URL"] == "postgres://db.test/demo"
    assert "dockerconfigjson" in written
    assert loads(written["dockerconfigjson"]) == {"auths": {"registry.test": {"auth": "cm9ib3QkZGVtbytrOHM6c2VjcmV0LWs4cw=="}}}


NEW_K8S = {"name": "robot$demo+k8s", "secret": "secret-k8s"}


@pytest.mark.parametrize("robot, addr, token, dry_run", [
    (None, VAULT, "t", False),
    (NEW_K8S, None, None, False),
    (None, VAULT, "t", True),
])
def test_pull_secret_is_not_written_without_new_robot_or_vault_or_in_dry_run(monkeypatch, capsys, *, robot, addr, token,
                                                                           dry_run):
    _, fake_vault = _fakes(monkeypatch)
    client = harbor.Harbor(URL, "admin", "admin-pass", dry_run=dry_run)
    harbor.publish_pull_secret(client, SLUG, robot, addr, token)
    assert not fake_vault.calls
    assert "dockerconfigjson" in capsys.readouterr().out


@pytest.fixture(name="cli_env")
def cli_env_fixture(monkeypatch):
    for var in ("HARBOR_URL", "HARBOR_USER", "HARBOR_PASSWORD", "VAULT_ADDR", "VAULT_TOKEN", "KUBE_API", "KUBE_API_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(cred, "_push_secret", lambda payload: None)
    monkeypatch.setattr("kubic_cli.main.HARBOR_EMAIL_DOMAIN", "example.test")


@pytest.mark.usefixtures("cli_env")
@pytest.mark.parametrize("command", ["create", "add-dev"])
def test_cli_harbor_users_without_email_domain_stops_before_any_write(tmp_path, monkeypatch, command):
    fake_harbor, fake_vault = _fakes(monkeypatch)
    if command == "add-dev":
        assert _create(tmp_path).exit_code == 0
    monkeypatch.setattr("kubic_cli.main.HARBOR_EMAIL_DOMAIN", "")
    run = _create if command == "create" else _add_dev
    r = run(tmp_path, *HARBOR_OPTS, "--harbor-users",
            "--vault-addr", VAULT, "--vault-token", "t")
    assert r.exit_code == 1, r.output
    assert "harbor_email_domain" in r.output
    assert not fake_harbor.calls
    assert not fake_vault.calls


HARBOR_OPTS = ["--harbor-url", URL, "--harbor-user", "admin", "--harbor-password", "admin-pass"]


def _create(gitops_path, *extra):
    return CliRunner().invoke(app, ["create-project", SLUG, "--repo-url", "git@host:demo.git", "--envs", "prod",
                                    "--devs", "jdoe", "--gitops-path", str(gitops_path), *extra])


@pytest.mark.usefixtures("cli_env")
def test_cli_without_harbor_config_makes_no_harbor_call(tmp_path, monkeypatch):
    fake_harbor, _ = _fakes(monkeypatch)
    r = _create(tmp_path)
    assert r.exit_code == 0, r.output
    assert not fake_harbor.calls
    assert "[INFO] Harbor non configuré" in r.output


@pytest.mark.usefixtures("cli_env")
def test_cli_configured_creates_project_and_robots_but_no_user_without_flag(tmp_path, monkeypatch):
    fake_harbor, _ = _fakes(monkeypatch)
    r = _create(tmp_path, *HARBOR_OPTS)
    assert r.exit_code == 0, r.output
    assert [c[1] for c in fake_harbor.writes] == ["projects", "robots", "robots"]
    assert not [c for c in fake_harbor.calls if c[1] == "users" or c[1].endswith("/members")]


@pytest.mark.usefixtures("cli_env")
def test_cli_harbor_users_flag_creates_dev_account_with_configured_domain(tmp_path, monkeypatch):
    fake_harbor, _ = _fakes(monkeypatch)
    r = _create(tmp_path, *HARBOR_OPTS, "--harbor-users")
    assert r.exit_code == 0, r.output
    users = [c[3] for c in fake_harbor.writes if c[1] == "users"]
    assert [(u["username"], u["email"]) for u in users] == [("jdoe", "jdoe@example.test")]
    assert fake_harbor.members[SLUG] == [{"entity_name": "jdoe", "role_id": 1}]


ADMIN_PASSWORD = "Adm1n-Placeholder-Pw"
SECRET_OPTS = ["--harbor-url", URL, "--harbor-user", "admin", "--harbor-password", ADMIN_PASSWORD]


@pytest.mark.usefixtures("cli_env")
def test_cli_harbor_error_exits_1_without_showing_admin_password(tmp_path, monkeypatch):
    _fakes(monkeypatch, fail={f"projects/{SLUG}": 500})
    r = _create(tmp_path, *SECRET_OPTS)
    assert r.exit_code == 1
    assert f"[ERROR] Harbor : Harbor GET {URL}/api/v2.0/projects/{SLUG} -> 500" in r.output
    assert ADMIN_PASSWORD not in r.output


@pytest.mark.usefixtures("cli_env")
def test_cli_new_k8s_robot_lands_as_dockerconfigjson_in_vault(tmp_path, monkeypatch):
    _, fake_vault = _fakes(monkeypatch)
    r = _create(tmp_path, *HARBOR_OPTS, "--vault-addr", VAULT, "--vault-token", "t")
    assert r.exit_code == 0, r.output
    assert loads(fake_vault.data[SHARED]["data"]["dockerconfigjson"]) == {
        "auths": {"registry.test": {"auth": "cm9ib3QkZGVtbytrOHM6c2VjcmV0LWs4cw=="}}}


@pytest.mark.usefixtures("cli_env")
def test_cli_skip_vault_leaves_vault_untouched_by_harbor(tmp_path, monkeypatch):
    _, fake_vault = _fakes(monkeypatch)
    r = _create(tmp_path, *HARBOR_OPTS, "--vault-addr", VAULT, "--vault-token", "t", "--skip-vault")
    assert r.exit_code == 0, r.output
    assert not fake_vault.calls
    assert "[WARN] Vault non configuré ou ignoré" in r.output


@pytest.mark.usefixtures("cli_env")
def test_cli_skip_harbor_makes_no_harbor_call(tmp_path, monkeypatch):
    fake_harbor, _ = _fakes(monkeypatch)
    r = _create(tmp_path, *HARBOR_OPTS, "--harbor-users", "--skip-harbor")
    assert r.exit_code == 0, r.output
    assert not fake_harbor.calls
    assert "[SKIP] Configuration Harbor ignorée (--skip-harbor)" in r.output


@pytest.mark.usefixtures("cli_env")
def test_cli_dry_run_writes_nothing_on_harbor_nor_vault(tmp_path, monkeypatch):
    fake_harbor, fake_vault = _fakes(monkeypatch)
    r = _create(tmp_path, *HARBOR_OPTS, "--harbor-users", "--vault-addr", VAULT, "--vault-token", "t", "--dry-run")
    assert r.exit_code == 0, r.output
    assert fake_harbor.writes == []
    assert [c for c in fake_vault.calls if c[0] not in ("GET", "LIST")] == []


def _add_dev(gitops_path, *extra):
    return CliRunner().invoke(app, ["add-dev", SLUG, "--devs", "asmith", "--gitops-path", str(gitops_path), *extra],
                              input="y\n")


@pytest.mark.usefixtures("cli_env")
def test_cli_add_dev_with_flag_creates_only_the_dev_accounts(tmp_path, monkeypatch):
    fake_harbor, _ = _fakes(monkeypatch, projects=[SLUG], robots=[(SLUG, "gitlab-ci"), (SLUG, "k8s")])
    assert _create(tmp_path).exit_code == 0
    r = _add_dev(tmp_path, *HARBOR_OPTS, "--harbor-users")
    assert r.exit_code == 0, r.output
    assert [c[1] for c in fake_harbor.writes] == ["users", f"projects/{SLUG}/members"]
    assert not [c for c in fake_harbor.calls if c[1] == "robots"]


@pytest.mark.usefixtures("cli_env")
def test_cli_add_dev_without_flag_makes_no_harbor_call(tmp_path, monkeypatch):
    fake_harbor, _ = _fakes(monkeypatch, projects=[SLUG])
    assert _create(tmp_path).exit_code == 0
    r = _add_dev(tmp_path, *HARBOR_OPTS)
    assert r.exit_code == 0, r.output
    assert not fake_harbor.calls


@pytest.mark.usefixtures("cli_env")
def test_cli_add_dev_harbor_error_exits_1(tmp_path, monkeypatch):
    _fakes(monkeypatch, fail={f"projects/{SLUG}": 403})
    assert _create(tmp_path).exit_code == 0
    r = _add_dev(tmp_path, *SECRET_OPTS, "--harbor-users")
    assert r.exit_code == 1
    assert f"[ERROR] Harbor : Harbor GET {URL}/api/v2.0/projects/{SLUG} -> 403" in r.output
    assert ADMIN_PASSWORD not in r.output


def test_network_error_becomes_harbor_error(monkeypatch):
    def unreachable(*args, **kwargs):
        raise harbor.requests.ConnectionError("connection refused")

    monkeypatch.setattr(harbor.requests, "request", unreachable)
    with pytest.raises(RuntimeError, match=f"Harbor GET {URL}/api/v2.0/projects/{SLUG} : ConnectionError"):
        harbor.provision(_client(), SLUG)


@pytest.mark.usefixtures("cli_env")
def test_cli_harbor_error_after_robot_creation_still_pushes_collected_secrets(tmp_path, monkeypatch):
    pushed = []
    monkeypatch.setattr(cred, "_push_secret", pushed.append)
    _fakes(monkeypatch, fail={"users": 409})
    r = _create(tmp_path, *HARBOR_OPTS, "--harbor-users")
    assert r.exit_code == 1
    assert [p for p in pushed if "secret: secret-" in p] == [
        f"login: robot${SLUG}+gitlab-ci\nsecret: secret-gitlab-ci\nurl: {URL}\n\n"
        f"login: robot${SLUG}+k8s\nsecret: secret-k8s\nurl: {URL}\n",
    ]


@pytest.mark.usefixtures("cli_env")
def test_cli_all_harbor_credentials_go_in_one_password_pusher_link(tmp_path, monkeypatch, capsys):
    pushed = []
    monkeypatch.setattr(cred, "_push_secret", lambda payload: pushed.append(payload) or "https://pwpush.test/p/1")
    _fakes(monkeypatch)
    r = _create(tmp_path, *HARBOR_OPTS, "--harbor-users")
    assert r.exit_code == 0, r.output
    harbor_pushes = [p for p in pushed if URL in p]
    assert len(harbor_pushes) == 1
    assert all(s in harbor_pushes[0] for s in ("secret-gitlab-ci", "secret-k8s", "login: jdoe"))
    assert r.output.count("https://pwpush.test/p/1") == 1


def test_existing_member_beyond_first_default_page_is_not_added_again(monkeypatch):
    lookalikes = [(f"li{i}x", 2) for i in range(10)]
    fake = _fake(monkeypatch, projects=[SLUG], robots=[(SLUG, "gitlab-ci"), (SLUG, "k8s")], users=["li"],
                 members={SLUG: [*lookalikes, ("li", 3)]})
    harbor.provision(_client(), SLUG, devs=["li"], email_domain="example.test")
    assert fake.writes == []


def test_member_post_conflict_counts_as_existing_membership(monkeypatch, capsys):
    _fake(monkeypatch, projects=[SLUG], robots=[(SLUG, "gitlab-ci"), (SLUG, "k8s")], users=["jdoe"],
          fail={("POST", f"projects/{SLUG}/members"): 409})
    harbor.provision(_client(), SLUG, devs=["jdoe"], email_domain="example.test")
    assert f"[EXISTS] Harbor membre jdoe de {SLUG}" in capsys.readouterr().out
