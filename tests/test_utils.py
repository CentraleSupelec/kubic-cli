from pathlib import Path

from kubic_cli import utils


def test_get_ssh_host():
    assert utils.get_ssh_host("git@gitlab.com:group/repo.git") == "gitlab.com"
    assert utils.get_ssh_host("ssh://git@myhost:2222/group/repo.git") == "myhost-2222"
    assert utils.get_ssh_host("https://github.com/org/repo.git") == "github.com"


def test_gen_pwd_length_and_charset():
    pwd = utils.gen_pwd(32)
    assert len(pwd) == 32
    assert all(c.isalnum() for c in pwd)


def test_safe_write(tmp_path: Path):
    file_path = tmp_path / "dummy.txt"
    utils.safe_write(file_path, "hello")
    assert file_path.read_text() == "hello"

    # second call should skip (no overwrite)
    utils.safe_write(file_path, "world")
    assert file_path.read_text() == "hello"

    # overwrite=True should replace
    utils.safe_write(file_path, "world", overwrite=True)
    assert file_path.read_text() == "world"


# ---------------------------------------------------------------------------
# Tests pour les nouvelles fonctions
# ---------------------------------------------------------------------------

def test_duration_to_seconds():
    """Test conversion duration string to seconds."""
    assert utils.duration_to_seconds("60s") == 60
    assert utils.duration_to_seconds("10m") == 600
    assert utils.duration_to_seconds("2h") == 7200
    assert utils.duration_to_seconds("1d") == 86400
    assert utils.duration_to_seconds("2160h") == 7776000
    
    # Invalid format should return default (3600)
    assert utils.duration_to_seconds("invalid") == 3600
    assert utils.duration_to_seconds("") == 3600


def test_smart_write(tmp_path: Path):
    """Test smart_write function for avoiding unnecessary rewrites."""
    file_path = tmp_path / "test.txt"
    
    # First write
    utils.smart_write(file_path, "content1")
    assert file_path.read_text() == "content1"
    
    # Same content should not rewrite
    utils.smart_write(file_path, "content1", overwrite=True)
    assert file_path.read_text() == "content1"
    
    # Different content should rewrite
    utils.smart_write(file_path, "content2", overwrite=True)
    assert file_path.read_text() == "content2"
    
    # Without overwrite should skip
    utils.smart_write(file_path, "content3")
    assert file_path.read_text() == "content2"


def test_validate_project_exists(tmp_path: Path):
    """Test project validation function."""
    # Non-existent project
    assert not utils.validate_project_exists(tmp_path, "nonexistent")
    
    # Create project structure
    apps_dir = tmp_path / "apps" / "myproject"
    apps_dir.mkdir(parents=True)
    
    # Should now validate
    assert utils.validate_project_exists(tmp_path, "myproject")


def test_get_existing_environments(tmp_path: Path):
    """Test getting existing environments from apps/*.json files."""
    # No project
    envs = utils.get_existing_environments(tmp_path, "nonexistent")
    assert envs == set()
    
    # Create project with environments
    apps_dir = tmp_path / "apps" / "myproject"
    apps_dir.mkdir(parents=True)
    
    (apps_dir / "dev.json").write_text('{"env": "dev"}')
    (apps_dir / "prod.json").write_text('{"env": "prod"}')
    
    envs = utils.get_existing_environments(tmp_path, "myproject")
    assert envs == {"dev", "prod"}


def test_parse_existing_environments_from_k8s_yaml(tmp_path: Path):
    """Test parsing environments from K8s ServiceAccount YAML."""
    user_yaml = tmp_path / "user-alice.yaml"

    # No file
    envs = utils.parse_existing_environments_from_k8s_yaml(user_yaml, "alice", "myapp")
    assert envs == set()

    # Create YAML with RoleBindings (NEW FORMAT: name is just username, not username-env)
    yaml_content = """apiVersion: v1
kind: ServiceAccount
metadata:
  name: alice
  namespace: default
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: alice
  namespace: myapp-dev
subjects:
  - kind: ServiceAccount
    name: alice
    namespace: default
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: alice
  namespace: myapp-prod
subjects:
  - kind: ServiceAccount
    name: alice
    namespace: default
"""
    user_yaml.write_text(yaml_content)

    envs = utils.parse_existing_environments_from_k8s_yaml(user_yaml, "alice", "myapp")
    assert envs == {"dev", "prod"}


def test_auto_detect_existing_developers(tmp_path: Path):
    """Test auto-detection of existing developers."""
    # No directory
    devs = utils.auto_detect_existing_developers(tmp_path, "myapp")
    assert devs == []
    
    # Create k8s-accounts directory with user files
    k8s_dir = tmp_path / "helm" / "argocd" / "templates" / "k8s-accounts"
    k8s_dir.mkdir(parents=True)
    
    # Create user files with valid content
    alice_yaml = k8s_dir / "user-alice.yaml"
    alice_yaml.write_text("""
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: alice-dev
  namespace: myapp-dev
""")
    
    bob_yaml = k8s_dir / "user-bob.yaml"
    bob_yaml.write_text("""
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: bob-prod
  namespace: myapp-prod
""")
    
    # File not related to this project (different namespace pattern)
    charlie_yaml = k8s_dir / "user-charlie.yaml"
    charlie_yaml.write_text("""
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: charlie-dev
  namespace: otherapp-dev
""")
    
    devs = utils.auto_detect_existing_developers(tmp_path, "myapp")
    assert sorted(devs) == ["alice", "bob"]  # charlie should be excluded


def test_generate_multi_environment_kubeconfig():
    """Test multi-environment kubeconfig generation."""
    kubeconfig = utils.generate_multi_environment_kubeconfig(
        dev_name="alice",
        slug="myapp",
        environments=["dev", "staging", "prod"],
        api_server="https://k8s.example.com",
        token="sample-token",
        cluster_name="kubic",
        ca_data="LS0tLS1CRUdJTi1DRVJUSUZJQ0FURS0tLS0t",
        default_env="dev"
    )
    
    # Check basic structure
    assert "apiVersion: v1" in kubeconfig
    assert "kind: Config" in kubeconfig
    assert "clusters:" in kubeconfig
    assert "contexts:" in kubeconfig
    assert "users:" in kubeconfig
    
    # Check cluster config
    assert "server: https://k8s.example.com" in kubeconfig
    assert "certificate-authority-data: LS0tLS1CRUdJTi1DRVJUSUZJQ0FURS0tLS0t" in kubeconfig
    assert "name: kubic" in kubeconfig
    
    # Check contexts for all environments
    assert "name: alice-dev@kubic" in kubeconfig
    assert "name: alice-staging@kubic" in kubeconfig
    assert "name: alice-prod@kubic" in kubeconfig
    
    # Check namespaces
    assert "namespace: myapp-dev" in kubeconfig
    assert "namespace: myapp-staging" in kubeconfig
    assert "namespace: myapp-prod" in kubeconfig
    
    # Check default context
    assert "current-context: alice-dev@kubic" in kubeconfig
    
    # Check user config
    assert "name: alice" in kubeconfig
    assert "token: sample-token" in kubeconfig


def test_generate_multi_environment_kubeconfig_single_env():
    """Test kubeconfig generation with single environment."""
    kubeconfig = utils.generate_multi_environment_kubeconfig(
        dev_name="bob",
        slug="myapp",
        environments=["prod"],
        api_server="https://k8s.example.com",
        token="sample-token",
        cluster_name="kubic",
        ca_data="LS0tLS1CRUdJTi1DRVJUSUZJQ0FURS0tLS0t"
    )
    
    # Should have only one context
    assert "name: bob-prod@kubic" in kubeconfig
    assert "current-context: bob-prod@kubic" in kubeconfig
    assert "namespace: myapp-prod" in kubeconfig
    
    # Should not have other environments
    assert "bob-dev@kubic" not in kubeconfig
    assert "bob-staging@kubic" not in kubeconfig


def test_generate_multi_environment_kubeconfig_empty_envs():
    """Test kubeconfig generation with empty environments list."""
    kubeconfig = utils.generate_multi_environment_kubeconfig(
        dev_name="charlie",
        slug="myapp",
        environments=[],
        api_server="https://k8s.example.com",
        token="sample-token",
        cluster_name="kubic",
        ca_data="LS0tLS1CRUdJTi1DRVJUSUZJQ0FURS0tLS0t"
    )

    # Should fallback to dev environment
    assert "name: charlie-dev@kubic" in kubeconfig
    assert "current-context: charlie-dev@kubic" in kubeconfig
    assert "namespace: myapp-dev" in kubeconfig


def test_is_new_developer(tmp_path: Path):
    """Test checking if a developer is new."""
    # Developer without file is new
    assert utils.is_new_developer(tmp_path, "alice")

    # Create k8s-accounts directory and user file
    k8s_dir = tmp_path / "helm" / "argocd" / "templates" / "k8s-accounts"
    k8s_dir.mkdir(parents=True)

    alice_yaml = k8s_dir / "user-alice.yaml"
    alice_yaml.write_text("apiVersion: v1\nkind: ServiceAccount")

    # Developer with file is not new
    assert not utils.is_new_developer(tmp_path, "alice")

    # Other developer without file is still new
    assert utils.is_new_developer(tmp_path, "bob")


def test_append_rolebindings_to_yaml(tmp_path: Path):
    """Test appending RoleBindings to existing YAML file."""
    yaml_file = tmp_path / "user-alice.yaml"

    # Create initial file with ServiceAccount
    initial_content = """apiVersion: v1
kind: ServiceAccount
metadata:
  name: alice
  namespace: default
---
apiVersion: v1
kind: Secret
metadata:
  name: alice-token
  namespace: default
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: alice-dev
  namespace: myapp-dev
"""
    yaml_file.write_text(initial_content)

    # Append new RoleBinding
    new_rolebinding = """---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: alice-staging
  namespace: myapp-staging
"""
    utils.append_rolebindings_to_yaml(yaml_file, new_rolebinding)

    # Verify content was appended
    final_content = yaml_file.read_text()
    assert "alice-dev" in final_content
    assert "alice-staging" in final_content

    # Verify original content is still there
    assert "kind: ServiceAccount" in final_content
    assert "kind: Secret" in final_content 