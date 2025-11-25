from pathlib import Path

import pytest
from typer.testing import CliRunner

from kubic_cli.gitops import ensure_account, ensure_rbac
from kubic_cli.main import app


# ---------------------------------------------------------------------------
# gitops.ensure_account
# ---------------------------------------------------------------------------

def test_ensure_account_adds_user(tmp_path: Path):
    cm = tmp_path / "argocd-cm.yaml"
    cm.write_text("data:\n  accounts.admin: apiKey,login\n")

    ensure_account(cm, "alice")

    content = cm.read_text()
    assert "accounts.alice" in content


def test_ensure_account_idempotent(tmp_path: Path):
    cm = tmp_path / "argocd-cm.yaml"
    cm.write_text("data:\n  accounts.admin: apiKey,login\n  accounts.bob: apiKey,login\n")

    # Première exécution — rien ne doit changer (bob déjà présent)
    ensure_account(cm, "bob")
    lines = cm.read_text().splitlines()
    # Une seule occurrence de bob
    assert sum("accounts.bob" in l for l in lines) == 1


# ---------------------------------------------------------------------------
# gitops.ensure_rbac
# ---------------------------------------------------------------------------

def test_ensure_rbac_creates_role_and_mappings(tmp_path: Path):
    rbac = tmp_path / "argocd-rbac-cm.yaml"
    rbac.touch()  # fichier vide

    ensure_rbac(rbac, "demo", ["alice", "bob"])

    text = rbac.read_text()
    assert "role:demo" in text
    assert "g, alice, role:demo" in text
    assert "g, bob, role:demo" in text


def test_ensure_rbac_adds_missing_user(tmp_path: Path):
    rbac = tmp_path / "argocd-rbac-cm.yaml"
    rbac.write_text("    p, role:demo, applications, get, default/demo-*, allow\n    g, demo, role:demo\n")

    # Ajout d'un nouvel utilisateur charlie
    ensure_rbac(rbac, "demo", ["charlie"])
    text = rbac.read_text()
    assert "g, charlie, role:demo" in text


# ---------------------------------------------------------------------------
# CLI create-project (sans appels HTTP)
# ---------------------------------------------------------------------------

def test_cli_create_project_basic(tmp_path: Path):
    runner = CliRunner()
    res = runner.invoke(
        app,
        [
            "create-project",
            "myproj",
            "--repo-url",
            "git@gitlab.com:org/myproj.git",
            "--envs",
            "prod",
            "--gitops-path",
            str(tmp_path),
        ],
    )
    assert res.exit_code == 0
    assert (tmp_path / "apps/myproj/prod.json").exists()


def test_cli_create_project_idempotent(tmp_path: Path):
    """Test that create-project is idempotent and safe to re-run."""
    runner = CliRunner()
    
    # First run
    res1 = runner.invoke(
        app,
        [
            "create-project",
            "myproj",
            "--repo-url",
            "git@gitlab.com:org/myproj.git",
            "--envs",
            "dev,prod",
            "--gitops-path",
            str(tmp_path),
            "--skip-vault",
        ],
    )
    assert res1.exit_code == 0
    assert (tmp_path / "apps/myproj/dev.json").exists()
    assert (tmp_path / "apps/myproj/prod.json").exists()
    
    # Second run should be safe
    res2 = runner.invoke(
        app,
        [
            "create-project",
            "myproj",
            "--repo-url",
            "git@gitlab.com:org/myproj.git",
            "--envs",
            "dev,prod,staging",
            "--gitops-path",
            str(tmp_path),
            "--skip-vault",
        ],
    )
    assert res2.exit_code == 0
    # Should now have all three environments
    assert (tmp_path / "apps/myproj/dev.json").exists()
    assert (tmp_path / "apps/myproj/prod.json").exists()
    assert (tmp_path / "apps/myproj/staging.json").exists()


# ---------------------------------------------------------------------------
# CLI add-environment
# ---------------------------------------------------------------------------

def test_cli_add_environment_basic(tmp_path: Path):
    """Test basic add-environment functionality."""
    runner = CliRunner()
    
    # First create a project
    runner.invoke(
        app,
        [
            "create-project",
            "myproj",
            "--repo-url",
            "git@gitlab.com:org/myproj.git",
            "--envs",
            "dev,prod",
            "--gitops-path",
            str(tmp_path),
            "--skip-vault",
        ],
    )
    
    # Then add a new environment
    res = runner.invoke(
        app,
        [
            "add-environment",
            "myproj",
            "--envs",
            "staging",
            "--gitops-path",
            str(tmp_path),
            "--skip-vault",
        ],
    )
    assert res.exit_code == 0
    
    # Should have all three environments
    assert (tmp_path / "apps/myproj/dev.json").exists()
    assert (tmp_path / "apps/myproj/prod.json").exists()
    assert (tmp_path / "apps/myproj/staging.json").exists()


def test_cli_add_environment_nonexistent_project(tmp_path: Path):
    """Test add-environment fails on non-existent project."""
    runner = CliRunner()
    
    res = runner.invoke(
        app,
        [
            "add-environment",
            "nonexistent",
            "--envs",
            "staging",
            "--gitops-path",
            str(tmp_path),
        ],
    )
    assert res.exit_code == 1
    assert "introuvable" in res.stdout


def test_cli_add_environment_existing_env(tmp_path: Path):
    """Test add-environment handles existing environments gracefully."""
    runner = CliRunner()
    
    # Create project with dev,prod
    runner.invoke(
        app,
        [
            "create-project",
            "myproj",
            "--repo-url",
            "git@gitlab.com:org/myproj.git",
            "--envs",
            "dev,prod",
            "--gitops-path",
            str(tmp_path),
            "--skip-vault",
        ],
    )
    
    # Try to add dev (already exists) and staging (new)
    res = runner.invoke(
        app,
        [
            "add-environment",
            "myproj",
            "--envs",
            "dev,staging",
            "--gitops-path",
            str(tmp_path),
            "--skip-vault",
        ],
    )
    assert res.exit_code == 0
    assert "déjà existants" in res.stdout
    assert "staging" in res.stdout
    
    # Should have staging.json created
    assert (tmp_path / "apps/myproj/staging.json").exists()


def test_cli_add_environment_no_new_envs(tmp_path: Path):
    """Test add-environment when no new environments to add."""
    runner = CliRunner()
    
    # Create project
    runner.invoke(
        app,
        [
            "create-project",
            "myproj",
            "--repo-url",
            "git@gitlab.com:org/myproj.git",
            "--envs",
            "dev,prod",
            "--gitops-path",
            str(tmp_path),
            "--skip-vault",
        ],
    )
    
    # Try to add existing environments only
    res = runner.invoke(
        app,
        [
            "add-environment",
            "myproj",
            "--envs",
            "dev,prod",
            "--gitops-path",
            str(tmp_path),
        ],
    )
    assert res.exit_code == 0
    assert "Aucun nouvel environnement" in res.stdout 