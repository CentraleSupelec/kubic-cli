from pathlib import Path

from kubic_cli import config as cfg


def test_defaults_present():
    # Ensure defaults not empty
    assert cfg.YAML_HEADER.startswith("#")
    assert isinstance(cfg.DEFAULT_GITOPS_PATH, Path)


def test_env_override(monkeypatch, tmp_path):
    monkeypatch.setenv("KUBIC_CLI_YAML_HEADER", "# ENV HEADER\n")
    monkeypatch.setenv("KUBIC_CLI_GITOPS_PATH", str(tmp_path))
    # reload module to apply env overrides
    import importlib
    import kubic_cli.config as cfg_reloaded
    importlib.reload(cfg_reloaded)

    assert cfg_reloaded.YAML_HEADER == "# ENV HEADER\n"
    assert cfg_reloaded.DEFAULT_GITOPS_PATH == tmp_path


def test_toml_override(monkeypatch, tmp_path):
    toml_path = tmp_path / "conf.toml"
    toml_path.write_text('yaml_header = "# TOML HEADER\\n"\ngitops_path = "toml-path"\n')
    monkeypatch.delenv("KUBIC_CLI_YAML_HEADER", raising=False)
    monkeypatch.delenv("KUBIC_CLI_GITOPS_PATH", raising=False)
    monkeypatch.setenv("KUBIC_CLI_CONFIG", str(toml_path))

    import importlib
    import kubic_cli.config as cfg2
    importlib.reload(cfg2)

    assert cfg2.YAML_HEADER == "# TOML HEADER\n"
    assert cfg2.DEFAULT_GITOPS_PATH == Path("toml-path") 