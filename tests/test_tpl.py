"""Tests for template rendering with YAML header.

Nous vidons les overrides éventuelles pour isoler le comportement.
"""

import importlib, os

import kubic_cli.config as cfg
from kubic_cli.tpl import render_yaml


def _reset_config_env():
    os.environ.pop("KUBIC_CLI_YAML_HEADER", None)
    os.environ.pop("KUBIC_CLI_CONFIG", None)
    importlib.reload(cfg)


def test_render_yaml_adds_header():
    _reset_config_env()
    head = cfg.YAML_HEADER
    content = render_yaml("k8s-rolebinding.yaml.j2", user="alice", namespace="demo-prod")
    assert content.startswith(head)


def test_render_yaml_no_duplicate_header():
    _reset_config_env()
    head = cfg.YAML_HEADER
    body = render_yaml("k8s-rolebinding.yaml.j2", user="alice", namespace="demo-prod")
    # header présent
    assert body.startswith(head)
    # pas de duplication
    assert body.count(head.strip()) == 1 