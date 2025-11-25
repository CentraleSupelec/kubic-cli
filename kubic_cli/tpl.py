from pathlib import Path
from jinja2 import Environment, FileSystemLoader, select_autoescape

from . import config

TEMPLATE_DIR = Path(__file__).parent / "templates"
_env = Environment(
    loader=FileSystemLoader(TEMPLATE_DIR),
    autoescape=select_autoescape(enabled_extensions=(".yaml", ".yml")),
    variable_start_string="[[",
    variable_end_string="]]",
)

__all__ = ["render"]

def render(name: str, **ctx) -> str:
    """Rend le template *name* avec le contexte fourni."""
    return _env.get_template(name).render(**ctx)

def render_yaml(name: str, **ctx) -> str:
    """Rend un template YAML et préfixe le header s'il n'est pas déjà présent."""
    body = render(name, **ctx)
    if body.startswith(config.YAML_HEADER.strip()):
        return body
    return config.YAML_HEADER + body

__all__.append("render_yaml")
