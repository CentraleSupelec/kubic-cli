from pathlib import Path
import secrets
import string
import typer

__all__ = ["safe_write", "get_ssh_host", "gen_pwd", "parse_existing_environments_from_k8s_yaml", "smart_write", "auto_detect_existing_developers", "validate_project_exists", "get_existing_environments", "duration_to_seconds", "generate_multi_environment_kubeconfig", "is_new_developer", "append_rolebindings_to_yaml"]

def safe_write(path: Path, content: str, overwrite: bool = False):
    """Write *content* to *path* except if it already exists (unless overwrite=True).
    Affiche le résultat via typer (WRITE / SKIP).
    """
    if path.exists() and not overwrite:
        typer.echo(f"[SKIP] {path} already exists")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    typer.echo(f"[WRITE] {path}")


def get_ssh_host(repo_url: str) -> str:
    """Extract the host part from various SSH URL formats (git@host:path or ssh://git@host:port/...).
    Returns a version where ':' is replaced by '-' to stay secret-key friendly.
    """
    if repo_url.startswith("ssh://"):
        without_scheme = repo_url.split("ssh://", 1)[1]
        at_split = without_scheme.split("@", 1)
        host_port_path = at_split[1] if len(at_split) == 2 else at_split[0]
        host = host_port_path.split("/", 1)[0]
    elif repo_url.startswith("git@"):
        host = repo_url.split("@", 1)[1].split(":", 1)[0]
    else:
        host = repo_url.split("//", 1)[-1].split("/", 1)[0]
    return host.replace(":", "-")


def gen_pwd(length: int = 20) -> str:
    """Return a random alphanumeric password of *length* characters."""
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def parse_existing_environments_from_k8s_yaml(yaml_file: Path, user: str, slug: str) -> set:
    """Parse existing environments from K8s ServiceAccount YAML file.

    Looks for RoleBinding resources in namespaces matching pattern: {slug}-{env}
    Returns set of environment names found.

    Note: Works with new format where RoleBinding name is just the username,
    not username-env (changed to fix metadata naming conventions).
    """
    if not yaml_file.exists():
        return set()

    try:
        content = yaml_file.read_text()
        envs = set()

        # Look for RoleBinding patterns like:
        # kind: RoleBinding
        # metadata:
        #   name: alice
        #   namespace: myapp-dev
        lines = content.split('\n')
        in_rolebinding = False
        in_metadata = False

        for line in lines:
            stripped = line.strip()

            # Detect RoleBinding start
            if stripped.startswith('kind:') and 'RoleBinding' in stripped:
                in_rolebinding = True
                continue

            # Detect metadata section
            if in_rolebinding and stripped.startswith('metadata:'):
                in_metadata = True
                continue

            # End of metadata section (subjects, roleRef, or new document)
            if in_metadata and (stripped.startswith('subjects:') or stripped.startswith('roleRef:') or stripped.startswith('---')):
                in_metadata = False
                in_rolebinding = False
                continue

            # Parse namespace in metadata section
            if in_metadata and stripped.startswith('namespace:'):
                namespace_value = stripped.split(':', 1)[1].strip()
                # Extract env from namespace like "myapp-dev" -> "dev"
                if namespace_value.startswith(f'{slug}-'):
                    env = namespace_value[len(f'{slug}-'):]
                    if env:  # Avoid empty strings
                        envs.add(env)

        return envs

    except Exception as e:
        typer.secho(f"[WARN] Could not parse existing environments from {yaml_file}: {e}", fg=typer.colors.YELLOW)
        return set()


def smart_write(path: Path, content: str, overwrite: bool = False):
    """Write content to path only if it differs from existing content.
    
    Avoids unnecessary file rewrites and git commits for identical content.
    """
    if path.exists():
        if not overwrite:
            typer.echo(f"[SKIP] {path} already exists")
            return
        
        # Check if content is identical
        existing_content = path.read_text()
        if existing_content == content:
            typer.echo(f"[UNCHANGED] {path}")
            return
    
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    typer.echo(f"[WRITE] {path}")


def auto_detect_existing_developers(gitops_path: Path, slug: str) -> list:
    """Auto-detect existing developers from K8s ServiceAccount files.
    
    Returns list of developer usernames found in user-*.yaml files.
    """
    k8s_acc_dir = gitops_path / "helm" / "argocd" / "templates" / "k8s-accounts"
    detected_devs = set()
    
    if not k8s_acc_dir.exists():
        return []
    
    for user_file in k8s_acc_dir.glob("user-*.yaml"):
        if user_file.is_file():
            # Extract username from filename like "user-alice.yaml" -> "alice"
            user_name = user_file.stem.replace("user-", "")
            
            # Validate it's actually for this project by checking content
            try:
                content = user_file.read_text()
                if f"namespace: {slug}-" in content:  # Should have namespaces like myapp-dev
                    detected_devs.add(user_name)
            except Exception as e:
                typer.secho(f"[WARN] Could not parse {user_file}: {e}", fg=typer.colors.YELLOW)
    
    return sorted(detected_devs)


def validate_project_exists(gitops_path: Path, slug: str) -> bool:
    """Validate that a project exists by checking for apps directory.
    
    Returns True if project exists, False otherwise.
    """
    apps_dir = gitops_path / "apps" / slug
    return apps_dir.exists() and apps_dir.is_dir()


def get_existing_environments(gitops_path: Path, slug: str) -> set:
    """Get existing environments from apps/*.json files.
    
    Returns set of environment names found.
    """
    apps_dir = gitops_path / "apps" / slug
    existing_envs = set()
    
    if not apps_dir.exists():
        return existing_envs
    
    for json_file in apps_dir.glob("*.json"):
        if json_file.is_file():
            existing_envs.add(json_file.stem)
    
    return existing_envs


def duration_to_seconds(duration: str) -> int:
    """Convert duration string like '2160h', '30d', '60m' to seconds.
    
    Supports: s (seconds), m (minutes), h (hours), d (days)
    Returns 3600 (1h) as default if parsing fails.
    """
    import re
    
    match = re.match(r"(\d+)([smhd])", duration)
    if not match:
        return 3600  # Default 1 hour
    
    value = int(match.group(1))
    unit = match.group(2)
    multipliers = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    
    return value * multipliers[unit]


def generate_multi_environment_kubeconfig(
    dev_name: str,
    slug: str,
    environments: list,
    api_server: str,
    token: str,
    cluster_name: str,
    ca_data: str,
    default_env: str = None
) -> str:
    """Generate kubeconfig with multiple contexts for different environments.

    Args:
        dev_name: Developer username
        slug: Project slug
        environments: List of environment names ['dev', 'staging', 'prod']
        api_server: Kubernetes API server URL
        token: ServiceAccount token (same for all environments)
        cluster_name: Cluster name in kubeconfig
        ca_data: Base64 encoded CA certificate
        default_env: Default environment to set as current-context

    Returns:
        Complete kubeconfig YAML as string
    """
    if not environments:
        environments = ['dev']

    if not default_env or default_env not in environments:
        default_env = environments[0]

    # Cluster configuration (same for all contexts)
    cluster_config = f"""clusters:
- cluster:
    server: {api_server}
    certificate-authority-data: {ca_data}
  name: {cluster_name}"""

    # Generate contexts (one per environment)
    contexts = []
    for env in sorted(environments):
        namespace = f"{slug}-{env}"
        context_name = f"{dev_name}-{env}@{cluster_name}"

        context_config = f"""- context:
    cluster: {cluster_name}
    namespace: {namespace}
    user: {dev_name}
  name: {context_name}"""
        contexts.append(context_config)

    contexts_config = "contexts:\n" + "\n".join(contexts)

    # Default context
    default_context = f"{dev_name}-{default_env}@{cluster_name}"

    # User configuration (same token for all environments)
    user_config = f"""users:
- name: {dev_name}
  user:
    token: {token}"""

    # Assemble final kubeconfig
    kubeconfig = f"""apiVersion: v1
kind: Config
{cluster_config}
{contexts_config}
current-context: {default_context}
preferences: {{}}
{user_config}"""

    return kubeconfig


def is_new_developer(gitops_path: Path, dev: str) -> bool:
    """Check if a developer is new (doesn't have an existing K8s account file).

    Args:
        gitops_path: Path to the GitOps repository
        dev: Developer username

    Returns:
        True if developer is new, False if they already have a file
    """
    k8s_acc_dir = gitops_path / "helm" / "argocd" / "templates" / "k8s-accounts"
    user_yaml_file = k8s_acc_dir / f"user-{dev}.yaml"
    return not user_yaml_file.exists()


def append_rolebindings_to_yaml(yaml_file: Path, rolebindings_content: str):
    """Append RoleBinding YAML content to an existing K8s account file.

    This function appends new RoleBindings to the end of the file without
    modifying the existing ServiceAccount and Secret objects.

    Args:
        yaml_file: Path to the existing user YAML file
        rolebindings_content: YAML content for the new RoleBindings (with --- separators)
    """
    if not yaml_file.exists():
        typer.secho(f"[ERROR] File {yaml_file} does not exist", fg=typer.colors.RED)
        return

    existing_content = yaml_file.read_text()

    # Ensure existing content ends with a newline
    if not existing_content.endswith('\n'):
        existing_content += '\n'

    # Append new rolebindings
    new_content = existing_content + rolebindings_content

    yaml_file.write_text(new_content)
    typer.echo(f"[APPEND] RoleBindings added to {yaml_file}")
