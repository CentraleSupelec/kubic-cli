import json
import re
from pathlib import Path
from typing import Optional

import requests
import typer
import base64

from . import cred, argo, vault, gitops
from .tpl import render_yaml
from .utils import safe_write, get_ssh_host, gen_pwd, parse_existing_environments_from_k8s_yaml, smart_write, auto_detect_existing_developers, validate_project_exists, get_existing_environments, duration_to_seconds, generate_multi_environment_kubeconfig, is_new_developer, append_rolebindings_to_yaml
from .config import DEFAULT_GITOPS_PATH

app = typer.Typer(
    help="Kubic CLI - Automatisation GitOps pour Kubernetes\n\nAutomatise la création d'applications dans un environnement Kubic (Argo CD + Vault).\n\nVoir README.md pour la documentation complète.",
    no_args_is_help=True,
    add_completion=False
)

@app.command()
def create_project(
    slug: str = typer.Argument(..., help="Identifiant du projet, utilisé comme nom de namespace / dossier"),
    repo_url: str = typer.Option(..., "--repo-url", help="URL SSH du dépôt contenant la chart Helm ou les manifests"),
    environments: str = typer.Option("prod", "--envs", help="Liste séparée par des virgules des environnements à créer (ex: dev,preprod,prod)"),
    gitops_path: Path = typer.Option(DEFAULT_GITOPS_PATH, "--gitops-path", exists=True, file_okay=False, dir_okay=True, help="Chemin du dépôt GitOps"),
    vault_addr: Optional[str] = typer.Option(None, "--vault-addr", envvar="VAULT_ADDR", help="Adresse du serveur Vault"),
    vault_token: Optional[str] = typer.Option(None, "--vault-token", envvar="VAULT_TOKEN", help="Token Vault ayant les droits d'admin"),
    skip_vault: bool = typer.Option(False, "--skip-vault", help="Ne pas configurer Vault pour ce projet"),
    devs: str = typer.Option("", "--devs", help="Liste des logins développeurs séparés par des virgules pour userpass Vault"),
    api_server: Optional[str] = typer.Option(None, "--api-server", envvar="KUBE_API", help="URL du serveur API Kubernetes pour créer le namespace"),
    api_token: Optional[str] = typer.Option(None, "--api-token", envvar="KUBE_API_TOKEN", help="Token Bearer pour l'API Kubernetes"),
    insecure: bool = typer.Option(False, "--insecure-skip-tls", help="Ne pas vérifier le certificat TLS du serveur API Kubernetes"),
    ca_file: Optional[Path] = typer.Option(None, "--cluster-ca", help="Chemin vers le certificat CA pour l'API Kubernetes"),
):
    """Crée les fichiers nécessaires (apps/, secrets Vault & Repository, compte ArgoCD).
    Création du namespace Kubernetes si --api-server et --api-token sont fournis.
    """
    # Création du namespace
    if api_server and api_token:
        ns_url = f"{api_server.rstrip('/')}/api/v1/namespaces"
        headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json",
        }
        env_list = [e.strip() for e in environments.split(",") if e.strip()]
        for env in env_list:
            ns = f"{slug}-{env}"
            body = {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": ns}}
            # Choix de la vérification TLS : fichier CA > --insecure.
            verify_opt = str(ca_file) if ca_file and ca_file.exists() else (not insecure)
            try:
                r = requests.post(ns_url, json=body, headers=headers, timeout=10, verify=verify_opt)
                if r.status_code == 201:
                    typer.echo(f"[WRITE] Namespace {ns} créé sur le cluster")
                elif r.status_code == 409:
                    typer.echo(f"[INFO] Namespace {ns} déjà existant sur le cluster")
                elif r.ok:
                    typer.echo(f"[INFO] Namespace {ns} : retour {r.status_code}")
                else:
                    typer.secho(
                        f"[WARN] Création du namespace {ns} a échoué ({r.status_code}) : {r.text}",
                        fg=typer.colors.YELLOW,
                    )
            except Exception as e:
                typer.secho(
                    f"[WARN] Impossible de créer le namespace {ns} sur le cluster : {e}",
                    fg=typer.colors.YELLOW,
                )
    else:
        typer.echo("[INFO] --api-server ou --api-token absent : namespace non créé")

    # Vérifier présence du dépôt GitOps
    if not gitops_path.exists():
        typer.secho(f"[WARN] Chemin GitOps {gitops_path} introuvable. Les fichiers seront créés à la racine du projet.", fg=typer.colors.YELLOW)
        gitops_path = Path(".")

    env_list = [e.strip() for e in environments.split(",") if e.strip()]
    typos = [e for e in env_list if not e]
    if typos:
        typer.echo(f"[WARN] environnements anormaux: {typos}")

    # 1. apps/<slug>/<env>.json
    apps_dir = gitops_path / "apps" / slug
    for env in env_list:
        json_path = apps_dir / f"{env}.json"
        data = {
            "valuesFiles": ["base.yaml", f"{env}.yaml"],
            "externalRepoURL": repo_url,
            "vaultCredentials": f"vault-token-{slug}",
            "_generated_by": "kubic-cli",
        }
        safe_write(json_path, json.dumps(data, indent=2) + "\n")

    # 2. Vault secret YAML (AppRole) - Éviter réécriture inutile
    if vault_addr:
        vault_dir = gitops_path / "helm" / "argocd" / "templates" / "vault"
        vault_content = render_yaml("vault-token.yaml.j2", slug=slug, vault_addr=vault_addr)
        smart_write(vault_dir / f"vault-token-{slug}.yaml", vault_content)
    else:
        typer.echo("[INFO] Aucun vault-addr fourni : Vault secret YAML non généré")

    # 3. repository secret - Éviter réécriture inutile
    repo_secret_dir = gitops_path / "helm" / "argocd" / "templates" / "repository"
    ssh_host = get_ssh_host(repo_url)
    repo_content = render_yaml("repository-secret.yaml.j2", slug=slug, repo_url=repo_url, ssh_host=ssh_host)
    smart_write(repo_secret_dir / f"repository-{slug}.yaml", repo_content)

    dev_list = [d.strip() for d in devs.split(",") if d.strip()] if devs else []

    if dev_list:
        cm_path = gitops_path / "helm" / "argocd" / "templates" / "argocd-cm.yaml"
        gitops.ensure_account(cm_path, slug)
        for dev in dev_list:
            gitops.ensure_account(cm_path, dev)

        rbac_path = gitops_path / "helm" / "argocd" / "templates" / "argocd-rbac-cm.yaml"
        gitops.ensure_rbac(rbac_path, slug, dev_list)

        # 5ter. Fichiers K8s ServiceAccount pour chaque dev - Logique incrémentale
        k8s_acc_dir = gitops_path / "helm" / "argocd" / "templates" / "k8s-accounts"
        for dev in dev_list:
            user_yaml_file = k8s_acc_dir / f"user-{dev}.yaml"

            if is_new_developer(gitops_path, dev):
                # Nouveau développeur : créer le fichier complet
                typer.echo(f"[INFO] Nouveau développeur {dev} : création complète")

                # ServiceAccount + Secret
                sa_content = render_yaml("k8s-serviceaccount.yaml.j2", user=dev)
                secret_content = render_yaml("k8s-secret.yaml.j2", user=dev)

                # RoleBindings pour tous les environnements
                rolebindings = []
                for env in sorted(env_list):
                    rb = render_yaml("k8s-rolebinding.yaml.j2", user=dev, slug=slug, env=env)
                    rolebindings.append(rb)

                # Assembler tout le contenu
                full_content = sa_content
                if not full_content.endswith('\n'):
                    full_content += '\n'
                full_content += "---\n" + secret_content
                for rb in rolebindings:
                    if not full_content.endswith('\n'):
                        full_content += '\n'
                    full_content += "---\n" + rb

                smart_write(user_yaml_file, full_content, overwrite=False)
            else:
                # Développeur existant : ajouter seulement les nouveaux RoleBindings
                existing_envs = parse_existing_environments_from_k8s_yaml(user_yaml_file, dev, slug)
                new_envs = set(env_list) - existing_envs

                if new_envs:
                    typer.echo(f"[INFO] Ajout environnements pour {dev} : {sorted(new_envs)}")

                    # Générer les nouveaux RoleBindings
                    rolebindings_content = ""
                    for env in sorted(new_envs):
                        rb = render_yaml("k8s-rolebinding.yaml.j2", user=dev, slug=slug, env=env)
                        if rolebindings_content and not rolebindings_content.endswith('\n'):
                            rolebindings_content += '\n'
                        rolebindings_content += "---\n" + rb

                    # Ajouter à la fin du fichier existant
                    append_rolebindings_to_yaml(user_yaml_file, rolebindings_content)
                else:
                    typer.echo(f"[INFO] Aucun nouvel environnement pour {dev}")

        typer.echo("[INFO] Utilisez 'setup-devs' après le déploiement pour générer les tokens/kubeconfigs")

    else:
        typer.echo("[INFO] Pas de devs fournis : aucune modification Argo CD (CM/RBAC)")

    # 6. Vault
    if skip_vault:
        typer.echo("[SKIP] Configuration Vault ignorée (--skip-vault)")
    elif not vault_addr or not vault_token:
        typer.echo("[INFO] Aucune adresse ou token Vault fourni : configuration Vault non effectuée")
    else:
        vault.provision(slug, env_list, addr=vault_addr, token=vault_token, devs=dev_list)

    typer.secho("\nTerminé. N'oubliez pas de :\n - Commit & push les modifications du dépôt GitOps\n - Créer la deploy key et le webhook dans GitLab", fg=typer.colors.GREEN)

    cred.flush()

@app.command("setup-devs")
def setup_devs(
    slug: str = typer.Argument(..., help="Identifiant du projet / namespace"),
    devs: str = typer.Option(..., "--devs", help="Liste des logins développeurs séparés par des virgules"),
    # Environnements - Support multi-environnements OU single environnement (rétrocompatibilité)
    envs: Optional[str] = typer.Option(None, "--envs", help="Environnements cibles séparés par des virgules (ex: dev,staging,prod) - auto-détection si omis"),
    env: Optional[str] = typer.Option(None, "--env", help="Environnement unique (rétrocompatibilité) - utiliser --envs de préférence"),
    gitops_path: Path = typer.Option(DEFAULT_GITOPS_PATH, "--gitops-path", exists=True, file_okay=False, dir_okay=True, help="Chemin du dépôt GitOps"),
    # Argo CD (options suspendues - pour usage futur)
    argocd_url: Optional[str] = typer.Option(None, "--argocd-url", envvar="ARGOCD_URL", help="[SUSPENDU] URL du serveur ArgoCD"),
    argocd_user: Optional[str] = typer.Option(None, "--argocd-user", envvar="ARGOCD_USER", help="[SUSPENDU] Login admin ArgoCD"),
    argocd_pass: Optional[str] = typer.Option(None, "--argocd-pass", envvar="ARGOCD_PASS", help="[SUSPENDU] Mot de passe admin ArgoCD"),
    argocd_token: Optional[str] = typer.Option(None, "--argocd-token", envvar="ARGOCD_TOKEN", help="[SUSPENDU] Token Bearer admin ArgoCD (alternative à user/pass)"),
    # Kubernetes API - Maintenant optionnels
    api_server: Optional[str] = typer.Option(None, "--api-server", envvar="KUBE_API", help="URL du serveur API Kubernetes"),
    api_token: Optional[str] = typer.Option(None, "--api-token", envvar="KUBE_API_TOKEN", help="Token Bearer pour l'API Kubernetes"),
    insecure: bool = typer.Option(False, "--insecure-skip-tls", help="Ne pas vérifier le certificat TLS de l'API"),
    duration: str = typer.Option("2160h", "--duration", help="Durée du token ServiceAccount (ex: 2160h)"),
    write_kubeconfig: Optional[Path] = typer.Option(None, "--write-kubeconfig", help="Dossier ou chemin fichier pour écrire un kubeconfig par dev (ou '-' pour stdout)"),
    cluster_name: str = typer.Option("kubic", "--cluster-name", help="Nom du cluster dans le kubeconfig généré"),
    context_name: Optional[str] = typer.Option(None, "--context-name", help="Nom du contexte (défaut <user>-<env>@<cluster> pour multi-env)"),
    ca_file: Optional[Path] = typer.Option(None, "--cluster-ca", help="Chemin vers le certificat CA à embarquer dans kubeconfig"),
):
    """Génère les tokens et kubeconfigs pour des développeurs EXISTANTS.

    ⚠️  Cette commande ne crée PAS de nouveaux développeurs !
    Pour ajouter de nouveaux développeurs, utilisez 'add-dev' d'abord.

    Fonctionnalités :
    • Génère un token ServiceAccount Kubernetes pour chaque développeur
    • Support multi-environnements avec kubeconfig multi-contextes
    • Auto-détection des environnements depuis les RoleBindings existants
    • Affiche un tableau récapitulatif avec liens Password Pusher

    Note : Génération mots de passe Argo CD temporairement suspendue
    (nécessite que les comptes soient créés via GitOps au préalable)
    """

    # 1. VALIDATION : Vérifier que le projet existe
    if not validate_project_exists(gitops_path, slug):
        typer.secho(f"[ERROR] Projet '{slug}' introuvable dans {gitops_path}/apps/{slug}", fg=typer.colors.RED)
        typer.echo("Utilisez 'create-project' pour créer un nouveau projet.")
        raise typer.Exit(1)

    # 2. VALIDATION : Liste des développeurs
    dev_list = [d.strip() for d in devs.split(",") if d.strip()]
    if not dev_list:
        typer.secho("[ERROR] Aucun dev fourni", fg=typer.colors.RED)
        raise typer.Exit(1)

    # 3. DÉTERMINATION : Environnements à traiter
    target_environments = {}  # {dev: [env1, env2, ...]}
    
    if envs:
        # Mode explicite : environnements spécifiés via --envs
        env_list = [e.strip() for e in envs.split(",") if e.strip()]
        for dev in dev_list:
            target_environments[dev] = env_list
        typer.echo(f"[INFO] Environnements explicites pour tous les développeurs: {env_list}")
        
    elif env:
        # Mode rétrocompatibilité : un seul environnement via --env
        for dev in dev_list:
            target_environments[dev] = [env]
        typer.echo(f"[INFO] Environnement unique (rétrocompatibilité): {env}")
        
    else:
        # Mode auto-détection : récupérer depuis les RoleBindings existants
        typer.echo("[INFO] Auto-détection des environnements depuis les RoleBindings existants...")
        
        for dev in dev_list:
            k8s_acc_dir = gitops_path / "helm" / "argocd" / "templates" / "k8s-accounts"
            user_yaml_file = k8s_acc_dir / f"user-{dev}.yaml"
            
            dev_envs = parse_existing_environments_from_k8s_yaml(user_yaml_file, dev, slug)
            
            if dev_envs:
                target_environments[dev] = sorted(dev_envs)
                typer.echo(f"[INFO] Environnements auto-détectés pour {dev}: {sorted(dev_envs)}")
            else:
                # Fallback sur 'dev' si aucun environnement détecté
                target_environments[dev] = ['dev']
                typer.secho(f"[WARN] Aucun environnement détecté pour {dev}, fallback sur 'dev'", fg=typer.colors.YELLOW)

    # 4. ARGO CD : Génération des mots de passe (TEMPORAIREMENT SUSPENDU)
    # FIXME: Cette section nécessite que les comptes ArgoCD soient déjà créés via GitOps
    # Workflow requis: create-project → commit/push → ArgoCD sync → setup-devs
    typer.echo("[INFO] Génération mots de passe Argo CD suspendue")
    typer.echo("       Les comptes doivent d'abord être créés via GitOps (commit → push → ArgoCD sync)")
    typer.echo("       Cette fonctionnalité sera réactivée dans une version future")
    
    # Code suspendu - à réactiver plus tard
    # if argocd_url and (argocd_token or (argocd_user and argocd_pass)):
    #     try:
    #         admin_token = argocd_token or argo.login(argocd_url, argocd_user, argocd_pass, verify=not insecure)
    #         for dev in dev_list:
    #             pwd = gen_pwd()
    #             argo.set_password(argocd_url, admin_token, dev, pwd, verify=not insecure)
    #             cred.collect("argocd", dev, pwd, argocd_url)
    #         typer.echo("[WRITE] Mots de passe Argo CD initialisés")
    #     except Exception as e:
    #         typer.secho(f"[WARN] Impossible de mettre à jour les mots de passe Argo CD: {e}", fg=typer.colors.YELLOW)
    # else:
    #     typer.echo("[INFO] Argo CD : URL ou credentials manquants → skip mot de passe")

    # 5. KUBERNETES : Génération des tokens ServiceAccount et kubeconfigs
    if api_server and api_token:
        # Vérification obligatoire du certificat CA pour les tokens Kubernetes
        if not ca_file or not ca_file.exists():
            typer.secho(
                "[ERROR] --cluster-ca est requis pour la génération de tokens Kubernetes (TokenRequest)",
                fg=typer.colors.RED,
            )
            raise typer.Exit(1)

        for dev in dev_list:
            dev_envs = target_environments[dev]
            
            # Générer UN token par développeur (fonctionne pour tous ses environnements)
            url = f"{api_server.rstrip('/')}/api/v1/namespaces/default/serviceaccounts/{dev}/token"
            headers = {"Authorization": f"Bearer {api_token}"}
            body = {
                "apiVersion": "authentication.k8s.io/v1",
                "kind": "TokenRequest",
                "spec": {"expirationSeconds": duration_to_seconds(duration)},
            }
            
            verify_opt = str(ca_file)
            try:
                r = requests.post(url, json=body, headers=headers, timeout=10, verify=verify_opt)
                if r.ok:
                    tok = r.json()["status"]["token"]
                    
                    # Collecter credentials avec info sur tous les namespaces accessibles
                    namespaces_list = [f"{slug}-{env}" for env in dev_envs]
                    cred.collect("k8s", dev, tok, api_server, note=f"ns {','.join(namespaces_list)}")
                    typer.echo(f"[WRITE] Token k8s généré pour {dev} (accès: {dev_envs})")

                    # Génération du kubeconfig multi-environnements
                    if write_kubeconfig:
                        ca_data = base64.b64encode(ca_file.read_bytes()).decode()
                        
                        # Support pour context_name custom (mode single environnement)
                        if context_name and len(dev_envs) == 1:
                            # Mode rétrocompatibilité avec context_name personnalisé
                            kubeconf = f"""apiVersion: v1
kind: Config
clusters:
- cluster:
    server: {api_server}
    certificate-authority-data: {ca_data}
  name: {cluster_name}
contexts:
- context:
    cluster: {cluster_name}
    namespace: {slug}-{dev_envs[0]}
    user: {dev}
  name: {context_name}
current-context: {context_name}
preferences: {{}}
users:
- name: {dev}
  user:
    token: {tok}"""
                        else:
                            # Mode multi-environnements (recommandé)
                            default_env = dev_envs[0] if dev_envs else 'dev'
                            kubeconf = generate_multi_environment_kubeconfig(
                                dev_name=dev,
                                slug=slug,
                                environments=dev_envs,
                                api_server=api_server,
                                token=tok,
                                cluster_name=cluster_name,
                                ca_data=ca_data,
                                default_env=default_env
                            )

                        if str(write_kubeconfig) == "-":
                            typer.echo(f"\n--- kubeconfig {dev} ---\n" + kubeconf)
                        else:
                            # Déterminer le chemin de sortie
                            if write_kubeconfig.is_dir():
                                out_path = write_kubeconfig / f"{dev}.kubeconfig"
                            elif len(dev_list) == 1:
                                out_path = write_kubeconfig
                            else:
                                out_path = write_kubeconfig.parent / f"{write_kubeconfig.stem}-{dev}{write_kubeconfig.suffix}"
                            
                            out_path.write_text(kubeconf)
                            typer.secho(f"[WRITE] kubeconfig -> {out_path} (contextes: {dev_envs})", fg=typer.colors.GREEN)
                else:
                    typer.secho(f"[WARN] TokenRequest pour {dev} a échoué ({r.status_code})", fg=typer.colors.YELLOW)
            except Exception as e:
                typer.secho(f"[WARN] Impossible de générer le token pour {dev} : {e}", fg=typer.colors.YELLOW)
    else:
        typer.echo("[INFO] --api-server ou --api-token manquant : skip tokens Kubernetes")

    # 6. AFFICHAGE : Résumé final
    typer.secho(f"\n✅ Configuration développeurs terminée pour le projet '{slug}'", fg=typer.colors.GREEN)
    for dev in dev_list:
        dev_envs = target_environments[dev]
        typer.echo(f"   {dev}: accès à {dev_envs}")
    
    cred.flush()


@app.command("add-environment")
def add_environment(
    slug: str = typer.Argument(..., help="Identifiant du projet existant"),
    environments: str = typer.Option(..., "--envs", help="Nouveaux environnements à ajouter (ex: staging,preprod)"),
    gitops_path: Path = typer.Option(DEFAULT_GITOPS_PATH, "--gitops-path", exists=True, file_okay=False, dir_okay=True, help="Chemin du dépôt GitOps"),
    # Vault
    vault_addr: Optional[str] = typer.Option(None, "--vault-addr", envvar="VAULT_ADDR", help="Adresse du serveur Vault"),
    vault_token: Optional[str] = typer.Option(None, "--vault-token", envvar="VAULT_TOKEN", help="Token Vault ayant les droits d'admin"),
    skip_vault: bool = typer.Option(False, "--skip-vault", help="Ne pas configurer Vault pour ces environnements"),
    # Kubernetes
    api_server: Optional[str] = typer.Option(None, "--api-server", envvar="KUBE_API", help="URL du serveur API Kubernetes"),
    api_token: Optional[str] = typer.Option(None, "--api-token", envvar="KUBE_API_TOKEN", help="Token Bearer pour l'API Kubernetes"),
    insecure: bool = typer.Option(False, "--insecure-skip-tls", help="Ne pas vérifier le certificat TLS"),
    ca_file: Optional[Path] = typer.Option(None, "--cluster-ca", help="Chemin vers le certificat CA pour l'API Kubernetes"),
):
    """Ajoute de nouveaux environnements à un projet Kubic existant.

    Cette commande est idempotente et préserve les environnements et développeurs existants.
    Auto-détecte les développeurs existants et met à jour leurs RoleBindings.

    Pour ajouter des développeurs, utilisez la commande 'add-dev'.
    """
    
    # 1. VALIDATION : Vérifier que le projet existe
    if not validate_project_exists(gitops_path, slug):
        typer.secho(f"[ERROR] Projet '{slug}' introuvable dans {gitops_path}/apps/{slug}", fg=typer.colors.RED)
        typer.echo("Utilisez 'create-project' pour créer un nouveau projet.")
        raise typer.Exit(1)
    
    # 2. AUTO-DÉTECTION : Récupérer environnements existants
    existing_envs = get_existing_environments(gitops_path, slug)
    new_env_list = [e.strip() for e in environments.split(",") if e.strip()]
    
    already_exist = set(new_env_list) & existing_envs
    really_new = set(new_env_list) - existing_envs
    
    if already_exist:
        typer.echo(f"[INFO] Environnements déjà existants (ignorés): {sorted(already_exist)}")
    
    if not really_new:
        typer.echo("[INFO] Aucun nouvel environnement à ajouter")
        return
    
    typer.echo(f"[INFO] Ajout des environnements: {sorted(really_new)}")
    
    # 3. AUTO-DÉTECTION : Récupérer développeurs existants
    dev_list = auto_detect_existing_developers(gitops_path, slug)
    if dev_list:
        typer.echo(f"[INFO] Développeurs auto-détectés: {dev_list}")
    else:
        typer.echo("[INFO] Aucun développeur détecté")
    
    # 4. RÉCUPÉRATION : Informations du projet existant (repo_url depuis un fichier JSON existant)
    apps_dir = gitops_path / "apps" / slug
    repo_url = None
    
    # Récupérer repo_url depuis un fichier JSON existant
    for json_file in apps_dir.glob("*.json"):
        try:
            data = json.loads(json_file.read_text())
            if "externalRepoURL" in data:
                repo_url = data["externalRepoURL"]
                break
        except Exception:
            continue
    
    if not repo_url:
        typer.secho("[ERROR] Impossible de récupérer l'URL du repository depuis les fichiers existants", fg=typer.colors.RED)
        raise typer.Exit(1)
    
    typer.echo(f"[INFO] Repository URL détectée: {repo_url}")
    
    # 5. CRÉATION NAMESPACES : Seulement les nouveaux environnements
    if api_server and api_token:
        ns_url = f"{api_server.rstrip('/')}/api/v1/namespaces"
        headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json",
        }
        for env in sorted(really_new):
            ns = f"{slug}-{env}"
            body = {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": ns}}
            verify_opt = str(ca_file) if ca_file and ca_file.exists() else (not insecure)
            try:
                r = requests.post(ns_url, json=body, headers=headers, timeout=10, verify=verify_opt)
                if r.status_code == 201:
                    typer.echo(f"[WRITE] Namespace {ns}")
                elif r.status_code == 409:
                    typer.echo(f"[EXISTS] Namespace {ns}")
                else:
                    typer.secho(f"[WARN] Namespace {ns} : {r.status_code} {r.text}", fg=typer.colors.YELLOW)
            except Exception as e:
                typer.secho(f"[WARN] Impossible de créer le namespace {ns}: {e}", fg=typer.colors.YELLOW)
    else:
        typer.echo("[INFO] --api-server ou --api-token absent : namespaces non créés")
    
    # 6. CRÉATION APPS JSON : Seulement les nouveaux environnements
    for env in sorted(really_new):
        json_path = apps_dir / f"{env}.json"
        data = {
            "valuesFiles": ["base.yaml", f"{env}.yaml"],
            "externalRepoURL": repo_url,
            "vaultCredentials": f"vault-token-{slug}",
            "_generated_by": "kubic-cli",
        }
        safe_write(json_path, json.dumps(data, indent=2) + "\n")
    
    # 7. VAULT KV : Merger avec les environnements existants (la logique vault.provision fait déjà le merge)
    if skip_vault:
        typer.echo("[SKIP] Configuration Vault ignorée (--skip-vault)")
    elif not vault_addr or not vault_token:
        typer.echo("[INFO] Aucune adresse ou token Vault fourni : configuration Vault non effectuée")
    else:
        # Appeler vault.provision avec TOUS les environnements (existants + nouveaux)
        all_env_list = sorted(existing_envs | really_new)
        vault.provision(slug, all_env_list, addr=vault_addr, token=vault_token, devs=dev_list)
    
    # 8. ROLEBINDINGS K8S : Ajouter les nouveaux environnements pour les développeurs existants
    if dev_list:
        k8s_acc_dir = gitops_path / "helm" / "argocd" / "templates" / "k8s-accounts"
        for dev in dev_list:
            user_yaml_file = k8s_acc_dir / f"user-{dev}.yaml"

            if not user_yaml_file.exists():
                typer.secho(f"[WARN] Fichier {user_yaml_file} introuvable pour {dev}, création complète", fg=typer.colors.YELLOW)

                # Créer le fichier complet avec tous les environnements
                sa_content = render_yaml("k8s-serviceaccount.yaml.j2", user=dev)
                secret_content = render_yaml("k8s-secret.yaml.j2", user=dev)

                rolebindings = []
                all_envs = sorted(existing_envs | really_new)
                for env in all_envs:
                    rb = render_yaml("k8s-rolebinding.yaml.j2", user=dev, slug=slug, env=env)
                    rolebindings.append(rb)

                full_content = sa_content
                if not full_content.endswith('\n'):
                    full_content += '\n'
                full_content += "---\n" + secret_content
                for rb in rolebindings:
                    if not full_content.endswith('\n'):
                        full_content += '\n'
                    full_content += "---\n" + rb

                smart_write(user_yaml_file, full_content, overwrite=False)
            else:
                # Développeur existant : ajouter seulement les nouveaux RoleBindings
                existing_dev_envs = parse_existing_environments_from_k8s_yaml(user_yaml_file, dev, slug)

                # Nouveaux environnements pour ce développeur
                new_envs_for_dev = really_new - existing_dev_envs

                if new_envs_for_dev:
                    typer.echo(f"[INFO] Ajout RoleBindings pour {dev}: {sorted(new_envs_for_dev)}")

                    # Générer les nouveaux RoleBindings
                    rolebindings_content = ""
                    for env in sorted(new_envs_for_dev):
                        rb = render_yaml("k8s-rolebinding.yaml.j2", user=dev, slug=slug, env=env)
                        if rolebindings_content and not rolebindings_content.endswith('\n'):
                            rolebindings_content += '\n'
                        rolebindings_content += "---\n" + rb

                    # Ajouter à la fin du fichier existant
                    append_rolebindings_to_yaml(user_yaml_file, rolebindings_content)
                else:
                    typer.echo(f"[INFO] {dev} a déjà accès à tous les environnements")
    
    typer.secho(f"\n✅ Environnements {sorted(really_new)} ajoutés avec succès au projet '{slug}'", fg=typer.colors.GREEN)
    if dev_list:
        typer.echo(f"   RoleBindings mis à jour pour: {dev_list}")
    typer.echo("\nN'oubliez pas de :")
    typer.echo(" - Commit & push les modifications du dépôt GitOps")
    if dev_list:
        typer.echo(" - Utiliser 'setup-devs' si vous devez mettre à jour les tokens/mots de passe développeurs")


@app.command("add-dev")
def add_dev(
    slug: str = typer.Argument(..., help="Identifiant du projet existant"),
    devs: str = typer.Option(..., "--devs", help="Développeurs à ajouter (séparés par des virgules)"),
    gitops_path: Path = typer.Option(DEFAULT_GITOPS_PATH, "--gitops-path", exists=True, file_okay=False, dir_okay=True, help="Chemin du dépôt GitOps"),
    # Vault
    vault_addr: Optional[str] = typer.Option(None, "--vault-addr", envvar="VAULT_ADDR", help="Adresse du serveur Vault"),
    vault_token: Optional[str] = typer.Option(None, "--vault-token", envvar="VAULT_TOKEN", help="Token Vault ayant les droits d'admin"),
    skip_vault: bool = typer.Option(False, "--skip-vault", help="Ne pas configurer Vault pour ces développeurs"),
):
    """Ajoute de nouveaux développeurs à un projet Kubic existant.

    Cette commande est idempotente et préserve les développeurs existants.
    Auto-détecte les environnements existants et crée les RoleBindings nécessaires.

    Pour générer les tokens/kubeconfigs, utilisez ensuite 'setup-devs'.
    """

    # 1. VALIDATION : Vérifier que le projet existe
    if not validate_project_exists(gitops_path, slug):
        typer.secho(f"[ERROR] Projet '{slug}' introuvable dans {gitops_path}/apps/{slug}", fg=typer.colors.RED)
        typer.echo("Utilisez 'create-project' pour créer un nouveau projet.")
        raise typer.Exit(1)

    # 2. VALIDATION : Liste des développeurs
    new_dev_list = [d.strip() for d in devs.split(",") if d.strip()]
    if not new_dev_list:
        typer.secho("[ERROR] Aucun développeur fourni", fg=typer.colors.RED)
        raise typer.Exit(1)

    # 3. AUTO-DÉTECTION : Récupérer développeurs existants
    existing_devs = set(auto_detect_existing_developers(gitops_path, slug))

    already_exist = set(new_dev_list) & existing_devs
    really_new = set(new_dev_list) - existing_devs

    if already_exist:
        typer.echo(f"[INFO] Développeurs déjà existants (ignorés): {sorted(already_exist)}")

    if not really_new:
        typer.echo("[INFO] Aucun nouveau développeur à ajouter")

    typer.echo(f"[INFO] Ajout des développeurs: {sorted(really_new)}")

    # 4. AUTO-DÉTECTION : Récupérer environnements existants
    existing_envs = get_existing_environments(gitops_path, slug)
    if not existing_envs:
        typer.secho("[ERROR] Aucun environnement trouvé pour ce projet", fg=typer.colors.RED)
        typer.echo("Utilisez 'add-environment' pour ajouter des environnements d'abord.")
        raise typer.Exit(1)

    typer.echo(f"[INFO] Environnements auto-détectés: {sorted(existing_envs)}")

    # 5. ARGO CD : Mise à jour des fichiers de configuration
    cm_path = gitops_path / "helm" / "argocd" / "templates" / "argocd-cm.yaml"
    for dev in sorted(really_new):
        gitops.ensure_account(cm_path, dev)

    rbac_path = gitops_path / "helm" / "argocd" / "templates" / "argocd-rbac-cm.yaml"
    gitops.ensure_rbac(rbac_path, slug, list(really_new))

    # 6. K8S SERVICEACCOUNT : Créer les fichiers pour chaque nouveau développeur
    k8s_acc_dir = gitops_path / "helm" / "argocd" / "templates" / "k8s-accounts"
    for dev in sorted(really_new):
        user_yaml_file = k8s_acc_dir / f"user-{dev}.yaml"

        typer.echo(f"[INFO] Création fichier K8s complet pour {dev}")

        # ServiceAccount + Secret
        sa_content = render_yaml("k8s-serviceaccount.yaml.j2", user=dev)
        secret_content = render_yaml("k8s-secret.yaml.j2", user=dev)

        # RoleBindings pour tous les environnements existants
        rolebindings = []
        for env in sorted(existing_envs):
            rb = render_yaml("k8s-rolebinding.yaml.j2", user=dev, slug=slug, env=env)
            rolebindings.append(rb)

        # Assembler tout le contenu
        full_content = sa_content
        if not full_content.endswith('\n'):
            full_content += '\n'
        full_content += "---\n" + secret_content
        for rb in rolebindings:
            if not full_content.endswith('\n'):
                full_content += '\n'
            full_content += "---\n" + rb

        smart_write(user_yaml_file, full_content, overwrite=False)

    # 7. VAULT : Configuration pour les nouveaux développeurs
    if skip_vault:
        typer.echo("[SKIP] Configuration Vault ignorée (--skip-vault)")
    elif not vault_addr or not vault_token:
        typer.echo("[INFO] Aucune adresse ou token Vault fourni : configuration Vault non effectuée")
    else:
        # Appeler vault.provision avec tous les environnements et seulement les nouveaux devs
        vault.provision(slug, sorted(existing_envs), addr=vault_addr, token=vault_token, devs=list(new_dev_list))

    typer.secho(f"\n✅ Développeurs {sorted(really_new)} ajoutés avec succès au projet '{slug}'", fg=typer.colors.GREEN)
    typer.echo(f"   Accès à tous les environnements: {sorted(existing_envs)}")
    typer.echo("\nN'oubliez pas de :")
    typer.echo(" - Commit & push les modifications du dépôt GitOps")
    typer.echo(" - Attendre le déploiement ArgoCD (sync)")
    typer.echo(" - Utiliser 'setup-devs' pour générer les tokens/kubeconfigs")

    cred.flush()


if __name__ == "__main__":
    app()
