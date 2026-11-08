import json
import re
from pathlib import Path
from typing import List, Optional

import requests
import typer
import base64

from . import cred, argo, vault, gitops, chart
from . import eso as eso_lib
from .utils import safe_write, get_ssh_host, gen_pwd, parse_existing_environments_from_k8s_yaml, smart_write, auto_detect_existing_developers, validate_project_exists, get_existing_environments, duration_to_seconds, generate_multi_environment_kubeconfig, is_new_developer
from .config import DEFAULT_GITOPS_PATH

app = typer.Typer(
    help="Kubic CLI - Automatisation GitOps pour Kubernetes\n\nAutomatise la création d'applications dans un environnement Kubic (Argo CD + Vault).\n\nVoir README.md pour la documentation complète.",
    no_args_is_help=True,
    add_completion=False
)

def _eso_precheck(eso: bool, gitops_path: Path, slug: str, env_list: List[str]):
    """External Secrets: refuse before any write (operator namespace, paths outside <slug>/)."""
    if not eso:
        return
    try:
        for env in env_list:
            eso_lib.target_paths(gitops_path, slug, env)
    except eso_lib.EsoError as e:
        typer.secho(f"[ERROR] ESO : {e}", fg=typer.colors.RED)
        raise typer.Exit(1)


def _eso_ensure(gitops_path: Path, slug: str, env_list: List[str], vault_addr, vault_token, skip_vault: bool,
                dry_run: bool = False):
    ctx = eso_lib.VaultCtx(vault_addr, vault_token) if vault_addr and vault_token and not skip_vault else None
    for env in env_list:
        try:
            eso_lib.ensure(gitops_path, slug, env, ctx, dry_run=dry_run)
        except eso_lib.EsoError as e:
            typer.secho(f"[ERROR] ESO {env} : {e}", fg=typer.colors.RED)
            raise typer.Exit(1)


def _write_app_json(json_path: Path, slug: str, env: str, repo_url: str, eso: bool, dry_run: bool = False):
    """--eso: externalSecrets, no vaultCredentials (rendered without AVP). --avp: vaultCredentials, no ESO key.
    An existing file is never rewritten; --avp only adds a missing vaultCredentials."""
    cred_name = f"vault-token-{slug}"
    if json_path.exists():
        text = json_path.read_text()
        if eso or "vaultCredentials" in json.loads(text):
            typer.echo(f"[SKIP] {json_path} already exists")
        else:
            if not dry_run:
                json_path.write_text(eso_lib.set_key(text, "vaultCredentials", cred_name))
            typer.echo(f"{'[DRY-RUN] ' if dry_run else ''}[WRITE] {json_path} vaultCredentials : {cred_name}")
        return
    data = {"valuesFiles": ["base.yaml", f"{env}.yaml"], "externalRepoURL": repo_url}
    if not eso:
        data["vaultCredentials"] = cred_name
    data.update({"project": slug, "_generated_by": "kubic-cli"})
    content = json.dumps(data, indent=2) + "\n"
    if eso:
        content = eso_lib.set_paths(content, eso_lib.default_paths(slug, env))
    safe_write(json_path, content, dry_run=dry_run)


def _write_user_accounts(gitops_path: Path, slug: str, devs, new_file_envs, added_envs, dry_run: bool = False):
    """Data file users/<dev>.yaml per new dev with the namespaces of new_file_envs;
    an existing account only gets the namespaces of added_envs it lacks."""
    for dev in devs:
        path = chart.user_file(gitops_path, dev)
        if not path.exists():
            namespaces = [eso_lib.namespace(slug, env) for env in sorted(new_file_envs)]
            smart_write(path, chart.dump(chart.user_data(dev, namespaces)), dry_run=dry_run)
            continue
        namespaces = [eso_lib.namespace(slug, env) for env in sorted(added_envs)]
        if dry_run:
            missing = [ns for ns in namespaces if ns not in chart.user_namespaces(path)]
            if missing:
                typer.echo(f"[DRY-RUN] [UPDATE] {path} : RoleBindings {missing}")
                continue
        elif chart.add_user_namespaces(path, dev, namespaces):
            continue
        typer.echo(f"[INFO] Aucun nouvel environnement pour {dev}")


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
    dry_run: bool = typer.Option(False, "--dry-run", help="Affiche les actions prévues sans rien écrire (fichiers, Vault, cluster)"),
    eso: bool = typer.Option(True, "--eso/--avp", help="Secrets Vault : --eso (défaut) External Secrets, sans AppRole AVP ; --avp ancien modèle argocd-vault-plugin, sans ESO"),
):
    """Crée les fichiers nécessaires (apps/, secrets Vault & Repository, compte ArgoCD, External Secrets).
    Création du namespace Kubernetes si --api-server et --api-token sont fournis.
    Idempotent : relancer sur un projet existant ne crée que ce qui manque.
    """
    env_list = [e.strip() for e in environments.split(",") if e.strip()]
    _eso_precheck(eso, gitops_path, slug, env_list)

    # Création du namespace
    if api_server and api_token:
        ns_url = f"{api_server.rstrip('/')}/api/v1/namespaces"
        headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json",
        }
        for env in env_list:
            ns = slug if slug == env else f"{slug}-{env}"
            body = {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": ns}}
            # Choix de la vérification TLS : fichier CA > --insecure.
            verify_opt = str(ca_file) if ca_file and ca_file.exists() else (not insecure)
            try:
                if dry_run:
                    r = requests.get(f"{ns_url}/{ns}", headers=headers, timeout=10, verify=verify_opt)
                    if r.status_code == 404:
                        typer.echo(f"[DRY-RUN] [WRITE] Namespace {ns}")
                    else:
                        typer.echo(f"[EXISTS] Namespace {ns}" if r.ok else f"[WARN] Namespace {ns} : retour {r.status_code}")
                    continue
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

    typos = [e for e in env_list if not e]
    if typos:
        typer.echo(f"[WARN] environnements anormaux: {typos}")

    # 1. apps/<slug>/<env>.json
    apps_dir = gitops_path / "apps" / slug
    for env in env_list:
        _write_app_json(apps_dir / f"{env}.json", slug, env, repo_url, eso, dry_run=dry_run)
    gitops.generate_appprojects(gitops_path, dry_run=dry_run)

    # 2. Vault secret YAML (AppRole AVP, mode --avp) - Éviter réécriture inutile
    if eso:
        typer.echo(f"[INFO] Mode ESO : vault-token-{slug}.yaml non géré")
    elif vault_addr:
        vault_file = chart.data_file(gitops_path, "vault-tokens", slug, f"vault/vault-token-{slug}.yaml")
        smart_write(vault_file, chart.dump(chart.vault_token_data(slug)), dry_run=dry_run)
    else:
        typer.echo("[INFO] Aucun vault-addr fourni : Vault secret YAML non généré")

    # 3. repository secret - Éviter réécriture inutile
    repo_file = chart.data_file(gitops_path, "repositories", slug, f"repository/repository-{slug}.yaml")
    smart_write(repo_file, chart.dump(chart.repository_data(slug, repo_url, get_ssh_host(repo_url))),
                dry_run=dry_run)

    dev_list = [d.strip() for d in devs.split(",") if d.strip()] if devs else []

    if dev_list:
        cm_path = gitops_path / "helm" / "argocd" / "templates" / "argocd-cm.yaml"
        for dev in dev_list:
            gitops.ensure_account(cm_path, dev, dry_run=dry_run)

        rbac_path = gitops_path / "helm" / "argocd" / "templates" / "argocd-rbac-cm.yaml"
        gitops.ensure_rbac(rbac_path, slug, dev_list, dry_run=dry_run)

        # 5ter. One-line K8s account file per dev, or new namespaces added to it
        _write_user_accounts(gitops_path, slug, dev_list, env_list, env_list, dry_run=dry_run)

        typer.echo("[INFO] Utilisez 'setup-devs' après le déploiement pour générer les tokens/kubeconfigs")

    else:
        typer.echo("[INFO] Pas de devs fournis : aucune modification Argo CD (CM/RBAC)")

    # 6. Vault
    if skip_vault:
        typer.echo("[SKIP] Configuration Vault ignorée (--skip-vault)")
    elif not vault_addr or not vault_token:
        typer.echo("[INFO] Aucune adresse ou token Vault fourni : configuration Vault non effectuée")
    else:
        vault.provision(slug, env_list, addr=vault_addr, token=vault_token, devs=dev_list, dry_run=dry_run, avp=not eso)

    # 7. External Secrets (mode --eso): after vault.provision, which creates the kv paths
    if eso:
        _eso_ensure(gitops_path, slug, env_list, vault_addr, vault_token, skip_vault, dry_run)

    if dry_run:
        typer.secho("\nDry-run : rien n'a été écrit.", fg=typer.colors.GREEN)
        return
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
    write_kubeconfig: Optional[Path] = typer.Option(None, "--write-kubeconfig", help="Répertoire où écrire <dev>.kubeconfig pour chaque dev, créé si absent (ou '-' pour stdout)"),
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

    # VALIDATION : --write-kubeconfig doit être un répertoire (créé si absent)
    if write_kubeconfig and str(write_kubeconfig) != "-":
        if write_kubeconfig.exists() and not write_kubeconfig.is_dir():
            typer.secho(f"[ERROR] --write-kubeconfig doit être un répertoire : {write_kubeconfig} est un fichier", fg=typer.colors.RED)
            raise typer.Exit(1)
        write_kubeconfig.mkdir(parents=True, exist_ok=True)

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
            user_yaml_file = chart.user_file(gitops_path, dev)
            
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
                    
                    namespaces_list = [slug if slug == env else f"{slug}-{env}" for env in dev_envs]
                    typer.echo(f"[WRITE] Token k8s généré pour {dev} (accès: {dev_envs})")

                    # Génération du kubeconfig multi-environnements
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
    namespace: {namespaces_list[0]}
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

                    # Collecter credentials : le kubeconfig complet est partagé via Password Pusher
                    cred.collect("k8s", dev, tok, api_server, note=f"ns {','.join(namespaces_list)}", payload=kubeconf)

                    if write_kubeconfig:
                        if str(write_kubeconfig) == "-":
                            typer.echo(f"\n--- kubeconfig {dev} ---\n" + kubeconf)
                        else:
                            out_path = write_kubeconfig / f"{dev}.kubeconfig"
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
    eso: bool = typer.Option(True, "--eso/--avp", help="Secrets Vault : --eso (défaut) External Secrets, sans AppRole AVP ; --avp ancien modèle argocd-vault-plugin, sans ESO"),
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
    if eso and any("vaultCredentials" in json.loads(f.read_text()) for f in apps_dir.glob("*.json")):
        typer.secho("[WARN] Projet existant en AVP (vaultCredentials) : les nouveaux environnements seront rendus "
                    "sans AVP. Utilisez --avp si la chart contient des <path:...>.", fg=typer.colors.YELLOW)
    _eso_precheck(eso, gitops_path, slug, sorted(really_new))
    
    # 5. CRÉATION NAMESPACES : Seulement les nouveaux environnements
    if api_server and api_token:
        ns_url = f"{api_server.rstrip('/')}/api/v1/namespaces"
        headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json",
        }
        for env in sorted(really_new):
            ns = slug if slug == env else f"{slug}-{env}"
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
        _write_app_json(apps_dir / f"{env}.json", slug, env, repo_url, eso)
    gitops.generate_appprojects(gitops_path)
    
    # 7. VAULT KV : Merger avec les environnements existants (la logique vault.provision fait déjà le merge)
    if skip_vault:
        typer.echo("[SKIP] Configuration Vault ignorée (--skip-vault)")
    elif not vault_addr or not vault_token:
        typer.echo("[INFO] Aucune adresse ou token Vault fourni : configuration Vault non effectuée")
    else:
        # Appeler vault.provision avec TOUS les environnements (existants + nouveaux)
        all_env_list = sorted(existing_envs | really_new)
        vault.provision(slug, all_env_list, addr=vault_addr, token=vault_token, devs=dev_list, avp=not eso)

    # 7bis. External Secrets (mode --eso) for the new environments only
    if eso:
        _eso_ensure(gitops_path, slug, sorted(really_new), vault_addr, vault_token, skip_vault)
    
    # 8. ROLEBINDINGS K8S : Ajouter les nouveaux environnements pour les développeurs existants
    if dev_list:
        _write_user_accounts(gitops_path, slug, dev_list, existing_envs | really_new, really_new)
    
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

    # Distinguer devs existants globalement (autres projets) vs vraiment nouveaux
    truly_new = {d for d in really_new if is_new_developer(gitops_path, d)}
    existing_globally = really_new - truly_new

    if existing_globally:
        typer.echo(f"[INFO] Devs existant déjà (rattachement au projet): {sorted(existing_globally)}")

    if truly_new:
        typer.secho(
            f"[WARN] Devs inconnus, seront créés: {sorted(truly_new)}",
            fg=typer.colors.YELLOW,
        )
        if not typer.confirm("Confirmer la création de ces nouveaux développeurs ?", default=False):
            typer.secho("[ABORT] Création annulée par l'utilisateur.", fg=typer.colors.RED)
            raise typer.Exit(1)

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

    # 6. K8S SERVICEACCOUNT : fichier pour chaque nouveau développeur, namespaces du projet pour les autres
    _write_user_accounts(gitops_path, slug, sorted(really_new), existing_envs, existing_envs)

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
