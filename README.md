# Kubic CLI

> Outil d'automatisation pour la gestion de projets Kubernetes avec Argo CD et Vault

Kubic CLI simplifie la création et la gestion de projets Kubernetes en automatisant la configuration de :
- 🗂️ **GitOps** : Arborescence de manifests pour Argo CD
- 🔐 **Vault** : Policies, AppRoles et secrets
- ☸️ **Kubernetes** : Namespaces, ServiceAccounts et RoleBindings
- 🔑 **Accès développeurs** : Génération automatique de tokens et kubeconfigs

---

## Installation

### Prérequis

- Docker ≥ 20.x
- Git ≥ 2.x
- Accès à un cluster Kubernetes
- (Optionnel) Accès à une instance Vault

### Configuration

#### 1. Cloner le repository

```bash
git clone https://github.com/votre-org/kubic-cli.git
cd kubic-cli
```

#### 2. Créer la structure de secrets

```bash
mkdir -p secrets
```

Créer `secrets/.env` avec vos variables d'environnement :

```bash
# Vault (optionnel)
VAULT_ADDR=https://vault.example.com
VAULT_TOKEN=your-vault-token

# Kubernetes API
KUBE_API=https://kubernetes.example.com:6443
KUBE_API_TOKEN=your-k8s-admin-token

# Argo CD (optionnel)
ARGOCD_URL=https://argocd.example.com
ARGOCD_TOKEN=your-argocd-token
```

Créer `secrets/ca.crt` avec le certificat CA de votre cluster Kubernetes.

#### 3. Configurer votre dépôt GitOps

Par défaut, l'outil cherche la structure GitOps dans `shared-k8s-prd/`. Vous pouvez :

**Option A : Créer un dossier local**
```bash
mkdir -p shared-k8s-prd/apps
mkdir -p shared-k8s-prd/helm/argocd/templates/{k8s-accounts,repository,vault}
```

**Option B : Utiliser un submodule Git**
```bash
git submodule add git@github.com:votre-org/gitops-repo.git shared-k8s-prd
```

**Option C : Spécifier un autre chemin**
```bash
export KUBIC_CLI_GITOPS_PATH=/path/to/your/gitops
```

#### Structure GitOps attendue

```
shared-k8s-prd/
├── apps/
│   └── <project-name>/
│       ├── dev.json
│       └── prod.json
└── helm/
    └── argocd/
        └── templates/
            ├── argocd-cm.yaml
            ├── argocd-rbac-cm.yaml
            ├── k8s-accounts/
            ├── repository/
            └── vault/
```

---

## Utilisation rapide

### Créer un nouveau projet

```bash
./kubic-cli create-project myapp \
  --repo-url git@github.com:org/myapp-chart.git \
  --envs dev,staging,prod \
  --devs alice,bob
```

**Ce qui est créé :**
- ✅ Fichiers JSON dans `apps/myapp/` pour chaque environnement
- ✅ Namespaces Kubernetes (`myapp-dev`, `myapp-staging`, `myapp-prod`)
- ✅ Secrets Vault (Repository, credentials Argo CD)
- ✅ ServiceAccounts et RoleBindings pour alice et bob
- ✅ Configuration Argo CD (comptes, RBAC)
- ✅ Vault policies et userpass pour les développeurs

### Ajouter un environnement

```bash
./kubic-cli add-environment myapp --envs preprod
```

### Ajouter un développeur

```bash
./kubic-cli add-dev myapp --devs charlie
```

### Générer les tokens et kubeconfigs

Après avoir déployé via GitOps (commit → push → ArgoCD sync) :

```bash
./kubic-cli setup-devs myapp \
  --devs alice,bob,charlie \
  --cluster-ca secrets/ca.crt \
  --write-kubeconfig ./configs/ \
  --duration 2160h
```

**Résultat :**
- 🎫 Tokens Kubernetes générés (valides 90 jours)
- 📄 Kubeconfigs multi-environnements créés dans `./configs/`
- 🔗 Liens Password Pusher pour partager les credentials de manière sécurisée

---

## Commandes disponibles

| Commande | Description |
|----------|-------------|
| `create-project` | Crée un nouveau projet avec environnements et développeurs |
| `add-environment` | Ajoute des environnements à un projet existant |
| `add-dev` | Ajoute des développeurs à un projet existant |
| `setup-devs` | Génère tokens K8s et kubeconfigs pour développeurs existants |

Toutes les commandes sont **idempotentes** et peuvent être relancées sans risque.

### Aide détaillée

```bash
./kubic-cli --help
./kubic-cli create-project --help
./kubic-cli add-dev --help
```

---

## Workflows typiques

### Workflow 1 : Nouveau projet complet

```bash
# 1. Créer le projet
./kubic-cli create-project myapp \
  --repo-url git@github.com:org/myapp.git \
  --envs dev,prod \
  --devs alice,bob

# 2. Déployer via GitOps
cd shared-k8s-prd
git add .
git commit -m "Add myapp project"
git push
# → Attendre ArgoCD sync

# 3. Générer les accès développeurs
./kubic-cli setup-devs myapp \
  --devs alice,bob \
  --cluster-ca secrets/ca.crt \
  --write-kubeconfig ./configs/

# 4. Distribuer les kubeconfigs
# Les fichiers sont dans ./configs/alice.kubeconfig et ./configs/bob.kubeconfig
```

### Workflow 2 : Ajouter un environnement

```bash
# 1. Ajouter l'environnement
./kubic-cli add-environment myapp --envs staging

# 2. Déployer
cd shared-k8s-prd && git add . && git commit -m "Add staging" && git push

# 3. Régénérer les kubeconfigs (auto-détection du nouvel environnement)
./kubic-cli setup-devs myapp --devs alice,bob --cluster-ca secrets/ca.crt --write-kubeconfig ./configs/
```

### Workflow 3 : Ajouter un développeur

```bash
# 1. Ajouter le développeur
./kubic-cli add-dev myapp --devs charlie

# 2. Déployer
cd shared-k8s-prd && git add . && git commit -m "Add charlie" && git push

# 3. Générer ses accès
./kubic-cli setup-devs myapp --devs charlie --cluster-ca secrets/ca.crt --write-kubeconfig ./configs/
```

---

## Configuration avancée

### Variables d'environnement

Toutes les options peuvent être définies via variables d'environnement :

| Variable | Description |
|----------|-------------|
| `VAULT_ADDR` | URL de Vault |
| `VAULT_TOKEN` | Token admin Vault |
| `KUBE_API` | URL du serveur API Kubernetes |
| `KUBE_API_TOKEN` | Token Bearer pour l'API Kubernetes |
| `ARGOCD_URL` | URL du serveur Argo CD |
| `ARGOCD_TOKEN` | Token Bearer admin Argo CD |
| `KUBIC_CLI_GITOPS_PATH` | Chemin du dépôt GitOps (défaut: `shared-k8s-prd`) |
| `KUBIC_CLI_YAML_HEADER` | Header ajouté aux fichiers YAML générés |

### Fichier de configuration

Créer `secrets/config.toml` (optionnel) :

```toml
yaml_header = "# Generated by kubic-cli\n"
gitops_path = "my-gitops-repo"
pw_push_url = "https://pwpush.com/p.json"
```

### Kubeconfig multi-environnements

Les kubeconfigs générés contiennent des contextes pour tous les environnements :

```bash
# Lister les contextes disponibles
kubectl config get-contexts --kubeconfig configs/alice.kubeconfig

# Changer de contexte
kubectl config use-context alice-dev@kubic --kubeconfig configs/alice.kubeconfig
kubectl config use-context alice-prod@kubic --kubeconfig configs/alice.kubeconfig
```

---

## Architecture et sécurité

### Séparation des responsabilités

**Commandes de création/modification** (écrivent dans GitOps + Vault) :
- `create-project` : Création initiale
- `add-environment` : Ajout d'environnements
- `add-dev` : Ajout de développeurs

**Commande de génération** (readonly pour GitOps) :
- `setup-devs` : Génération des tokens et kubeconfigs

### Bonnes pratiques

✅ **Ne commitez jamais** :
- Les fichiers dans `secrets/`
- Les kubeconfigs générés
- Les tokens ou mots de passe

✅ **Utilisez git-crypt** pour chiffrer les secrets si vous devez les versionner

✅ **Rotation des tokens** : Les tokens K8s ont une durée limitée (configurée via `--duration`)

✅ **Password Pusher** : Partagez les credentials via les liens auto-expirables générés

---

## Options utiles

### Skip Vault

Si vous n'utilisez pas Vault :

```bash
./kubic-cli create-project myapp \
  --repo-url git@... \
  --envs dev,prod \
  --skip-vault
```

### Personnaliser le nom du cluster

```bash
./kubic-cli setup-devs myapp \
  --devs alice \
  --cluster-name production-cluster \
  --cluster-ca secrets/ca.crt \
  --write-kubeconfig ./configs/
```

### Durée personnalisée des tokens

```bash
# Token valide 30 jours (720 heures)
./kubic-cli setup-devs myapp \
  --devs alice \
  --duration 720h \
  --cluster-ca secrets/ca.crt \
  --write-kubeconfig ./configs/
```

### Afficher le kubeconfig dans le terminal

```bash
./kubic-cli setup-devs myapp \
  --devs alice \
  --cluster-ca secrets/ca.crt \
  --write-kubeconfig -
```

---

## Dépannage

### "ServiceAccount not found"

Le ServiceAccount n'a pas encore été créé dans le cluster. Assurez-vous que :
1. Les fichiers GitOps ont été committés et pushés
2. Argo CD a synchronisé l'application
3. Le ServiceAccount existe : `kubectl get sa -n default`

### "Aucun environnement détecté"

La commande `setup-devs` n'a pas trouvé de RoleBindings. Vérifiez que :
1. Le développeur a été ajouté avec `create-project` ou `add-dev`
2. Les fichiers GitOps ont été déployés
3. Le fichier `user-{dev}.yaml` existe dans `k8s-accounts/`

### "--cluster-ca est requis"

Le certificat CA est nécessaire pour générer des tokens. Assurez-vous que `secrets/ca.crt` existe ou utilisez `--cluster-ca /path/to/ca.crt`.

---

## Développement

### Lancer les tests

```bash
docker build -t kubic-cli:local .
docker run --rm kubic-cli:local pytest
```

### Structure du projet

```
kubic-cli/
├── kubic_cli/              # Code source Python
│   ├── main.py            # Commandes CLI (Typer)
│   ├── vault.py           # Intégration Vault
│   ├── gitops.py          # Gestion fichiers GitOps
│   ├── utils.py           # Fonctions utilitaires
│   ├── config.py          # Configuration
│   ├── cred.py            # Gestion credentials
│   └── templates/         # Templates Jinja2
├── tests/                  # Tests unitaires
├── Dockerfile             # Image Docker
└── kubic-cli              # Wrapper shell
```

---

## Contribution

Les contributions sont les bienvenues ! Merci de :

1. Fork le projet
2. Créer une branche pour votre feature (`git checkout -b feature/amazing`)
3. Commiter vos changements (`git commit -m 'Add amazing feature'`)
4. Pousser vers la branche (`git push origin feature/amazing`)
5. Ouvrir une Pull Request

---

## License

[Choisir une license : MIT, Apache 2.0, etc.]

---

## Support

- 📖 Documentation : Consultez `./kubic-cli <command> --help`
- 🐛 Issues : [GitHub Issues](https://github.com/votre-org/kubic-cli/issues)
- 💬 Discussions : [GitHub Discussions](https://github.com/votre-org/kubic-cli/discussions)

---

**Fait avec ❤️ pour simplifier la gestion Kubernetes**
