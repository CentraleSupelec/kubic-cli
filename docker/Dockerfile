FROM python:3.11-slim AS runtime

# Disable Python stdout/stderr buffering & pip cache
ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    # Emplacement par défaut du fichier TOML de configuration
    KUBIC_CLI_CONFIG=/run/secrets/config.toml

WORKDIR /app

# Dépendances Python (installées avant copie du code pour cache efficace)
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Code source
COPY kubic_cli/ kubic_cli/

# Ajout du dossier de travail au PYTHONPATH (utile si la commande est lancée
# avec -v $(pwd):/app pour voir les modifications locales)
ENV PYTHONPATH=/app

# Commande par défaut : le cli kubic
ENTRYPOINT ["python", "-m", "kubic_cli.main"] 