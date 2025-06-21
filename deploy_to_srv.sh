#!/usr/bin/env bash
set -euo pipefail

SRC=~/Projects/bmad-bridge/
DST=/srv/bmad-github-bridge/

# Create full destination directory structure if it doesn't exist
sudo mkdir -p "$DST"

# Sync files to production server
sudo rsync -av --delete \
  --exclude '.git' \
  --exclude 'tests' \
  --exclude 'docker-compose.dev.yml' \
  --exclude 'nginx' \
  --exclude 'venv' \
  --exclude '.cursor' \
  --exclude '__pycache__' \
  "$SRC" "$DST"

# Deploy using production compose file
sudo /usr/bin/docker compose -f "${DST}/docker-compose.yml" up -d --build 