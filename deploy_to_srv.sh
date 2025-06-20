#!/usr/bin/env bash
set -euo pipefail
SRC=~/Projects/bmad-bridge/
DST=/srv/bmad-github-bridge/github-bridge/
rsync -av --delete \
  --exclude '.git' \
  --exclude 'tests' \
  --exclude 'docker-compose.dev.yml' \
  "$SRC" "$DST"
/usr/bin/docker compose -f /srv/bmad-github-bridge/docker-compose.yml up -d --build 