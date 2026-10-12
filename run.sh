#!/usr/bin/env bash
# Lance JWT Editor — Zenix Web. Crée le venv au premier lancement si besoin.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

VENV="$DIR/.venv"

if [[ ! -x "$VENV/bin/python" ]]; then
  echo "[JWT Editor] Premier lancement : préparation de l'environnement…"
  "$DIR/install.sh" --no-launch
fi

# shellcheck disable=SC1091
source "$VENV/bin/activate"
exec python "$DIR/app.py" "$@"
