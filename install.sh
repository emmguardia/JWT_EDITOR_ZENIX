#!/usr/bin/env bash
# Installe JWT Editor — Zenix Web sur Ubuntu/Debian :
#  1) dépendances système pour pywebview (GTK + WebKit)
#  2) venv Python + pywebview
#  3) lanceur .desktop avec icône dans le menu d'applications
#
# Usage : ./install.sh            (installe + propose de lancer)
#         ./install.sh --no-launch
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$DIR/.venv"
PY="${PYTHON:-python3}"

LAUNCH=1
[[ "${1:-}" == "--no-launch" ]] && LAUNCH=0

echo "==> JWT Editor — Zenix Web : installation"

# ---------------------------------------------------------------------------
# 1) Dépendances système (pywebview a besoin du binding GObject + WebKitGTK)
# ---------------------------------------------------------------------------
need_sys=(python3-venv python3-gi python3-gi-cairo gir1.2-gtk-3.0)
# WebKitGTK : le nom du paquet varie selon la version d'Ubuntu
webkit_candidates=(gir1.2-webkit2-4.1 gir1.2-webkit2-4.0 gir1.2-webkit-6.0)

missing_check() {
  # vrai si le binding gi WebKit est importable
  "$PY" - <<'PYEOF' 2>/dev/null
import gi
ok = False
for v in ("4.1", "4.0", "6.0"):
    try:
        gi.require_version("WebKit2", v); ok = True; break
    except Exception:
        pass
    try:
        gi.require_version("WebKit", "6.0"); ok = True; break
    except Exception:
        pass
raise SystemExit(0 if ok else 1)
PYEOF
}

if command -v apt-get >/dev/null 2>&1; then
  if ! missing_check; then
    echo "==> Installation des dépendances système (GTK/WebKit) — mot de passe demandé"
    SUDO=""
    if [[ $EUID -ne 0 ]]; then
      if command -v sudo >/dev/null 2>&1; then SUDO="sudo";
      elif command -v pkexec >/dev/null 2>&1; then SUDO="pkexec"; fi
    fi
    # on tente d'installer un paquet WebKit parmi les candidats
    webkit_pkg=""
    for c in "${webkit_candidates[@]}"; do
      if apt-cache show "$c" >/dev/null 2>&1; then webkit_pkg="$c"; break; fi
    done
    $SUDO apt-get update
    $SUDO apt-get install -y "${need_sys[@]}" ${webkit_pkg:-}
  else
    echo "==> Dépendances GTK/WebKit déjà présentes."
  fi
else
  echo "!! apt-get introuvable : installe manuellement python3-venv, python3-gi et WebKitGTK."
fi

# ---------------------------------------------------------------------------
# 2) venv + pywebview  (--system-site-packages pour voir le binding gi système)
# ---------------------------------------------------------------------------
if [[ ! -d "$VENV" ]]; then
  echo "==> Création du venv"
  "$PY" -m venv --system-site-packages "$VENV"
fi
# shellcheck disable=SC1091
source "$VENV/bin/activate"
pip install --upgrade pip >/dev/null
pip install -r "$DIR/requirements.txt"
deactivate

# ---------------------------------------------------------------------------
# 3) Lanceur .desktop + icône
# ---------------------------------------------------------------------------
APPS_DIR="$HOME/.local/share/applications"
mkdir -p "$APPS_DIR"
DESKTOP="$APPS_DIR/jwt-editor-zenix.desktop"
cat > "$DESKTOP" <<EOF
[Desktop Entry]
Type=Application
Name=JWT Editor — Zenix Web
Comment=Décodeur / éditeur JWT + crack HMAC (hashcat)
Exec=$DIR/run.sh
Icon=$DIR/assets/icon.svg
Terminal=false
Categories=Development;Security;Utility;
StartupNotify=true
EOF
chmod +x "$DESKTOP" "$DIR/run.sh" "$DIR/install.sh"
# rafraîchit le menu si possible
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$APPS_DIR" >/dev/null 2>&1 || true

echo "==> Installé."
echo "    Lanceur : $DESKTOP"
echo "    (cherche « JWT Editor » dans ton menu d'applications, ou lance ./run.sh)"

if [[ "$LAUNCH" -eq 1 ]]; then
  echo "==> Lancement…"
  exec "$DIR/run.sh"
fi
