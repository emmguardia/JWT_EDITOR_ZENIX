#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JWT Editor — Zenix Web
Application de bureau (pywebview) : décodage/édition/re-signature de JWT
(100 % côté client en JS) + crack du secret HMAC via hashcat (ou John, option).

Le backend Python ne sert QUE pour le crack et l'installation de hashcat :
 - rien du token n'est envoyé sur le réseau ; il est juste écrit dans un
   fichier temporaire local pour être passé à hashcat/john.
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile

import webview  # pywebview

# Dossier contenant l'UI web
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WEB_DIR = os.path.join(BASE_DIR, "web")
INDEX = os.path.join(WEB_DIR, "index.html")

# Mode hashcat pour les JWT HMAC (HS256/384/512)
HASHCAT_MODE = "16500"
# Garde-fou : on ne laisse pas un crack tourner indéfiniment (secondes)
CRACK_TIMEOUT = 60 * 20  # 20 min


# Dossier des wordlists gérées par l'app. On importe dedans (copie) ; l'utilisateur
# peut ensuite supprimer ses fichiers d'origine (Téléchargements, etc.).
WORDLISTS_DIR = os.path.join(BASE_DIR, "wordlists")
os.makedirs(WORDLISTS_DIR, exist_ok=True)

# Types de dialogue fichier : enum FileDialog (pywebview récent), repli sur les
# anciennes constantes si besoin.
try:
    DLG_OPEN = webview.FileDialog.OPEN
    DLG_SAVE = webview.FileDialog.SAVE
except AttributeError:  # pragma: no cover
    DLG_OPEN = webview.OPEN_DIALOG
    DLG_SAVE = webview.SAVE_DIALOG


def safe_name(name: str):
    """Renvoie un simple nom de fichier sûr (anti-traversée) ou None."""
    base = os.path.basename(name or "")
    if not base or base in (".", "..") or "/" in base or "\\" in base:
        return None
    return base


def unique_dst(dst: str) -> str:
    """Évite d'écraser un fichier existant en suffixant -1, -2, …"""
    if not os.path.exists(dst):
        return dst
    root, ext = os.path.splitext(dst)
    i = 1
    while os.path.exists("%s-%d%s" % (root, i, ext)):
        i += 1
    return "%s-%d%s" % (root, i, ext)


class Api:
    """Méthodes appelables depuis le JS via window.pywebview.api.*"""

    # ---- détection / installation de hashcat -----------------------------
    def check_hashcat(self) -> bool:
        return shutil.which("hashcat") is not None

    def check_john(self) -> bool:
        return shutil.which("john") is not None

    # ---- gestion des wordlists -------------------------------------------
    def _window(self):
        return webview.windows[0] if webview.windows else None

    def list_wordlists(self) -> dict:
        """Liste les wordlists importées dans wordlists/ (nom, taille, date)."""
        items = []
        try:
            for n in sorted(os.listdir(WORDLISTS_DIR)):
                p = os.path.join(WORDLISTS_DIR, n)
                if os.path.isfile(p):
                    st = os.stat(p)
                    items.append({"name": n, "size": st.st_size, "mtime": int(st.st_mtime)})
        except OSError as e:
            return {"items": [], "error": str(e)}
        return {"items": items, "dir": WORDLISTS_DIR}

    def import_wordlist(self) -> dict:
        """Ouvre un sélecteur de fichiers natif et copie la/les wordlist(s)
        choisie(s) dans wordlists/."""
        win = self._window()
        if not win:
            return {"ok": False, "error": "fenêtre indisponible"}
        try:
            paths = win.create_file_dialog(DLG_OPEN, allow_multiple=True)
        except Exception as e:  # pragma: no cover
            return {"ok": False, "error": str(e)}
        if not paths:
            return {"ok": False, "cancelled": True}

        added, errors = [], []
        for src in paths:
            base = safe_name(src)
            if not base:
                errors.append("nom invalide : %s" % src)
                continue
            dst = os.path.join(WORDLISTS_DIR, base)
            # déjà dans le dossier de l'app : rien à copier
            if os.path.abspath(src) == os.path.abspath(dst):
                added.append(base)
                continue
            dst = unique_dst(dst)
            try:
                shutil.copy2(src, dst)
                added.append(os.path.basename(dst))
            except OSError as e:
                errors.append("%s : %s" % (base, e))
        return {"ok": len(added) > 0, "added": added, "errors": errors}

    def delete_wordlist(self, name: str) -> dict:
        base = safe_name(name)
        if not base:
            return {"ok": False, "error": "nom invalide"}
        p = os.path.join(WORDLISTS_DIR, base)
        if not os.path.isfile(p):
            return {"ok": False, "error": "introuvable"}
        try:
            os.remove(p)
        except OSError as e:
            return {"ok": False, "error": str(e)}
        return {"ok": True}

    def export_wordlist(self, name: str) -> dict:
        """Copie une wordlist gérée vers un emplacement choisi (sélecteur natif)."""
        base = safe_name(name)
        if not base:
            return {"ok": False, "error": "nom invalide"}
        src = os.path.join(WORDLISTS_DIR, base)
        if not os.path.isfile(src):
            return {"ok": False, "error": "introuvable"}
        win = self._window()
        if not win:
            return {"ok": False, "error": "fenêtre indisponible"}
        try:
            dest = win.create_file_dialog(DLG_SAVE, save_filename=base)
        except Exception as e:  # pragma: no cover
            return {"ok": False, "error": str(e)}
        if not dest:
            return {"ok": False, "cancelled": True}
        if isinstance(dest, (list, tuple)):
            dest = dest[0]
        try:
            shutil.copy2(src, dest)
        except OSError as e:
            return {"ok": False, "error": str(e)}
        return {"ok": True, "path": dest}

    def install_hashcat(self) -> dict:
        """
        Installe hashcat via apt, avec élévation graphique (pkexec).
        Ubuntu/Debian uniquement. Renvoie {ok, output, error}.
        """
        if self.check_hashcat():
            return {"ok": True, "output": "hashcat est déjà installé."}

        if shutil.which("apt-get") is None:
            return {
                "ok": False,
                "error": "apt-get introuvable : installe hashcat avec le gestionnaire "
                         "de paquets de ta distribution.",
            }

        # pkexec ouvre une fenêtre graphique de demande de mot de passe.
        if shutil.which("pkexec") is None:
            return {
                "ok": False,
                "error": "pkexec introuvable. Installe hashcat manuellement : "
                         "sudo apt install hashcat",
            }

        cmd = ["pkexec", "sh", "-c", "apt-get update && apt-get install -y hashcat"]
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=CRACK_TIMEOUT
            )
        except subprocess.TimeoutExpired:
            return {"ok": False, "error": "délai dépassé pendant l'installation."}
        except Exception as e:  # pragma: no cover
            return {"ok": False, "error": str(e)}

        output = (proc.stdout or "") + (proc.stderr or "")
        if proc.returncode == 0 and self.check_hashcat():
            return {"ok": True, "output": output}
        # code 126/127 pkexec = annulé / non autorisé
        if proc.returncode in (126, 127):
            return {"ok": False, "error": "installation annulée ou non autorisée.", "output": output}
        return {"ok": False, "error": "apt a échoué (code %s)." % proc.returncode, "output": output}

    # ---- crack ------------------------------------------------------------
    def crack(self, token: str, wordlist_name: str, use_john: bool = False) -> dict:
        """
        Écrit le JWT dans un fichier temporaire et lance hashcat (ou John)
        contre une wordlist importée (nom dans wordlists/).
        Renvoie {found, secret, output, error}.
        """
        token = (token or "").strip()
        base = safe_name(wordlist_name)
        if not base:
            return {"found": False, "error": "wordlist invalide."}
        wordlist = os.path.join(WORDLISTS_DIR, base)

        if not token or token.count(".") < 2:
            return {"found": False, "error": "JWT invalide."}
        if not os.path.isfile(wordlist):
            return {"found": False, "error": "Wordlist introuvable : %s" % base}

        engine = "john" if use_john else "hashcat"
        if shutil.which(engine) is None:
            return {"found": False, "error": "%s n'est pas installé." % engine}

        # fichier temporaire contenant le hash (= le JWT brut pour -m 16500)
        tmp = tempfile.NamedTemporaryFile(
            mode="w", prefix="jwtzenix_", suffix=".hash", delete=False
        )
        try:
            tmp.write(token + "\n")
            tmp.close()
            if use_john:
                return self._crack_john(tmp.name, wordlist)
            return self._crack_hashcat(tmp.name, wordlist)
        finally:
            # nettoyage du fichier temporaire + potfiles résiduels
            for p in (tmp.name,):
                try:
                    os.remove(p)
                except OSError:
                    pass

    def _crack_hashcat(self, hashfile: str, wordlist: str) -> dict:
        # potfile dédié pour isoler le résultat de ce run
        potfile = hashfile + ".pot"
        base = [
            "hashcat", "-a", "0", "-m", HASHCAT_MODE,
            "--potfile-path", potfile, "--force",
            hashfile, wordlist,
        ]
        try:
            run = subprocess.run(base, capture_output=True, text=True, timeout=CRACK_TIMEOUT)
        except subprocess.TimeoutExpired:
            self._rm(potfile)
            return {"found": False, "error": "délai de crack dépassé (%ss)." % CRACK_TIMEOUT}
        except Exception as e:  # pragma: no cover
            self._rm(potfile)
            return {"found": False, "error": str(e)}

        out = (run.stdout or "") + "\n" + (run.stderr or "")

        # --show relit le potfile et donne "jwt:secret"
        show = subprocess.run(
            ["hashcat", "-m", HASHCAT_MODE, "--potfile-path", potfile, "--show", hashfile],
            capture_output=True, text=True,
        )
        self._rm(potfile)
        secret = self._parse_show(show.stdout)
        full = out + "\n--- show ---\n" + (show.stdout or "")
        if secret is not None:
            return {"found": True, "secret": secret, "output": full}
        # hashcat renvoie 1 quand "exhausted" sans trouver : ce n'est pas une erreur
        return {"found": False, "output": full}

    def _crack_john(self, hashfile: str, wordlist: str) -> dict:
        """Fallback expérimental John the Ripper (voir README)."""
        try:
            run = subprocess.run(
                ["john", "--wordlist=%s" % wordlist, hashfile],
                capture_output=True, text=True, timeout=CRACK_TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            return {"found": False, "error": "délai de crack dépassé (%ss)." % CRACK_TIMEOUT}
        except Exception as e:  # pragma: no cover
            return {"found": False, "error": str(e)}

        show = subprocess.run(["john", "--show", hashfile], capture_output=True, text=True)
        out = (run.stdout or "") + (run.stderr or "") + "\n--- show ---\n" + (show.stdout or "")
        # john --show : "fichier:secret" sur la 1re ligne utile
        secret = None
        for line in (show.stdout or "").splitlines():
            line = line.strip()
            if not line or line.endswith("password hash cracked, 0 left"):
                continue
            if ":" in line and "cracked" not in line:
                secret = line.split(":", 1)[1]
                break
        if secret:
            return {"found": True, "secret": secret, "output": out}
        return {"found": False, "output": out}

    # ---- utilitaires ------------------------------------------------------
    @staticmethod
    def _parse_show(show_stdout: str):
        """Extrait le secret depuis la sortie de `hashcat --show` (token:secret)."""
        if not show_stdout:
            return None
        for line in show_stdout.splitlines():
            line = line.rstrip("\n")
            if not line:
                continue
            # format attendu : <jwt>:<secret> ; le JWT contient 2 points,
            # le secret est tout ce qui suit le 3e ':'
            # on retrouve le secret après la dernière occurrence du token.
            m = re.match(r"^(eyJ[^\s:]+\.[^\s:]+\.[^\s:]+):(.*)$", line)
            if m:
                return m.group(2)
        return None

    @staticmethod
    def _rm(path):
        try:
            os.remove(path)
        except OSError:
            pass


def main():
    if not os.path.isfile(INDEX):
        sys.stderr.write("Interface introuvable : %s\n" % INDEX)
        sys.exit(1)

    api = Api()
    webview.create_window(
        "JWT Editor — Zenix Web",
        INDEX,
        js_api=api,
        width=1180,
        height=900,
        min_size=(720, 600),
        background_color="#0d1117",
    )
    # debug=True ouvre l'inspecteur (utile en dev) ; mettre False pour l'usage normal.
    webview.start(debug=("--debug" in sys.argv))


if __name__ == "__main__":
    main()
