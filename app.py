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


def expand(path: str) -> str:
    """Développe ~ et les variables d'environnement d'un chemin."""
    return os.path.expanduser(os.path.expandvars(path or ""))


class Api:
    """Méthodes appelables depuis le JS via window.pywebview.api.*"""

    # ---- détection / installation de hashcat -----------------------------
    def check_hashcat(self) -> bool:
        return shutil.which("hashcat") is not None

    def check_john(self) -> bool:
        return shutil.which("john") is not None

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
    def crack(self, token: str, wordlist: str, use_john: bool = False) -> dict:
        """
        Écrit le JWT dans un fichier temporaire et lance hashcat (ou John).
        Renvoie {found, secret, output, error}.
        """
        token = (token or "").strip()
        wordlist = expand(wordlist)

        if not token or token.count(".") < 2:
            return {"found": False, "error": "JWT invalide."}
        if not os.path.isfile(wordlist):
            return {"found": False, "error": "Wordlist introuvable : %s" % wordlist}

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
