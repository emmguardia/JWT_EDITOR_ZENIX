# JWT Editor — Zenix Web

Application de bureau (Linux) pour **décoder, éditer, re-signer** des JSON Web Tokens
— comme [jwt.io](https://jwt.io) mais **100 % en local chez toi** — avec en plus
une fonction de **crack du secret HMAC via hashcat**.

Pas de serveur, pas de navigateur : un double-clic sur l'icône ouvre une vraie
fenêtre. Le décodage, la vérification et la re-signature se font entièrement
côté client (JS) : **aucun token ne quitte ta machine**. Seul le crack appelle
hashcat en local.

![thème sombre, badge Zenix Web](assets/icon.svg)

## Fonctionnalités

- **Décodage temps réel** : colle un JWT, vois instantanément Header, Payload et
  Signature. Coloration des 3 parties comme jwt.io. Les claims `iat`/`exp`/`nbf`
  sont affichés en dates lisibles (avec marquage « EXPIRÉ »).
- **Vérification** HS256 / HS384 / HS512 : saisis un secret → VALIDE / INVALIDE.
- **Édition + re-signature** : modifie Header et Payload, clique *Re-signer* pour
  régénérer un token signé avec le secret et l'algo du header. Gère aussi
  `alg:none` (token sans signature). Bouton *Copier*.
- **Crack du secret HMAC** via `hashcat -a 0 -m 16500` (mode JWT). Si le secret
  est dans la wordlist, il s'affiche et est pré-rempli pour vérifier/re-signer.
  Détection automatique de l'absence de hashcat + bouton d'installation.
- **Gestionnaire de wordlists** intégré : *Importer* copie n'importe quel fichier
  dans le dossier `wordlists/` de l'app (tu peux ensuite supprimer l'original de
  tes Téléchargements) ; *Exporter* en récupère une copie ailleurs ; *Supprimer*
  la retire du dossier. On choisit la wordlist à utiliser dans la liste.
- **Onglet « Mot de passe »** : crack d'un hash quelconque avec hashcat, en
  **brute-force** (masque : jeux de caractères `a-z/A-Z/0-9/spéciaux` + longueur max)
  ou par **dictionnaire** (mêmes wordlists). Choix du type de hash
  (MD5, SHA1, SHA-256/512, NTLM, bcrypt, md5crypt, sha512crypt).
- **Onglet « URL »** : brute-force d'un login HTTP (façon `hydra http-post-form`),
  en Python pur. URL + corps avec marqueurs `^USER^`/`^PASS^`, détection du succès
  par texte (présent/absent) ou code HTTP, en-têtes custom, threads, timeout,
  option TLS non vérifié. **Sur cibles autorisées uniquement.**

## Prérequis

- **Python 3** (venv).
- Dépendances système pour l'affichage (GTK + WebKitGTK) — installées
  automatiquement par `install.sh` sur Ubuntu/Debian.
- **hashcat** pour le crack. S'il manque, l'app propose de l'installer
  (`apt`, via une fenêtre de mot de passe `pkexec`).

## Installation / lancement

```bash
cd ~/Github/JWT_EDITOR_ZENIX
./install.sh
```

`install.sh` :
1. installe les dépendances système GTK/WebKit (demande le mot de passe),
2. crée un venv et installe `pywebview`,
3. pose un lanceur **« JWT Editor — Zenix Web »** dans ton menu d'applications
   (avec icône), puis lance l'app.

Ensuite, lancement normal : **double-clic sur l'icône** dans le menu, ou :

```bash
./run.sh
```

## Workflow

1. **Coller** le JWT dans *Token encodé* → Header / Payload / Signature s'affichent.
2. **Vérifier** : saisir le secret, bouton *Vérifier* → VALIDE / INVALIDE.
3. **Éditer & re-signer** : modifier le JSON, bouton *Re-signer* → nouveau token.
4. **Cracker** : le token est repris automatiquement ; choisir la wordlist,
   bouton *Cracker*. Un spinner tourne pendant hashcat. Le secret trouvé
   s'affiche (ou « non trouvé »).

### Token de test

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Im1hcmMiLCJpYXQiOjE3OTE3OTgyNzF9.4knehEXkOyKOUsmUEcRHc4oSJEBJGeabLVzUDzXQQ9k
```

Décodage attendu :
- Header : `{"alg":"HS256","typ":"JWT"}`
- Payload : `{"username":"marc","iat":1791798271}`

C'est un HS256 : lance le crack avec une wordlist (ex. rockyou) pour retrouver
le secret, puis *Vérifier* pour confirmer.

## Crack : détails

- Mode hashcat **16500** (JWT HMAC HS256/384/512), attaque par dictionnaire (`-a 0`),
  `--force` activé, potfile isolé par run, timeout de 20 min.
- Le JWT est écrit dans un fichier temporaire local (supprimé après), jamais
  transmis sur le réseau.
- Les wordlists vivent dans `wordlists/` (à la racine du projet, ignoré par git).
  Utilise *Importer…* pour en ajouter autant que tu veux ; elles sont copiées,
  donc tu peux supprimer les originaux. *Exporter* / *Supprimer* pour gérer la place.

### Onglet « Mot de passe »

Pour cracker un hash qui n'est pas un JWT. Colle le hash, choisis son type, puis :
- **Brute-force (masque)** : coche les jeux de caractères (`a-z`, `A-Z`, `0-9`,
  spéciaux) et une longueur max ; hashcat teste toutes les combinaisons de 1 à N
  caractères (`-a 3 -i`). Au-delà de 6-7 caractères ça peut être très long.
- **Dictionnaire** : réutilise les wordlists importées (`-a 0`).

### Onglet « URL » (brute-force de login HTTP)

En Python pur (stdlib `urllib` + threads, aucune dépendance en plus). Tu donnes
l'URL du formulaire et le corps avec les marqueurs `^USER^` / `^PASS^` ; chaque
mot de passe de la wordlist est testé, et le succès est détecté selon ton choix :
texte d'échec absent, texte de succès présent, ou code HTTP attendu (les
redirections 3xx ne sont pas suivies, pour pouvoir détecter un 302 de login réussi).
Garde-fous : max 50 000 essais, 50 threads, et 10 min par attaque.

## ⚠️ Avertissement légal

Cet outil est destiné à un **usage légal uniquement** : CTF, exercices, et tests
d'intrusion **sur des systèmes que tu es explicitement autorisé à auditer**.
Cracker un secret JWT que tu ne possèdes pas, ou sur un système sans autorisation
écrite, est illégal. Tu es seul responsable de l'usage que tu en fais.

---

Fait pour **Zenix Web** · thème sombre · 0 dépendance réseau pour la crypto.
