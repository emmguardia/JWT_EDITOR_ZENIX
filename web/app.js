/*
 * app.js — logique de l'interface.
 *  - Onglet JWT : décodage / vérification / re-signature (100 % local via crypto.js)
 *                 + crack du secret HMAC (hashcat -m 16500).
 *  - Onglet Mot de passe : crack d'un hash (brute-force masque ou dictionnaire).
 * Le crack appelle le backend Python (pywebview) qui lance hashcat en local.
 */
(function () {
  "use strict";

  const SAMPLE =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
    "eyJ1c2VybmFtZSI6Im1hcmMiLCJpYXQiOjE3OTE3OTgyNzF9." +
    "4knehEXkOyKOUsmUEcRHc4oSJEBJGeabLVzUDzXQQ9k";

  const $ = (id) => document.getElementById(id);

  const els = {};
  [
    "token-input", "token-colored", "decode-error",
    "header-edit", "payload-edit", "signature-view", "claims-dates",
    "secret-input", "btn-verify", "verify-result",
    "btn-resign", "resign-wrap", "resign-output", "btn-copy", "btn-sample",
    "crack-token", "btn-wl-import", "btn-wl-import-mdp",
    "btn-crack", "btn-install-hashcat", "crack-spinner",
    "crack-result", "crack-log-wrap", "crack-log", "hashcat-status",
    "mdp-hash", "mdp-type", "mdp-brute", "mdp-dict", "mdp-maxlen",
    "mdp-cs-l", "mdp-cs-u", "mdp-cs-d", "mdp-cs-s",
    "mdp-crack", "mdp-spinner", "mdp-result", "mdp-log-wrap", "mdp-log",
    "mdp-hashcat-status",
  ].forEach((id) => (els[id] = $(id)));

  function escapeHtml(s) {
    return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }

  // Contrôleur de zone « résultat + log brut » (réutilisé par les 2 onglets)
  function outputCtrl(resEl, logWrapEl, logEl) {
    return {
      set(kind, html) { resEl.className = "crack-result " + kind; resEl.innerHTML = html; },
      log(text) {
        if (!text) { logWrapEl.hidden = true; return; }
        logEl.textContent = text;
        logWrapEl.hidden = false;
      },
    };
  }
  const jwtOut = outputCtrl(els["crack-result"], els["crack-log-wrap"], els["crack-log"]);
  const mdpOut = outputCtrl(els["mdp-result"], els["mdp-log-wrap"], els["mdp-log"]);

  function api() {
    return (window.pywebview && window.pywebview.api) || null;
  }

  // ==========================================================================
  // ONGLETS
  // ==========================================================================
  function switchTab(name) {
    document.querySelectorAll(".tab").forEach((t) =>
      t.classList.toggle("active", t.dataset.tab === name));
    document.querySelectorAll(".tab-panel").forEach((p) => {
      p.hidden = p.dataset.panel !== name;
    });
  }
  document.querySelectorAll(".tab").forEach((t) =>
    t.addEventListener("click", () => switchTab(t.dataset.tab)));

  // ==========================================================================
  // ONGLET JWT — décodage / vérif / re-signature
  // ==========================================================================
  function showError(msg) {
    els["decode-error"].textContent = msg;
    els["decode-error"].hidden = false;
  }
  function clearError() {
    els["decode-error"].hidden = true;
    els["decode-error"].textContent = "";
  }

  function renderColored(token) {
    const t = token.trim();
    if (!t) {
      els["token-colored"].classList.remove("show");
      els["token-colored"].innerHTML = "";
      return;
    }
    const parts = t.split(".");
    const classes = ["tc-header", "tc-payload", "tc-signature"];
    els["token-colored"].innerHTML = parts
      .map((p, i) => `<span class="${classes[i] || "tc-signature"}">${escapeHtml(p)}</span>`)
      .join('<span class="tc-dot">.</span>');
    els["token-colored"].classList.add("show");
  }

  function renderClaims(payload) {
    const box = els["claims-dates"];
    box.innerHTML = "";
    if (!payload || typeof payload !== "object") return;
    const now = Math.floor(Date.now() / 1000);
    const labels = { iat: "émis (iat)", exp: "expire (exp)", nbf: "valide dès (nbf)" };
    ["iat", "nbf", "exp"].forEach((k) => {
      if (payload[k] == null) return;
      const ts = Number(payload[k]);
      if (!isFinite(ts)) return;
      const d = new Date(ts * 1000);
      const str = isNaN(d.getTime()) ? "date invalide" : d.toLocaleString("fr-FR");
      const chip = document.createElement("span");
      chip.className = "claim-chip";
      let suffix = "";
      if (k === "exp" && ts < now) { chip.classList.add("expired"); suffix = " — EXPIRÉ"; }
      if (k === "nbf" && ts > now) { suffix = " — pas encore valide"; }
      chip.innerHTML = `${labels[k]} : <b>${escapeHtml(str)}${suffix}</b>`;
      box.appendChild(chip);
    });
  }

  const pretty = (obj) => JSON.stringify(obj, null, 2);

  function onTokenChange() {
    const token = els["token-input"].value;
    renderColored(token);
    els["crack-token"].value = token.trim();
    clearError();
    els["verify-result"].textContent = "";
    els["verify-result"].className = "verify-result";

    if (!token.trim()) {
      els["header-edit"].value = "";
      els["payload-edit"].value = "";
      els["signature-view"].value = "";
      els["claims-dates"].innerHTML = "";
      return;
    }
    try {
      const d = JWT.decode(token);
      els["header-edit"].value = pretty(d.header);
      els["payload-edit"].value = pretty(d.payload);
      els["signature-view"].value = d.signature;
      renderClaims(d.payload);
    } catch (e) {
      showError("Décodage impossible : " + e.message);
      els["header-edit"].value = "";
      els["payload-edit"].value = "";
      els["signature-view"].value = "";
      els["claims-dates"].innerHTML = "";
    }
  }

  function onVerify() {
    const token = els["token-input"].value.trim();
    const secret = els["secret-input"].value;
    const out = els["verify-result"];
    if (!token) { out.textContent = "Aucun token à vérifier."; out.className = "verify-result ko"; return; }
    try {
      const r = JWT.verify(token, secret);
      if (r.alg === "none") {
        out.textContent = r.valid ? "alg:none — token sans signature" : "alg:none mais une signature est présente";
        out.className = "verify-result " + (r.valid ? "ok" : "ko");
        return;
      }
      out.textContent = r.valid
        ? `✓ Signature VALIDE (${r.alg}) avec ce secret`
        : `✗ Signature INVALIDE (${r.alg}) avec ce secret`;
      out.className = "verify-result " + (r.valid ? "ok" : "ko");
    } catch (e) {
      out.textContent = "Erreur : " + e.message;
      out.className = "verify-result ko";
    }
  }

  function onResign() {
    clearError();
    let header, payload;
    try { header = JSON.parse(els["header-edit"].value); }
    catch (e) { showError("Header : JSON invalide (" + e.message + ")"); return; }
    try { payload = JSON.parse(els["payload-edit"].value); }
    catch (e) { showError("Payload : JSON invalide (" + e.message + ")"); return; }

    const alg = header.alg || "HS256";
    const isNone = String(alg).toLowerCase() === "none";
    const secret = els["secret-input"].value;
    if (!isNone && !secret) { showError("Secret vide : renseigne le secret pour re-signer en " + alg + "."); return; }

    try {
      const token = JWT.sign(header, payload, secret, alg);
      els["resign-output"].value = token;
      els["resign-wrap"].hidden = false;
      els["token-input"].value = token;
      onTokenChange();
    } catch (e) {
      showError("Re-signature impossible : " + e.message);
    }
  }

  function onCopy() {
    const v = els["resign-output"].value;
    if (!v) return;
    navigator.clipboard?.writeText(v).then(
      () => flash(els["btn-copy"], "Copié ✓"),
      () => { els["resign-output"].select(); document.execCommand && document.execCommand("copy"); flash(els["btn-copy"], "Copié ✓"); }
    );
  }
  function flash(btn, txt) {
    const old = btn.textContent;
    btn.textContent = txt;
    setTimeout(() => (btn.textContent = old), 1200);
  }

  // ==========================================================================
  // hashcat : statut + installation
  // ==========================================================================
  function setPill(id, present) {
    const p = $(id);
    if (!p) return;
    if (present === null) { p.textContent = "hashcat : (backend indisponible)"; p.className = "pill pill-unknown"; }
    else if (present) { p.textContent = "hashcat : installé ✓"; p.className = "pill pill-ok"; }
    else { p.textContent = "hashcat : absent"; p.className = "pill pill-ko"; }
  }

  async function refreshHashcatStatus() {
    const a = api();
    if (!a) { setPill("hashcat-status", null); setPill("mdp-hashcat-status", null); return; }
    let present;
    try { present = await a.check_hashcat(); }
    catch (e) { setPill("hashcat-status", null); setPill("mdp-hashcat-status", null); return; }
    setPill("hashcat-status", present);
    setPill("mdp-hashcat-status", present);
    els["btn-install-hashcat"].hidden = !!present;
  }

  async function onInstallHashcat() {
    const a = api();
    if (!a) return;
    const btn = els["btn-install-hashcat"];
    btn.disabled = true;
    const old = btn.textContent;
    btn.textContent = "Installation… (mot de passe demandé)";
    jwtOut.set("ko", "Installation de hashcat en cours (une fenêtre de mot de passe va s'ouvrir)…");
    try {
      const r = await a.install_hashcat();
      if (r && r.ok) jwtOut.set("ok", "hashcat installé ✓");
      else { jwtOut.set("err", "Échec de l'installation : " + ((r && r.error) || "inconnue")); jwtOut.log((r && r.output) || ""); }
    } catch (e) {
      jwtOut.set("err", "Échec de l'installation : " + e.message);
    } finally {
      btn.disabled = false;
      btn.textContent = old;
      refreshHashcatStatus();
    }
  }

  // ==========================================================================
  // WORDLISTS (partagées entre les 2 onglets)
  // ==========================================================================
  const WL_CONTAINERS = [
    { list: "wordlist-list", empty: "wl-empty" },
    { list: "wordlist-list-mdp", empty: "wl-empty-mdp" },
  ];
  let wordlistItems = [];
  let selectedWordlist = null;

  function humanSize(n) {
    if (n == null) return "";
    const u = ["o", "Ko", "Mo", "Go", "To"];
    let i = 0, v = n;
    while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
    return (i === 0 ? v : v.toFixed(1)) + " " + u[i];
  }

  function wlMsg(kind, text) {
    document.querySelectorAll(".wl-msg").forEach((box) => {
      box.className = "wl-msg " + (kind || "");
      box.textContent = text || "";
    });
  }

  function buildWlRow(it, groupId) {
    const li = document.createElement("li");
    li.className = "wl-item" + (it.name === selectedWordlist ? " selected" : "");
    li.dataset.name = it.name;

    const pick = document.createElement("label");
    pick.className = "wl-pick";
    const radio = document.createElement("input");
    radio.type = "radio";
    radio.name = "wl-" + groupId;
    radio.checked = it.name === selectedWordlist;
    radio.addEventListener("change", () => { selectedWordlist = it.name; renderWordlists(); });
    const name = document.createElement("span");
    name.className = "wl-name";
    name.textContent = it.name;
    name.title = it.name;
    const size = document.createElement("span");
    size.className = "wl-size";
    size.textContent = humanSize(it.size);
    const tag = document.createElement("span");
    tag.className = "wl-tag";
    tag.textContent = "utilisée";
    tag.hidden = it.name !== selectedWordlist;
    pick.append(radio, name, size, tag);

    const actions = document.createElement("span");
    actions.className = "wl-row-actions";
    const btnExp = document.createElement("button");
    btnExp.type = "button"; btnExp.className = "wl-mini"; btnExp.textContent = "Exporter";
    btnExp.addEventListener("click", () => exportWordlist(it.name));
    const btnDel = document.createElement("button");
    btnDel.type = "button"; btnDel.className = "wl-mini danger-text"; btnDel.textContent = "Supprimer";
    btnDel.addEventListener("click", () => deleteWordlist(it.name));
    actions.append(btnExp, btnDel);

    li.append(pick, actions);
    return li;
  }

  function renderWordlists() {
    WL_CONTAINERS.forEach((c) => {
      const list = $(c.list), empty = $(c.empty);
      if (!list) return;
      list.innerHTML = "";
      if (empty) empty.hidden = wordlistItems.length > 0;
      wordlistItems.forEach((it) => list.appendChild(buildWlRow(it, c.list)));
    });
  }

  async function refreshWordlists() {
    const a = api();
    if (!a) { WL_CONTAINERS.forEach((c) => { const e = $(c.empty); if (e) e.hidden = false; }); return; }
    let data;
    try { data = await a.list_wordlists(); }
    catch (e) { wlMsg("err", "Lecture des wordlists impossible : " + e.message); return; }
    wordlistItems = (data && data.items) || [];
    if (!wordlistItems.some((it) => it.name === selectedWordlist)) {
      selectedWordlist = wordlistItems.length ? wordlistItems[0].name : null;
    }
    renderWordlists();
  }

  async function onImportWordlist() {
    const a = api();
    if (!a) { wlMsg("err", "Backend indisponible."); return; }
    wlMsg("", "Sélection du fichier…");
    try {
      const r = await a.import_wordlist();
      if (r && r.cancelled) { wlMsg("", ""); return; }
      if (r && r.ok) {
        if (r.added && r.added.length) selectedWordlist = r.added[r.added.length - 1];
        await refreshWordlists();
        let msg = "Importé : " + (r.added || []).join(", ");
        if (r.errors && r.errors.length) msg += " · erreurs : " + r.errors.join(" ; ");
        wlMsg("ok", msg);
      } else {
        wlMsg("err", "Import impossible" + (r && r.errors && r.errors.length ? " : " + r.errors.join(" ; ") : (r && r.error ? " : " + r.error : "")));
      }
    } catch (e) {
      wlMsg("err", "Import impossible : " + e.message);
    }
  }

  async function exportWordlist(name) {
    const a = api();
    if (!a || !name) return;
    wlMsg("", "Choix de la destination…");
    try {
      const r = await a.export_wordlist(name);
      if (r && r.cancelled) { wlMsg("", ""); return; }
      if (r && r.ok) wlMsg("ok", "Exporté vers : " + r.path);
      else wlMsg("err", "Export impossible : " + ((r && r.error) || "inconnue"));
    } catch (e) {
      wlMsg("err", "Export impossible : " + e.message);
    }
  }

  async function deleteWordlist(name) {
    const a = api();
    if (!a || !name) return;
    if (!confirm("Supprimer la wordlist « " + name + " » du dossier de l'app ?")) return;
    try {
      const r = await a.delete_wordlist(name);
      if (r && r.ok) { await refreshWordlists(); wlMsg("ok", "Supprimé : " + name); }
      else wlMsg("err", "Suppression impossible : " + ((r && r.error) || "inconnue"));
    } catch (e) {
      wlMsg("err", "Suppression impossible : " + e.message);
    }
  }

  // ==========================================================================
  // ONGLET JWT — crack du secret
  // ==========================================================================
  async function onCrack() {
    const a = api();
    if (!a) { jwtOut.set("err", "Backend indisponible : lance l'application via run.sh / le lanceur."); return; }

    const token = els["crack-token"].value.trim();
    const wordlist = selectedWordlist;
    if (!token) { jwtOut.set("err", "Aucun token à cracker."); return; }
    try { JWT.decode(token); } catch (e) { jwtOut.set("err", "Token invalide : " + e.message); return; }
    if (!wordlist) { jwtOut.set("err", "Importe et sélectionne une wordlist d'abord."); return; }

    els["btn-crack"].disabled = true;
    els["crack-spinner"].hidden = false;
    jwtOut.set("ko", "Crack en cours… (selon la wordlist, cela peut prendre un moment)");
    jwtOut.log("");
    try {
      const r = await a.crack(token, wordlist);
      if (r && r.found) {
        jwtOut.set("ok", 'Secret trouvé : <span class="secret">' + escapeHtml(r.secret) + "</span>");
        els["secret-input"].value = r.secret;
      } else if (r && r.error) {
        jwtOut.set("err", "Erreur : " + escapeHtml(r.error));
      } else {
        jwtOut.set("ko", "Secret non trouvé avec cette wordlist.");
      }
      jwtOut.log((r && r.output) || "");
    } catch (e) {
      jwtOut.set("err", "Erreur backend : " + e.message);
    } finally {
      els["btn-crack"].disabled = false;
      els["crack-spinner"].hidden = true;
    }
  }

  // ==========================================================================
  // ONGLET MOT DE PASSE — crack d'un hash
  // ==========================================================================
  function currentAttack() {
    const r = document.querySelector('input[name="mdp-attack"]:checked');
    return r ? r.value : "brute";
  }
  function onAttackChange() {
    const atk = currentAttack();
    els["mdp-brute"].hidden = atk !== "brute";
    els["mdp-dict"].hidden = atk !== "dict";
  }

  async function onMdpCrack() {
    const a = api();
    if (!a) { mdpOut.set("err", "Backend indisponible : lance l'application via run.sh / le lanceur."); return; }

    const hash = els["mdp-hash"].value.trim();
    const mode = els["mdp-type"].value;
    const attack = currentAttack();
    if (!hash) { mdpOut.set("err", "Colle un hash à cracker."); return; }

    let charsets = null, maxLen = null, wordlist = null;
    if (attack === "brute") {
      charsets = [];
      if (els["mdp-cs-l"].checked) charsets.push("l");
      if (els["mdp-cs-u"].checked) charsets.push("u");
      if (els["mdp-cs-d"].checked) charsets.push("d");
      if (els["mdp-cs-s"].checked) charsets.push("s");
      if (!charsets.length) { mdpOut.set("err", "Choisis au moins un jeu de caractères."); return; }
      maxLen = parseInt(els["mdp-maxlen"].value, 10) || 6;
    } else {
      wordlist = selectedWordlist;
      if (!wordlist) { mdpOut.set("err", "Importe et sélectionne une wordlist d'abord."); return; }
    }

    els["mdp-crack"].disabled = true;
    els["mdp-spinner"].hidden = false;
    mdpOut.set("ko", "Crack en cours…");
    mdpOut.log("");
    try {
      const r = await a.crack_hash(hash, mode, attack, wordlist, charsets, maxLen);
      if (r && r.found) {
        mdpOut.set("ok", 'Mot de passe trouvé : <span class="secret">' + escapeHtml(r.secret) + "</span>");
      } else if (r && r.error) {
        mdpOut.set("err", "Erreur : " + escapeHtml(r.error));
      } else {
        mdpOut.set("ko", "Mot de passe non trouvé avec ces réglages.");
      }
      mdpOut.log((r && r.output) || "");
    } catch (e) {
      mdpOut.set("err", "Erreur backend : " + e.message);
    } finally {
      els["mdp-crack"].disabled = false;
      els["mdp-spinner"].hidden = true;
    }
  }

  // ==========================================================================
  // Câblage
  // ==========================================================================
  els["token-input"].addEventListener("input", onTokenChange);
  els["btn-sample"].addEventListener("click", () => {
    els["token-input"].value = SAMPLE;
    els["secret-input"].value = "";
    onTokenChange();
  });
  els["btn-verify"].addEventListener("click", onVerify);
  els["btn-resign"].addEventListener("click", onResign);
  els["btn-copy"].addEventListener("click", onCopy);
  els["btn-crack"].addEventListener("click", onCrack);
  els["btn-install-hashcat"].addEventListener("click", onInstallHashcat);
  els["btn-wl-import"].addEventListener("click", onImportWordlist);
  els["btn-wl-import-mdp"].addEventListener("click", onImportWordlist);

  document.querySelectorAll('input[name="mdp-attack"]').forEach((r) =>
    r.addEventListener("change", onAttackChange));
  els["mdp-crack"].addEventListener("click", onMdpCrack);

  function onReady() {
    refreshHashcatStatus();
    refreshWordlists();
  }
  window.addEventListener("pywebviewready", onReady);
  setTimeout(onReady, 800);
})();
