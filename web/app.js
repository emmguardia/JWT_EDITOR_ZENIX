/*
 * app.js — logique de l'interface.
 *  - Décodage / vérification / re-signature : 100 % local via JWT (crypto.js).
 *  - Crack : appelle le backend Python (pywebview) qui lance hashcat/john.
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
    "btn-resign", "resign-wrap", "resign-output", "btn-copy",
    "btn-sample",
    "crack-token", "opt-john",
    "wordlist-list", "btn-wl-import", "wl-empty", "wl-msg",
    "btn-crack", "btn-install-hashcat", "crack-spinner",
    "crack-result", "crack-log-wrap", "crack-log",
    "hashcat-status",
  ].forEach((id) => (els[id] = $(id)));

  // --------------------------------------------------------------------------
  // Décodage + affichage
  // --------------------------------------------------------------------------
  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }

  function showError(msg) {
    els["decode-error"].textContent = msg;
    els["decode-error"].hidden = false;
  }
  function clearError() {
    els["decode-error"].hidden = true;
    els["decode-error"].textContent = "";
  }

  // Colorise les 3 parties du token comme jwt.io
  function renderColored(token) {
    const t = token.trim();
    if (!t) {
      els["token-colored"].classList.remove("show");
      els["token-colored"].innerHTML = "";
      return;
    }
    const parts = t.split(".");
    const classes = ["tc-header", "tc-payload", "tc-signature"];
    const html = parts
      .map((p, i) => `<span class="${classes[i] || "tc-signature"}">${escapeHtml(p)}</span>`)
      .join('<span class="tc-dot">.</span>');
    els["token-colored"].innerHTML = html;
    els["token-colored"].classList.add("show");
  }

  // Dates lisibles pour iat/exp/nbf
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

  function pretty(obj) {
    return JSON.stringify(obj, null, 2);
  }

  function onTokenChange() {
    const token = els["token-input"].value;
    renderColored(token);
    // reporte le token dans la section crack
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

  // --------------------------------------------------------------------------
  // Vérification
  // --------------------------------------------------------------------------
  function onVerify() {
    const token = els["token-input"].value.trim();
    const secret = els["secret-input"].value;
    const out = els["verify-result"];
    if (!token) { out.textContent = "Aucun token à vérifier."; out.className = "verify-result ko"; return; }
    try {
      const r = JWT.verify(token, secret);
      if (r.alg === "none") {
        out.textContent = r.valid ? "alg:none — token sans signature (structurellement valide)" : "alg:none mais une signature est présente";
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

  // --------------------------------------------------------------------------
  // Re-signature
  // --------------------------------------------------------------------------
  function onResign() {
    clearError();
    let header, payload;
    try {
      header = JSON.parse(els["header-edit"].value);
    } catch (e) { showError("Header : JSON invalide (" + e.message + ")"); return; }
    try {
      payload = JSON.parse(els["payload-edit"].value);
    } catch (e) { showError("Payload : JSON invalide (" + e.message + ")"); return; }

    const alg = header.alg || "HS256";
    const isNone = String(alg).toLowerCase() === "none";
    const secret = els["secret-input"].value;
    if (!isNone && !secret) { showError("Secret vide : renseigne le secret pour re-signer en " + alg + "."); return; }

    try {
      const token = JWT.sign(header, payload, secret, alg);
      els["resign-output"].value = token;
      els["resign-wrap"].hidden = false;
      // on met aussi à jour le champ principal pour cohérence
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
      () => {
        // repli : sélection manuelle
        els["resign-output"].select();
        document.execCommand && document.execCommand("copy");
        flash(els["btn-copy"], "Copié ✓");
      }
    );
  }
  function flash(btn, txt) {
    const old = btn.textContent;
    btn.textContent = txt;
    setTimeout(() => (btn.textContent = old), 1200);
  }

  // --------------------------------------------------------------------------
  // Pont vers le backend Python (pywebview)
  // --------------------------------------------------------------------------
  function api() {
    return (window.pywebview && window.pywebview.api) || null;
  }

  async function refreshHashcatStatus() {
    const pill = els["hashcat-status"];
    const a = api();
    if (!a) { pill.textContent = "hashcat : (backend indisponible)"; pill.className = "pill pill-unknown"; return; }
    try {
      const present = await a.check_hashcat();
      if (present) {
        pill.textContent = "hashcat : installé ✓";
        pill.className = "pill pill-ok";
        els["btn-install-hashcat"].hidden = true;
      } else {
        pill.textContent = "hashcat : absent";
        pill.className = "pill pill-ko";
        els["btn-install-hashcat"].hidden = false;
      }
    } catch (e) {
      pill.textContent = "hashcat : erreur de détection";
      pill.className = "pill pill-unknown";
    }
  }

  async function onInstallHashcat() {
    const a = api();
    if (!a) return;
    const btn = els["btn-install-hashcat"];
    btn.disabled = true;
    const old = btn.textContent;
    btn.textContent = "Installation… (mot de passe demandé)";
    setResult("ko", "Installation de hashcat en cours (une fenêtre de mot de passe va s'ouvrir)…");
    try {
      const r = await a.install_hashcat();
      if (r && r.ok) {
        setResult("ok", "hashcat installé ✓");
      } else {
        setResult("err", "Échec de l'installation : " + ((r && r.error) || "inconnue"));
        showLog((r && r.output) || "");
      }
    } catch (e) {
      setResult("err", "Échec de l'installation : " + e.message);
    } finally {
      btn.disabled = false;
      btn.textContent = old;
      refreshHashcatStatus();
    }
  }

  function setResult(kind, html) {
    const box = els["crack-result"];
    box.className = "crack-result " + kind;
    box.innerHTML = html;
  }
  function showLog(text) {
    if (!text) { els["crack-log-wrap"].hidden = true; return; }
    els["crack-log"].textContent = text;
    els["crack-log-wrap"].hidden = false;
  }

  // ---- gestion des wordlists ----
  let selectedWordlist = null; // nom de la wordlist utilisée pour le crack

  function humanSize(n) {
    if (n == null) return "";
    const u = ["o", "Ko", "Mo", "Go", "To"];
    let i = 0, v = n;
    while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
    return (i === 0 ? v : v.toFixed(1)) + " " + u[i];
  }

  function wlMsg(kind, text) {
    const box = els["wl-msg"];
    box.className = "wl-msg " + (kind || "");
    box.textContent = text || "";
  }

  // Construit la liste de lignes (radio = wordlist active)
  function renderWordlists(items) {
    const list = els["wordlist-list"];
    list.innerHTML = "";
    els["wl-empty"].hidden = items.length > 0;

    // garde la sélection si elle existe encore, sinon prend la 1re
    if (!items.some((it) => it.name === selectedWordlist)) {
      selectedWordlist = items.length ? items[0].name : null;
    }

    items.forEach((it) => {
      const li = document.createElement("li");
      li.className = "wl-item" + (it.name === selectedWordlist ? " selected" : "");
      li.dataset.name = it.name;

      const pick = document.createElement("label");
      pick.className = "wl-pick";
      const radio = document.createElement("input");
      radio.type = "radio";
      radio.name = "wl";
      radio.value = it.name;
      radio.checked = it.name === selectedWordlist;
      radio.addEventListener("change", () => {
        selectedWordlist = it.name;
        // met à jour le surlignage sans tout reconstruire
        list.querySelectorAll(".wl-item").forEach((el) =>
          el.classList.toggle("selected", el.dataset.name === selectedWordlist));
        refreshTags();
      });
      const name = document.createElement("span");
      name.className = "wl-name";
      name.textContent = it.name;
      name.title = it.name;
      const size = document.createElement("span");
      size.className = "wl-size";
      size.textContent = humanSize(it.size);
      pick.append(radio, name, size);

      const actions = document.createElement("span");
      actions.className = "wl-row-actions";
      const tag = document.createElement("span");
      tag.className = "wl-tag";
      tag.textContent = "utilisée";
      tag.hidden = it.name !== selectedWordlist;
      const btnExp = document.createElement("button");
      btnExp.type = "button";
      btnExp.className = "wl-mini";
      btnExp.textContent = "Exporter";
      btnExp.addEventListener("click", () => exportWordlist(it.name));
      const btnDel = document.createElement("button");
      btnDel.type = "button";
      btnDel.className = "wl-mini danger-text";
      btnDel.textContent = "Supprimer";
      btnDel.addEventListener("click", () => deleteWordlist(it.name));
      actions.append(tag, btnExp, btnDel);

      li.append(pick, actions);
      list.appendChild(li);
    });
  }

  // Met à jour les badges "utilisée" selon la sélection courante
  function refreshTags() {
    els["wordlist-list"].querySelectorAll(".wl-item").forEach((el) => {
      const tag = el.querySelector(".wl-tag");
      if (tag) tag.hidden = el.dataset.name !== selectedWordlist;
    });
  }

  async function refreshWordlists() {
    const a = api();
    if (!a) { els["wl-empty"].hidden = false; return; }
    let data;
    try {
      data = await a.list_wordlists();
    } catch (e) {
      wlMsg("err", "Lecture des wordlists impossible : " + e.message);
      return;
    }
    renderWordlists((data && data.items) || []);
  }

  async function onImportWordlist() {
    const a = api();
    if (!a) { wlMsg("err", "Backend indisponible."); return; }
    wlMsg("", "Sélection du fichier…");
    try {
      const r = await a.import_wordlist();
      if (r && r.cancelled) { wlMsg("", ""); return; }
      if (r && r.ok) {
        // sélectionne automatiquement la dernière importée
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
      if (r && r.ok) {
        await refreshWordlists();
        wlMsg("ok", "Supprimé : " + name);
      } else {
        wlMsg("err", "Suppression impossible : " + ((r && r.error) || "inconnue"));
      }
    } catch (e) {
      wlMsg("err", "Suppression impossible : " + e.message);
    }
  }

  async function onCrack() {
    const a = api();
    if (!a) { setResult("err", "Backend indisponible : lance l'application via run.sh / le lanceur."); return; }

    const token = els["crack-token"].value.trim();
    const wordlist = selectedWordlist;
    const useJohn = els["opt-john"].checked;

    if (!token) { setResult("err", "Aucun token à cracker."); return; }
    // petite validation structurelle
    try { JWT.decode(token); } catch (e) { setResult("err", "Token invalide : " + e.message); return; }
    if (!wordlist) { setResult("err", "Importe et sélectionne une wordlist d'abord."); return; }

    els["btn-crack"].disabled = true;
    els["crack-spinner"].hidden = false;
    setResult("ko", "Crack en cours… (cela peut prendre un moment selon la wordlist)");
    showLog("");

    try {
      const r = await a.crack(token, wordlist, useJohn);
      if (r && r.found) {
        setResult("ok", "Secret trouvé : <span class=\"secret\">" + escapeHtml(r.secret) + "</span>");
        // pré-remplit le secret pour vérif/re-signature
        els["secret-input"].value = r.secret;
      } else if (r && r.error) {
        setResult("err", "Erreur : " + escapeHtml(r.error));
      } else {
        setResult("ko", "Secret non trouvé avec cette wordlist.");
      }
      showLog((r && r.output) || "");
    } catch (e) {
      setResult("err", "Erreur backend : " + e.message);
    } finally {
      els["btn-crack"].disabled = false;
      els["crack-spinner"].hidden = true;
    }
  }

  // --------------------------------------------------------------------------
  // Câblage
  // --------------------------------------------------------------------------
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

  function onReady() {
    refreshHashcatStatus();
    refreshWordlists();
  }
  // Le backend pywebview peut ne pas être prêt immédiatement
  window.addEventListener("pywebviewready", onReady);
  // repli si l'évènement est déjà passé
  setTimeout(onReady, 800);
})();
