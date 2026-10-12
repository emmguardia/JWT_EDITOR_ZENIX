/*
 * crypto.js — JWT : décodage, vérification et re-signature, 100 % côté client.
 *
 * On n'utilise PAS window.crypto.subtle : dans le WebView GTK de pywebview,
 * on n'est pas toujours en "secure context", donc subtle peut être absent.
 * On implémente donc HMAC-SHA256/384/512 en JS pur. Les tokens étant petits,
 * la performance n'a aucune importance.
 *
 * Tout est exposé sous l'objet global `JWT`.
 */
(function (global) {
  "use strict";

  // ---------------------------------------------------------------------------
  // Utilitaires base64url <-> octets / texte
  // ---------------------------------------------------------------------------
  const enc = new TextEncoder();
  const dec = new TextDecoder("utf-8", { fatal: false });

  function utf8ToBytes(str) {
    return enc.encode(str);
  }

  function bytesToUtf8(bytes) {
    return dec.decode(bytes);
  }

  // base64url (sans padding) depuis des octets
  function bytesToB64url(bytes) {
    let bin = "";
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  // octets depuis une chaîne base64url
  function b64urlToBytes(str) {
    let s = str.replace(/-/g, "+").replace(/_/g, "/");
    // remet le padding
    while (s.length % 4) s += "=";
    let bin;
    try {
      bin = atob(s);
    } catch (e) {
      throw new Error("base64url invalide");
    }
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function b64urlFromString(str) {
    return bytesToB64url(utf8ToBytes(str));
  }

  function concatBytes(a, b) {
    const out = new Uint8Array(a.length + b.length);
    out.set(a, 0);
    out.set(b, a.length);
    return out;
  }

  // ---------------------------------------------------------------------------
  // SHA-256 (sur Uint32)
  // ---------------------------------------------------------------------------
  const K256 = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ]);

  function rotr32(x, n) {
    return (x >>> n) | (x << (32 - n));
  }

  function sha256(msg) {
    let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a,
        h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;

    const l = msg.length;
    const bitLen = l * 8;
    const withOne = l + 1;
    const padZeros = (56 - (withOne % 64) + 64) % 64;
    const total = withOne + padZeros + 8;
    const m = new Uint8Array(total);
    m.set(msg);
    m[l] = 0x80;
    const dv = new DataView(m.buffer);
    dv.setUint32(total - 8, Math.floor(bitLen / 0x100000000));
    dv.setUint32(total - 4, bitLen >>> 0);

    const w = new Uint32Array(64);
    for (let i = 0; i < total; i += 64) {
      for (let t = 0; t < 16; t++) w[t] = dv.getUint32(i + t * 4);
      for (let t = 16; t < 64; t++) {
        const x = w[t - 15], y = w[t - 2];
        const s0 = rotr32(x, 7) ^ rotr32(x, 18) ^ (x >>> 3);
        const s1 = rotr32(y, 17) ^ rotr32(y, 19) ^ (y >>> 10);
        w[t] = (w[t - 16] + s0 + w[t - 7] + s1) | 0;
      }
      let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
      for (let t = 0; t < 64; t++) {
        const S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        const ch = (e & f) ^ (~e & g);
        const temp1 = (h + S1 + ch + K256[t] + w[t]) | 0;
        const S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const temp2 = (S0 + maj) | 0;
        h = g; g = f; f = e; e = (d + temp1) | 0;
        d = c; c = b; b = a; a = (temp1 + temp2) | 0;
      }
      h0 = (h0 + a) | 0; h1 = (h1 + b) | 0; h2 = (h2 + c) | 0; h3 = (h3 + d) | 0;
      h4 = (h4 + e) | 0; h5 = (h5 + f) | 0; h6 = (h6 + g) | 0; h7 = (h7 + h) | 0;
    }
    const out = new Uint8Array(32);
    const odv = new DataView(out.buffer);
    [h0, h1, h2, h3, h4, h5, h6, h7].forEach((x, i) => odv.setUint32(i * 4, x >>> 0));
    return out;
  }

  // ---------------------------------------------------------------------------
  // SHA-512 / SHA-384 (sur BigInt 64 bits)
  // ---------------------------------------------------------------------------
  const MASK64 = (1n << 64n) - 1n;

  const K512 = [
    0x428a2f98d728ae22n, 0x7137449123ef65cdn, 0xb5c0fbcfec4d3b2fn, 0xe9b5dba58189dbbcn,
    0x3956c25bf348b538n, 0x59f111f1b605d019n, 0x923f82a4af194f9bn, 0xab1c5ed5da6d8118n,
    0xd807aa98a3030242n, 0x12835b0145706fben, 0x243185be4ee4b28cn, 0x550c7dc3d5ffb4e2n,
    0x72be5d74f27b896fn, 0x80deb1fe3b1696b1n, 0x9bdc06a725c71235n, 0xc19bf174cf692694n,
    0xe49b69c19ef14ad2n, 0xefbe4786384f25e3n, 0x0fc19dc68b8cd5b5n, 0x240ca1cc77ac9c65n,
    0x2de92c6f592b0275n, 0x4a7484aa6ea6e483n, 0x5cb0a9dcbd41fbd4n, 0x76f988da831153b5n,
    0x983e5152ee66dfabn, 0xa831c66d2db43210n, 0xb00327c898fb213fn, 0xbf597fc7beef0ee4n,
    0xc6e00bf33da88fc2n, 0xd5a79147930aa725n, 0x06ca6351e003826fn, 0x142929670a0e6e70n,
    0x27b70a8546d22ffcn, 0x2e1b21385c26c926n, 0x4d2c6dfc5ac42aedn, 0x53380d139d95b3dfn,
    0x650a73548baf63den, 0x766a0abb3c77b2a8n, 0x81c2c92e47edaee6n, 0x92722c851482353bn,
    0xa2bfe8a14cf10364n, 0xa81a664bbc423001n, 0xc24b8b70d0f89791n, 0xc76c51a30654be30n,
    0xd192e819d6ef5218n, 0xd69906245565a910n, 0xf40e35855771202an, 0x106aa07032bbd1b8n,
    0x19a4c116b8d2d0c8n, 0x1e376c085141ab53n, 0x2748774cdf8eeb99n, 0x34b0bcb5e19b48a8n,
    0x391c0cb3c5c95a63n, 0x4ed8aa4ae3418acbn, 0x5b9cca4f7763e373n, 0x682e6ff3d6b2b8a3n,
    0x748f82ee5defb2fcn, 0x78a5636f43172f60n, 0x84c87814a1f0ab72n, 0x8cc702081a6439ecn,
    0x90befffa23631e28n, 0xa4506cebde82bde9n, 0xbef9a3f7b2c67915n, 0xc67178f2e372532bn,
    0xca273eceea26619cn, 0xd186b8c721c0c207n, 0xeada7dd6cde0eb1en, 0xf57d4f7fee6ed178n,
    0x06f067aa72176fban, 0x0a637dc5a2c898a6n, 0x113f9804bef90daen, 0x1b710b35131c471bn,
    0x28db77f523047d84n, 0x32caab7b40c72493n, 0x3c9ebe0a15c9bebcn, 0x431d67c49c100d4cn,
    0x4cc5d4becb3e42b6n, 0x597f299cfc657e2an, 0x5fcb6fab3ad6faecn, 0x6c44198c4a475817n,
  ];

  const H512 = [
    0x6a09e667f3bcc908n, 0xbb67ae8584caa73bn, 0x3c6ef372fe94f82bn, 0xa54ff53a5f1d36f1n,
    0x510e527fade682d1n, 0x9b05688c2b3e6c1fn, 0x1f83d9abfb41bd6bn, 0x5be0cd19137e2179n,
  ];

  const H384 = [
    0xcbbb9d5dc1059ed8n, 0x629a292a367cd507n, 0x9159015a3070dd17n, 0x152fecd8f70e5939n,
    0x67332667ffc00b31n, 0x8eb44a8768581511n, 0xdb0c2e0d64f98fa7n, 0x47b5481dbefa4fa4n,
  ];

  function rotr64(x, n) {
    return ((x >> n) | (x << (64n - n))) & MASK64;
  }

  function sha512core(msg, is384) {
    let H = (is384 ? H384 : H512).slice();

    const l = msg.length;
    const withOne = l + 1;
    const padZeros = ((112 - (withOne % 128)) + 128) % 128;
    const total = withOne + padZeros + 16;
    const m = new Uint8Array(total);
    m.set(msg);
    m[l] = 0x80;
    const dv = new DataView(m.buffer);
    // longueur sur 128 bits big-endian ; nos messages sont petits -> poids fort = 0
    dv.setBigUint64(total - 16, 0n);
    dv.setBigUint64(total - 8, (BigInt(l) * 8n) & MASK64);

    const w = new Array(80);
    for (let i = 0; i < total; i += 128) {
      for (let t = 0; t < 16; t++) w[t] = dv.getBigUint64(i + t * 8);
      for (let t = 16; t < 80; t++) {
        const x = w[t - 15], y = w[t - 2];
        const s0 = rotr64(x, 1n) ^ rotr64(x, 8n) ^ (x >> 7n);
        const s1 = rotr64(y, 19n) ^ rotr64(y, 61n) ^ (y >> 6n);
        w[t] = (w[t - 16] + s0 + w[t - 7] + s1) & MASK64;
      }
      let [a, b, c, d, e, f, g, h] = H;
      for (let t = 0; t < 80; t++) {
        const S1 = rotr64(e, 14n) ^ rotr64(e, 18n) ^ rotr64(e, 41n);
        const ch = (e & f) ^ ((~e & MASK64) & g);
        const temp1 = (h + S1 + ch + K512[t] + w[t]) & MASK64;
        const S0 = rotr64(a, 28n) ^ rotr64(a, 34n) ^ rotr64(a, 39n);
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const temp2 = (S0 + maj) & MASK64;
        h = g; g = f; f = e; e = (d + temp1) & MASK64;
        d = c; c = b; b = a; a = (temp1 + temp2) & MASK64;
      }
      H = [
        (H[0] + a) & MASK64, (H[1] + b) & MASK64, (H[2] + c) & MASK64, (H[3] + d) & MASK64,
        (H[4] + e) & MASK64, (H[5] + f) & MASK64, (H[6] + g) & MASK64, (H[7] + h) & MASK64,
      ];
    }
    const nWords = is384 ? 6 : 8;
    const out = new Uint8Array(nWords * 8);
    const odv = new DataView(out.buffer);
    for (let i = 0; i < nWords; i++) odv.setBigUint64(i * 8, H[i]);
    return out;
  }

  const sha384 = (msg) => sha512core(msg, true);
  const sha512 = (msg) => sha512core(msg, false);

  // ---------------------------------------------------------------------------
  // HMAC générique
  // ---------------------------------------------------------------------------
  function hmac(keyBytes, msgBytes, hashFn, blockSize) {
    if (keyBytes.length > blockSize) keyBytes = hashFn(keyBytes);
    const key = new Uint8Array(blockSize);
    key.set(keyBytes);
    const oPad = new Uint8Array(blockSize);
    const iPad = new Uint8Array(blockSize);
    for (let i = 0; i < blockSize; i++) {
      oPad[i] = key[i] ^ 0x5c;
      iPad[i] = key[i] ^ 0x36;
    }
    const inner = hashFn(concatBytes(iPad, msgBytes));
    return hashFn(concatBytes(oPad, inner));
  }

  const ALGOS = {
    HS256: { fn: sha256, block: 64 },
    HS384: { fn: sha384, block: 128 },
    HS512: { fn: sha512, block: 128 },
  };

  // Signature HMAC d'un "signing input" (header.payload) -> base64url
  function hmacSignature(signingInput, secret, alg) {
    const a = ALGOS[alg];
    if (!a) throw new Error("Algorithme HMAC non supporté : " + alg);
    const mac = hmac(utf8ToBytes(secret), utf8ToBytes(signingInput), a.fn, a.block);
    return bytesToB64url(mac);
  }

  // ---------------------------------------------------------------------------
  // JWT : décodage / signature / vérification
  // ---------------------------------------------------------------------------

  // Décode un JWT en ses 3 parties. Lève une erreur si mal formé.
  function decode(token) {
    const t = (token || "").trim();
    if (!t) throw new Error("Token vide");
    const parts = t.split(".");
    if (parts.length < 2 || parts.length > 3) {
      throw new Error("Un JWT doit comporter 2 ou 3 parties séparées par des points");
    }
    const headerJson = bytesToUtf8(b64urlToBytes(parts[0]));
    const payloadJson = bytesToUtf8(b64urlToBytes(parts[1]));
    let header, payload;
    try {
      header = JSON.parse(headerJson);
    } catch (e) {
      throw new Error("Header : JSON invalide");
    }
    try {
      payload = JSON.parse(payloadJson);
    } catch (e) {
      throw new Error("Payload : JSON invalide");
    }
    return {
      header: header,
      payload: payload,
      signature: parts[2] || "",
      parts: parts,
    };
  }

  // Re-signe à partir d'objets header/payload + secret. alg vient du header.
  function sign(headerObj, payloadObj, secret, alg) {
    const useAlg = alg || (headerObj && headerObj.alg) || "HS256";
    const h = b64urlFromString(JSON.stringify(headerObj));
    const p = b64urlFromString(JSON.stringify(payloadObj));
    const signingInput = h + "." + p;
    if (String(useAlg).toLowerCase() === "none") {
      return signingInput + ".";
    }
    const sig = hmacSignature(signingInput, secret, useAlg);
    return signingInput + "." + sig;
  }

  // Vérifie la signature d'un token existant avec un secret.
  function verify(token, secret) {
    const d = decode(token);
    const alg = d.header && d.header.alg;
    if (!alg) throw new Error("Header sans champ 'alg'");
    if (String(alg).toLowerCase() === "none") {
      return { valid: d.signature === "", alg: "none" };
    }
    if (!ALGOS[alg]) {
      throw new Error("Algorithme non supporté pour la vérification : " + alg);
    }
    const signingInput = d.parts[0] + "." + d.parts[1];
    const expected = hmacSignature(signingInput, secret, alg);
    return { valid: expected === d.signature, alg: alg };
  }

  global.JWT = {
    decode: decode,
    sign: sign,
    verify: verify,
    hmacSignature: hmacSignature,
    b64urlFromString: b64urlFromString,
    // exposés pour d'éventuels tests
    _sha256: sha256,
    _sha384: sha384,
    _sha512: sha512,
    _hmac: hmac,
    _utf8ToBytes: utf8ToBytes,
    _bytesToB64url: bytesToB64url,
  };
})(typeof window !== "undefined" ? window : globalThis);
