// Shared config + storage helpers (textdb.dev slots, ECDH P-256 + AES-GCM encryption)
window.RSVP = (function () {
  const API = 'https://textdb.dev/api/data/hw26-406b0b58-a1c0-48bd-8e84-0ea06c80f3db-';
  const HOST_PUB = {kty:"EC",crv:"P-256",x:"t3id-krrcsfY28_wVnmKqKqG352xfYy10Bhy9sU4qZs",y:"lezYntGTgtNZNzufMg6fq1Qz7-PYtgP5MnHn3bdI23Q"};
  const b64 = (buf) => { let s=''; const a=new Uint8Array(buf); for (let i=0;i<a.length;i++) s+=String.fromCharCode(a[i]); return btoa(s); };
  const unb64 = (s) => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  const sleep = (ms) => new Promise(r => setTimeout(r, ms));

  async function getSlot(n) {
    for (let t = 0; t < 3; t++) {
      try {
        const r = await fetch(API + n + '?_=' + Date.now(), {cache: 'no-store'});
        if (r.ok) return (await r.text()).trim();
      } catch (e) {}
      await sleep(400 * (t + 1));
    }
    throw new Error('read failed');
  }
  async function putSlot(n, value) {
    for (let t = 0; t < 3; t++) {
      try {
        const r = await fetch(API + n, {method: 'POST', body: value, headers: {'Content-Type': 'text/plain'}});
        if (r.ok) return;
      } catch (e) {}
      await sleep(500 * (t + 1));
    }
    throw new Error('write failed');
  }
  // slots are filled contiguously from 1; exponential + binary search for the first empty one
  async function firstEmpty() {
    let lo = 0, hi = 1;
    while (await getSlot(hi)) { lo = hi; hi *= 2; if (hi > 4096) throw new Error('full'); }
    while (hi - lo > 1) { const mid = (lo + hi) >> 1; if (await getSlot(mid)) lo = mid; else hi = mid; }
    return hi;
  }
  async function encrypt(obj, id) {
    const hostKey = await crypto.subtle.importKey('jwk', HOST_PUB, {name:'ECDH', namedCurve:'P-256'}, false, []);
    const eph = await crypto.subtle.generateKey({name:'ECDH', namedCurve:'P-256'}, true, ['deriveKey']);
    const key = await crypto.subtle.deriveKey({name:'ECDH', public: hostKey}, eph.privateKey, {name:'AES-GCM', length:256}, false, ['encrypt']);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({name:'AES-GCM', iv}, key, new TextEncoder().encode(JSON.stringify(obj)));
    const epk = await crypto.subtle.exportKey('jwk', eph.publicKey);
    return JSON.stringify({v:1, id, e:[epk.x, epk.y], i:b64(iv), c:b64(ct)});
  }
  async function decrypt(raw, d) {
    const rec = JSON.parse(raw);
    const priv = await crypto.subtle.importKey('jwk', {...HOST_PUB, d}, {name:'ECDH', namedCurve:'P-256'}, false, ['deriveKey']);
    const epk = await crypto.subtle.importKey('jwk', {kty:'EC', crv:'P-256', x:rec.e[0], y:rec.e[1]}, {name:'ECDH', namedCurve:'P-256'}, false, []);
    const key = await crypto.subtle.deriveKey({name:'ECDH', public: epk}, priv, {name:'AES-GCM', length:256}, false, ['decrypt']);
    const pt = await crypto.subtle.decrypt({name:'AES-GCM', iv: unb64(rec.i)}, key, unb64(rec.c));
    return {id: rec.id, ...JSON.parse(new TextDecoder().decode(pt))};
  }
  // Save an RSVP; reuses this device's previous slot if it still belongs to it
  async function save(data) {
    let mine = null;
    try { mine = JSON.parse(localStorage.getItem('hw26_rsvp') || 'null'); } catch (e) {}
    const id = (mine && mine.id) || (crypto.randomUUID ? crypto.randomUUID() : String(Math.random()).slice(2) + Date.now());
    const value = await encrypt(data, id);
    let n = null;
    if (mine && mine.slot) {
      const cur = await getSlot(mine.slot);
      if (cur.includes('"id":"' + id + '"')) n = mine.slot;
    }
    if (n) { await putSlot(n, value); }
    else {
      n = await firstEmpty();
      for (let tries = 0; ; tries++) {
        if (tries > 20) throw new Error('could not claim slot');
        await putSlot(n, value);
        await sleep(1200 + Math.random() * 800);
        const back = await getSlot(n);
        if (back.includes('"id":"' + id + '"')) break;      // claimed
        n++; while (await getSlot(n)) n++;                   // collision: move on
      }
    }
    localStorage.setItem('hw26_rsvp', JSON.stringify({id, slot: n, data}));
    return n;
  }
  return {getSlot, putSlot, decrypt, save, sleep};
})();
