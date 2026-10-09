import test from 'node:test';
import assert from 'node:assert/strict';
import * as C from '../js/crypto.js';
import { scramClient } from '../js/transports.js';
import { evaluate } from '../js/scoring.js';
import { parseXml } from '../js/xml.js';

async function link(o1, o2) {
  const a = new C.Session(o1); const b = new C.Session(o2);
  const evA = []; const evB = [];
  let r = await a.begin(); evA.push(...r.ev);
  let toB = r.out; let toA = [];
  for (let i = 0; i < 10 && (toA.length || toB.length); i++) {
    const nb = toB; toB = [];
    for (const w of nb) { const x = await b.handle(w); toA.push(...x.out); evB.push(...x.ev); }
    const na = toA; toA = [];
    for (const w of na) { const x = await a.handle(w); toB.push(...x.out); evA.push(...x.ev); }
  }
  return { a, b, evA, evB };
}
const types = (ev) => ev.map((e) => e.type);

for (const curve of C.CURVES) {
  for (const mode of ['ratchet', 'ecdh', 'static']) {
    for (const auth of mode === 'static' ? ['none'] : ['none', 'sign', 'psk']) {
      test(`${mode}/${curve}/${auth}: handshake, both directions, reorder, replay`, async () => {
        const id1 = await C.makeIdentity(); const id2 = await C.makeIdentity();
        const base = { mode, curve, auth, passphrase: 'a long shared secret' };
        const { a, b, evA, evB } = await link({ ...base, identity: id1, staticKey: await C.makeStatic(curve) }, { ...base, identity: id2, staticKey: await C.makeStatic(curve) });
        assert.ok(types(evA).includes('ready') && types(evB).includes('ready'));
        assert.equal(a.sas, b.sas);
        if (auth === 'sign') { assert.equal(evA.find((e) => e.type === 'peerKey').fp, id2.fp); assert.equal(evB.find((e) => e.type === 'peerKey').fp, id1.fp); }
        const m1 = await a.send('one'); const m2 = await a.send('two');
        assert.equal((await b.handle(m2)).ev[0].text, 'two');
        assert.equal((await b.handle(m1)).ev[0].text, 'one');
        assert.equal((await b.handle(m1)).ev[0].type, 'error'); // replay
        assert.equal((await a.handle(await b.send('back'))).ev[0].text, 'back');
        assert.equal((await b.handle(await a.send('ünïcode ✓'))).ev[0].text, 'ünïcode ✓');
      });
    }
  }
}

test('ratchet: tampered ciphertext is rejected and state survives', async () => {
  const { a, b } = await link({ mode: 'ratchet', curve: 'P-256', auth: 'none' }, { mode: 'ratchet', curve: 'P-256', auth: 'none' });
  const w = await a.send('secret');
  const obj = C.parseWire(w); obj.c = obj.c.slice(0, -4) + (obj.c.slice(-4) === 'AAAA' ? 'BBBB' : 'AAAA');
  const forged = C.WIRE_PREFIX + C.b64u(new TextEncoder().encode(JSON.stringify(obj)));
  assert.equal((await b.handle(forged)).ev[0].type, 'error');
  assert.equal((await b.handle(w)).ev[0].text, 'secret'); // genuine one still fine
});

test('wrong shared secret (psk auth) fails to read messages', async () => {
  const { a, b } = await link({ mode: 'ratchet', curve: 'P-256', auth: 'psk', passphrase: 'correct passphrase' }, { mode: 'ratchet', curve: 'P-256', auth: 'psk', passphrase: 'WRONG passphrase!!' });
  assert.notEqual(a.sas, b.sas); // SAS differs => mismatch visible
  assert.equal((await b.handle(await a.send('x'))).ev[0].type, 'error');
});

test('sign auth: man-in-the-middle swapping the signature is detected', async () => {
  const id = await C.makeIdentity(); const evil = await C.makeIdentity();
  const base = { mode: 'ratchet', curve: 'P-256', auth: 'sign' };
  const a = new C.Session({ ...base, identity: id }); const b = new C.Session({ ...base, identity: await C.makeIdentity() });
  const hs1 = (await a.begin()).out[0];
  const hs2 = C.parseWire((await b.handle(hs1)).out[0]);
  const e = new C.Session({ ...base, identity: evil });
  void e;
  hs2.k = C.b64u(evil.pub); // attacker claims B's message with own key; signature no longer matches
  const r = await a.handle(C.WIRE_PREFIX + C.b64u(new TextEncoder().encode(JSON.stringify(hs2))));
  assert.match(r.ev[0].reason, /INVALID/);
});

test('mismatched settings are reported', async () => {
  const a = new C.Session({ mode: 'ratchet', curve: 'P-256', auth: 'none' }); const b = new C.Session({ mode: 'ecdh', curve: 'P-256', auth: 'none' });
  const r = await b.handle((await a.begin()).out[0]);
  assert.match(r.ev[0].reason, /different settings/);
});

test('handshake commitment: swapped ephemeral key is rejected', async () => {
  const o = { mode: 'ratchet', curve: 'P-256', auth: 'none' };
  const a = new C.Session(o); const b = new C.Session(o);
  const hs2 = (await b.handle((await a.begin()).out[0])).out[0];
  const hs3 = C.parseWire((await a.handle(hs2)).out[0]);
  hs3.e = C.b64u((await C.genDH('P-256')).pub);
  const r = await b.handle(C.WIRE_PREFIX + C.b64u(new TextEncoder().encode(JSON.stringify(hs3))));
  assert.match(r.ev[0].reason, /commitment/);
});

test('passphrase mode round trip + wrong passphrase', async () => {
  const a = new C.Session({ mode: 'psk', passphrase: 'twelve+ chars ok' }); const b = new C.Session({ mode: 'psk', passphrase: 'twelve+ chars ok' });
  assert.equal((await b.handle(await a.send('hello psk'))).ev[0].text, 'hello psk');
  const c = new C.Session({ mode: 'psk', passphrase: 'nope' });
  assert.equal((await c.handle(await a.send('x'))).ev[0].type, 'error');
});

test('one-time pad: round trip, pad wiped, replay and forgery rejected, exhaustion', async () => {
  const pad = C.generatePad(2048);
  const a = new C.Session({ mode: 'otp', pad: pad.slice(), side: 'A' }); const b = new C.Session({ mode: 'otp', pad: pad.slice(), side: 'B' });
  const before = a.padRemaining();
  const w = await a.send('meet at noon');
  assert.ok(a.padRemaining() < before);
  assert.equal((await b.handle(w)).ev[0].text, 'meet at noon');
  assert.equal((await b.handle(w)).ev[0].type, 'error'); // replay (and pad already wiped)
  assert.ok(a.o.pad.slice(0, 32).every((x) => x === 0), 'used pad bytes zeroed');
  const w2 = C.parseWire(await a.send('two')); w2.c = C.b64u(new Uint8Array(64));
  assert.equal((await b.handle(C.WIRE_PREFIX + C.b64u(new TextEncoder().encode(JSON.stringify(w2))))).ev[0].type, 'error');
  assert.equal((await a.handle(await b.send('reply'))).ev[0].text, 'reply');
  await assert.rejects(async () => { for (let i = 0; i < 50; i++) await a.send('x'.repeat(200)); }, /exhausted/);
});

test('SCRAM-SHA-256 matches RFC 7677 test vector', async () => {
  const s = await scramClient('SHA-256', 'user', 'pencil', 'rOprNGfwEbeRWgbNEkqO');
  assert.equal(s.first(), 'n,,n=user,r=rOprNGfwEbeRWgbNEkqO');
  const fin = await s.final('r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096');
  assert.equal(fin, 'c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=');
  assert.ok(s.verify('v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4='));
  assert.ok(!s.verify('v=AAAA'));
});

test('xml parser handles stanzas, entities, namespaces', () => {
  const x = parseXml('<stream:features xmlns:stream="s"><mechanisms xmlns="m"><mechanism>PLAIN</mechanism></mechanisms></stream:features>');
  assert.equal(x.name, 'features');
  assert.equal(x.children[0].children[0].text, 'PLAIN');
  const m = parseXml('<message to="a@b"><body>1 &lt; 2 &amp; &#x41;</body></message>');
  assert.equal(m.children[0].text, '1 < 2 & A');
});

test('scoring: sanity and the PFS / authentication story', () => {
  const base = { proto: 'irc', url: 'wss://irc.example/ws', route: 'direct', anon: 'none', e2e: 'ratchet', curve: 'P-256', auth: 'none', verified: false, passLen: 0 };
  const r = evaluate(base);
  assert.equal(r.pfs.level, 'full');
  assert.ok(r.layers.some((l) => /Double Ratchet/.test(l.name)) && r.layers.some((l) => /TLS/.test(l.name)));
  const signed = evaluate({ ...base, auth: 'sign', verified: true });
  assert.equal(signed.pfs.level, 'full'); assert.equal(signed.deniability.ok, false);
  const stat = evaluate({ ...base, e2e: 'static', verified: true });
  assert.equal(stat.pfs.level, 'none');
  assert.ok(signed.privacy.score > stat.privacy.score);
  assert.ok(evaluate({ ...base, e2e: 'none' }).encryption.score <= 45);
  assert.ok(evaluate({ ...base, url: 'ws://x.example' }).warnings.some((w) => /not encrypted/.test(w)));
  const tor = evaluate({ ...base, anon: 'tor' }); // direct route cannot really use Tor
  assert.ok(tor.warnings.some((w) => /cannot route itself/.test(w)));
  assert.equal(tor.privacy.parts[0].pts, 0);
  const torOk = evaluate({ ...base, anon: 'tor', route: 'bridge', bridgeUrl: 'ws://127.0.0.1:8765', bridgeInfo: { tls: true, protocol: 'TLSv1.3', cipher: 'TLS_AES_256_GCM_SHA384', authorized: true } });
  assert.ok(torOk.privacy.score > r.privacy.score && torOk.encryption.score > r.encryption.score);
  assert.ok(torOk.layers[0].kind === 'anon');
});
