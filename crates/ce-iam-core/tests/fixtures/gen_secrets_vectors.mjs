// Golden-vector generator for ce-iam-core::secrets — RUN AGAINST THE CANONICAL JS VAULT.
//
//   node gen_secrets_vectors.mjs > secrets_vectors.json
//
// It imports the SAME crypto.mjs + vault.mjs that the production JS vault uses, drives a real vault
// over an in-memory store with a FIXED owner device key and a FIXED clock, and emits everything the
// Rust port must reproduce byte-for-byte:
//
//   * deriveOwnerMaster(owner, ns)         — deterministic master from the owner scalar.
//   * a real `d.<owner>` enrollment record  — wrappedMaster (Rust must UNWRAP to the same master) +
//     the signed record (Rust must VERIFY the signature, and reproduce signRecord's canonical bytes).
//   * a sealed secret                       — Rust must OPEN it to the same plaintext.
//   * a signed challenge (fixed nonce/ts)   — Rust must VERIFY it.
//   * the device id derivation              — Rust must recompute it.
//
// Randomized outputs (wrap IV, seal IV) are baked into the vectors; the Rust gate is DECRYPT/VERIFY
// parity on those, plus byte-identical output on the deterministic pieces (derive, canonical, id).

import * as C from '../../../../../ce-secrets/src/crypto.mjs';
import * as A from '../../../../../ce-secrets/src/auth.mjs';
import * as V from '../../../../../ce-secrets/src/vault.mjs';

// A FIXED owner device key (real P-256 keys; pinned so the vectors are reproducible). Reuse the key
// already embedded in the committed vectors so regeneration is deterministic; override with
// OWNER_KEY=<json>, or generate a fresh one only if neither is available.
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
const HERE = dirname(fileURLToPath(import.meta.url));
function pinnedOwner() {
  if (process.env.OWNER_KEY) return JSON.parse(process.env.OWNER_KEY);
  const f = join(HERE, 'secrets_vectors.json');
  if (existsSync(f)) {
    try { return JSON.parse(readFileSync(f, 'utf8')).owner; } catch { /* fall through */ }
  }
  return null;
}
const OWNER = pinnedOwner() || (await C.generateDeviceKey());

const NS = 'golden-ns';
const TS = '2026-06-26T00:00:00.000Z';
const now = () => TS;

// In-memory store with the ctx shape the vault expects.
function memStore() {
  const m = new Map();
  return {
    async get(k) { return m.has(k) ? structuredClone(m.get(k)) : null; },
    async put(k, v) { m.set(k, structuredClone(v)); },
    async del(k) { m.delete(k); },
    async list(p) { return [...m.entries()].filter(([k]) => k.startsWith(p)).map(([k, value]) => ({ key: k, value: structuredClone(value) })); },
    _dump() { return Object.fromEntries(m); },
  };
}

// Patch Date so vault timestamps are the fixed TS (vault.mjs uses new Date().toISOString()).
const RealDate = Date;
globalThis.Date = class extends RealDate {
  constructor(...a) { if (a.length === 0) { super(RealDate.parse(TS)); } else { super(...a); } }
  static now() { return RealDate.parse(TS); }
  toISOString() { return TS; }
};

const store = memStore();
const ctx = { store, device: OWNER, ns: NS };

// 1) init the vault from the owner -> derives master, enrolls owner, writes meta.
await V.initVault(ctx, 'owner device');
const master = await C.deriveOwnerMaster(OWNER, NS);
const deviceRec = await store.get(`d.${OWNER.id}`);

// 2) seal a secret under the master.
const plaintext = 'super-secret-value-42';
const sealed = await C.sealSecret(master, C.enc.utf8.enc(plaintext));

// 3) put a secret THROUGH the vault (full record + signRecord) so the record canonicalization is pinned.
await V.putSecret(ctx, 'db-password', C.enc.utf8.enc(plaintext), 'opaque');
const secretRec = await store.get('s.db-password');

// 4) sign a challenge with a fixed nonce/ts.
const NONCE = 'golden-nonce-0001';
const AUD = 'ce-watch';
const proof = await V.signChallenge(ctx, AUD, NONCE, TS);

// 5) issue a grant (its signed record + token).
const grant = await V.issueGrant(ctx, 'ce-cast', { read: ['db-password'] });

// Canonical string signRecord actually hashes for the device record (signature covers this).
function stableStringify(o) { return JSON.stringify(o, Object.keys(o).sort()); }
const deviceSignedBody = { ...deviceRec }; delete deviceSignedBody.sig;
const secretSignedBody = { ...secretRec }; delete secretSignedBody.sig;

const out = {
  note: 'Golden vectors for ce-iam-core::secrets vs ce-secrets/src/{crypto,vault}.mjs. Rust must reproduce/verify these byte-for-byte.',
  version: 1,
  ns: NS,
  ts: TS,
  owner: OWNER,
  deviceId: OWNER.id,
  master: { hex: C.enc.hex.enc(master) },
  enrollment: {
    key: `d.${OWNER.id}`,
    record: deviceRec,
    signedCanonical: stableStringify(deviceSignedBody),
    expectUnwrapMasterHex: C.enc.hex.enc(master),
  },
  secretSealed: {
    plaintext,
    sealed,
    expectOpenPlaintext: plaintext,
  },
  secretRecord: {
    key: 's.db-password',
    record: secretRec,
    signedCanonical: stableStringify(secretSignedBody),
    expectFp: await C.fingerprint(C.enc.utf8.enc(plaintext)),
  },
  challenge: {
    aud: AUD,
    nonce: NONCE,
    ts: TS,
    proof,
    canonical: A.stable_stringify({ aud: AUD, deviceId: OWNER.id, nonce: NONCE, ts: TS }),
    expectVerify: true,
  },
  grant: {
    token: grant.token,
    record: grant.grant,
    audience: 'ce-cast',
    action: 'read',
    name: 'db-password',
    expectVerify: true,
  },
};

process.stdout.write(JSON.stringify(out, null, 2) + '\n');
