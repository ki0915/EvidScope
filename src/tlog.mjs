// Dependency-free (node:crypto only) transparency-log primitives and the EvidScope verifier:
// RFC 6962/9162 Merkle trees, C2SP signed-note, tlog-checkpoint, tlog-cosignature (cosignature/v1, subtree/v1),
// tlog-witness client helpers and c2sp.org/tlog-proof@v1. Validated against test/fixtures/c2sp-vectors.json
// (Go golang.org/x/mod sumdb + filippo.io/torchwood) and a live litewitness.
// This module must not import other EvidScope modules so it can be published standalone.
import {createHash, createPublicKey, createPrivateKey, sign as edSign, verify as edVerify} from 'node:crypto';

export const SIG_ED25519 = 0x01, SIG_COSIG_ED25519 = 0x04, SIG_COSIG_MLDSA44 = 0x06;
export const EMPTY_ROOT = createHash('sha256').digest();
export const TRANSPARENCY_FORMAT = 'evidscope-transparency-v1';
export const HEADS_LEAF_FORMAT = 'evidscope-heads-leaf-v1';
export const HEADS_ENTRY_FORMAT = 'evidscope-heads-entry-v1';
const EMDASH = '—';
const sha256 = (...parts) => { const h = createHash('sha256'); for (const p of parts) h.update(p); return h.digest(); };

// Same canonical JSON as src/crypto.mjs (sorted keys, no whitespace), duplicated to keep this module standalone.
export function canonicalJson(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canonicalJson).join(',') + ']';
  return '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + canonicalJson(v[k])).join(',') + '}';
}

// ---------- encodings ----------
export const b64 = buf => Buffer.from(buf).toString('base64');
// Canonical padded RFC 4648 base64 only: Buffer.from(s,'base64') silently accepts junk, missing padding and non-zero pad bits.
export function fromB64(s) {
  if (typeof s !== 'string' || s.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(s)) throw Error('non-canonical base64');
  const b = Buffer.from(s, 'base64');
  if (b.toString('base64') !== s) throw Error('non-canonical base64');
  return b;
}
const DEC = /^(0|[1-9][0-9]*)$/;
export function parseSize(s) {
  if (!DEC.test(s)) throw Error('bad decimal');
  const n = Number(s);
  if (!Number.isSafeInteger(n)) throw Error('size too large');
  return n;
}
export const hashFromHex = hex => {
  if (typeof hex !== 'string' || !/^[a-f0-9]{64}$/.test(hex)) throw Error('Record hash must be 64 lowercase hex characters');
  return Buffer.from(hex, 'hex');
};
const hash32 = (value, what) => {
  const buf = typeof value === 'string' ? fromB64(value) : value;
  if (!Buffer.isBuffer(buf) || buf.length !== 32) throw Error(`bad ${what || 'hash'}`);
  return buf;
};

// ---------- keys ----------
export function isValidKeyName(name) {
  return typeof name === 'string' && name.length > 0 && !/[\s\u0085+]/u.test(name) && Buffer.from(name, 'utf8').toString('utf8') === name;
}
export const keyId = (name, type, pub) => sha256(Buffer.from(name, 'utf8'), Buffer.from([0x0a, type]), pub).subarray(0, 4);
export const vkeyString = (name, type, pub) => `${name}+${keyId(name, type, pub).toString('hex')}+${b64(Buffer.concat([Buffer.from([type]), pub]))}`;
export function parseVkey(vkey) {
  if (typeof vkey !== 'string') throw Error('malformed vkey');
  const i = vkey.indexOf('+'), j = vkey.indexOf('+', i + 1);
  if (i < 0 || j < 0) throw Error('malformed vkey');
  const name = vkey.slice(0, i), idHex = vkey.slice(i + 1, j), key = fromB64(vkey.slice(j + 1));
  if (!isValidKeyName(name) || !/^[0-9a-f]{8}$/.test(idHex) || key.length < 2) throw Error('malformed vkey');
  const type = key[0], pub = key.subarray(1);
  if ((type === SIG_ED25519 || type === SIG_COSIG_ED25519) && pub.length !== 32) throw Error('bad Ed25519 key length');
  if (type === SIG_COSIG_MLDSA44 && pub.length !== 1312) throw Error('bad ML-DSA-44 key length');
  if (!keyId(name, type, pub).equals(Buffer.from(idHex, 'hex'))) throw Error('vkey key ID mismatch');
  return {name, id: Buffer.from(idHex, 'hex'), type, pub, vkey};
}
const asPublicKey = key => (typeof key === 'object' && key?.type === 'public' ? key : createPublicKey(key));
export const ed25519Public = raw => createPublicKey({key: {kty: 'OKP', crv: 'Ed25519', x: Buffer.from(raw).toString('base64url')}, format: 'jwk'});
const PKCS8_ED25519 = Buffer.from('302e020100300506032b657004220420', 'hex');
const SPKI_MLDSA44 = Buffer.from('30820532300b06096086480165030403110382052100', 'hex');
export const ed25519PrivateFromSeed = seed => createPrivateKey({key: Buffer.concat([PKCS8_ED25519, seed]), format: 'der', type: 'pkcs8'});
export const ed25519RawPublic = key => Buffer.from(asPublicKey(key).export({format: 'jwk'}).x, 'base64url');
// SPKI prefix for id-ml-dsa-44 (2.16.840.1.101.3.4.3.17).
export const mldsa44Public = raw => createPublicKey({key: Buffer.concat([SPKI_MLDSA44, raw]), format: 'der', type: 'spki'});
// The vault (log) key signs notes for many origins; its key ID differs per origin because the name is hashed in.
export const logVkey = (origin, publicKey) => vkeyString(origin, SIG_ED25519, ed25519RawPublic(publicKey));
export const noteSigner = (name, privateKey) => ({name, privateKey, pub: ed25519RawPublic(privateKey)});

// ---------- signed note ----------
export function signNote(text, signer) {
  if (!text.endsWith('\n')) throw Error('note text must end with newline');
  const id = keyId(signer.name, SIG_ED25519, signer.pub);
  return `${text}\n${EMDASH} ${signer.name} ${b64(Buffer.concat([id, edSign(null, Buffer.from(text, 'utf8'), signer.privateKey)]))}\n`;
}
// verifiers: [{name, id, type, verify(textBuf, sigBytesAfterKeyId) -> bool}]. Unknown signatures are ignored,
// a failing known signature rejects the note, and at least one known signature must verify.
export function openNote(note, verifiers, {maxSigs = 100, maxBytes = 1024 * 1024} = {}) {
  if (typeof note !== 'string' || Buffer.byteLength(note) > maxBytes) throw Error('malformed note: not UTF-8');
  if (Buffer.from(note, 'utf8').toString('utf8') !== note) throw Error('malformed note: not UTF-8');
  if (/[\u0000-\u0009\u000b-\u001f]/.test(note)) throw Error('malformed note: control character');
  const split = note.lastIndexOf('\n\n');
  if (split < 0) throw Error('malformed note: no signature block');
  const text = note.slice(0, split + 1), block = note.slice(split + 2);
  if (!block.length || !block.endsWith('\n')) throw Error('malformed note: signatures must end with newline');
  const lines = block.slice(0, -1).split('\n');
  if (lines.length > maxSigs) throw Error('malformed note: too many signatures');
  const sigs = [], unknown = [], seen = new Set(), textBuf = Buffer.from(text, 'utf8');
  for (const line of lines) {
    if (!line.startsWith(EMDASH + ' ')) throw Error('malformed note: bad signature line');
    const rest = line.slice(2), sp = rest.indexOf(' ');
    if (sp < 0) throw Error('malformed note: bad signature line');
    const name = rest.slice(0, sp), sigB64 = rest.slice(sp + 1), raw = fromB64(sigB64);
    if (!isValidKeyName(name) || raw.length < 5) throw Error('malformed note: bad signature line');
    const id = raw.subarray(0, 4), k = `${name}+${id.toString('hex')}`;
    const matches = verifiers.filter(v => v.name === name && v.id.equals(id));
    if (matches.length > 1) throw Error('ambiguous verifier ' + k);
    if (!matches.length) { unknown.push({name, id: id.toString('hex'), b64: sigB64, line: line + '\n'}); continue; }
    if (seen.has(k)) continue;
    seen.add(k);
    if (!matches[0].verify(textBuf, raw.subarray(4))) throw Error('invalid signature for key ' + k);
    sigs.push({name, id: id.toString('hex'), type: matches[0].type, b64: sigB64, raw, line: line + '\n'});
  }
  if (!sigs.length) throw Error('note has no verifiable signatures');
  return {text, sigs, unknown};
}
export function noteVerifier(vkey) {
  const k = parseVkey(vkey);
  if (k.type !== SIG_ED25519) throw Error('not an Ed25519 note vkey');
  const pk = ed25519Public(k.pub);
  return {...k, verify: (msg, sig) => sig.length === 64 && edVerify(null, msg, pk, sig)};
}
// Signature lines (each ending in LF) of a signed note, without verification.
export function noteSignatureLines(note) {
  const split = note.lastIndexOf('\n\n');
  if (split < 0) throw Error('malformed note: no signature block');
  return note.slice(split + 2).split('\n').filter(Boolean).map(l => l + '\n');
}
export function noteText(note) {
  const split = note.lastIndexOf('\n\n');
  if (split < 0) throw Error('malformed note: no signature block');
  return note.slice(0, split + 1);
}

// ---------- checkpoint ----------
export const formatCheckpoint = ({origin, size, root, extensions = []}) => `${origin}\n${size}\n${b64(root)}\n` + extensions.map(e => e + '\n').join('');
export function parseCheckpoint(text) {
  if (typeof text !== 'string' || !text.endsWith('\n')) throw Error('malformed checkpoint');
  const lines = text.slice(0, -1).split('\n');
  if (lines.length < 3) throw Error('malformed checkpoint');
  const [origin, sizeS, rootS, ...extensions] = lines;
  if (!origin || Buffer.byteLength(origin) > 255) throw Error('malformed checkpoint: origin');
  const size = parseSize(sizeS), root = fromB64(rootS);
  if (root.length !== 32) throw Error('malformed checkpoint: root');
  if (extensions.some(e => !e)) throw Error('malformed checkpoint: empty extension line');
  if (size === 0 && !root.equals(EMPTY_ROOT)) throw Error('size 0 must have empty-tree root');
  return {origin, size, root, extensions};
}

// ---------- cosignatures ----------
export const cosignatureMessage = (timestamp, checkpointText) => Buffer.from(`cosignature/v1\ntime ${BigInt(timestamp)}\n${checkpointText}`, 'utf8');
function canonicalCheckpointText(text) {
  const t = text.toString('utf8'), c = parseCheckpoint(t);
  return formatCheckpoint(c) === t ? c : null;
}
// subtree/v1 (ML-DSA-44) signs a binary message over [0,size) without extension lines.
export function subtreeMessage(cosignerName, timestamp, origin, start, end, root) {
  const u64 = v => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(v)); return b; };
  const name = Buffer.from(cosignerName, 'utf8'), o = Buffer.from(origin, 'utf8');
  if (name.length > 255 || o.length > 255) throw Error('name too long');
  const len = b => Buffer.from([b.length]);
  return Buffer.concat([Buffer.from('subtree/v1\n\0'), len(name), name, u64(timestamp), len(o), o, u64(start), u64(end), root]);
}
// Pluggable verifiers keyed by signature type; 0x04 is what litewitness emits today.
export const cosignatureVerifiers = {
  [SIG_COSIG_ED25519]: k => {
    const pk = ed25519Public(k.pub);
    return (text, sig) => {
      if (sig.length !== 72) return false;
      const ts = sig.readBigUInt64BE(0);
      if (ts > 0x7fffffffffffffffn) return false;
      const c = canonicalCheckpointText(text);
      return !!c && edVerify(null, cosignatureMessage(ts, text.toString('utf8')), pk, sig.subarray(8));
    };
  },
  [SIG_COSIG_MLDSA44]: k => {
    const pk = mldsa44Public(k.pub);
    return (text, sig) => {
      if (sig.length !== 8 + 2420) return false;
      const ts = sig.readBigUInt64BE(0), c = canonicalCheckpointText(text);
      if (!c || c.extensions.length || ts === 0n) return false;
      return edVerify(null, subtreeMessage(k.name, ts, c.origin, 0, c.size, c.root), pk, sig.subarray(8));
    };
  },
};
export function cosignatureVerifier(vkey) {
  const k = parseVkey(vkey), make = cosignatureVerifiers[k.type];
  if (!make) throw Error('not a supported cosignature vkey');
  return {...k, verify: make(k)};
}
export function cosign(checkpointText, {name, privateKey, pub}, timestamp) {
  const id = keyId(name, SIG_COSIG_ED25519, pub), ts = Buffer.alloc(8);
  ts.writeBigUInt64BE(BigInt(timestamp));
  return `${EMDASH} ${name} ${b64(Buffer.concat([id, ts, edSign(null, cosignatureMessage(timestamp, checkpointText), privateKey)]))}\n`;
}
export const cosignatureTimestamp = sigRaw => Number(sigRaw.readBigUInt64BE(4));

// ---------- RFC 6962 Merkle tree ----------
export const leafHash = data => sha256(Buffer.from([0]), data);
export const nodeHash = (l, r) => sha256(Buffer.from([1]), l, r);
export const recordLeaf = hex => leafHash(hashFromHex(hex));
const split = n => { let k = 1; while (k * 2 < n) k *= 2; return k; };
// JS bitwise operators are int32: never use (m&(m-1)) for sizes; divide instead.
const isPow2 = x => { while (x > 1) { if (x % 2) return false; x /= 2; } return x === 1; };
const half = x => Math.floor(x / 2);
const popcount = n => { let c = 0; while (n > 0) { c += n % 2; n = half(n); } return c; };
export function mth(leaves) {
  const n = leaves.length;
  if (!n) return EMPTY_ROOT;
  if (n === 1) return leaves[0];
  const k = split(n);
  return nodeHash(mth(leaves.slice(0, k)), mth(leaves.slice(k)));
}
// Frontier ("peaks"): MTH of the maximal complete subtrees, left to right, one per set bit of size.
export function frontierAppend(peaks, size, leaf) {
  const p = peaks.slice();
  let h = leaf, m = size;
  while (m % 2 === 1) { h = nodeHash(p.pop(), h); m = half(m); }
  p.push(h);
  return p;
}
export function frontierRoot(peaks) {
  if (!peaks.length) return EMPTY_ROOT;
  let acc = peaks[peaks.length - 1];
  for (let i = peaks.length - 2; i >= 0; i--) acc = nodeHash(peaks[i], acc);
  return acc;
}
export const peaksToBlob = peaks => Buffer.concat(peaks);
export function blobToPeaks(blob, size) {
  const buf = Buffer.from(blob ?? []);
  if (!Number.isSafeInteger(size) || size < 0 || buf.length !== 32 * popcount(size)) throw Error('Truncated or inconsistent tlog frontier');
  const out = [];
  for (let i = 0; i < buf.length; i += 32) out.push(buf.subarray(i, i + 32));
  return out;
}
// One streaming pass that returns the roots at the requested sizes (sizes beyond the leaf count are omitted).
export function rootsAtSizes(leaves, sizes) {
  const want = new Set(sizes), out = new Map();
  let peaks = [], n = 0;
  if (want.has(0)) out.set(0, EMPTY_ROOT);
  for (const leaf of leaves) {
    peaks = frontierAppend(peaks, n, leaf);
    n++;
    if (want.has(n)) out.set(n, frontierRoot(peaks));
  }
  return {roots: out, size: n, peaks};
}
// Recursive reference proofs (RFC 9162 2.1.3.1 / 2.1.4.1). Use merkleLevels for many proofs over large trees.
export function inclusionProof(leaves, index) {
  const n = leaves.length;
  if (index < 0 || index >= n) throw Error('bad index');
  if (n === 1) return [];
  const k = split(n);
  if (index < k) return [...inclusionProof(leaves.slice(0, k), index), mth(leaves.slice(k))];
  return [...inclusionProof(leaves.slice(k), index - k), mth(leaves.slice(0, k))];
}
export function verifyInclusion(leaf, index, size, proof, root) {
  if (!(Number.isSafeInteger(index) && Number.isSafeInteger(size) && index >= 0 && index < size)) return false;
  let fn = index, sn = size - 1, r = leaf;
  for (const p of proof) {
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      r = nodeHash(p, r);
      if (fn % 2 === 0) while (fn % 2 === 0 && fn !== 0) { fn = half(fn); sn = half(sn); }
    } else r = nodeHash(r, p);
    fn = half(fn); sn = half(sn);
  }
  return sn === 0 && r.equals(root);
}
function subproof(m, n, b, range) {
  const out = [];
  const sub = (lo, hi, mm, bb) => {
    const nn = hi - lo;
    if (mm === nn) { if (!bb) out.push(range(lo, hi)); return; }
    const k = split(nn);
    if (mm <= k) { sub(lo, lo + k, mm, bb); out.push(range(lo + k, hi)); } else { sub(lo + k, hi, mm - k, false); out.push(range(lo, lo + k)); }
  };
  sub(0, n, m, b);
  return out;
}
export function consistencyProof(leaves, m) {
  const n = leaves.length;
  if (!(m > 0 && m <= n)) throw Error('bad sizes');
  return subproof(m, n, true, (lo, hi) => mth(leaves.slice(lo, hi)));
}
// Every old-side node of PROOF(m,n) is a frontier node of m and every new-side node lies inside [m,n),
// so the proof needs only peaks(m) plus the new leaves: O(n-m).
export function consistencyProofFromFrontier(m, peaksM, newLeaves) {
  const n = m + newLeaves.length;
  if (!(m > 0 && m <= n)) throw Error('bad sizes');
  const peak = new Map();
  let lo = 0, i = 0, r = m;
  for (let bit = 2 ** Math.floor(Math.log2(m)); bit >= 1; bit /= 2) {
    if (r >= bit) { peak.set(`${lo},${lo + bit}`, peaksM[i++]); lo += bit; r -= bit; }
  }
  const range = (lo, hi) => {
    if (hi <= m) { const p = peak.get(`${lo},${hi}`); if (!p) throw Error('needed old node is not a frontier node'); return p; }
    if (lo >= m) return mth(newLeaves.slice(lo - m, hi - m));
    throw Error('straddling range');
  };
  return subproof(m, n, true, range);
}
export function verifyConsistency(m, n, oldRoot, newRoot, proof) {
  if (!(Number.isSafeInteger(m) && Number.isSafeInteger(n) && m >= 0 && m <= n)) return false;
  if (m === 0) return proof.length === 0;
  if (m === n) return proof.length === 0 && oldRoot.equals(newRoot);
  if (!proof.length) return false;
  const path = isPow2(m) ? [oldRoot, ...proof] : proof;
  let fn = m - 1, sn = n - 1;
  while (fn % 2 === 1) { fn = half(fn); sn = half(sn); }
  let fr = path[0], sr = path[0];
  for (const c of path.slice(1)) {
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      fr = nodeHash(c, fr); sr = nodeHash(c, sr);
      if (fn % 2 === 0) while (fn % 2 === 0 && fn !== 0) { fn = half(fn); sn = half(sn); }
    } else sr = nodeHash(sr, c);
    fn = half(fn); sn = half(sn);
  }
  return fr.equals(oldRoot) && sr.equals(newRoot) && sn === 0;
}
// All tree levels in contiguous buffers (2n hashes): O(n) build, O(log n) per proof. A node without a
// sibling is promoted unchanged, which matches the RFC 6962 split at the largest power of two.
export function merkleLevels(leaves) {
  const levels = [Buffer.concat(leaves)];
  let count = leaves.length;
  while (count > 1) {
    const prev = levels[levels.length - 1], next = Buffer.alloc(32 * Math.ceil(count / 2));
    for (let i = 0; i + 1 < count; i += 2) nodeHash(prev.subarray(32 * i, 32 * i + 32), prev.subarray(32 * i + 32, 32 * i + 64)).copy(next, 16 * i);
    if (count % 2) prev.copy(next, 16 * (count - 1), 32 * (count - 1), 32 * count);
    levels.push(next);
    count = Math.ceil(count / 2);
  }
  return {size: leaves.length, levels};
}
// MTH(D[lo:hi]) for a range that is a node of the tree (lo aligned to the range's level).
export function levelRange({size, levels}, lo, hi) {
  if (!(lo >= 0 && lo < hi && hi <= size)) throw Error('bad range');
  let level = 0;
  while (2 ** level < hi - lo) level++;
  const width = 2 ** level;
  if (lo % width !== 0 || (hi !== lo + width && hi !== size)) throw Error('range is not a tree node');
  const i = lo / width;
  return Buffer.from(levels[level].subarray(32 * i, 32 * i + 32));
}
export const levelsRoot = tree => (tree.size ? levelRange(tree, 0, tree.size) : EMPTY_ROOT);
export function levelsInclusionProof(tree, index) {
  if (!(index >= 0 && index < tree.size)) throw Error('bad index');
  const out = [];
  const path = (lo, hi, i) => {
    if (hi - lo === 1) return;
    const k = split(hi - lo);
    if (i < lo + k) { path(lo, lo + k, i); out.push(levelRange(tree, lo + k, hi)); } else { path(lo + k, hi, i); out.push(levelRange(tree, lo, lo + k)); }
  };
  path(0, tree.size, index);
  return out;
}
export function levelsConsistencyProof(tree, m, n = tree.size) {
  if (!(m > 0 && m <= n && n <= tree.size)) throw Error('bad sizes');
  if (n !== tree.size) throw Error('levels must be built for the new size');
  return subproof(m, n, true, (lo, hi) => levelRange(tree, lo, hi));
}

// ---------- tlog-witness client ----------
export function addCheckpointBody(oldSize, proof, signedNote) {
  if (proof.length > 63) throw Error('too many proof lines');
  if (oldSize === 0 && proof.length) throw Error('old 0 requires empty proof');
  return `old ${oldSize}\n` + proof.map(h => b64(h) + '\n').join('') + '\n' + signedNote;
}
export function parseAddCheckpointBody(body) {
  const blank = body.indexOf('\n\n');
  if (blank < 0) throw Error('missing blank line');
  const head = body.slice(0, blank).split('\n'), note = body.slice(blank + 2);
  if (!head[0].startsWith('old ')) throw Error('missing old line');
  const old = parseSize(head[0].slice(4)), proof = head.slice(1).map(h => hash32(h, 'proof hash'));
  if (proof.length > 63) throw Error('too many proof lines');
  return {old, proof, note};
}
export function parseConflictBody(contentType, body) {
  if (!/^text\/x\.tlog\.size\b/.test(contentType || '')) throw Error('409 without text/x.tlog.size');
  if (!/^(0|[1-9][0-9]*)\n$/.test(body)) throw Error('bad 409 body');
  return parseSize(body.slice(0, -1));
}
export function parseCosignatureResponse(body) {
  if (typeof body !== 'string' || !body.endsWith('\n')) throw Error('bad cosignature response');
  return body.slice(0, -1).split('\n').map(l => { if (!l.startsWith(EMDASH + ' ')) throw Error('bad cosignature line'); return l + '\n'; });
}
// POST <prefix>/add-checkpoint. Network errors become status 0 so callers can treat them as unknown state.
export async function postAddCheckpoint(prefix, body, {timeoutMs = 5000, fetchImpl = fetch} = {}) {
  const url = String(prefix).replace(/\/+$/, '') + '/add-checkpoint';
  try {
    const r = await fetchImpl(url, {method: 'POST', headers: {'content-type': 'text/plain'}, body, signal: AbortSignal.timeout(timeoutMs), redirect: 'error'});
    const text = await r.text();
    return {status: r.status, type: r.headers.get('content-type') || '', body: text.length > 65536 ? text.slice(0, 65536) : text};
  } catch (error) {
    return {status: 0, type: '', body: '', error: error?.name || 'network error'};
  }
}

// ---------- c2sp.org/tlog-proof@v1 ----------
export function formatTlogProof(index, proof, signedCheckpoint, extra) {
  const head = 'c2sp.org/tlog-proof@v1\n' + (extra ? `extra ${b64(extra)}\n` : '') + `index ${index}\n`;
  return head + proof.map(h => b64(h) + '\n').join('') + '\n' + signedCheckpoint;
}
export function parseTlogProof(s) {
  let rest = s;
  const take = () => {
    const i = rest.indexOf('\n');
    if (i < 0) throw Error('malformed tlog proof');
    const l = rest.slice(0, i);
    rest = rest.slice(i + 1);
    return l;
  };
  if (take() !== 'c2sp.org/tlog-proof@v1') throw Error('not a tlog proof');
  let l = take(), extra = null;
  if (l.startsWith('extra ')) { extra = fromB64(l.slice(6)); l = take(); }
  if (!l.startsWith('index ')) throw Error('malformed tlog proof: index');
  const index = parseSize(l.slice(6)), proof = [];
  for (;;) { const h = take(); if (h === '') break; proof.push(hash32(h, 'proof hash')); }
  return {extra, index, proof, signedCheckpoint: rest};
}
// policy: {origin, logVkeys:[...], witnesses:[{vkey}|vkey], quorum}. Requires the log signature and >= quorum distinct cosigners.
export function verifyCheckpointWithPolicy(signedCheckpoint, policy) {
  const logV = policy.logVkeys.map(noteVerifier), witV = (policy.witnesses || []).map(w => cosignatureVerifier(typeof w === 'string' ? w : w.vkey));
  const n = openNote(signedCheckpoint, [...logV, ...witV]), c = parseCheckpoint(n.text);
  if (c.origin !== policy.origin) throw Error('unexpected origin');
  if (!n.sigs.some(s => logV.some(v => v.name === s.name && v.id.toString('hex') === s.id))) throw Error('log signature missing');
  const cos = n.sigs.filter(s => witV.some(v => v.name === s.name && v.id.toString('hex') === s.id));
  if (cos.length < (policy.quorum ?? 0)) throw Error(`witness quorum not met: ${cos.length}/${policy.quorum}`);
  return {checkpoint: c, cosignatures: cos.map(s => ({name: s.name, keyId: s.id, timestamp: cosignatureTimestamp(s.raw)}))};
}
export function verifyTlogProof(proofText, leafHashValue, policy) {
  const p = parseTlogProof(proofText), r = verifyCheckpointWithPolicy(p.signedCheckpoint, policy);
  if (!verifyInclusion(leafHashValue, p.index, r.checkpoint.size, p.proof, r.checkpoint.root)) throw Error('inclusion proof failed');
  return {...r, index: p.index, extra: p.extra};
}

// ---------- EvidScope origins and heads log ----------
export const ORIGIN_BASE_RE = /^[a-z0-9.-]+(\/[A-Za-z0-9._~-]+)*$/;
export function validateOriginBase(base) {
  if (typeof base !== 'string' || !ORIGIN_BASE_RE.test(base) || Buffer.byteLength(base) > 200) {
    throw Error('Transparency origin base must match ' + ORIGIN_BASE_RE + ' and be at most 200 bytes');
  }
  return base;
}
// Hashed tenant IDs keep customer names out of witness origin listings.
export const tenantLogId = tenant => sha256(Buffer.from(String(tenant), 'utf8')).toString('hex').slice(0, 32);
export const tenantOrigin = (base, tenant) => `${base}/t/${tenantLogId(tenant)}`;
export const headsOrigin = base => `${base}/heads`;
export function originBaseOf(origin, tenant) {
  const suffix = `/t/${tenantLogId(tenant)}`;
  if (typeof origin !== 'string' || !origin.endsWith(suffix)) throw Error('Transparency origin is not bound to the tenant');
  return validateOriginBase(origin.slice(0, -suffix.length));
}
export function headsEntry(log, size, root) {
  if (typeof log !== 'string' || !Number.isSafeInteger(size) || size < 0) throw Error('bad heads entry');
  return {log, size, root: Buffer.isBuffer(root) ? root.toString('hex') : root};
}
export const headsEntryLeaf = e => leafHash(Buffer.from(canonicalJson({format: HEADS_ENTRY_FORMAT, log: e.log, root: e.root, size: e.size}), 'utf8'));
export const sortHeadsEntries = entries => entries.slice().sort((a, b) => (a.log < b.log ? -1 : a.log > b.log ? 1 : 0));
export function headsLeafContent(entries) {
  const sorted = sortHeadsEntries(entries);
  for (let i = 1; i < sorted.length; i++) if (sorted[i].log === sorted[i - 1].log) throw Error('duplicate heads entry');
  return {entries: sorted.length, entriesRoot: mth(sorted.map(headsEntryLeaf)).toString('hex')};
}
export const headsLeafData = leaf => Buffer.from(canonicalJson({entries: leaf.entries, entriesRoot: leaf.entriesRoot, format: HEADS_LEAF_FORMAT}), 'utf8');
export const headsLeafHash = leaf => leafHash(headsLeafData(leaf));

// ---------- EvidScope verifier ----------
export const DEFAULT_MAX_STALENESS_SECONDS = 86400;
const nowSeconds = now => Math.floor((now ?? Date.now()) / 1000);
const witnessVerifiers = witnesses => (witnesses || []).map(w => cosignatureVerifier(typeof w === 'string' ? w : w.vkey));
const policyOf = options => {
  const witnesses = (options.witnesses || []).length;
  return {witnesses, quorum: options.quorum ?? (witnesses ? 1 : 0), maxStalenessSeconds: options.maxStalenessSeconds ?? DEFAULT_MAX_STALENESS_SECONDS};
};
function originBaseFor(tenant, origin, originBase) {
  if (originBase !== undefined && originBase !== null) {
    validateOriginBase(originBase);
    if (origin !== undefined && origin !== tenantOrigin(originBase, tenant)) throw Error('Transparency origin differs from pinned origin base');
    return originBase;
  }
  return originBaseOf(origin, tenant);
}
function openLogNote(note, origin, publicKey, extraVerifiers = []) {
  const logV = noteVerifier(logVkey(origin, publicKey)), n = openNote(note, [logV, ...extraVerifiers]), c = parseCheckpoint(n.text);
  if (c.origin !== origin) throw Error('Transparency checkpoint origin mismatch');
  if (!n.sigs.some(s => s.name === logV.name && s.id === logV.id.toString('hex'))) throw Error('Transparency checkpoint log signature missing');
  if (c.extensions.length) throw Error('Transparency checkpoint has unexpected extension lines');
  return {note: n, checkpoint: c};
}
// Counts distinct configured cosigners; future timestamps beyond the skew reject the evidence.
function witnessSummary(opened, verifiers, options, skewSeconds = 300) {
  const t = nowSeconds(options.now), policy = policyOf(options), witnesses = [];
  for (const s of opened.sigs) {
    if (!verifiers.some(v => v.name === s.name && v.id.toString('hex') === s.id)) continue;
    const timestamp = cosignatureTimestamp(s.raw);
    if (timestamp > t + skewSeconds) throw Error('Witness cosignature timestamp is in the future');
    witnesses.push({name: s.name, keyId: s.id, timestamp, ageSeconds: Math.max(0, t - timestamp)});
  }
  const fresh = witnesses.filter(w => w.ageSeconds <= policy.maxStalenessSeconds).length;
  const met = n => policy.quorum > 0 && n >= policy.quorum;
  return {witnesses, quorum: policy.quorum, quorumMet: met(witnesses.length), fresh: met(fresh)};
}
// The heads leaf must be the newest leaf of the cosigned heads checkpoint, so the cosignature time applies to it.
function verifyHeads(heads, {tenantOriginValue, base, publicKey, verifiers, options}) {
  const hOrigin = headsOrigin(base);
  if (!heads || heads.origin !== hOrigin) throw Error('Transparency heads origin mismatch');
  const opened = openLogNote(heads.checkpoint, hOrigin, publicKey, verifiers), cp = opened.checkpoint, leaf = heads.leaf, entry = heads.entry;
  const hex64 = /^[a-f0-9]{64}$/, count = v => Number.isSafeInteger(v) && v > 0;
  if (!leaf || !count(leaf.entries) || !hex64.test(leaf.entriesRoot || '')) throw Error('Transparency heads leaf invalid');
  if (!entry || entry.log !== tenantOriginValue || !count(entry.size) || !hex64.test(entry.root || '')) {
    throw Error('Transparency heads entry is not bound to this tenant log');
  }
  if (heads.leafIndex !== cp.size - 1) throw Error('Transparency heads leaf is not the newest cosigned leaf');
  const leafProof = (heads.leafProof || []).map(h => hash32(h, 'proof hash')), entryProof = (heads.entryProof || []).map(h => hash32(h, 'proof hash'));
  if (!verifyInclusion(headsLeafHash(leaf), heads.leafIndex, cp.size, leafProof, cp.root)) throw Error('Transparency heads leaf inclusion proof failed');
  if (!verifyInclusion(headsEntryLeaf(entry), heads.entryIndex, leaf.entries, entryProof, Buffer.from(leaf.entriesRoot, 'hex'))) {
    throw Error('Transparency heads entry inclusion proof failed');
  }
  return {cp, entry, summary: witnessSummary(opened.note, verifiers, options)};
}
function finishResult(result, options) {
  result.witnessPolicy = policyOf(options);
  result.rollbackChecked = !!(result.minimumCheckpoint?.satisfied || result.heads?.fresh);
  if (options.require) {
    if (!result.present) throw Error('Transparency evidence missing');
    if (result.witnessPolicy.quorum > 0 && !result.heads?.quorumMet) throw Error('Transparency witness quorum not met');
  }
  return result;
}
const headsResult = (heads, material, base) => ({
  origin: headsOrigin(base), size: heads.cp.size, leafIndex: material.heads.leafIndex, witnessedTenantSize: heads.entry.size, ...heads.summary,
});
// Prefix semantics: a minimum checkpoint (C2SP note of the tenant log, or an evidscope-checkpoint-v1 object) must be
// a prefix of the export; a larger or conflicting minimum means rollback, truncation or a fork.
function checkMinimum(minimumCheckpoint, {tenant, tOrigin, publicKey, records, count, rootAt}) {
  if (typeof minimumCheckpoint === 'object' && minimumCheckpoint?.format === 'evidscope-checkpoint-v1') {
    const size = minimumCheckpoint.count, head = minimumCheckpoint.head;
    if (minimumCheckpoint.tenant !== tenant || !Number.isSafeInteger(size) || size < 0) throw Error('Minimum checkpoint tenant mismatch');
    if (size > count) throw Error('Export is older than the minimum checkpoint: possible rollback or truncation');
    if (size > 0 ? records[size - 1]?.hash !== head : head !== '0'.repeat(64)) throw Error('Export conflicts with the minimum checkpoint (fork)');
    return {kind: 'v1', size, satisfied: true};
  }
  if (typeof minimumCheckpoint !== 'string') throw Error('Unsupported minimum checkpoint');
  if (!tOrigin) throw Error('A C2SP minimum checkpoint needs the export transparency origin or an origin base');
  const {checkpoint} = openLogNote(minimumCheckpoint, tOrigin, publicKey);
  if (checkpoint.size > count) throw Error('Export is older than the minimum checkpoint: possible rollback or truncation');
  if (!rootAt(checkpoint.size).equals(checkpoint.root)) throw Error('Export conflicts with the minimum checkpoint (fork)');
  return {kind: 'note', size: checkpoint.size, satisfied: true};
}
// Full-export verification: every leaf is present, so prefix roots are recomputed instead of shipping consistency proofs.
// leaves: leaf hashes of seq 1..count, already chain-verified by the caller.
export function verifyBundleTransparency({bundle, leaves, publicKey, options = {}}) {
  const tenant = bundle.checkpoint.tenant, count = leaves.length, material = bundle.transparency;
  const hasMinimum = options.minimumCheckpoint !== undefined && options.minimumCheckpoint !== null;
  if (material && material.format !== TRANSPARENCY_FORMAT) throw Error('Unsupported transparency evidence');
  const base = material || options.originBase ? originBaseFor(tenant, material?.origin, options.originBase) : null;
  const tOrigin = base ? tenantOrigin(base, tenant) : null;
  const tenantNote = material ? openLogNote(material.checkpoint, tOrigin, publicKey).checkpoint : null;
  if (tenantNote && tenantNote.size > count) throw Error('Transparency checkpoint is ahead of exported records: Truncated or inconsistent export');
  const verifiers = witnessVerifiers(options.witnesses);
  const heads = material?.heads ? verifyHeads(material.heads, {tenantOriginValue: tOrigin, base, publicKey, verifiers, options}) : null;
  const cache = new Map();
  const rootAt = size => {
    if (!cache.has(size)) { const {roots} = rootsAtSizes(leaves, [size]); cache.set(size, roots.get(size)); }
    return cache.get(size);
  };
  const sizes = [count, ...(tenantNote ? [tenantNote.size] : []), ...(heads ? [heads.entry.size] : [])];
  for (const [k, v] of rootsAtSizes(leaves, sizes).roots) cache.set(k, v);
  const result = {present: !!material, count, exportRoot: b64(rootAt(count)), heads: null};
  if (tenantNote) {
    if (!rootAt(tenantNote.size).equals(tenantNote.root)) throw Error('Transparency checkpoint root differs from exported records (fork)');
    Object.assign(result, {origin: tOrigin, originBase: base, size: tenantNote.size, root: b64(tenantNote.root), unsignedTail: count - tenantNote.size});
  }
  if (heads) {
    if (heads.entry.size > count) throw Error('Export is behind witnessed tenant head: possible rollback or truncation');
    if (rootAt(heads.entry.size).toString('hex') !== heads.entry.root) throw Error('Witnessed tenant head differs from exported records (fork)');
    result.heads = headsResult(heads, material, base);
  }
  if (hasMinimum) result.minimumCheckpoint = checkMinimum(options.minimumCheckpoint, {tenant, tOrigin, publicKey, records: bundle.records, count, rootAt});
  return finishResult(result, options);
}
// Case reports carry only the action's records: inclusion proofs bind them to the signed tenant tree and a
// consistency proof binds the witnessed tenant head to the report checkpoint. snapshot is verified by the caller.
export function verifyReportTransparency({report, publicKey, options = {}}) {
  const s = report.snapshot, tenant = s.tenant, count = s.checkpoint.count, material = report.transparency;
  if (!material) return finishResult({present: false, heads: null}, options);
  if (material.format !== TRANSPARENCY_FORMAT) throw Error('Unsupported transparency evidence');
  const base = originBaseFor(tenant, material.origin, options.originBase), tOrigin = tenantOrigin(base, tenant);
  const tenantNote = openLogNote(material.checkpoint, tOrigin, publicKey).checkpoint;
  if (tenantNote.size !== count) throw Error('Transparency checkpoint size differs from report checkpoint');
  const proven = new Map();
  for (const item of material.inclusion || []) {
    if (!Number.isSafeInteger(item?.seq) || item.seq < 1 || item.seq > count || proven.has(item.seq)) throw Error('Transparency inclusion entry invalid');
    const proof = (item.proof || []).map(h => hash32(h, 'proof hash'));
    if (!verifyInclusion(recordLeaf(item.hash), item.seq - 1, count, proof, tenantNote.root)) {
      throw Error('Transparency inclusion proof failed for sequence ' + item.seq);
    }
    proven.set(item.seq, item.hash);
  }
  if (count > 0 && proven.get(count) !== s.checkpoint.head) throw Error('Transparency checkpoint is not bound to the report checkpoint head');
  const events = s.action?.events || [];
  for (const e of events) if (proven.get(e.seq) !== e.hash) throw Error('Report event is not included in the signed tenant tree');
  const verifiers = witnessVerifiers(options.witnesses);
  const result = {present: true, origin: tOrigin, originBase: base, size: count, root: b64(tenantNote.root), includedEvents: events.length, heads: null};
  if (material.heads) {
    const heads = verifyHeads(material.heads, {tenantOriginValue: tOrigin, base, publicKey, verifiers, options});
    if (heads.entry.size > count) throw Error('Report is behind witnessed tenant head: possible rollback or truncation');
    const proof = (material.heads.consistency || []).map(h => hash32(h, 'proof hash'));
    if (!verifyConsistency(heads.entry.size, count, Buffer.from(heads.entry.root, 'hex'), tenantNote.root, proof)) {
      throw Error('Witnessed tenant head is inconsistent with the report checkpoint (fork)');
    }
    result.heads = headsResult(heads, material, base);
  }
  return finishResult(result, options);
}
