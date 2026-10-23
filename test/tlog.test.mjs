import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createHash, generateKeyPairSync, verify as cverify} from 'node:crypto';
import * as T from '../src/tlog.mjs';

const V = JSON.parse(readFileSync(new URL('./fixtures/c2sp-vectors.json', import.meta.url)));
const H = x => Buffer.from(x.hex, 'hex');
const leaves = V.tree.leaves.map(l => H(l.leaf_hash));
const hex = list => list.map(h => h.toString('hex'));
const synthetic = n => [...Array(n)].map((_, i) => T.leafHash(createHash('sha256').update(`leaf-${i}`).digest()));

test('C2SP vectors: keys, key IDs and vkeys', () => {
  const priv = T.ed25519PrivateFromSeed(Buffer.from(V.log_key.seed_hex, 'hex')), pub = T.ed25519RawPublic(priv);
  assert.equal(pub.toString('hex'), V.log_key.public_key_hex);
  assert.equal(T.keyId(V.log_key.key_name, 1, pub).toString('hex'), V.log_key.key_id_hex);
  assert.equal(T.vkeyString(V.log_key.key_name, 1, pub), V.log_key.vkey);
  assert.equal(T.logVkey(V.log_key.key_name, priv), V.log_key.vkey);
  const w = T.ed25519RawPublic(T.ed25519PrivateFromSeed(Buffer.from(V.witness_key.seed_hex, 'hex')));
  assert.equal(T.vkeyString(V.witness_key.key_name, 4, w), V.witness_key.vkey);
  assert.equal(T.keyId(V.witness_key.key_name, 1, w).toString('hex'), V.witness_key.wrong_type_key_id_hex_if_0x01_used);
  const p = T.parseVkey(V.mldsa44_cosignature.vkey);
  assert.equal(p.type, 6); assert.equal(p.pub.length, 1312);
  assert.throws(() => T.parseVkey(V.log_key.vkey.replace('+4e352908+', '+4e352909+')), /key ID/);
  assert.throws(() => T.parseVkey('bad name+4e352908+AQOh'), /malformed/);
  assert.throws(() => T.noteVerifier(V.witness_key.vkey), /not an Ed25519 note vkey/);
});

test('C2SP vectors: leaf hashes, roots and frontier; raw 32-byte leaf data', () => {
  V.tree.leaves.forEach(l => assert.equal(T.leafHash(Buffer.from(l.data_hex, 'hex')).toString('hex'), l.leaf_hash.hex));
  V.tree.leaves.forEach(l => assert.equal(T.recordLeaf(l.data_hex).toString('hex'), l.leaf_hash.hex));
  let peaks = [];
  for (const r of V.tree.roots_by_size) {
    assert.equal(T.mth(leaves.slice(0, r.size)).toString('hex'), r.root.hex);
    assert.deepEqual(hex(peaks), r.frontier_left_to_right.map(x => x.hex));
    assert.equal(T.frontierRoot(peaks).toString('hex'), r.root.hex);
    assert.deepEqual(hex(T.blobToPeaks(T.peaksToBlob(peaks), r.size)), hex(peaks));
    if (r.size < leaves.length) peaks = T.frontierAppend(peaks, r.size, leaves[r.size]);
  }
  const alt = V.tree.NOT_RECOMMENDED_hex_string_leaf_data;
  assert.equal(T.mth(V.tree.leaves.map(l => T.leafHash(Buffer.from(l.data_hex, 'ascii')))).toString('hex'), alt.root_5.hex);
  assert.notEqual(alt.root_5.hex, V.checkpoint.root.hex);
  assert.throws(() => T.recordLeaf('A'.repeat(64)), /lowercase hex/);
  assert.throws(() => T.blobToPeaks(Buffer.alloc(32), 3), /frontier/);
});

test('C2SP vectors: signed checkpoints are byte-identical to Go and open with the log key', () => {
  const privateKey = T.ed25519PrivateFromSeed(Buffer.from(V.log_key.seed_hex, 'hex')), signer = T.noteSigner(V.log_key.key_name, privateKey);
  for (const cp of [V.checkpoint, V.checkpoint_size3]) {
    const text = T.formatCheckpoint({origin: cp.origin, size: cp.size, root: H(cp.root)});
    assert.equal(text, cp.note_text);
    assert.equal(T.signNote(text, signer), cp.signed_note);
    const n = T.openNote(cp.signed_note, [T.noteVerifier(V.log_key.vkey)]);
    assert.equal(n.text, cp.note_text); assert.equal(n.sigs.length, 1);
    const c = T.parseCheckpoint(n.text);
    assert.equal(c.size, cp.size); assert.equal(c.root.toString('hex'), cp.root.hex);
  }
  assert.equal(T.openNote(V.signed_note_spec_example.signed_note, [T.noteVerifier(V.signed_note_spec_example.vkey)]).text, 'This is an example message.\n');
});

test('C2SP vectors: negative notes, lenient base64 and size parsing are rejected', () => {
  const v = [T.noteVerifier(V.log_key.vkey)];
  for (const c of V.negative) {
    if (c.note_text) { assert.throws(() => T.parseCheckpoint(c.note_text), undefined, c.name); continue; }
    assert.throws(() => T.openNote(c.signed_note, v), undefined, c.name);
  }
  assert.throws(() => T.fromB64(V.checkpoint.root.b64.replace('=', '')));
  assert.throws(() => T.fromB64('JUe8IYY6eYn0hM8r4VvzdqinJvMTgevs4DqEMWA/Wl1='));
  assert.throws(() => T.fromB64('JUe8IYY6eYn0hM8r4VvzdqinJvMTgevs4DqEMWA_Wl0='));
  assert.throws(() => T.parseSize('01'), /decimal/);
  assert.throws(() => T.parseSize(String(2 ** 53)), /too large/);
  assert.throws(() => T.parseCheckpoint(`o\n0\n${T.b64(Buffer.alloc(32, 1))}\n`), /empty-tree/);
});

test('C2SP vectors: inclusion and consistency proofs match Go for every pair up to size 5', () => {
  const tree = T.merkleLevels(leaves);
  for (const c of V.inclusion_all) {
    assert.deepEqual(hex(T.inclusionProof(leaves.slice(0, c.tree_size), c.leaf_index)), c.proof.map(x => x.hex));
    if (c.tree_size === leaves.length) assert.deepEqual(hex(T.levelsInclusionProof(tree, c.leaf_index)), c.proof.map(x => x.hex));
    assert.ok(T.verifyInclusion(H(c.leaf_hash), c.leaf_index, c.tree_size, c.proof.map(H), H(c.root)));
  }
  for (const c of V.consistency_all) {
    assert.deepEqual(hex(T.consistencyProof(leaves.slice(0, c.new_size), c.old_size)), c.proof.map(x => x.hex), `${c.old_size}->${c.new_size}`);
    let peaks = [];
    for (let i = 0; i < c.old_size; i++) peaks = T.frontierAppend(peaks, i, leaves[i]);
    assert.deepEqual(hex(T.consistencyProofFromFrontier(c.old_size, peaks, leaves.slice(c.old_size, c.new_size))), c.proof.map(x => x.hex));
    assert.ok(T.verifyConsistency(c.old_size, c.new_size, H(c.old_root), H(c.new_root), c.proof.map(H)));
  }
});

test('C2SP vectors: cosignature/v1, ML-DSA-44 subtree/v1, witness request bodies and tlog-proof', () => {
  const C = V.cosignature;
  assert.equal(T.cosignatureMessage(C.timestamp, V.checkpoint.note_text).toString('hex'), C.signed_message_hex);
  const wpriv = T.ed25519PrivateFromSeed(Buffer.from(V.witness_key.seed_hex, 'hex'));
  assert.equal(T.cosign(V.checkpoint.note_text, {name: V.witness_key.key_name, privateKey: wpriv, pub: T.ed25519RawPublic(wpriv)}, C.timestamp), C.line);
  const n = T.openNote(C.cosigned_note, [T.noteVerifier(V.log_key.vkey), T.cosignatureVerifier(V.witness_key.vkey)]);
  assert.equal(n.sigs.length, 2); assert.equal(T.cosignatureTimestamp(n.sigs[1].raw), C.timestamp);
  // Only-witness verifiers still accept the note: policies must also require the log key.
  assert.equal(T.openNote(C.cosigned_note, [T.cosignatureVerifier(V.witness_key.vkey)]).unknown.length, 1);
  const M = V.mldsa44_cosignature, raw = Buffer.from(M.signature_bytes_b64, 'base64');
  const message = T.subtreeMessage(M.key_name, M.timestamp, V.checkpoint.origin, 0, V.checkpoint.size, H(V.checkpoint.root));
  assert.equal(message.toString('hex'), M.cosigned_subtree_message_hex);
  let mldsa = true;
  try { T.mldsa44Public(Buffer.from(M.public_key_b64, 'base64')); } catch { mldsa = false; }
  if (mldsa) {
    assert.ok(cverify(null, Buffer.from(M.cosigned_subtree_message_hex, 'hex'), T.mldsa44Public(Buffer.from(M.public_key_b64, 'base64')), raw.subarray(12)));
    const verifier = T.cosignatureVerifier(M.vkey);
    assert.ok(verifier.verify(Buffer.from(V.checkpoint.note_text), raw.subarray(4)));
    assert.ok(!verifier.verify(Buffer.from(V.checkpoint_size3.note_text), raw.subarray(4)));
  }
  const W = V.witness_requests;
  assert.equal(T.addCheckpointBody(0, [], V.checkpoint_size3.signed_note), W.first_old0_size3);
  assert.equal(T.addCheckpointBody(3, V.consistency.proof.map(H), V.checkpoint.signed_note), W.next_old3_size5);
  assert.deepEqual(T.parseAddCheckpointBody(W.next_old3_size5).old, 3);
  assert.equal(T.parseConflictBody('text/x.tlog.size', '5\n'), 5);
  assert.throws(() => T.parseConflictBody('text/plain', '5\n'), /x\.tlog\.size/);
  assert.throws(() => T.addCheckpointBody(0, [leaves[0]], V.checkpoint.signed_note), /old 0/);
  const P = V.tlog_proof, leaf = T.leafHash(Buffer.from(P.leaf_data_hex, 'hex'));
  const policy = {origin: V.checkpoint.origin, logVkeys: [V.log_key.vkey], witnesses: [{vkey: V.witness_key.vkey}], quorum: 1};
  const r = T.verifyTlogProof(P.proof_text, leaf, policy);
  assert.equal(r.index, 2); assert.equal(r.cosignatures[0].timestamp, C.timestamp);
  const p = T.parseTlogProof(P.proof_text);
  assert.equal(T.formatTlogProof(p.index, p.proof, p.signedCheckpoint), P.proof_text);
  assert.throws(() => T.verifyTlogProof(P.proof_text.replace(C.line, ''), leaf, policy), /quorum/);
  assert.throws(() => T.verifyTlogProof(P.proof_text, leaves[3], policy), /inclusion/);
});

test('property: frontier root equals recursive MTH for every size up to 300 and levels agree', () => {
  const all = synthetic(300);
  let peaks = [];
  for (let n = 0; n <= 300; n++) {
    const expected = T.mth(all.slice(0, n));
    assert.ok(T.frontierRoot(peaks).equals(expected), `frontier ${n}`);
    if (n && n % 37 === 0) assert.ok(T.levelsRoot(T.merkleLevels(all.slice(0, n))).equals(expected), `levels ${n}`);
    if (n < 300) peaks = T.frontierAppend(peaks, n, all[n]);
  }
  const {roots, size} = T.rootsAtSizes(all, [0, 1, 7, 128, 300, 301]);
  assert.equal(size, 300); assert.equal(roots.has(301), false);
  for (const s of [0, 1, 7, 128, 300]) assert.ok(roots.get(s).equals(T.mth(all.slice(0, s))));
});

test('property: inclusion and consistency proofs for every pair up to size 70 (generators and verifiers agree)', () => {
  const all = synthetic(70);
  for (let n = 1; n <= 70; n++) {
    const prefix = all.slice(0, n), root = T.mth(prefix), tree = T.merkleLevels(prefix);
    let peaks = [];
    for (let m = 1; m <= n; m++) {
      const proof = T.consistencyProof(prefix, m);
      peaks = T.frontierAppend(peaks, m - 1, all[m - 1]);
      assert.deepEqual(hex(T.consistencyProofFromFrontier(m, peaks, prefix.slice(m))), hex(proof), `frontier ${m}->${n}`);
      assert.deepEqual(hex(T.levelsConsistencyProof(tree, m)), hex(proof), `levels ${m}->${n}`);
      assert.ok(T.verifyConsistency(m, n, T.mth(all.slice(0, m)), root, proof), `verify ${m}->${n}`);
      assert.ok(proof.length <= 63);
      if (proof.length) {
        const bad = proof.slice(); bad[bad.length - 1] = Buffer.alloc(32);
        assert.ok(!T.verifyConsistency(m, n, T.mth(all.slice(0, m)), root, bad));
      }
      if (m < n) assert.ok(!T.verifyConsistency(m, n, T.mth(all.slice(1, m + 1)), root, proof), `fork ${m}->${n}`);
    }
    for (let i = 0; i < n; i++) {
      const proof = T.inclusionProof(prefix, i);
      assert.deepEqual(hex(T.levelsInclusionProof(tree, i)), hex(proof), `levels incl ${i}/${n}`);
      assert.ok(T.verifyInclusion(all[i], i, n, proof, root));
      if (n > 1) assert.ok(!T.verifyInclusion(all[(i + 1) % n], i, n, proof, root));
    }
    assert.ok(!T.verifyInclusion(all[0], n, n, [], root));
  }
});

test('property: sampled proofs over larger trees and int32-unsafe sizes', () => {
  const all = synthetic(1500), tree = T.merkleLevels(all), root = T.levelsRoot(tree);
  assert.ok(root.equals(T.mth(all)));
  for (const m of [1, 2, 3, 511, 512, 513, 1023, 1024, 1025, 1499]) {
    const proof = T.levelsConsistencyProof(tree, m);
    assert.ok(T.verifyConsistency(m, 1500, T.mth(all.slice(0, m)), root, proof), `${m}`);
  }
  for (const i of [0, 1, 700, 1023, 1024, 1499]) assert.ok(T.verifyInclusion(all[i], i, 1500, T.levelsInclusionProof(tree, i), root));
  // With identical leaves MTH depends only on the size, so huge virtual trees are cheap; JS int32 bitwise traps appear above 2^31.
  const L = T.leafHash(createHash('sha256').update('x').digest()), memo = new Map(), split = n => { let k = 1; while (k * 2 < n) k *= 2; return k; };
  const M = n => { if (memo.has(n)) return memo.get(n); const k = split(n), h = n === 1 ? L : T.nodeHash(M(k), M(n - k)); memo.set(n, h); return h; };
  const cons = (m, n) => {
    const out = [], sub = (lo, hi, mm, b) => {
      const nn = hi - lo;
      if (mm === nn) { if (!b) out.push(M(nn)); return; }
      const k = split(nn);
      if (mm <= k) { sub(lo, lo + k, mm, b); out.push(M(hi - lo - k)); } else { sub(lo + k, hi, mm - k, false); out.push(M(k)); }
    };
    sub(0, n, m, true); return out;
  };
  const incl = (i, n) => { if (n === 1) return []; const k = split(n); return i < k ? [...incl(i, k), M(n - k)] : [...incl(i - k, n - k), M(k)]; };
  const pairs = [[2 ** 32 + 2 ** 31, 2 ** 33 + 5], [2 ** 32, 2 ** 32 + 1], [2 ** 40 - 1, 2 ** 40 + 3], [3 * 2 ** 31, 2 ** 34],
    [2 ** 52 + 1, 2 ** 52 + 7], [6, 2 ** 35]];
  for (const [m, n] of pairs) {
    assert.ok(T.verifyConsistency(m, n, M(m), M(n), cons(m, n)), `${m}->${n}`);
    for (const i of [0, m - 1, n - 1, Math.floor(n / 3)]) assert.ok(T.verifyInclusion(L, i, n, incl(i, n), M(n)), `${i}/${n}`);
  }
});

test('EvidScope origins, heads leaves and the bundle verifier bind tenant, prefix roots and witnesses', () => {
  const {privateKey, publicKey} = generateKeyPairSync('ed25519'), base = 'evidscope.test/unit', tenant = 'alpha';
  assert.equal(T.tenantOrigin(base, tenant), `${base}/t/${T.tenantLogId(tenant)}`);
  assert.equal(T.originBaseOf(T.tenantOrigin(base, tenant), tenant), base);
  assert.throws(() => T.validateOriginBase('Evid scope/x'), /origin base/);
  assert.throws(() => T.originBaseOf(T.tenantOrigin(base, 'beta'), tenant), /not bound/);
  const records = [...Array(9)].map((_, i) => ({seq: i + 1, hash: createHash('sha256').update('r' + i).digest('hex')}));
  const recordLeaves = records.map(r => T.recordLeaf(r.hash)), origin = T.tenantOrigin(base, tenant);
  const sign = (o, size, root) => T.signNote(T.formatCheckpoint({origin: o, size, root}), T.noteSigner(o, privateKey));
  const note = size => sign(origin, size, T.mth(recordLeaves.slice(0, size)));
  const entries = [T.headsEntry(origin, 6, T.mth(recordLeaves.slice(0, 6))), T.headsEntry(T.tenantOrigin(base, 'beta'), 2, Buffer.alloc(32, 7))];
  const sorted = T.sortHeadsEntries(entries), leaf = T.headsLeafContent(entries), entryIndex = sorted.findIndex(e => e.log === origin);
  const headsLeaves = [T.leafHash(Buffer.from('earlier')), T.headsLeafHash(leaf)], hOrigin = T.headsOrigin(base);
  const wkey = generateKeyPairSync('ed25519').privateKey, wpub = T.ed25519RawPublic(wkey), wname = 'witness.test/w1', wvkey = T.vkeyString(wname, 4, wpub);
  const headsText = T.formatCheckpoint({origin: hOrigin, size: 2, root: T.mth(headsLeaves)}), ts = Math.floor(Date.now() / 1000) - 10;
  const cosigned = sign(hOrigin, 2, T.mth(headsLeaves)) + T.cosign(headsText, {name: wname, privateKey: wkey, pub: wpub}, ts);
  const heads = {origin: hOrigin, checkpoint: cosigned, leafIndex: 1, leafProof: T.inclusionProof(headsLeaves, 1).map(T.b64), leaf,
    entry: sorted[entryIndex], entryIndex, entryProof: T.inclusionProof(sorted.map(T.headsEntryLeaf), entryIndex).map(T.b64)};
  const bundle = {checkpoint: {tenant}, records, transparency: {format: T.TRANSPARENCY_FORMAT, origin, checkpoint: note(9), heads}};
  const check = (options, b = bundle, leaves = recordLeaves, key = publicKey) => T.verifyBundleTransparency({bundle: b, leaves, publicKey: key, options});
  const ok = check({witnesses: [wvkey], originBase: base, maxStalenessSeconds: 60});
  assert.equal(ok.present, true); assert.equal(ok.rollbackChecked, true); assert.equal(ok.heads.quorumMet, true); assert.equal(ok.heads.witnessedTenantSize, 6);
  const stale = check({witnesses: [wvkey], maxStalenessSeconds: 60, now: Date.now() + 3600e3});
  assert.equal(stale.rollbackChecked, false); assert.equal(stale.heads.quorumMet, true);
  assert.equal(check({}).rollbackChecked, false);
  assert.throws(() => check({witnesses: [T.vkeyString('other/w', 4, wpub)], require: true}), /quorum/);
  assert.throws(() => check({}, bundle, recordLeaves.slice(0, 5)), /Truncated|behind/);
  const forked = recordLeaves.slice(); forked[2] = T.leafHash(Buffer.from('fork'));
  assert.throws(() => check({}, bundle, forked), /fork/);
  assert.throws(() => check({}, bundle, recordLeaves, generateKeyPairSync('ed25519').publicKey), /signature/);
  assert.throws(() => check({}, {...bundle, checkpoint: {tenant: 'beta'}}), /not bound/);
  assert.throws(() => check({originBase: 'evidscope.test/other'}), /pinned origin base/);
  const min = check({minimumCheckpoint: note(4)});
  assert.deepEqual(min.minimumCheckpoint, {kind: 'note', size: 4, satisfied: true}); assert.equal(min.rollbackChecked, true);
  assert.throws(() => check({minimumCheckpoint: sign(origin, 12, Buffer.alloc(32))}), /older than the minimum/);
  assert.throws(() => check({minimumCheckpoint: sign(origin, 4, Buffer.alloc(32))}), /fork/);
  const legacy = {...bundle, transparency: undefined};
  assert.throws(() => check({require: true}, legacy), /missing/);
  assert.equal(check({minimumCheckpoint: {format: 'evidscope-checkpoint-v1', tenant, count: 3, head: records[2].hash}}, legacy).rollbackChecked, true);
  assert.throws(() => check({minimumCheckpoint: {format: 'evidscope-checkpoint-v1', tenant, count: 10, head: records[2].hash}}, legacy), /older/);
  const badEntry = {...bundle, transparency: {...bundle.transparency, heads: {...heads, entry: {...heads.entry, size: 5}}}};
  assert.throws(() => check({}, badEntry), /inclusion/);
  const olderLeaf = {...bundle, transparency: {...bundle.transparency, heads: {...heads, leafIndex: 0}}};
  assert.throws(() => check({}, olderLeaf), /newest/);
});

test('a cosigned tenant checkpoint binds a signing key holder only when fresh, under the pinned origin base and extended by the export', () => {
  const {privateKey, publicKey} = generateKeyPairSync('ed25519'), base = 'evidscope.test/unit', tenant = 'alpha', origin = T.tenantOrigin(base, tenant);
  const records = [...Array(9)].map((_, i) => ({seq: i + 1, hash: createHash('sha256').update('r' + i).digest('hex')}));
  const leaves = records.map(r => T.recordLeaf(r.hash)), rootOf = size => T.mth(leaves.slice(0, size));
  const sign = (o, size, root) => T.signNote(T.formatCheckpoint({origin: o, size, root}), T.noteSigner(o, privateKey));
  const wkey = generateKeyPairSync('ed25519').privateKey, wname = 'witness.test/w1', wvkey = T.vkeyString(wname, 4, T.ed25519RawPublic(wkey));
  const now = Math.floor(Date.now() / 1000), witness = {name: wname, privateKey: wkey, pub: T.ed25519RawPublic(wkey)};
  const cosigned = (size, ts, root = rootOf(size), o = origin) => sign(o, size, root) + T.cosign(T.formatCheckpoint({origin: o, size, root}), witness, ts);
  const bundle = tenantCosigned => ({checkpoint: {tenant}, records,
    transparency: {format: T.TRANSPARENCY_FORMAT, origin, checkpoint: sign(origin, 9, rootOf(9)), ...(tenantCosigned ? {tenantCosigned} : {})}});
  const policy = {witnesses: [wvkey], originBase: base, maxStalenessSeconds: 600};
  const check = (b, options = policy) => T.verifyBundleTransparency({bundle: b, leaves, publicKey, options});
  const strict = {...policy, requireTenantWitness: true};

  let r = check(bundle({checkpoint: cosigned(7, now - 10)}), strict);
  assert.deepEqual([r.rollbackChecked, r.rollbackCheckedAgainst, r.heads], [true, 'signing_key_holder', null]);
  assert.deepEqual([r.tenantCosigned.origin, r.tenantCosigned.size, r.tenantCosigned.quorumMet, r.tenantCosigned.fresh], [origin, 7, true, true]);
  assert.equal(r.tenantCosigned.witnesses[0].name, wname);
  // A stale cosignature bounds nothing: a rollback after it is possible.
  r = check(bundle({checkpoint: cosigned(7, now - 3600)}));
  assert.deepEqual([r.rollbackChecked, r.rollbackCheckedAgainst, r.tenantCosigned.quorumMet, r.tenantCosigned.fresh], [false, null, true, false]);
  assert.throws(() => check(bundle({checkpoint: cosigned(7, now - 3600)}), strict), /cosignatures are older than 600 seconds/);
  // Without a pinned origin base a key holder could have signed a fresh origin: the quorum only binds database tamper.
  const {originBase: _, ...unpinned} = policy;
  assert.equal(check(bundle({checkpoint: cosigned(7, now - 10)}), unpinned).rollbackCheckedAgainst, 'database_tamper');
  assert.throws(() => check(bundle({checkpoint: cosigned(7, now - 10)}), {...unpinned, requireTenantWitness: true}), /needs a pinned origin base/);
  // No witnesses configured, no evidence, or a foreign witness: never the stronger level.
  assert.equal(check(bundle({checkpoint: cosigned(7, now - 10)}), {originBase: base}).rollbackCheckedAgainst, null);
  assert.throws(() => check(bundle(null), strict), /tenant witness evidence missing/);
  const foreign = T.vkeyString('witness.test/other', 4, T.ed25519RawPublic(generateKeyPairSync('ed25519').privateKey));
  assert.throws(() => check(bundle({checkpoint: cosigned(7, now - 10)}), {...strict, witnesses: [foreign]}), /tenant witness quorum not met: 0\/1/);
  // The export must extend the cosigned checkpoint, which must name this tenant log and carry valid signatures.
  assert.throws(() => check(bundle({checkpoint: cosigned(7, now - 10, Buffer.alloc(32, 1))})), /tenant checkpoint differs from exported records \(fork\)/);
  assert.throws(() => check(bundle({checkpoint: cosigned(12, now - 10, Buffer.alloc(32, 2))})), /behind the witnessed tenant checkpoint/);
  assert.throws(() => check(bundle({checkpoint: cosigned(7, now - 10, rootOf(7), T.tenantOrigin(base, 'beta'))})), /origin mismatch/);
  const lines = cosigned(7, now - 10).split('\n'), raw = Buffer.from(lines.at(-2).split(' ')[2], 'base64');
  raw[raw.length - 1] ^= 1;
  lines[lines.length - 2] = lines.at(-2).split(' ').slice(0, 2).join(' ') + ' ' + raw.toString('base64');
  assert.throws(() => check(bundle({checkpoint: lines.join('\n')})), /invalid signature for key witness\.test\/w1/);
  assert.throws(() => check(bundle({checkpoint: 42})), /tenant cosigned checkpoint invalid/);
  assert.throws(() => check(bundle({checkpoint: cosigned(7, now + 3600)})), /in the future/);
});
