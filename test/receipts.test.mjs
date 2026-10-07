// DSSE v1 / in-toto Statement v1 (src/dsse.mjs) and c2sp.org/tlog-policy (src/tlog-policy.mjs) against their specifications.
import test from 'node:test';
import assert from 'node:assert/strict';
import {createPublicKey, generateKeyPairSync, verify} from 'node:crypto';
import {readFileSync} from 'node:fs';
import * as D from '../src/dsse.mjs';
import * as P from '../src/tlog-policy.mjs';
import {caseReportFileName, safeFileName, tenantTlogPolicy} from '../src/receipts.mjs';
import * as T from '../src/tlog.mjs';

const V = JSON.parse(readFileSync(new URL('./fixtures/c2sp-vectors.json', import.meta.url), 'utf8'));
const witnessKey = name => {
  const {privateKey} = generateKeyPairSync('ed25519'), pub = T.ed25519RawPublic(privateKey);
  return {name, privateKey, pub, vkey: T.vkeyString(name, T.SIG_COSIG_ED25519, pub)};
};
const logKey = origin => {
  const {privateKey} = generateKeyPairSync('ed25519');
  return {origin, privateKey, vkey: T.logVkey(origin, privateKey), signer: T.noteSigner(origin, privateKey)};
};
const now = Date.now(), ts = Math.floor(now / 1000) - 60;

test('PAE and the DSSE protocol test vector (ECDSA P-256), in standard and URL-safe base64', () => {
  assert.equal(D.pae('http://example.com/HelloWorld', Buffer.from('hello world')).toString(), 'DSSEv1 29 http://example.com/HelloWorld 11 hello world');
  assert.equal(D.pae('t', Buffer.alloc(0)).toString(), 'DSSEv1 1 t 0 ');
  assert.equal(D.pae('ü', Buffer.from('x')).toString(), 'DSSEv1 2 ü 1 x');
  const coord = n => Buffer.from(BigInt(n).toString(16).padStart(64, '0'), 'hex').toString('base64url');
  const key = createPublicKey({format: 'jwk', key: {kty: 'EC', crv: 'P-256',
    x: coord('46950820868899156662930047687818585632848591499744589407958293238635476079160'),
    y: coord('5640078356564379163099075877009565129882514886557779369047442380624545832820')}});
  const p256 = {verify: (m, s) => verify('sha256', m, {key, dsaEncoding: 'ieee-p1363'}, s)}, payloadTypes = ['http://example.com/HelloWorld'];
  const sig = 'A3JqsQGtVsJ2O2xqrI5IcnXip5GToJ3F+FnZ+O88SjtR6rDAajabZKciJTfUiHqJPcIAriEGAHTVeCUjW2JIZA==';
  const envelope = {payload: 'aGVsbG8gd29ybGQ=', payloadType: payloadTypes[0], signatures: [{sig}]};
  assert.equal(D.openEnvelope(envelope, [p256], {payloadTypes}).body.toString(), 'hello world');
  const urlSafe = {...envelope, payload: 'aGVsbG8gd29ybGQ', signatures: [{sig: sig.replaceAll('+', '-').replace(/=+$/, '')}]};
  assert.equal(D.openEnvelope(urlSafe, [p256], {payloadTypes}).body.toString(), 'hello world');
  assert.throws(() => D.openEnvelope({...envelope, payloadType: 'http://example.com/Other'}, [p256], {payloadTypes}), /signature verification failed/);
  assert.throws(() => D.openEnvelope(envelope, [p256]), /Unsupported DSSE payload type/);
});

test('DSSE envelopes accept only canonical base64 and count distinct accepting keys', async () => {
  assert.equal(D.decodeBase64('aGVsbG8gd29ybGQ=').toString(), 'hello world');
  for (const bad of ['aGVsbG8gd29ybGR=', 'aGVsbG8gd29ybGQ==', 'aGVsbG8gd29ybGQ=\n', ' aGVs', 'ab+_', 'aGVsbG8gd29ybGQ=x', 'YQ=', 'Y', 12]) {
    assert.throws(() => D.decodeBase64(bad), /not canonical/, String(bad));
  }
  const a = generateKeyPairSync('ed25519'), b = generateKeyPairSync('ed25519'), body = Buffer.from('{"x":1}');
  const signer = k => ({keyid: D.keyFingerprint(k.publicKey), sign: async m => (await import('node:crypto')).sign(null, m, k.privateKey)});
  const one = await D.signEnvelope(D.INTOTO_PAYLOAD_TYPE, body, signer(a));
  assert.equal(one.signatures[0].keyid, D.sha256Hex(a.publicKey.export({format: 'der', type: 'spki'})));
  const two = {...one, signatures: [...one.signatures, ...(await D.signEnvelope(D.INTOTO_PAYLOAD_TYPE, body, signer(b))).signatures]};
  const va = D.ed25519Verifier(a.publicKey), vb = D.ed25519Verifier(b.publicKey);
  assert.deepEqual(D.openEnvelope(two, [va, vb], {threshold: 2}).keyids, [va.keyid, vb.keyid]);
  assert.throws(() => D.openEnvelope(one, [va, vb], {threshold: 2}), /verification failed/);
  // A failing signature is skipped, not fatal; keyids are hints only, so a wrong keyid does not matter.
  const noisy = {...one, signatures: [{keyid: 'x', sig: Buffer.alloc(64).toString('base64')}, {...one.signatures[0], keyid: vb.keyid}]};
  assert.equal(D.openEnvelope(noisy, [va]).body.toString(), '{"x":1}');
  assert.throws(() => D.openEnvelope({...one, signatures: []}, [va]), /signature count/);
  assert.throws(() => D.openEnvelope({...one, signatures: [{sig: one.signatures[0].sig, keyid: 7}]}, [va]), /Malformed DSSE signature/);
  assert.throws(() => D.ed25519Verifier(generateKeyPairSync('ec', {namedCurve: 'P-256'}).publicKey), /Ed25519/);
});

test('in-toto Statement v1 parsing matches subjects by digest and rejects malformed statements', () => {
  const s = D.intotoStatement([{name: 'a.json', sha256: 'ab'.repeat(32)}], 'https://example.com/p', {k: 1});
  assert.equal(D.matchingSubject(D.parseStatement(Buffer.from(JSON.stringify(s))), 'ab'.repeat(32)).name, 'a.json');
  assert.equal(D.matchingSubject(s, 'cd'.repeat(32)), null);
  const bad = [{...s, _type: 'https://in-toto.io/Statement/v0.1'}, {...s, subject: []}, {...s, subject: [{name: 'a', digest: {sha256: 'AB'.repeat(32)}}]},
    {...s, subject: [{name: 'a', digest: {}}]}, {...s, predicateType: ''}, {...s, predicate: [1]}];
  for (const value of bad) assert.throws(() => D.parseStatement(Buffer.from(JSON.stringify(value))), /in-toto|Statement/);
  assert.throws(() => D.parseStatement(Buffer.from([0x7b, 0xff, 0x7d])), /not UTF-8/);
});

test('tlog-policy parses the specification example and evaluates nested group quorums', () => {
  const log = logKey('example.com/log'), w = Object.fromEntries(['X1', 'X2', 'X3', 'Y1', 'Y2', 'Y3'].map(n => [n, witnessKey(`witness.example/${n}`)]));
  const text = `# example from c2sp.org/tlog-policy\nlog ${log.vkey}\n\n${['X1', 'X2', 'X3'].map(n => `witness ${n} ${w[n].vkey}`).join('\n')}\n`
    + 'group X-witnesses 2 X1 X2 X3\n\n' + ['Y1', 'Y2', 'Y3'].map(n => `\twitness ${n}  ${w[n].vkey} https://witness.example/${n}`).join('\n')
    + '\n  group Y-witnesses any Y1 Y2 Y3\n\ngroup X-and-Y all X-witnesses Y-witnesses\nquorum X-and-Y';
  const policy = P.parseTlogPolicy(text);
  assert.deepEqual([policy.logs.length, policy.witnesses.length, policy.groups.map(g => [g.name, g.k]), policy.quorum],
    [1, 6, [['X-witnesses', 2], ['Y-witnesses', 1], ['X-and-Y', 2]], 'X-and-Y']);
  assert.equal(policy.witnesses[3].url, 'https://witness.example/Y1');
  const cp = T.formatCheckpoint({origin: log.origin, size: 1, root: T.leafHash(Buffer.from('a'))}), signed = T.signNote(cp, log.signer);
  const cosigned = names => signed + names.map(n => T.cosign(cp, w[n], ts)).join('');
  const met = names => P.verifyPolicyCheckpoint(cosigned(names), policy, {now}).quorumMet;
  assert.equal(met(['X1', 'X2', 'Y3']), true);
  assert.equal(met(['X1', 'Y1', 'Y2']), false);
  assert.equal(met(['X2', 'X3']), false);
  assert.equal(met([]), false);
  const r = P.verifyPolicyCheckpoint(cosigned(['X1', 'X3', 'Y2']), policy, {now});
  assert.deepEqual(r.cosignatures.map(c => c.witness), ['X1', 'X3', 'Y2']);
  assert.equal(r.log, log.vkey);
});

test('tlog-policy rejects what the specification rules out', () => {
  const log = logKey('example.com/log'), a = witnessKey('w.example/a'), b = witnessKey('w.example/b');
  const head = `log ${log.vkey}\nwitness A ${a.vkey}\nwitness B ${b.vkey}\n`;
  const cases = [
    [head + 'quorum A\r\n', /forbidden octet 0x0d/], [head + 'quorum A\x00\n', /forbidden octet 0x00/], [head, /no quorum line/],
    [head + 'quorum A\nquorum B\n', /exactly one quorum/], [head + 'quorum C\n', /not defined/], ['quorum A\n' + head, /not defined/],
    [head + 'frobnicate A\nquorum A\n', /unknown keyword/], [head + `witness A ${witnessKey('w.example/c').vkey}\nquorum A\n`, /already defined/],
    [head + `witness C ${a.vkey}\nquorum A\n`, /duplicate witness key/],
    [head + `log ${T.logVkey('other.example/log', log.privateKey)}\nquorum A\n`, /duplicate log key/],
    [head + 'group G 1 A none\nquorum G\n', /none cannot be a group member/], [head + 'group G 1 A C\nquorum G\n', /not defined on a preceding line/],
    [head + 'group G 1 A A\nquorum G\n', /more than once/], [head + 'group G 1 A\ngroup H 1 A B\nquorum H\n', /more than once/],
    [head + 'group G 0 A B\nquorum G\n', /threshold/], [head + 'group G 3 A B\nquorum G\n', /threshold/], [head + 'group G -1 A B\nquorum G\n', /threshold/],
    [head + 'group G two A B\nquorum G\n', /threshold/], [head + 'group G any\nquorum G\n', /expected "group/],
    [head + 'group G any A\ngroup G any B\nquorum G\n', /already defined/],
    [head + 'witness none ' + witnessKey('w.example/n').vkey + '\nquorum A\n', /already defined/], [head + 'quorum A B\n', /expected "quorum/],
    [head + `log ${a.vkey}\nquorum A\n`, /log key type 0x4/], [head + `witness C ${log.vkey}\nquorum A\n`, /cosignature vkey/],
    [head + 'log example.com/log+00000000+AQ==\nquorum A\n', /vkey|base64|length/], [head + 'log a b c\nquorum A\n', /expected "log/],
  ];
  for (const [text, error] of cases) assert.throws(() => P.parseTlogPolicy(text), error, JSON.stringify(text.slice(head.length)));
  // Comments and blank lines are ignored, a final newline is optional, and quorum none needs no witnesses.
  assert.equal(P.parseTlogPolicy(`  # comment with ü\n\t\nlog ${log.vkey}\n#quorum A\nquorum none`).quorum, 'none');
  // Names are opaque octets: "K" and the Kelvin sign are different names.
  const kelvin = P.parseTlogPolicy(Buffer.concat([Buffer.from(`witness K ${a.vkey}\nwitness `), Buffer.from('\u212a', 'utf8'),
    Buffer.from(` ${b.vkey}\nquorum K\n`)]));
  assert.deepEqual(kelvin.witnesses.map(w => P.policyName(w.name)), ['K', '\u212a']);
  const many = Array.from({length: 65}, (_, i) => `witness w${i} ${witnessKey(`w.example/${i}`).vkey}`).join('\n') + '\nquorum w0\n';
  assert.throws(() => P.parseTlogPolicy(many), /too many witnesses/);
  assert.throws(() => P.parseTlogPolicy('# x'.repeat(30000)), /larger than/);
});

test('a checkpoint needs a listed log named after its origin; listed keys must verify and future cosignatures are refused', () => {
  const a = logKey('example.com/a'), a2 = logKey('example.com/a'), b = logKey('example.com/b');
  const w = witnessKey('w.example/w'), stranger = witnessKey('w.example/s');
  const policy = P.parseTlogPolicy(`log ${a.vkey}\nlog ${a2.vkey}\nlog ${b.vkey}\nwitness W ${w.vkey}\nquorum W\n`);
  const cp = T.formatCheckpoint({origin: 'example.com/a', size: 2, root: T.mth([T.leafHash(Buffer.from('x')), T.leafHash(Buffer.from('y'))])});
  // Any one listed log for the origin is enough (the spec), not all of them.
  const byA2 = T.signNote(cp, a2.signer) + T.cosign(cp, w, ts) + T.cosign(cp, stranger, ts);
  assert.equal(P.verifyPolicyCheckpoint(byA2, policy, {now}).quorumMet, true);
  // Signed only by a listed log whose key name is another origin.
  const byB = T.signNote(cp, {...b.signer, name: 'example.com/b'}) + T.cosign(cp, w, ts);
  assert.throws(() => P.verifyPolicyCheckpoint(byB, policy, {now}), /not signed by a policy log for its origin example.com\/a/);
  const broken = T.signNote(cp, a.signer) + T.cosign(cp, w, ts).replace(/.{6}\n$/, 'AAAAAA\n');
  assert.throws(() => P.verifyPolicyCheckpoint(broken, policy, {now}), /invalid signature|non-canonical/);
  assert.throws(() => P.verifyPolicyCheckpoint(T.signNote(cp, a.signer) + T.cosign(cp, w, ts + 3600), policy, {now}), /dated in the future/);
  assert.equal(P.verifyPolicyCheckpoint(T.signNote(cp, a.signer) + T.cosign(cp, stranger, ts), policy, {now}).quorumMet, false);
});

test('the Go-generated tlog-proof vector verifies under its torchwood policy, and only with the witness for quorum w1', () => {
  const v = V.tlog_proof, leaf = T.leafHash(Buffer.from(v.leaf_data_hex, 'hex')), policy = P.parseTlogPolicy(v.torchwood_policy);
  const r = P.verifyPolicyProof(v.proof_text, leaf, policy, {now});
  assert.deepEqual([r.index, r.size, r.quorum, r.quorumMet], [v.leaf_index, 5, 'w1', true]);
  const withoutWitness = v.proof_text.split('\n').filter(l => !l.includes('test-witness ')).join('\n');
  assert.equal(P.verifyPolicyProof(withoutWitness, leaf, policy, {now}).quorumMet, false);
  assert.equal(P.verifyPolicyProof(withoutWitness, leaf, P.parseTlogPolicy(v.torchwood_policy_log_only), {now}).quorumMet, true);
  assert.throws(() => P.verifyPolicyProof(v.proof_text, T.leafHash(Buffer.from('other')), policy, {now}), /inclusion proof failed/);
  // Unauthenticated extra data is returned for display but plays no part in the result.
  const extra = v.proof_text.replace('c2sp.org/tlog-proof@v1\n', 'c2sp.org/tlog-proof@v1\nextra aGk=\n');
  assert.equal(P.verifyPolicyProof(extra, leaf, policy, {now}).extra.toString(), 'hi');
});

test('formatTlogPolicy and the EvidScope tenant policy produce parseable policies with plain tokens', () => {
  const {privateKey} = generateKeyPairSync('ed25519'), origin = 'vault.test/evidscope/t/abc', w = [witnessKey('w.example/1'), witnessKey('w.example/2')];
  const none = tenantTlogPolicy({origin, publicKey: privateKey});
  assert.match(none, new RegExp(`^log ${T.logVkey(origin, privateKey).replaceAll('+', '\\+')}\nquorum none\n$`, 'm'));
  assert.equal(P.parseTlogPolicy(tenantTlogPolicy({origin, publicKey: privateKey, witnesses: [w[0].vkey], quorum: 1})).quorum, 'witness-1');
  const two = P.parseTlogPolicy(tenantTlogPolicy({origin, publicKey: privateKey, witnesses: w.map(x => x.vkey), quorum: 2}));
  assert.deepEqual([two.quorum, two.groups[0].k, two.groups[0].members], ['witnesses', 2, ['witness-1', 'witness-2']]);
  assert.throws(() => tenantTlogPolicy({origin, publicKey: privateKey, witnesses: [w[0].vkey], quorum: 2}), /quorum/);
  assert.throws(() => P.formatTlogPolicy({logs: ['a b'], quorum: 'none'}), /Invalid tlog-policy token/);
  assert.throws(() => P.formatTlogPolicy({witnesses: [{name: '#w', vkey: w[0].vkey}], quorum: '#w'}), /Invalid tlog-policy token/);
});

test('receipt file names stay single safe path components', () => {
  const name = id => caseReportFileName({snapshot: {case: {id}, checkpoint: {count: 3}}});
  for (const id of ['9fabd2a5-c6b5-43f2-b7ce-a04634d4ce6f', 'a..b', '../../etc/passwd', 'x/y\\z', '...', 'ü'.repeat(200)]) {
    assert.equal(safeFileName(name(id)), name(id), id);
  }
  assert.equal(name('a..b'), 'evidscope-case-a_.b-3.json');
  for (const bad of ['../x', 'a/b', '.hidden', 'a..b', '', 'x'.repeat(129), null]) assert.equal(safeFileName(bad), null, String(bad));
});
