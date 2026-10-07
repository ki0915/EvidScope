// c2sp.org/tlog-policy: parse, format and evaluate a transparency log trust policy (logs, witnesses, quorum), and verify a
// c2sp.org/tlog-proof@v1 under it. Signatures are checked with ./tlog.mjs; no other EvidScope module is imported.
import {SIG_ED25519, cosignatureTimestamp, cosignatureVerifier, noteVerifier, openNote, parseCheckpoint, parseTlogProof, parseVkey,
  verifyInclusion} from './tlog.mjs';

// The spec asks implementations to support at least 32 logs, 32 witnesses and 32 groups.
export const TLOG_POLICY_LIMITS = Object.freeze({bytes: 65536, logs: 64, witnesses: 64, groups: 64});
const latin1Utf8 = (token, what) => {
  const bytes = Buffer.from(token, 'latin1'), text = bytes.toString('utf8');
  if (!Buffer.from(text, 'utf8').equals(bytes)) throw Error(`${what} is not UTF-8`);
  return text;
};
// Names are opaque octet strings, held here as latin1 strings (one character per octet); shown as UTF-8 when they decode.
export const policyName = name => { try { return latin1Utf8(name, 'name'); } catch { return JSON.stringify(name); } };

export function parseTlogPolicy(input, limits = TLOG_POLICY_LIMITS) {
  const bytes = typeof input === 'string' ? Buffer.from(input, 'utf8') : Buffer.from(input);
  if (bytes.length > limits.bytes) throw Error('tlog-policy is larger than ' + limits.bytes + ' bytes');
  // Allowed octets: 0x09, 0x0A, 0x20-0x7E and 0x80-0xFF (no CR or other control characters).
  const bad = bytes.findIndex(b => b !== 0x09 && b !== 0x0a && (b < 0x20 || b === 0x7f));
  if (bad >= 0) throw Error(`tlog-policy contains forbidden octet 0x${bytes[bad].toString(16).padStart(2, '0')}`);
  const lines = bytes.toString('latin1').split('\n');
  if (lines.at(-1) === '') lines.pop();
  const logs = [], witnesses = [], groups = [], defined = new Set(['none']), listed = new Set();
  let quorum = null;
  const define = (name, at) => {
    if (defined.has(name)) throw Error(`${at}: name ${policyName(name)} is already defined`);
    defined.add(name);
  };
  lines.forEach((line, i) => {
    const at = `tlog-policy line ${i + 1}`, fields = line.split(/[ \t]+/).filter(Boolean);
    if (!fields.length || fields[0].startsWith('#')) return;
    const [keyword, ...args] = fields;
    if (keyword === 'log') {
      if (args.length < 1 || args.length > 2) throw Error(`${at}: expected "log <vkey> [<url>]"`);
      const k = parseVkey(latin1Utf8(args[0], `${at}: log vkey`));
      if (k.type !== SIG_ED25519) throw Error(`${at}: log key type 0x${k.type.toString(16)} is not supported (Ed25519 0x01 only)`);
      if (logs.some(l => l.pub.equals(k.pub))) throw Error(`${at}: duplicate log key`);
      if (logs.push({...k, url: args[1] ?? null}) > limits.logs) throw Error('tlog-policy lists too many logs');
    } else if (keyword === 'witness') {
      if (args.length < 2 || args.length > 3) throw Error(`${at}: expected "witness <name> <vkey> [<url>]"`);
      const [name, vkey, url = null] = args, verifier = cosignatureVerifier(latin1Utf8(vkey, `${at}: witness vkey`));
      if (witnesses.some(w => w.verifier.pub.equals(verifier.pub))) throw Error(`${at}: duplicate witness key`);
      define(name, at);
      if (witnesses.push({name, vkey: verifier.vkey, url, verifier}) > limits.witnesses) throw Error('tlog-policy lists too many witnesses');
    } else if (keyword === 'group') {
      if (args.length < 3) throw Error(`${at}: expected "group <name> all|any|<k> <name>..."`);
      const [name, threshold, ...members] = args, n = members.length;
      for (const m of members) {
        if (m === 'none') throw Error(`${at}: none cannot be a group member`);
        if (!defined.has(m)) throw Error(`${at}: group member ${policyName(m)} is not defined on a preceding line`);
        if (listed.has(m)) throw Error(`${at}: ${policyName(m)} is listed as a group member more than once`);
        listed.add(m);
      }
      const k = threshold === 'all' ? n : threshold === 'any' ? 1 : /^[0-9]{1,6}$/.test(threshold) ? Number(threshold) : NaN;
      if (!(k >= 1 && k <= n)) throw Error(`${at}: group threshold must be all, any or a decimal k with 1 <= k <= ${n}`);
      define(name, at);
      if (groups.push({name, k, members}) > limits.groups) throw Error('tlog-policy defines too many groups');
    } else if (keyword === 'quorum') {
      if (args.length !== 1) throw Error(`${at}: expected "quorum <name>"`);
      if (quorum !== null) throw Error(`${at}: a policy has exactly one quorum line`);
      if (!defined.has(args[0])) throw Error(`${at}: quorum ${policyName(args[0])} is not defined on a preceding line`);
      quorum = args[0];
    } else throw Error(`${at}: unknown keyword ${policyName(keyword)}`);
  });
  if (quorum === null) throw Error('tlog-policy has no quorum line');
  return {logs, witnesses, groups, quorum};
}

// witnesses: [{name, vkey}]; quorum: 'none', a witness name, or {name, k, members} for one group. Names must be plain tokens.
export function formatTlogPolicy({comments = [], logs = [], witnesses = [], quorum = 'none'}) {
  const token = s => { if (typeof s !== 'string' || !/^[\x21-\x7e]+$/.test(s) || s.startsWith('#')) throw Error('Invalid tlog-policy token ' + s); return s; };
  const out = comments.map(c => `# ${String(c).replace(/[\x00-\x1f\x7f]/g, ' ')}`);
  for (const vkey of logs) out.push(`log ${token(vkey)}`);
  for (const w of witnesses) out.push(`witness ${token(w.name)} ${token(w.vkey)}`);
  if (typeof quorum === 'string') out.push(`quorum ${token(quorum)}`);
  else out.push(`group ${token(quorum.name)} ${quorum.k} ${quorum.members.map(token).join(' ')}`, `quorum ${token(quorum.name)}`);
  const text = out.join('\n') + '\n';
  parseTlogPolicy(text);
  return text;
}

function witnessed(policy, name, cosigners) {
  if (name === 'none' || cosigners.has(name)) return true;
  const group = policy.groups.find(g => g.name === name);
  return !!group && group.members.filter(m => witnessed(policy, m, cosigners)).length >= group.k;
}
// A checkpoint is valid when a listed log whose key name is the checkpoint origin signed it and its verified cosignatures
// satisfy the quorum. As in signed-note, a listed key whose signature fails rejects the note; unknown signatures are ignored.
// Timestamps beyond skewSeconds in the future are refused (application policy; the spec leaves timestamps to applications).
export function verifyPolicyCheckpoint(signedCheckpoint, policy, {now = Date.now(), skewSeconds = 300} = {}) {
  const logV = policy.logs.map(l => noteVerifier(l.vkey)), opened = openNote(signedCheckpoint, [...logV, ...policy.witnesses.map(w => w.verifier)]);
  const checkpoint = parseCheckpoint(opened.text), sig = v => opened.sigs.find(s => s.name === v.name && s.id === v.id.toString('hex'));
  const log = logV.find(v => v.name === checkpoint.origin && sig(v));
  if (!log) throw Error('Checkpoint is not signed by a policy log for its origin ' + checkpoint.origin);
  const cosigners = new Map(), limit = Math.floor(now / 1000) + skewSeconds;
  for (const w of policy.witnesses) {
    const s = sig(w.verifier);
    if (!s) continue;
    const timestamp = cosignatureTimestamp(s.raw);
    if (timestamp > limit) throw Error(`Cosignature of witness ${policyName(w.name)} is dated in the future`);
    cosigners.set(w.name, {witness: policyName(w.name), keyName: w.verifier.name, keyId: s.id, timestamp});
  }
  return {checkpoint, origin: checkpoint.origin, log: log.vkey, cosignatures: [...cosigners.values()], quorum: policyName(policy.quorum),
    quorumMet: witnessed(policy, policy.quorum, cosigners)};
}
// leaf: the RFC 6962 leaf hash of the entry (application specific). The quorum is reported, not enforced, here.
export function verifyPolicyProof(proofText, leaf, policy, options) {
  const p = parseTlogProof(proofText), r = verifyPolicyCheckpoint(p.signedCheckpoint, policy, options);
  if (!verifyInclusion(leaf, p.index, r.checkpoint.size, p.proof, r.checkpoint.root)) throw Error('tlog-proof inclusion proof failed');
  return {...r, index: p.index, size: r.checkpoint.size, signedCheckpoint: p.signedCheckpoint, extra: p.extra};
}
