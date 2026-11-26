// DSSE v1 envelopes (github.com/secure-systems-lab/dsse, protocol 1.0.2) carrying in-toto Statement v1 payloads
// (github.com/in-toto/attestation). Standalone (node:crypto only) so the packaged verifier can ship it unchanged.
import {createHash, createPublicKey, verify as cryptoVerify} from 'node:crypto';

export const INTOTO_PAYLOAD_TYPE = 'application/vnd.in-toto+json';
export const STATEMENT_V1 = 'https://in-toto.io/Statement/v1';
const plain = v => !!v && typeof v === 'object' && !Array.isArray(v);
export const sha256Hex = bytes => createHash('sha256').update(bytes).digest('hex');

// PAE(type, body) = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body; LEN is the ASCII decimal byte length.
export function pae(payloadType, body) {
  const type = Buffer.from(payloadType, 'utf8'), data = Buffer.from(body);
  return Buffer.concat([Buffer.from(`DSSEv1 ${type.length} `), type, Buffer.from(` ${data.length} `), data]);
}
// Verifiers must accept standard and URL-safe base64. Only canonical encodings pass (standard padded; URL-safe with or
// without padding), so junk characters or non-zero pad bits cannot hide in an accepted envelope.
export function decodeBase64(s, what = 'field') {
  if (typeof s === 'string' && s.length % 4 === 0 && /^[A-Za-z0-9+/]*={0,2}$/.test(s)) {
    const b = Buffer.from(s, 'base64');
    if (b.toString('base64') === s) return b;
  }
  if (typeof s === 'string' && /^[A-Za-z0-9_-]*={0,2}$/.test(s)) {
    const bare = s.replace(/=+$/, ''), b = Buffer.from(bare, 'base64url');
    if (b.toString('base64url') === bare && (bare === s || s.length % 4 === 0)) return b;
  }
  throw Error(`DSSE ${what} is not canonical standard or URL-safe base64`);
}
const asPublicKey = key => (key?.type === 'public' ? key : createPublicKey(key));
// keyid convention of EvidScope: SHA-256 of the DER SubjectPublicKeyInfo, as in case reports (publicKeyFingerprint).
export const keyFingerprint = key => sha256Hex(asPublicKey(key).export({format: 'der', type: 'spki'}));
export function ed25519Verifier(key) {
  const publicKey = asPublicKey(key);
  if (publicKey.asymmetricKeyType !== 'ed25519') throw Error('DSSE verification key must be an Ed25519 public key');
  return {keyid: keyFingerprint(publicKey), verify: (message, sig) => sig.length === 64 && cryptoVerify(null, message, publicKey, sig)};
}

// signer: {keyid, sign(paeBytes) -> signature bytes or a promise of them}.
export async function signEnvelope(payloadType, body, signer) {
  const sig = await signer.sign(pae(payloadType, body));
  if (!(sig instanceof Uint8Array) || !sig.length) throw Error('DSSE signer returned no signature');
  return {payloadType, payload: Buffer.from(body).toString('base64'), signatures: [{keyid: signer.keyid, sig: Buffer.from(sig).toString('base64')}]};
}
// (t, n)-envelope check: a signature that fails or matches no verifier is skipped, and at least `threshold` distinct
// verifiers must accept. The returned body is the exact verified byte string; callers parse it and nothing else.
export function openEnvelope(envelope, verifiers, {threshold = 1, payloadTypes = [INTOTO_PAYLOAD_TYPE], maxSignatures = 16} = {}) {
  if (!plain(envelope) || typeof envelope.payloadType !== 'string' || !Array.isArray(envelope.signatures)) throw Error('Malformed DSSE envelope');
  if (!envelope.signatures.length || envelope.signatures.length > maxSignatures) throw Error('DSSE envelope signature count out of range');
  const body = decodeBase64(envelope.payload, 'payload'), message = pae(envelope.payloadType, body), accepted = new Set();
  for (const s of envelope.signatures) {
    if (!plain(s) || (s.keyid !== undefined && typeof s.keyid !== 'string')) throw Error('Malformed DSSE signature');
    const sig = decodeBase64(s.sig, 'signature');
    for (const [i, v] of verifiers.entries()) if (!accepted.has(i) && v.verify(message, sig)) accepted.add(i);
  }
  if (accepted.size < Math.max(1, threshold)) throw Error('DSSE signature verification failed');
  if (!payloadTypes.includes(envelope.payloadType)) throw Error('Unsupported DSSE payload type ' + JSON.stringify(envelope.payloadType));
  return {payloadType: envelope.payloadType, body, keyids: [...accepted].map(i => verifiers[i].keyid ?? null)};
}

export const intotoStatement = (subjects, predicateType, predicate) => ({_type: STATEMENT_V1,
  subject: subjects.map(s => ({name: s.name, digest: {sha256: s.sha256}})), predicateType, predicate});
// Parses verified payload bytes. Consumers ignore unknown fields; digests must be lowercase hex.
export function parseStatement(body) {
  const bytes = Buffer.from(body), text = bytes.toString('utf8');
  if (!Buffer.from(text, 'utf8').equals(bytes)) throw Error('in-toto statement is not UTF-8');
  let s;
  try { s = JSON.parse(text); } catch { throw Error('in-toto statement is not JSON'); }
  if (!plain(s) || s._type !== STATEMENT_V1) throw Error('Payload is not an in-toto Statement v1');
  if (!Array.isArray(s.subject) || !s.subject.length) throw Error('in-toto statement has no subject');
  for (const sub of s.subject) {
    if (!plain(sub) || !plain(sub.digest) || !Object.keys(sub.digest).length || (sub.name !== undefined && typeof sub.name !== 'string')) {
      throw Error('in-toto statement subject is malformed');
    }
    if (Object.values(sub.digest).some(d => typeof d !== 'string' || !/^[0-9a-f]+$/.test(d))) throw Error('in-toto subject digest must be lowercase hex');
  }
  if (typeof s.predicateType !== 'string' || !s.predicateType) throw Error('in-toto statement has no predicateType');
  if (s.predicate !== undefined && s.predicate !== null && !plain(s.predicate)) throw Error('in-toto predicate must be an object');
  return s;
}
// Subjects are matched purely by digest.
export const matchingSubject = (statement, sha256) => statement.subject.find(s => s.digest.sha256 === sha256) ?? null;
