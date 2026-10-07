// Vault side of the standard receipts (docs/receipts.md). Everything a response states is read inside the request's snapshot;
// only the DSSE signature, through the attestation signer (src/attestation-signer.mjs), completes after it.
import {verify} from 'node:crypto';
import {canonical} from './crypto.mjs';
import {INTOTO_PAYLOAD_TYPE, intotoStatement, pae, sha256Hex, signEnvelope} from './dsse.mjs';
import {fail} from './model.mjs';
import * as R from './receipts.mjs';
import * as T from './tlog.mjs';
import {parseTlogPolicy, verifyPolicyProof} from './tlog-policy.mjs';
import {hasTable, ledgerLeaves, verifiedTenantRow} from './transparency.mjs';

const firstLeaves = (db, tenant, size) => {
  const out = [];
  for (const leaf of ledgerLeaves(db, tenant)) { if (out.length >= size) break; out.push(leaf); }
  return out;
};
const inconsistent = error => fail(409, '원장과 서명된 테넌트 로그가 일치하지 않아 영수증을 발급할 수 없습니다: ' + error.message);

export async function attestFile({name, content, predicateType, predicate}, signer) {
  const sha256 = sha256Hex(Buffer.from(content, 'utf8'));
  const body = Buffer.from(canonical(intotoStatement([{name, sha256}], predicateType, predicate)), 'utf8');
  const envelope = await signEnvelope(INTOTO_PAYLOAD_TYPE, body, signer);
  if (!verify(null, pae(INTOTO_PAYLOAD_TYPE, body), signer.publicKey, Buffer.from(envelope.signatures[0].sig, 'base64'))) {
    throw Error('Attestation signer returned a signature that does not verify with the vault key');
  }
  return {format: R.ATTESTED_FILE_FORMAT, file: {name, mediaType: 'application/json', sha256, content}, envelope};
}
// Subject text is what the plain route serializes (JSON.stringify), so the attested file is byte for byte the usual response.
export function exportAttestation(bundle, now = Date.now()) {
  const facts = R.exportFacts(bundle), plan = R.proofPlan('export', bundle);
  const tlogProofs = plan.length ? R.buildTlogProofs(plan, bundle.records.map(r => T.recordLeaf(r.hash)), facts.tlog) : [];
  return {name: R.exportFileName(bundle), content: JSON.stringify(bundle), predicateType: R.EXPORT_PREDICATE,
    predicate: {...facts, issuedAt: new Date(now).toISOString(), tlogProofs}};
}
// db must be the snapshot the report was read from: proofs against the witnessed checkpoint need the tenant's leaves.
export function caseReportAttestation(db, report) {
  const facts = R.caseReportFacts(report), plan = R.proofPlan('case-report', report);
  let tlogProofs = [];
  if (plan.length) {
    const size = T.parseCheckpoint(T.noteText(facts.tlog.checkpoint)).size;
    tlogProofs = R.buildTlogProofs(plan, firstLeaves(db, report.snapshot.tenant, size), facts.tlog);
  }
  return {name: R.caseReportFileName(report), content: JSON.stringify(report), predicateType: R.CASE_REPORT_PREDICATE, predicate: {...facts, tlogProofs}};
}

// Newest checkpoint of the tenant log in [minSize, maxSize] cosigned by configured witnesses, with the quorum if any reached it.
function cosignedCheckpoint(db, config, origin, logV, minSize, maxSize) {
  if (!config.witnessTenantLogs || !config.witnesses.length || !hasTable(db, 'tlog_checkpoints') || !hasTable(db, 'tlog_cosignatures')) return null;
  const marks = config.witnesses.map(() => '?').join(','), ids = config.witnesses.map(w => w.keyId);
  const best = db.prepare(`SELECT c.size FROM tlog_cosignatures c JOIN tlog_checkpoints k ON k.origin=c.origin AND k.size=c.size
    WHERE c.origin=? AND c.size>=? AND c.size<=? AND c.key_id IN (${marks}) GROUP BY c.size ORDER BY (COUNT(DISTINCT c.key_id)>=?) DESC,c.size DESC LIMIT 1`)
    .get(origin, minSize, maxSize, ...ids, Math.max(1, config.quorum));
  if (!best) return null;
  const r = verifiedTenantRow(db.prepare('SELECT origin,size,root,peaks,note FROM tlog_checkpoints WHERE origin=? AND size=?').get(origin, best.size), logV);
  const lines = db.prepare('SELECT key_id,name,line FROM tlog_cosignatures WHERE origin=? AND size=? ORDER BY name,key_id').all(origin, r.size)
    .filter(l => config.witnesses.some(w => w.keyId === l.key_id && w.name === l.name));
  return {size: r.size, root: r.root, note: r.note + lines.map(l => l.line).join('')};
}
// c2sp.org/tlog-proof for one ledger record against the newest witnessed tenant checkpoint covering it, else the vault-signed
// current one. The proof is verified under the deployment policy before it leaves the vault; the quorum is reported, not required.
export function recordReceipt({db, config, publicKey, tenant, seq, now = Date.now()}) {
  const origin = T.tenantOrigin(config.base, tenant), logV = T.noteVerifier(T.logVkey(origin, publicKey));
  const state = hasTable(db, 'tlog_state')
    ? db.prepare('SELECT tenant,origin,size,root,peaks,note FROM tlog_state WHERE tenant=? AND origin=?').get(tenant, origin) : null;
  if (!state || seq > state.size) fail(404, '서명된 테넌트 로그에 아직 없는 기록입니다');
  let receipt;
  try {
    const current = verifiedTenantRow(state, logV), row = db.prepare('SELECT seq,body,hash FROM ledger WHERE tenant=? AND seq=?').get(tenant, seq);
    if (!row || sha256Hex(Buffer.from(row.body, 'utf8')) !== row.hash) throw Error('ledger record ' + seq + ' differs from its hash');
    const record = JSON.parse(row.body);
    if (record.tenant !== tenant || record.seq !== seq) throw Error('ledger record ' + seq + ' names another tenant or sequence');
    const target = cosignedCheckpoint(db, config, origin, logV, seq, current.size) ?? current, tree = T.merkleLevels(firstLeaves(db, tenant, target.size));
    if (tree.size !== target.size || !T.levelsRoot(tree).equals(target.root)) throw Error('ledger leaves differ from the signed checkpoint');
    const proof = T.formatTlogProof(seq - 1, T.levelsInclusionProof(tree, seq - 1), target.note), policy = R.deploymentTlogPolicy(config, publicKey, tenant);
    const v = verifyPolicyProof(proof, T.recordLeaf(row.hash), parseTlogPolicy(policy), {now});
    receipt = {format: R.RECORD_RECEIPT_FORMAT, tenant, seq, hash: row.hash, type: record.type ?? null, origin, checkpointSize: v.size,
      quorum: v.quorum, quorumMet: v.quorumMet, witnessed: v.quorum !== 'none' && v.quorumMet, cosignatures: v.cosignatures, record: row.body, proof, policy};
  } catch (error) {
    if (error.status) throw error;
    inconsistent(error);
  }
  return receipt;
}

export function createReceipts({store, config, signer, now = () => Date.now()}) {
  return {
    // ?attest=intoto on the export and case-report routes; another value is a client error.
    requested(url) {
      const values = url.searchParams.getAll('attest');
      if (values.length && (values.length !== 1 || values[0] !== 'intoto')) fail(400, 'attest 값은 intoto만 지원합니다');
      return values.length === 1;
    },
    attestExport: bundle => attestFile(exportAttestation(bundle, now()), signer),
    attestCaseReport(report) {
      let statement;
      try { statement = caseReportAttestation(store.db, report); } catch (error) { inconsistent(error); }
      return attestFile(statement, signer);
    },
    record(p, url) {
      if (!store.tlog || config.mode === 'off') fail(409, '투명성 로그가 꺼져 있어 기록 영수증을 발급할 수 없습니다');
      const raw = url.searchParams.get('seq') ?? '', seq = Number(raw);
      if (!/^[1-9][0-9]{0,15}$/.test(raw) || !Number.isSafeInteger(seq)) fail(400, 'seq 오류');
      return store.transaction(() => recordReceipt({db: store.db, config, publicKey: signer.publicKey, tenant: p.tenant, seq, now: now()}));
    },
  };
}
