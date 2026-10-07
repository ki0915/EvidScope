import {createHash} from 'node:crypto';

// Static credential configuration, shared by the vault start (src/service.mjs), a signed config rebinding
// (src/recovery-state.mjs) and the local upgrade (scripts/upgrade-local.mjs). Principal ids must be unique: the vault
// attributes ledger records, ingest nonces, source receipts and analysis leases to the id, so two credentials sharing
// an id would share that identity (round-2 re-audit, S6).
export function duplicatePrincipalIds(principals=[]){
 const seen=new Set(),duplicates=new Set();
 for(const p of principals){if(seen.has(p?.id))duplicates.add(p.id);seen.add(p?.id);}
 return [...duplicates];
}

// A worker credential is identified by a labelled SHA-256 fingerprint of its bearer token, never by the token or the id
// alone: analysis scopes and leases are keyed by it. Principal objects without a token (in-process unit fixtures) fall
// back to their id; a loaded configuration always gives every principal its own token.
export function credentialFingerprint(p){
 if(typeof p?.token==='string'&&p.token)return 'sha256:'+createHash('sha256').update('evidscope/worker-credential/v1\n').update(p.token).digest('hex');
 return 'id:'+p?.id;
}
