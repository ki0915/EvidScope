// Shared opt-in transparency flags for the offline verifier CLIs. Positional arguments keep their meaning.
import {readFileSync} from 'node:fs';

export const transparencyFlags = {
  witness: {type: 'string', multiple: true},
  quorum: {type: 'string'},
  'origin-base': {type: 'string'},
  'max-staleness': {type: 'string'},
  'require-transparency': {type: 'boolean'},
  'require-tenant-witness': {type: 'boolean'},
  'heads-key': {type: 'string', multiple: true},
  'require-heads-signer': {type: 'boolean'},
};
const count = (value, name) => {
  if (!/^(0|[1-9][0-9]*)$/.test(value) || !Number.isSafeInteger(Number(value))) throw Error(`--${name} must be a non-negative integer`);
  return Number(value);
};
// A minimum checkpoint file holds either a C2SP tenant note or an evidscope-checkpoint-v1 JSON object.
function minimumCheckpoint(file) {
  const raw = readFileSync(file, 'utf8');
  try {
    const value = JSON.parse(raw);
    if (value && typeof value === 'object') return value;
  } catch { /* a signed note is not JSON */ }
  return raw;
}
// Returns undefined (legacy behaviour) unless the input carries transparency material or a flag asks for it.
export function transparencyOptions(values, present) {
  const asked = ['witness', 'quorum', 'origin-base', 'max-staleness', 'require-transparency', 'require-tenant-witness', 'min-checkpoint', 'heads-key',
    'require-heads-signer'].some(k => values[k] !== undefined);
  if (!present && !asked) return undefined;
  return {
    require: !!values['require-transparency'],
    // --require-tenant-witness: fail unless a fresh witness quorum cosigned the tenant log itself under the pinned origin base
    // (rollbackCheckedAgainst 'signing_key_holder'); heads evidence alone only binds an attacker without the vault key.
    ...(values['require-tenant-witness'] ? {requireTenantWitness: true} : {}),
    // --heads-key: the heads signer's vkey for <origin base>/heads (repeat it for rotated keys). A heads checkpoint it signed, with a
    // fresh quorum, is reported as 'vault_host'; --require-heads-signer fails unless that holds (docs/signer.md).
    ...(values['heads-key'] !== undefined ? {headsKeys: values['heads-key']} : {}),
    ...(values['require-heads-signer'] ? {requireHeadsSigner: true} : {}),
    witnesses: values.witness || [],
    ...(values.quorum !== undefined ? {quorum: count(values.quorum, 'quorum')} : {}),
    ...(values['origin-base'] !== undefined ? {originBase: values['origin-base']} : {}),
    ...(values['max-staleness'] !== undefined ? {maxStalenessSeconds: count(values['max-staleness'], 'max-staleness')} : {}),
    ...(values['min-checkpoint'] !== undefined ? {minimumCheckpoint: minimumCheckpoint(values['min-checkpoint'])} : {}),
  };
}
