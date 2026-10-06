// Shared opt-in transparency flags for the offline verifier CLIs. Positional arguments keep their meaning.
import {readFileSync} from 'node:fs';

export const transparencyFlags = {
  witness: {type: 'string', multiple: true},
  quorum: {type: 'string'},
  'origin-base': {type: 'string'},
  'max-staleness': {type: 'string'},
  'require-transparency': {type: 'boolean'},
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
  const asked = ['witness', 'quorum', 'origin-base', 'max-staleness', 'require-transparency', 'min-checkpoint'].some(k => values[k] !== undefined);
  if (!present && !asked) return undefined;
  return {
    require: !!values['require-transparency'],
    witnesses: values.witness || [],
    ...(values.quorum !== undefined ? {quorum: count(values.quorum, 'quorum')} : {}),
    ...(values['origin-base'] !== undefined ? {originBase: values['origin-base']} : {}),
    ...(values['max-staleness'] !== undefined ? {maxStalenessSeconds: count(values['max-staleness'], 'max-staleness')} : {}),
    ...(values['min-checkpoint'] !== undefined ? {minimumCheckpoint: minimumCheckpoint(values['min-checkpoint'])} : {}),
  };
}
