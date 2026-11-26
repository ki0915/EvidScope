// Embedding vectors for governance-mapping retrieval (docs/governance-model.md). The vectors are computed on the PC inside the
// offline llama.cpp container (scripts/governance_mapping_embed.py) and shipped as one JSON file keyed by text digest, so the
// ranking in src/governance-mapping.mjs is a pure function of (text, that file): same file, same ranks, and a factsheet can name
// the file by its digest. Without a file, retrieval stays TF-IDF only.
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';

export const EMBEDDING_FILE_ENV = 'EVIDSCOPE_GOVERNANCE_EMBEDDINGS';
export const EMBEDDINGS_SCHEMA_VERSION = 1;
// Texts are keyed by the sha256 of their NFC form, the same digest scripts/governance_mapping_embed.py checks on its input lines.
export const textDigest = text => createHash('sha256').update(String(text ?? '').normalize('NFC'), 'utf8').digest('hex');

const unit = v => { let n = 0; for (const x of v) n += x * x; n = Math.sqrt(n) || 1; return v.map(x => x / n); };
export function cosine(a, b) { let d = 0; for (let i = 0; i < a.length; i++) d += a[i] * b[i]; return d; }

// {schemaVersion: 1, model: {file, sha256, dims, pooling}, vectors: {<digest>: number[]}} as the embed script writes it. Every vector
// is unit-normalised here, so cosine is a dot product whatever the server did.
export function parseEmbeddings(json, {source = 'inline'} = {}) {
  const text = typeof json === 'string' ? json : JSON.stringify(json), value = typeof json === 'string' ? JSON.parse(json) : json;
  if (value?.schemaVersion !== EMBEDDINGS_SCHEMA_VERSION || typeof value.model?.sha256 !== 'string' || !Number.isInteger(value.model.dims)
    || value.model.dims < 1 || !value.vectors || typeof value.vectors !== 'object' || Array.isArray(value.vectors)) throw Error('embeddings_file_invalid');
  const vectors = new Map();
  for (const [digest, v] of Object.entries(value.vectors)) {
    if (!/^[a-f0-9]{64}$/.test(digest) || !Array.isArray(v) || v.length !== value.model.dims || !v.every(Number.isFinite))
      throw Error('embeddings_vector_invalid');
    vectors.set(digest, unit(Float64Array.from(v)));
  }
  return Object.freeze({source, model: Object.freeze({...value.model}), dims: value.model.dims, vectors,
    digest: createHash('sha256').update(text, 'utf8').digest('hex')});
}
export const loadEmbeddings = file => parseEmbeddings(readFileSync(file, 'utf8'), {source: file});
// The vector of a text, or null when the file has none (the caller then ranks by TF-IDF alone and says so).
export const vectorFor = (index, text) => index?.vectors.get(textDigest(text)) ?? null;

// Reciprocal rank fusion of ranked lists of {id, …}: an id scores 1/(k + rank) in each list it appears in; ties break on id, so
// the result is deterministic. Items keep the fields of their first appearance; score is the fused score.
export function rrfFuse(rankings, {k = 60} = {}) {
  const score = new Map(), first = new Map();
  for (const list of rankings) list.forEach((x, rank) => {
    if (!first.has(x.id)) first.set(x.id, x);
    score.set(x.id, (score.get(x.id) || 0) + 1 / (k + rank + 1)); });
  return [...score.entries()].sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1)).map(([id, s]) => ({...first.get(id), score: s}));
}

// The texts a dataset needs embedded, once each and in digest order: every prompt (examples, queries, training rows) and every
// catalog entry text. Written by `scripts/governance-mapping.mjs embed-texts` for the embed script.
export function embeddingTexts(texts) {
  const seen = new Map();
  for (const t of texts) { const s = String(t ?? ''); if (s && !seen.has(textDigest(s))) seen.set(textDigest(s), s); }
  return [...seen.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1)).map(([digest, text]) => ({digest, text}));
}
