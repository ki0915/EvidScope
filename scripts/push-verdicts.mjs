// Pushes EvidScope verdicts onto the same traces in Langfuse (scores) and Arize Phoenix (trace and span annotations), on the
// operator's side: the vault makes no outbound calls (docs/observability-integration.md). The export is verified offline with
// the trusted key first; only then can an action read `verified`. Preview is the default and contacts neither tool.
//   node scripts/push-verdicts.mjs (--export EXPORT.json | --evidscope https://audit.example/) --key TRUST_ANCHOR.pem
//     [CHECKPOINT and transparency flags as scripts/verify.mjs] [--no-replay] [--link-base https://audit.example/]
//     [--langfuse https://cloud.langfuse.com [--langfuse-environment NAME]] [--phoenix https://phoenix.example] [--send]
// Credentials come from the environment only: EVIDSCOPE_TOKEN (auditor), LANGFUSE_PUBLIC_KEY + LANGFUSE_SECRET_KEY, PHOENIX_API_KEY.
import {readFileSync, statSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {parseArgs} from 'node:util';
import {transparencyFlags, transparencyOptions} from '../src/verify-options.mjs';
import {actionVerdicts, assessExport, langfuseScores, phoenixAnnotations, REASONS} from '../src/observability-export.mjs';

const MiB = 1024 * 1024;
export const HTTP_LIMITS = Object.freeze({exportBytes: 512 * MiB, responseBytes: MiB, timeoutMs: 15000, attempts: 3, retryAfterCapMs: 5000,
  langfuseBatch: 200, langfuseBatchBytes: 2 * MiB, phoenixBatch: 100});
export const USAGE = 'Usage: node scripts/push-verdicts.mjs (--export EXPORT.json | --evidscope https://audit.example/) --key TRUST_ANCHOR.pem\n'
  + '  [--checkpoint CHECKPOINT.json] [--witness VKEY]... [--quorum N] [--origin-base BASE] [--max-staleness S] [--require-transparency]\n'
  + '  [--require-tenant-witness] [--heads-key VKEY]... [--require-heads-signer] [--min-checkpoint FILE] [--no-replay]\n'
  + '  [--link-base https://audit.example/] [--langfuse URL [--langfuse-environment NAME]] [--phoenix URL] [--send]\n'
  + 'Env: EVIDSCOPE_TOKEN (auditor bearer), LANGFUSE_PUBLIC_KEY and LANGFUSE_SECRET_KEY, PHOENIX_API_KEY (optional).';
export class UsageError extends Error {}

const loopback = url => url.protocol === 'http:' && ['127.0.0.1', '[::1]', 'localhost'].includes(url.hostname);
// HTTPS only (plain http for loopback test servers), no credentials, query or fragment; a path prefix is kept (self-hosted
// Langfuse or Phoenix under a sub-path) and ends with '/'.
export function serviceBase(raw, what, {rootOnly = false} = {}) {
  let url;
  try { url = new URL(raw); } catch { throw new UsageError(`${what} must be an absolute URL`); }
  if (!(url.protocol === 'https:' || loopback(url))) throw new UsageError(`${what} must use https (plain http only for loopback)`);
  if (url.username || url.password || url.search || url.hash) throw new UsageError(`${what} must not carry credentials, a query or a fragment`);
  if (rootOnly && url.pathname !== '/') throw new UsageError(`${what} must be the service root, e.g. https://audit.example/`);
  if (!url.pathname.endsWith('/')) url.pathname += '/';
  return url;
}
const where = url => `${url.origin}${url.pathname}`;
class HttpError extends Error {}
async function bounded(response, max) {
  const chunks = [];
  let size = 0;
  for await (const chunk of response.body || []) {
    if ((size += chunk.length) > max) throw new HttpError(`response exceeds ${max} bytes`);
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}
const pause = ms => new Promise(r => setTimeout(r, ms));
// One HTTP exchange: no redirects (a 3xx is an error, never followed), bounded body, timeout, and at most `attempts` tries on
// network errors, 429 and 5xx. Errors name the method and URL only; headers (credentials) never reach a message.
export async function request(url, {method = 'GET', headers = {}, body, maxBytes = HTTP_LIMITS.responseBytes, attempts = HTTP_LIMITS.attempts,
  timeoutMs = HTTP_LIMITS.timeoutMs} = {}) {
  let last;
  for (let attempt = 1; attempt <= attempts; attempt++) {
    let response;
    try {
      response = await fetch(url, {method, headers, body, redirect: 'manual', signal: AbortSignal.timeout(timeoutMs)});
    } catch (error) {
      last = new HttpError(`${method} ${where(url)} failed: ${error.name === 'TimeoutError' ? 'timeout' : 'network error'}`);
      if (attempt < attempts) await pause(250 * 2 ** (attempt - 1));
      continue;
    }
    if (response.status >= 300 && response.status < 400) {
      await response.body?.cancel();
      throw new HttpError(`${method} ${where(url)} answered a redirect (HTTP ${response.status}); redirects are never followed`);
    }
    let bytes;
    try { bytes = await bounded(response, maxBytes); } catch (error) {
      throw new HttpError(`${method} ${where(url)}: ${error instanceof HttpError ? error.message : 'response read failed'}`);
    }
    if ((response.status === 429 || response.status >= 500) && attempt < attempts) {
      const after = Number(response.headers.get('retry-after'));
      last = new HttpError(`${method} ${where(url)}: HTTP ${response.status}`);
      await pause(Number.isFinite(after) && after >= 0 ? Math.min(after * 1000, HTTP_LIMITS.retryAfterCapMs) : 250 * 2 ** (attempt - 1));
      continue;
    }
    return {status: response.status, bytes, json: () => JSON.parse(bytes.toString('utf8'))};
  }
  throw last;
}

function readBounded(path, max, what) {
  const st = statSync(path);
  if (!st.isFile() || st.size > max) throw new UsageError(`${what} ${path} must be a regular file of at most ${Math.round(max / MiB)} MiB`);
  return readFileSync(path);
}
// The export comes from a file or from GET /api/export with an auditor token; either way it is only bytes until verified.
export async function loadExport({file, base, token}) {
  if (file) return {bytes: readBounded(file, HTTP_LIMITS.exportBytes, 'Export'), source: 'file'};
  if (!token) throw new UsageError('Set EVIDSCOPE_TOKEN to an auditor bearer token to read the export from the EvidScope API');
  const response = await request(new URL('api/export', base), {headers: {authorization: `Bearer ${token}`, accept: 'application/json'},
    maxBytes: HTTP_LIMITS.exportBytes});
  if (response.status !== 200) throw new HttpError(`GET ${where(new URL('api/export', base))}: HTTP ${response.status}`);
  return {bytes: response.bytes, source: 'api'};
}

function batches(items, size, maxBytes = Infinity) {
  const out = [];
  let current = [], bytes = 0;
  for (const item of items) {
    const length = Buffer.byteLength(JSON.stringify(item));
    if (current.length && (current.length >= size || bytes + length > maxBytes)) { out.push(current); current = []; bytes = 0; }
    current.push(item); bytes += length;
  }
  if (current.length) out.push(current);
  return out;
}
// Langfuse public API: Basic auth (public key : secret key). Scores go as score-create events to POST /api/public/ingestion
// (207 with per-event successes and errors); findings scores of actions that are no longer verified are deleted by id.
export async function pushLangfuse({base, publicKey, secretKey, scores}) {
  const authorization = `Basic ${Buffer.from(`${publicKey}:${secretKey}`).toString('base64')}`, result = {accepted: 0, errors: [], deleted: 0};
  for (const batch of batches(scores.events, HTTP_LIMITS.langfuseBatch, HTTP_LIMITS.langfuseBatchBytes)) {
    const url = new URL('api/public/ingestion', base);
    const response = await request(url, {method: 'POST', headers: {authorization, 'content-type': 'application/json'}, body: JSON.stringify({batch})});
    if (![200, 207].includes(response.status)) throw new HttpError(`POST ${where(url)}: HTTP ${response.status}`);
    let body;
    try { body = response.json(); } catch { throw new HttpError(`POST ${where(url)}: response is not JSON`); }
    const errors = Array.isArray(body?.errors) ? body.errors : [];
    result.accepted += Array.isArray(body?.successes) ? body.successes.length : 0;
    for (const e of errors.slice(0, 20)) result.errors.push({id: String(e?.id ?? ''), status: Number(e?.status) || null});
    if (errors.length > 20) result.errors.push({more: errors.length - 20});
  }
  for (const id of scores.deletes) {
    const url = new URL(`api/public/scores/${encodeURIComponent(id)}`, base);
    const response = await request(url, {method: 'DELETE', headers: {authorization}});
    if ([200, 204].includes(response.status)) result.deleted++;
    else if (response.status !== 404) result.errors.push({id, status: response.status, operation: 'delete'});
  }
  return result;
}
// Phoenix REST API: Bearer API key. sync=true so a missing trace or span is reported (404) instead of silently queued; a batch
// that names one is retried item by item and the missing items are counted, not failed.
export async function pushPhoenix({base, apiKey, annotations}) {
  const headers = {'content-type': 'application/json', ...(apiKey ? {authorization: `Bearer ${apiKey}`} : {})};
  const result = {inserted: 0, notFound: 0, errors: []};
  const post = async (path, data) => {
    const url = new URL(`v1/${path}?sync=true`, base);
    return {url, response: await request(url, {method: 'POST', headers, body: JSON.stringify({data})})};
  };
  for (const [path, items] of [['trace_annotations', annotations.traces], ['span_annotations', annotations.spans]]) {
    for (const batch of batches(items, HTTP_LIMITS.phoenixBatch)) {
      const {url, response} = await post(path, batch);
      if (response.status === 200) { result.inserted += batch.length; continue; }
      if (response.status !== 404) { result.errors.push({path, status: response.status, items: batch.length, url: where(url)}); continue; }
      for (const item of batch) {
        const single = await post(path, [item]);
        if (single.response.status === 200) result.inserted++;
        else if (single.response.status === 404) result.notFound++;
        else result.errors.push({path, status: single.response.status, items: 1});
      }
    }
  }
  return result;
}

const OPTIONS = {...transparencyFlags, 'min-checkpoint': {type: 'string'}, export: {type: 'string'}, evidscope: {type: 'string'}, key: {type: 'string'},
  checkpoint: {type: 'string'}, 'no-replay': {type: 'boolean'}, 'link-base': {type: 'string'}, langfuse: {type: 'string'},
  'langfuse-environment': {type: 'string'}, phoenix: {type: 'string'}, send: {type: 'boolean'}};
export function parse(argv) {
  let values;
  try { ({values} = parseArgs({args: argv, options: OPTIONS, strict: true, allowPositionals: false})); } catch (error) { throw new UsageError(error.message); }
  try { transparencyOptions(values, false); } catch (error) { throw new UsageError(error.message); }
  if (!values.export === !values.evidscope) throw new UsageError('Give exactly one of --export or --evidscope');
  if (!values.key) throw new UsageError('Missing --key TRUST_ANCHOR.pem: the trust anchor comes from the operator, never from the export or the API');
  if (values['langfuse-environment'] !== undefined && !/^(?!langfuse)[a-z0-9_-]{1,40}$/.test(values['langfuse-environment']))
    throw new UsageError('--langfuse-environment must be lowercase letters, digits, - or _ and must not start with langfuse');
  return {values, evidscope: values.evidscope && serviceBase(values.evidscope, '--evidscope', {rootOnly: true}),
    linkBase: values['link-base'] && serviceBase(values['link-base'], '--link-base', {rootOnly: true}).href,
    langfuse: values.langfuse && serviceBase(values.langfuse, '--langfuse'), phoenix: values.phoenix && serviceBase(values.phoenix, '--phoenix')};
}

const summary = v => ({actionId: v.actionId, traceId: v.traceId, verdict: v.verdict, reasons: v.reasons, witness: v.witness, analysis: v.analysis,
  ledgerSeq: v.ledger?.seq ?? null, openFindings: v.findings?.open ?? null, spans: v.spans.length});
// Returns {code, output}: 0 when the export verified and every requested push succeeded (or the preview was built), 1 otherwise,
// 2 for usage errors. `env` supplies the credentials; nothing from it is ever copied into the output.
export async function run(argv, env = process.env) {
  const {values, evidscope, linkBase, langfuse, phoenix} = parse(argv);
  if (values.send && !langfuse && !phoenix) throw new UsageError('--send needs --langfuse and/or --phoenix');
  if (values.send && langfuse && (!env.LANGFUSE_PUBLIC_KEY || !env.LANGFUSE_SECRET_KEY))
    throw new UsageError('Set LANGFUSE_PUBLIC_KEY and LANGFUSE_SECRET_KEY to push to Langfuse; nothing was sent');
  const publicKey = readBounded(values.key, 64 * 1024, 'Key file').toString('utf8');
  const expectedCheckpoint = values.checkpoint ? JSON.parse(readBounded(values.checkpoint, MiB, 'Checkpoint file').toString('utf8')) : undefined;
  const loaded = await loadExport({file: values.export, base: evidscope, token: env.EVIDSCOPE_TOKEN});
  // Transparency is checked when the export carries it or a flag asks for it, as in scripts/verify.mjs.
  const transparency = bundle => transparencyOptions(values, bundle.transparency !== undefined);
  const assessment = assessExport(loaded.bytes, {publicKey, expectedCheckpoint, transparency, replay: !values['no-replay']});
  const verdicts = actionVerdicts(assessment, {linkBase});
  const output = {mode: values.send ? 'sent' : 'preview', export: {source: loaded.source, sha256: assessment.exportSha256, tenant: assessment.tenant ?? null,
    checkpoint: assessment.checkpoint ?? null, verdict: assessment.verdict, reasons: assessment.reasons, messages: assessment.messages ?? [],
    witness: assessment.witness ?? 'none'}, verdicts: verdicts.map(summary), reasonText: REASONS};
  const scores = langfuse ? langfuseScores(verdicts, {environment: values['langfuse-environment']}) : null;
  const annotations = phoenix ? phoenixAnnotations(verdicts) : null;
  let failed = assessment.verdict !== 'verified';
  if (!values.send) {
    // The preview shows exactly what would leave this machine, so an operator can check it before --send.
    if (scores) output.langfuse = {endpoint: where(new URL('api/public/ingestion', langfuse)), events: scores.events, deletes: scores.deletes};
    if (annotations) output.phoenix = {endpoint: where(phoenix), traceAnnotations: annotations.traces, spanAnnotations: annotations.spans};
    return {code: failed ? 1 : 0, output};
  }
  if (scores) {
    try { output.langfuse = await pushLangfuse({base: langfuse, publicKey: env.LANGFUSE_PUBLIC_KEY, secretKey: env.LANGFUSE_SECRET_KEY, scores}); }
    catch (error) { output.langfuse = {error: error instanceof HttpError ? error.message : 'push failed'}; }
    failed ||= !!output.langfuse.error || output.langfuse.errors.length > 0;
  }
  if (annotations) {
    try { output.phoenix = await pushPhoenix({base: phoenix, apiKey: env.PHOENIX_API_KEY, annotations}); }
    catch (error) { output.phoenix = {error: error instanceof HttpError ? error.message : 'push failed'}; }
    if (!env.PHOENIX_API_KEY && output.phoenix) output.phoenix.authenticated = false;
    failed ||= !!output.phoenix.error || output.phoenix.errors.length > 0;
  }
  return {code: failed ? 1 : 0, output};
}

// Defence in depth: no credential value from the environment is printed, whatever produced the text.
export function redact(text, env = process.env) {
  let out = String(text);
  for (const name of ['EVIDSCOPE_TOKEN', 'LANGFUSE_PUBLIC_KEY', 'LANGFUSE_SECRET_KEY', 'PHOENIX_API_KEY'])
    if (typeof env[name] === 'string' && env[name].length >= 4) out = out.split(env[name]).join('[REDACTED]');
  return out;
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const {code, output} = await run(process.argv.slice(2));
    process.stdout.write(redact(JSON.stringify(output, null, 2)) + '\n');
    process.exitCode = code;
  } catch (error) {
    process.stderr.write(redact(error instanceof UsageError ? `${error.message}\n${USAGE}` : error.message) + '\n');
    process.exitCode = error instanceof UsageError ? 2 : 1;
  }
}
