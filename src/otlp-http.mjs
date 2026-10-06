// OTLP/HTTP traces receiver (POST /v1/traces) for the ingress gateway and the single-process vault.
// Decodes and minimizes at the edge, forwards a JSON event batch to the vault's /api/ingest/otlp and
// answers per the OTLP/HTTP spec: the response uses the request's Content-Type, partial success is
// 200 + partialSuccess, transient failures are 503 + Retry-After (never 500: exporters drop data on 500).
import zlib from 'node:zlib';
import {createHash} from 'node:crypto';
import {promisify} from 'node:util';
import {decodeTraceRequest, mapTraceRequest, rejectionSummary, OTLP_BATCH_FORMAT, OTLP_MAPPING_VERSION} from './otlp.mjs';
import {encodeExportTraceServiceResponse, encodeStatus} from './otlp-protobuf.mjs';

export const OTLP_TRACES_PATH = '/v1/traces';
export const OTLP_FORWARD_CHUNK = 512;
const inflaters = {
  gzip: promisify(zlib.gunzip), deflate: promisify(zlib.inflate), deflateRaw: promisify(zlib.inflateRaw), zstd: promisify(zlib.zstdDecompress),
};
const MEDIA_TYPES = new Map([['application/json', 'json'], ['application/x-protobuf', 'protobuf'], ['application/protobuf', 'protobuf']]);
const ENCODINGS = new Map([['', ''], ['identity', ''], ['gzip', 'gzip'], ['x-gzip', 'gzip'], ['deflate', 'deflate'], ['zstd', 'zstd']]);
// google.rpc.Code for the Status body; OTLP clients decide on the HTTP status only.
const GRPC_CODES = {400: 3, 401: 16, 403: 7, 405: 12, 413: 8, 415: 3, 503: 14};

export function otlpLimits(env = process.env) {
  const n = (name, fallback) => { const v = Number(env[name]); return Number.isSafeInteger(v) && v > 0 ? v : fallback; };
  return {maxBodyBytes: n('OTLP_MAX_BODY_BYTES', 4 * 1024 * 1024), maxDecodedBytes: n('OTLP_MAX_DECODED_BYTES', 8 * 1024 * 1024),
    maxSpans: n('OTLP_MAX_SPANS', 8192), maxInflight: n('OTLP_MAX_INFLIGHT', 8), forwardTimeoutMs: n('OTLP_FORWARD_TIMEOUT_MS', 15000)};
}

export class OtlpHttpError extends Error {
  constructor(status, message, retryAfter) { super(message); this.status = status; this.retryAfter = retryAfter; }
}
const busy = (message = 'temporarily unable to store spans; retry later', retryAfter = 5) => new OtlpHttpError(503, message, retryAfter);

// Translate a vault /api/ingest/otlp failure into an OTLP status. Anything that is not a definite
// client error becomes a retryable 503 so the Collector queues instead of dropping evidence.
export function vaultFailure(status, retryAfter) {
  if (status === 401) return new OtlpHttpError(401, 'authentication failed');
  if (status === 403) return new OtlpHttpError(403, 'credential is not an OTLP source');
  if (status === 400) return new OtlpHttpError(400, 'batch rejected by the evidence store');
  if (status === 413) return new OtlpHttpError(413, 'too many spans in one request; lower the exporter batch size');
  const seconds = Number(retryAfter);
  const message = status === 503 ? 'analysis backlog or storage unavailable; retry later' : 'evidence store unavailable; retry later';
  return busy(message, Number.isSafeInteger(seconds) && seconds > 0 && seconds <= 300 ? seconds : 5);
}

// Forwarder for the ingress gateway: one vault call per chunk with only the bearer header.
export function remoteForwarder(base, {timeoutMs = 15000} = {}) {
  return async (authorization, body) => {
    let response;
    try {
      response = await fetch(new URL('/api/ingest/otlp', base), {method: 'POST', headers: {'content-type': 'application/json', authorization}, body,
        signal: AbortSignal.timeout(timeoutMs), redirect: 'manual'});
    } catch { throw busy('evidence store unreachable; retry later'); }
    const chunks = []; let size = 0;
    try {
      for await (const chunk of response.body || []) { if ((size += chunk.length) > 65536) throw Error('response too large'); chunks.push(chunk); }
    } catch { throw busy('evidence store response unreadable; retry later'); }
    if (response.status !== 200) throw vaultFailure(response.status, response.headers.get('retry-after'));
    try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { throw busy('evidence store response unreadable; retry later'); }
  };
}

// Forwarder for MODE=vault (and tests): calls the service in process.
export function localForwarder(service) {
  return async (authorization, body) => {
    try { return await service.handle('POST', new URL('http://localhost/api/ingest/otlp'), {authorization, 'content-type': 'application/json'}, body); }
    catch (error) { throw error?.status ? vaultFailure(error.status) : busy(); }
  };
}

// The body is read, decompressed and decoded only for a token the vault accepts as an OTLP source: before this check an
// unauthenticated 8 KiB gzip body cost seconds of CPU and up to 1 GB of heap. The probe is an empty batch (one principal
// lookup at the vault, also served by vaults that predate it). Verdicts are cached per token hash for a short time; the
// vault still authenticates every real batch, so a cached "allowed" never stores anything by itself.
export const OTLP_AUTH_PROBE = JSON.stringify({format: OTLP_BATCH_FORMAT, mapping: OTLP_MAPPING_VERSION, events: []});
export function tokenGate(check, {allowMs = 30000, denyMs = 5000, maxEntries = 1024, now = Date.now} = {}) {
  const verdicts = new Map(), pending = new Map();
  async function lookup(key, authorization) {
    let denied = null;
    try { await check(authorization); } catch (error) { if (error?.status !== 401 && error?.status !== 403) throw error; denied = error; }
    const verdict = {denied, until: now() + (denied ? denyMs : allowMs)};
    if (verdicts.size >= maxEntries) verdicts.delete(verdicts.keys().next().value);
    verdicts.set(key, verdict);
    return verdict;
  }
  return async authorization => {
    const key = createHash('sha256').update(authorization).digest('base64url');
    let verdict = verdicts.get(key);
    if (!verdict || verdict.until <= now()) {
      verdicts.delete(key);
      let running = pending.get(key); // concurrent requests with one token share one vault call
      if (!running) { running = lookup(key, authorization).finally(() => pending.delete(key)); pending.set(key, running); }
      verdict = await running;
    }
    if (verdict.denied) throw new OtlpHttpError(verdict.denied.status, verdict.denied.message);
  };
}

const mediaType = value => String(value || '').split(';')[0].trim().toLowerCase();

async function readBody(req, limit) {
  const declared = req.headers['content-length'];
  if (declared !== undefined && Number(declared) > limit) throw new OtlpHttpError(413, `request body exceeds ${limit} bytes`);
  const parts = []; let size = 0;
  // destroyOnReturn:false keeps the socket so the 413 answer can still be written.
  for await (const chunk of req.iterator({destroyOnReturn: false})) {
    if ((size += chunk.length) > limit) throw new OtlpHttpError(413, `request body exceeds ${limit} bytes`);
    parts.push(chunk);
  }
  return Buffer.concat(parts, size);
}

async function decompress(raw, encoding, limit) {
  const tooLarge = () => new OtlpHttpError(413, `decompressed body exceeds ${limit} bytes`);
  if (!encoding) { if (raw.length > limit) throw tooLarge(); return raw; }
  const options = {maxOutputLength: limit};
  try {
    if (encoding !== 'deflate') return await inflaters[encoding](raw, options);
    try { return await inflaters.deflate(raw, options); }
    catch (error) { if (error?.code !== 'Z_DATA_ERROR') throw error; return await inflaters.deflateRaw(raw, options); }
  } catch (error) {
    if (error?.code === 'ERR_BUFFER_TOO_LARGE' || error instanceof RangeError) throw tooLarge();
    throw new OtlpHttpError(400, `invalid ${encoding} body`);
  }
}

export function createOtlpHttp({forward, authenticate = tokenGate(authorization => forward(authorization, OTLP_AUTH_PROBE)), limits = otlpLimits(),
  log = () => {}}) {
  let inflight = 0;
  function send(res, type, status, body, headers = {}) {
    res.statusCode = status;
    res.setHeader('Content-Type', type);
    for (const [name, value] of Object.entries(headers)) res.setHeader(name, value);
    res.end(body);
  }
  function fail(req, res, error, consumed = false) {
    const type = MEDIA_TYPES.has(mediaType(req.headers['content-type'])) ? mediaType(req.headers['content-type']) : 'application/json';
    const status = error instanceof OtlpHttpError || [400, 413, 415].includes(error?.status) ? error.status : 503;
    const message = status === 503 && !(error instanceof OtlpHttpError) ? 'temporarily unable to store spans; retry later' : error.message;
    const code = GRPC_CODES[status] ?? 2, headers = {};
    if (status === 503) headers['Retry-After'] = String(error.retryAfter || 5);
    if (status === 405) headers.Allow = 'POST';
    if (!consumed) headers.Connection = 'close'; // unread request bytes must not be parsed as the next request
    if (status === 503 && !(error instanceof OtlpHttpError)) log({component: 'otlp', error: error?.code || error?.name || 'unknown'});
    send(res, type, status, MEDIA_TYPES.get(type) === 'protobuf' ? encodeStatus(code, message) : JSON.stringify({code, message}), headers);
  }
  async function handle(req, res, {originAllowed = () => true} = {}) {
    let consumed = false;
    try {
      if (req.method !== 'POST') throw new OtlpHttpError(405, 'only POST is supported');
      if (req.headers.origin && !originAllowed(req.headers.origin)) throw new OtlpHttpError(403, 'cross-origin requests are not allowed');
      const type = mediaType(req.headers['content-type']), format = MEDIA_TYPES.get(type);
      if (!format) throw new OtlpHttpError(415, 'unsupported Content-Type; use application/x-protobuf or application/json');
      const encoding = ENCODINGS.get(String(req.headers['content-encoding'] || '').trim().toLowerCase());
      if (encoding === undefined) throw new OtlpHttpError(415, 'unsupported Content-Encoding; use gzip, deflate, zstd or none');
      const authorization = req.headers.authorization || '';
      if (!/^Bearer [\x21-\x7e]+$/.test(authorization)) throw new OtlpHttpError(401, 'bearer token required');
      await authenticate(authorization);
      if (inflight >= limits.maxInflight) throw busy('receiver busy; retry later', 1);
      inflight++;
      try {
        const raw = await readBody(req, limits.maxBodyBytes);
        consumed = true;
        const body = await decompress(raw, encoding, limits.maxDecodedBytes);
        const mapped = mapTraceRequest(decodeTraceRequest(body, format, {maxSpans: limits.maxSpans}), {now: Date.now()});
        const rejected = {...mapped.rejected};
        // At least one vault call even for an empty batch: the vault authenticates the token.
        for (let i = 0; i === 0 || i < mapped.events.length; i += OTLP_FORWARD_CHUNK) {
          const events = mapped.events.slice(i, i + OTLP_FORWARD_CHUNK);
          const result = await forward(authorization, JSON.stringify({format: OTLP_BATCH_FORMAT, mapping: OTLP_MAPPING_VERSION, events}));
          for (const [reason, count] of Object.entries(result?.reasons || {})) {
            if (/^[a-z_]{1,40}$/.test(reason) && Number.isSafeInteger(count) && count > 0) rejected[reason] = (rejected[reason] || 0) + count;
          }
        }
        const summary = rejectionSummary(rejected);
        const payload = format === 'protobuf' ? encodeExportTraceServiceResponse(summary.total, summary.message)
          : JSON.stringify(summary.total ? {partialSuccess: {rejectedSpans: String(summary.total), errorMessage: summary.message}} : {});
        send(res, type, 200, payload);
      } finally { inflight--; }
    } catch (error) { if (!res.headersSent) fail(req, res, error, consumed); else res.destroy(); }
  }
  return {handle, unavailable: (req, res) => fail(req, res, busy('receiver busy or shutting down; retry later', 1))};
}
