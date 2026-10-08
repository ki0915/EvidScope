import {fail} from './model.mjs';

// Ingress-to-vault forwarding of source events in envelopes (round 6, docs/performance.md). The ingress gateway puts the
// /api/ingest requests that arrive in the same event-loop turn, per bearer token, into one internal POST; the vault answers each
// item exactly as /api/ingest would (status and JSON body), because it runs each through the same route with the item's own
// timestamp, nonce, HMAC signature and raw body. Nothing changes for sources: each one still gets its own 202 after the COMMIT
// that holds its event. The envelope saves the HTTP exchange per event at both ends.
export const INGEST_FORWARD_PATH = '/internal/ingest-forward', INGEST_FORWARD_FORMAT = 'evidscope-ingest-forward-v1';
export const INGEST_FORWARD_MAX_EVENTS = 64, INGEST_FORWARD_MAX_BYTES = 1024 * 1024, INGEST_FORWARD_ITEM_BYTES = 16384;
// Set on every vault answer to the envelope path, so the gateway can tell a vault that predates it (fall back to one call each).
export const INGEST_FORWARD_HEADER = 'x-evidscope-ingest-forward';
const ITEM_HEADERS = ['x-evid-timestamp', 'x-evid-nonce', 'x-evid-signature'];
const UNAVAILABLE = '저장소 또는 서비스 연결 실패; 접수 성공이 아닙니다';

// Vault side. headers: the envelope's request headers (its bearer is the bearer of every item, checked again per item);
// ingest(headers, body) is the /api/ingest route; admit(n) may refuse the envelope before any item runs (admission control).
// Resolves {format, items: [{status, body}]} in item order; an item error never fails the envelope.
export async function forwardedIngest(ingest, headers, text, {admit = () => {}, log = () => {}} = {}) {
  let envelope; try { envelope = JSON.parse(text); } catch { fail(400, 'JSON 형식 오류'); }
  const items = envelope?.items;
  if (envelope?.format !== INGEST_FORWARD_FORMAT || !Array.isArray(items) || !items.length || items.length > INGEST_FORWARD_MAX_EVENTS
    || items.some(item => !item || typeof item !== 'object' || typeof item.body !== 'string' || !item.headers || typeof item.headers !== 'object'
      || ITEM_HEADERS.some(name => item.headers[name] !== undefined && typeof item.headers[name] !== 'string')))fail(400, '수집 전달 묶음 형식 오류');
  admit(items.length);
  const answers = await Promise.all(items.map(async item => {
    if (Buffer.byteLength(item.body) > INGEST_FORWARD_ITEM_BYTES) return {status: 413, body: {error: `요청 크기 한도 ${INGEST_FORWARD_ITEM_BYTES} bytes 초과`}};
    const itemHeaders = {authorization: headers.authorization || ''};
    for (const name of ITEM_HEADERS) if (item.headers[name] !== undefined) itemHeaders[name] = item.headers[name];
    try { return {status: 202, body: await ingest(itemHeaders, item.body)}; }
    catch (error) {
      if (!error?.status) log(error);
      return {status: error?.status || 503, body: {error: error?.status ? error.message : UNAVAILABLE, ...(error?.status && error.details || {})}};
    }
  }));
  return {format: INGEST_FORWARD_FORMAT, items: answers};
}

// Gateway side. send(authorization, envelopeText) => {status, headers, body: Buffer} posts one envelope; single(headers, body)
// forwards one request the old way. forward(headers, body) resolves {status, body: string} or rejects like a failed upstream call.
// An envelope the vault refuses as a whole (bearer, role, busy) gives every item that answer; an answer without
// INGEST_FORWARD_HEADER (a vault that predates envelopes) sends each item alone and stops using envelopes for retryMs.
export function createForwardCoalescer({send, single, maxEvents = INGEST_FORWARD_MAX_EVENTS, maxBytes = INGEST_FORWARD_MAX_BYTES - 65536,
  retryMs = 60000, now = Date.now} = {}) {
  if (!Number.isSafeInteger(maxEvents) || maxEvents < 1 || maxEvents > INGEST_FORWARD_MAX_EVENTS) throw TypeError('Invalid forward batch size');
  const groups = new Map(); let immediate = null, unsupportedUntil = 0;
  const stats = {envelopes: 0, events: 0, single: 0, fallbacks: 0};
  async function alone(group) {
    stats.single += group.length;
    await Promise.all(group.map(async ({headers, body, resolve, reject}) => {
      try { resolve(await single(headers, body)); } catch (error) { reject(error); }
    }));
  }
  async function dispatch(authorization, group) {
    if (group.length === 1 || now() < unsupportedUntil) return alone(group);
    const items = group.map(item => `{"headers":${JSON.stringify(item.itemHeaders)},"body":${item.escaped}}`);
    const text = `{"format":${JSON.stringify(INGEST_FORWARD_FORMAT)},"items":[${items.join(',')}]}`;
    let response;
    try { response = await send(authorization, text); } catch (error) { for (const item of group) item.reject(error); return; }
    // A vault that predates envelopes answers 403, 404 or 413; a busy vault (503) or a bad bearer (401) answers every item alike.
    if (!response.headers[INGEST_FORWARD_HEADER] && ![401, 503].includes(response.status)) {
      unsupportedUntil = now() + retryMs; stats.fallbacks++; return alone(group);
    }
    stats.envelopes++; stats.events += group.length;
    const textBody = response.body.toString('utf8');
    if (response.status !== 200) { for (const item of group) item.resolve({status: response.status, body: textBody}); return; }
    let answers;
    try { answers = JSON.parse(textBody).items; if (!Array.isArray(answers) || answers.length !== group.length) throw Error(); }
    catch { const error = Error('Invalid forward answer'); for (const item of group) item.reject(error); return; }
    group.forEach((item, index) => item.resolve({status: answers[index].status, body: JSON.stringify(answers[index].body)}));
  }
  function flush() {
    immediate = null;
    const ready = [...groups]; groups.clear();
    for (const [authorization, group] of ready) dispatch(authorization, group.items);
  }
  return {
    get stats() { return {...stats}; },
    forward(headers, body) {
      return new Promise((resolve, reject) => {
        const authorization = headers.authorization || '', itemHeaders = {};
        for (const name of ITEM_HEADERS) if (typeof headers[name] === 'string') itemHeaders[name] = headers[name];
        // The body as a JSON string, as it goes into the envelope; the vault refuses an envelope above INGEST_FORWARD_MAX_BYTES.
        const escaped = JSON.stringify(body), size = Buffer.byteLength(escaped) + 256;
        let group = groups.get(authorization);
        if (group && (group.items.length >= maxEvents || group.bytes + size > maxBytes)) {
          groups.delete(authorization); dispatch(authorization, group.items); group = null;
        }
        if (!group) groups.set(authorization, group = {items: [], bytes: 0});
        group.items.push({headers, itemHeaders, body, escaped, resolve, reject}); group.bytes += size;
        immediate ??= setImmediate(flush);
      });
    },
  };
}
