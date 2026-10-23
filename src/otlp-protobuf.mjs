// Dependency-free, bounded decoder for the subset of
// opentelemetry.proto.collector.trace.v1.ExportTraceServiceRequest that EvidScope maps.
// Field order independent (the Collector writes descending field numbers, the JS SDK ascending
// with explicit defaults). Unknown fields are skipped by wire type. Attribute values are decoded
// only for allowlisted keys; span names, events, links, trace state and status messages are
// skipped without being decoded.

export class OtlpDecodeError extends Error {
  constructor(message, status = 400) { super(message); this.status = status; }
}

const utf8 = new TextDecoder('utf-8', {fatal: false}); // OTLP: replace invalid UTF-8 with U+FFFD
const MAX_ARRAY_VALUES = 16;

// Structural budget shared with the JSON decoder. Every ResourceSpans/ScopeSpans is a container and every KeyValue or
// array element a value, so the work per request is bounded by the span limit rather than by how small each element is
// (8 KiB of gzip holding 4M empty ResourceSpans used to decode into ~1 GB of objects).
export function structureLimits(maxSpans) {
  return {spans: maxSpans, containers: Math.max(64, 4 * maxSpans), values: Math.max(4096, 64 * maxSpans)};
}
const LIMIT_NAMES = {spans: 'spans', containers: 'ResourceSpans/ScopeSpans', values: 'attributes and array values'};
export function structureBudget(maxSpans) {
  const limits = structureLimits(maxSpans), used = {spans: 0, containers: 0, values: 0};
  return kind => {
    if (++used[kind] > limits[kind]) throw new OtlpDecodeError(`more than ${limits[kind]} ${LIMIT_NAMES[kind]} in one request`, 413);
  };
}
// Attribute map of a resource or span without allowlisted attributes: shared, so empty containers allocate nothing.
class NoAttributes extends Map { set() { throw new TypeError('shared empty attribute map'); } }
export const NO_ATTRIBUTES = Object.freeze(new NoAttributes());
const longestKey = new WeakMap();
const keyLimit = allow => {
  let n = longestKey.get(allow);
  if (n === undefined) longestKey.set(allow, n = Math.max(0, ...[...allow].map(k => Buffer.byteLength(k))));
  return n;
};

function varint(r) {
  let result = 0n, shift = 0n;
  for (let i = 0; i < 10; i++) {
    if (r.pos >= r.end) throw new OtlpDecodeError('truncated varint');
    const byte = r.buf[r.pos++];
    result |= BigInt(byte & 0x7f) << shift;
    if (!(byte & 0x80)) return result & 0xffffffffffffffffn;
    shift += 7n;
  }
  throw new OtlpDecodeError('varint too long');
}
// Field keys and lengths: Number arithmetic is exact for up to 7 bytes (2^49); longer encodings take the 64-bit path.
function uvarint(r) {
  const start = r.pos;
  let result = 0, scale = 1;
  for (let i = 0; i < 7; i++) {
    if (r.pos >= r.end) throw new OtlpDecodeError('truncated varint');
    const byte = r.buf[r.pos++];
    result += (byte & 0x7f) * scale;
    if (!(byte & 0x80)) return result;
    scale *= 128;
  }
  r.pos = start;
  return Number(varint(r));
}
function length(r) {
  const n = uvarint(r);
  if (n > r.end - r.pos) throw new OtlpDecodeError('truncated length-delimited field');
  const start = r.pos; r.pos += n; return [start, r.pos];
}
function fixed64(r) {
  if (r.pos + 8 > r.end) throw new OtlpDecodeError('truncated fixed64');
  const value = r.buf.readBigUInt64LE(r.pos); r.pos += 8; return value;
}
function fixed32(r) {
  if (r.pos + 4 > r.end) throw new OtlpDecodeError('truncated fixed32');
  const value = r.buf.readUInt32LE(r.pos); r.pos += 4; return value;
}
function skip(r, wireType) {
  if (wireType === 0) varint(r);
  else if (wireType === 1) fixed64(r);
  else if (wireType === 2) length(r);
  else if (wireType === 5) fixed32(r);
  else throw new OtlpDecodeError(`unsupported wire type ${wireType}`);
}
// Calls visit(field, wireType, reader) for every field of the message in [start,end).
// visit returns true when it consumed the value; otherwise the value is skipped.
function fields(buf, [start, end], visit) {
  const r = {buf, pos: start, end};
  while (r.pos < r.end) {
    const key = uvarint(r), field = Math.floor(key / 8), wireType = key % 8;
    if (field === 0 || field > 536870911) throw new OtlpDecodeError('invalid field number');
    if (wireType === 3 || wireType === 4 || wireType > 5) throw new OtlpDecodeError(`unsupported wire type ${wireType}`);
    if (!visit(field, wireType, r)) skip(r, wireType);
  }
}
function expect(wireType, expected, name) {
  if (wireType !== expected) throw new OtlpDecodeError(`wire type ${wireType} for ${name}`);
}
const text = (buf, [s, e]) => utf8.decode(buf.subarray(s, e));

// AnyValue -> scalar (string | boolean | decimal string for int64 | number) or array of scalars.
// kvlist and bytes values are not materialized (undefined).
function anyValue(buf, range, charge, nested = false) {
  let value;
  fields(buf, range, (field, wireType, r) => {
    switch (field) {
      case 1: expect(wireType, 2, 'string_value'); value = text(buf, length(r)); return true;
      case 2: expect(wireType, 0, 'bool_value'); value = varint(r) !== 0n; return true;
      case 3: expect(wireType, 0, 'int_value'); value = BigInt.asIntN(64, varint(r)).toString(); return true;
      case 4: { expect(wireType, 1, 'double_value'); const at = r.pos; fixed64(r); value = buf.readDoubleLE(at); return true; }
      case 5: {
        expect(wireType, 2, 'array_value');
        if (nested) { length(r); value = undefined; return true; } // nested arrays are dropped, so they are skipped undecoded
        const items = [];
        fields(buf, length(r), (f2, w2, r2) => {
          if (f2 !== 1) return false;
          expect(w2, 2, 'ArrayValue.values');
          charge('values');
          const item = length(r2);
          if (items.length < MAX_ARRAY_VALUES) { const v = anyValue(buf, item, charge, true); if (v !== undefined) items.push(v); }
          return true;
        });
        value = items; return true;
      }
      case 6: expect(wireType, 2, 'kvlist_value'); length(r); value = undefined; return true;
      case 7: expect(wireType, 2, 'bytes_value'); length(r); value = undefined; return true;
      default: return false;
    }
  });
  return value;
}

// KeyValue fields may arrive value-before-key, so remember the value range until the key is known.
// Keys longer than every allowlisted key are compared by length only and never decoded.
function keyValue(buf, range, allow) {
  let key, valueRange;
  const limit = keyLimit(allow);
  fields(buf, range, (field, wireType, r) => {
    if (field === 1) { expect(wireType, 2, 'KeyValue.key'); const [s, e] = length(r); key = e - s <= limit ? text(buf, [s, e]) : null; return true; }
    if (field === 2) { expect(wireType, 2, 'KeyValue.value'); valueRange = length(r); return true; }
    return false;
  });
  return typeof key === 'string' && allow.has(key) ? [key, valueRange] : null;
}
// Returns the attribute map, allocated on the first allowlisted key; the first occurrence wins, as in the JSON path.
function attribute(buf, range, allow, map, charge) {
  charge('values');
  const kv = keyValue(buf, range, allow);
  if (!kv || map.has(kv[0])) return map;
  if (map === NO_ATTRIBUTES) map = new Map();
  map.set(kv[0], kv[1] ? anyValue(buf, kv[1], charge) : undefined);
  return map;
}

function span(buf, range, allow, charge) {
  const s = {traceId: '', spanId: '', parentSpanId: '', kind: 0, startTimeUnixNano: '0', endTimeUnixNano: '0', statusCode: 0, attributes: NO_ATTRIBUTES};
  fields(buf, range, (field, wireType, r) => {
    switch (field) {
      case 1: expect(wireType, 2, 'trace_id'); s.traceId = buf.subarray(...length(r)).toString('hex'); return true;
      case 2: expect(wireType, 2, 'span_id'); s.spanId = buf.subarray(...length(r)).toString('hex'); return true;
      case 4: expect(wireType, 2, 'parent_span_id'); s.parentSpanId = buf.subarray(...length(r)).toString('hex'); return true;
      case 6: expect(wireType, 0, 'kind'); s.kind = Number(BigInt.asIntN(32, varint(r))); return true;
      case 7: expect(wireType, 1, 'start_time_unix_nano'); s.startTimeUnixNano = fixed64(r).toString(); return true;
      case 8: expect(wireType, 1, 'end_time_unix_nano'); s.endTimeUnixNano = fixed64(r).toString(); return true;
      case 9: expect(wireType, 2, 'attributes'); s.attributes = attribute(buf, length(r), allow, s.attributes, charge); return true;
      case 15: {
        expect(wireType, 2, 'status');
        fields(buf, length(r), (f2, w2, r2) => {
          if (f2 === 3) { expect(w2, 0, 'status.code'); s.statusCode = Number(BigInt.asIntN(32, varint(r2))); return true; }
          return false; // message (2) is free text and never decoded
        });
        return true;
      }
      case 16: expect(wireType, 5, 'flags'); fixed32(r); return true;
      default: return false; // 3 trace_state, 5 name, 10-14 events/links/counters: skipped undecoded
    }
  });
  return s;
}

// Returns {resourceSpans:[{resource:Map, scopeSpans:[{spans:[...]}]}]} with only allowlisted attributes. ResourceSpans and
// ScopeSpans without spans are counted against the budget but not returned.
export function decodeTraceRequestProtobuf(buf, {spanKeys, resourceKeys, maxSpans = 8192} = {}) {
  if (!Buffer.isBuffer(buf)) buf = Buffer.from(buf);
  const out = {resourceSpans: []}, charge = structureBudget(maxSpans);
  fields(buf, [0, buf.length], (field, wireType, r) => {
    if (field !== 1) return false;
    expect(wireType, 2, 'resource_spans');
    charge('containers');
    let resource = NO_ATTRIBUTES, scopeSpans = null;
    fields(buf, length(r), (f2, w2, r2) => {
      if (f2 === 1) {
        expect(w2, 2, 'ResourceSpans.resource');
        fields(buf, length(r2), (f3, w3, r3) => {
          if (f3 !== 1) return false;
          expect(w3, 2, 'Resource.attributes'); resource = attribute(buf, length(r3), resourceKeys, resource, charge); return true;
        });
        return true;
      }
      if (f2 === 2) {
        expect(w2, 2, 'ResourceSpans.scope_spans');
        charge('containers');
        let spans = null;
        fields(buf, length(r2), (f3, w3, r3) => {
          if (f3 !== 2) return false; // scope (1) and schema_url (3) are not needed
          expect(w3, 2, 'ScopeSpans.spans');
          charge('spans');
          (spans ||= []).push(span(buf, length(r3), spanKeys, charge)); return true;
        });
        if (spans) (scopeSpans ||= []).push({spans});
        return true;
      }
      return false;
    });
    if (scopeSpans) out.resourceSpans.push({resource, scopeSpans});
    return true;
  });
  return out;
}

function encodeVarint(value) {
  const out = []; let v = BigInt(value);
  do { let byte = Number(v & 0x7fn); v >>= 7n; if (v) byte |= 0x80; out.push(byte); } while (v);
  return Buffer.from(out);
}
const field = (tag, payload) => Buffer.concat([Buffer.from([tag]), encodeVarint(payload.length), payload]);

// ExportTraceServiceResponse: empty for full success, else partial_success{rejected_spans, error_message}.
export function encodeExportTraceServiceResponse(rejected = 0, message = '') {
  if (!rejected && !message) return Buffer.alloc(0);
  const msg = Buffer.from(message, 'utf8');
  const inner = Buffer.concat([
    rejected ? Buffer.concat([Buffer.from([0x08]), encodeVarint(rejected)]) : Buffer.alloc(0),
    msg.length ? field(0x12, msg) : Buffer.alloc(0),
  ]);
  return field(0x0a, inner);
}
// google.rpc.Status{code=1, message=2}
export function encodeStatus(code, message) {
  return Buffer.concat([code ? Buffer.concat([Buffer.from([0x08]), encodeVarint(code)]) : Buffer.alloc(0), field(0x12, Buffer.from(message, 'utf8'))]);
}

// Client side (scripts/replay-otlp.mjs): ExportTraceServiceResponse -> {rejectedSpans, errorMessage}.
export function decodeExportTraceServiceResponse(buf) {
  const out = {rejectedSpans: 0n, errorMessage: ''};
  fields(buf, [0, buf.length], (field, wireType, r) => {
    if (field !== 1) return false;
    expect(wireType, 2, 'partial_success');
    fields(buf, length(r), (f2, w2, r2) => {
      if (f2 === 1) { expect(w2, 0, 'rejected_spans'); out.rejectedSpans = BigInt.asIntN(64, varint(r2)); return true; }
      if (f2 === 2) { expect(w2, 2, 'error_message'); out.errorMessage = text(buf, length(r2)); return true; }
      return false;
    });
    return true;
  });
  return out;
}
