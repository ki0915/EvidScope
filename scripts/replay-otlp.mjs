// Replays saved OTLP trace exports (ExportTraceServiceRequest) to an EvidScope OTLP/HTTP receiver.
// usage: node scripts/replay-otlp.mjs <https://ingress/v1/traces> FILE... [--token-env NAME] [--no-gzip]
//   FILE: *.json (one request), *.jsonl|*.ndjson (one request per line), *.pb|*.bin (protobuf); a trailing .gz is
//   sent as-is with Content-Encoding: gzip. The bearer token is read from the environment (default
//   EVIDSCOPE_OTLP_TOKEN), never from argv. Bodies are never printed; only status counts are reported.
import {readFileSync} from 'node:fs';
import {gzipSync} from 'node:zlib';
import {decodeExportTraceServiceResponse} from '../src/otlp-protobuf.mjs';

const args = process.argv.slice(2), files = [];
let target, tokenEnv = 'EVIDSCOPE_OTLP_TOKEN', gzip = true, bad = false;
for (let i = 0; i < args.length; i++) {
  if (args[i] === '--token-env' && args[i + 1]) tokenEnv = args[++i];
  else if (args[i] === '--no-gzip') gzip = false;
  else if (args[i].startsWith('--')) bad = true;
  else if (!target) target = args[i];
  else files.push(args[i]);
}
const usage = () => { console.error('usage: node scripts/replay-otlp.mjs <https://ingress/v1/traces> FILE... [--token-env NAME] [--no-gzip]'); process.exit(2); };
if (bad || !target || !files.length) usage();
let url;
try { url = new URL(target); } catch { usage(); }
if (url.username || url.password || url.hash || !['https:', 'http:'].includes(url.protocol) || url.protocol === 'http:' && !['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname)) {
  console.error('Use HTTPS, or loopback HTTP, without URL credentials or fragment.'); process.exit(2);
}
const token = process.env[tokenEnv];
if (!token || /[^\x21-\x7e]/.test(token)) { console.error(`Set the OTLP source bearer token in ${tokenEnv}.`); process.exit(2); }

function requests(file) {
  const compressed = file.endsWith('.gz'), name = compressed ? file.slice(0, -3) : file, raw = readFileSync(file);
  const type = /\.(pb|bin)$/.test(name) ? 'application/x-protobuf' : 'application/json';
  if (/\.(jsonl|ndjson)$/.test(name)) {
    if (compressed) throw Error(`${file}: compressed JSON lines are not supported`);
    return raw.toString('utf8').split(/\r?\n/).filter(line => line.trim()).map(line => ({type, body: Buffer.from(line), encoded: false}));
  }
  return [{type, body: raw, encoded: compressed}];
}

const summary = {requests: 0, delivered: 0, rejectedSpans: 0, failed: 0, statuses: {}};
for (const file of files) {
  for (const {type, body, encoded} of requests(file)) {
    summary.requests++;
    const payload = encoded || !gzip ? body : gzipSync(body);
    let response;
    for (let attempt = 1; ; attempt++) {
      try {
        response = await fetch(url, {method: 'POST', redirect: 'error', signal: AbortSignal.timeout(60000),
          headers: {'content-type': type, authorization: `Bearer ${token}`, ...(encoded || gzip ? {'content-encoding': 'gzip'} : {})}, body: payload});
      } catch { response = null; }
      const retryable = !response || [429, 502, 503, 504].includes(response.status);
      if (!retryable || attempt >= 5) break;
      const wait = Math.min(60, Number(response?.headers.get('retry-after')) || 2 ** attempt);
      await response?.arrayBuffer();
      await new Promise(resolve => setTimeout(resolve, wait * 1000));
    }
    const status = response ? response.status : 'network_error';
    summary.statuses[status] = (summary.statuses[status] || 0) + 1;
    if (response?.status !== 200) { summary.failed++; await response?.arrayBuffer(); continue; }
    summary.delivered++;
    const bytes = Buffer.from(await response.arrayBuffer());
    try {
      if (response.headers.get('content-type') === 'application/x-protobuf') summary.rejectedSpans += Number(decodeExportTraceServiceResponse(bytes).rejectedSpans);
      else if (bytes.length) summary.rejectedSpans += Number(JSON.parse(bytes).partialSuccess?.rejectedSpans || 0);
    } catch { /* an unparseable 2xx body is reported as delivered; the receiver committed the request */ }
  }
}
console.log(JSON.stringify(summary));
if (summary.failed) process.exitCode = 1;
