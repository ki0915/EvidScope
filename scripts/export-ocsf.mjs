// Map the findings of a verified EvidScope export to OCSF Detection Finding (2004) events.
// Usage:
//   node scripts/export-ocsf.mjs EXPORT.json TRUSTED_PUBLIC_KEY.pem [--ocsf-version 1.3.0|1.9.0] [--out FINDINGS.ndjson]
//   node scripts/export-ocsf.mjs EXPORT.json TRUSTED_PUBLIC_KEY.pem --hec-url https://splunk.example:8088/services/collector/event
//        [--hec-token-env SPLUNK_HEC_TOKEN] [--index NAME] [--sourcetype ocsf:evidscope:detection_finding]
// Without --out the NDJSON goes to stdout. Events are sent to Splunk HEC only when --hec-url is given and the token
// environment variable is set; plain http is accepted for loopback test collectors only.
import {readFileSync, writeFileSync} from 'node:fs';
import {ocsfFromBundle, hecEnvelope, SPLUNK_SOURCETYPE} from '../src/ocsf.mjs';

const usage = 'Usage: node scripts/export-ocsf.mjs EXPORT.json TRUSTED_PUBLIC_KEY.pem [--ocsf-version 1.3.0|1.9.0] [--out FILE.ndjson] '
  + '[--hec-url URL [--hec-token-env NAME] [--index NAME] [--sourcetype NAME]]';
const valued = ['--ocsf-version', '--out', '--hec-url', '--hec-token-env', '--index', '--sourcetype'];

function parse(argv) {
  const options = {positional: []};
  for (let i = 0; i < argv.length; i++) {
    if (!argv[i].startsWith('--')) { options.positional.push(argv[i]); continue; }
    if (!valued.includes(argv[i]) || argv[i + 1] === undefined) throw Error(usage);
    options[argv[i].slice(2)] = argv[++i];
  }
  if (options.positional.length !== 2) throw Error(usage);
  return options;
}

function collector(raw) {
  const url = new URL(raw), loopback = ['127.0.0.1', '[::1]', 'localhost'].includes(url.hostname);
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback)) throw Error('HEC URL must use https (http only for loopback)');
  if (url.username || url.password) throw Error('HEC URL must not contain credentials; pass the token via --hec-token-env');
  return url;
}

async function sendToHec(events, options) {
  const url = collector(options['hec-url']), tokenEnv = options['hec-token-env'] || 'SPLUNK_HEC_TOKEN', token = process.env[tokenEnv];
  if (!token) throw Error(`HEC token environment variable ${tokenEnv} is not set; nothing was sent`);
  const lines = events.map(event => JSON.stringify(hecEnvelope(event, {sourcetype: options.sourcetype || SPLUNK_SOURCETYPE, index: options.index})));
  let sent = 0;
  while (sent < lines.length) {
    const batch = [];
    let bytes = 0;
    while (sent + batch.length < lines.length && batch.length < 100 && (bytes + lines[sent + batch.length].length < 900000 || !batch.length)) {
      bytes += lines[sent + batch.length].length + 1;
      batch.push(lines[sent + batch.length]);
    }
    const response = await fetch(url, {method: 'POST', headers: {authorization: `Splunk ${token}`, 'content-type': 'application/json'},
      body: batch.join('\n'), redirect: 'error', signal: AbortSignal.timeout(10000)});
    const text = await response.text();
    let code;
    try { code = JSON.parse(text).code; } catch { code = undefined; }
    if (!response.ok || code !== 0) throw Error(`HEC rejected batch at event ${sent}: HTTP ${response.status} ${text.slice(0, 200)}`);
    sent += batch.length;
  }
  return sent;
}

try {
  const options = parse(process.argv.slice(2)), [bundlePath, keyPath] = options.positional;
  const events = ocsfFromBundle(JSON.parse(readFileSync(bundlePath, 'utf8')), readFileSync(keyPath, 'utf8'), {version: options['ocsf-version']});
  if (options['hec-url']) {
    const sent = await sendToHec(events, options);
    console.error(JSON.stringify({events: events.length, sent, destination: 'splunk_hec'}));
  } else {
    const ndjson = events.map(event => JSON.stringify(event) + '\n').join('');
    if (options.out) writeFileSync(options.out, ndjson, {mode: 0o600});
    else process.stdout.write(ndjson);
    console.error(JSON.stringify({events: events.length, destination: options.out ? 'file' : 'stdout'}));
  }
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
