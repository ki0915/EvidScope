// Links from EvidScope's action and trace views to the same trace in Langfuse or Phoenix (TRACE_LINKS_FILE), and the
// #action= deep link back (docs/observability-integration.md).
import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, readFileSync, mkdirSync} from 'node:fs';
import {resolve, join} from 'node:path';
import {initialize} from '../scripts/init.mjs';
import {createService} from '../src/service.mjs';
import {decodeTraceRequest, mapTraceRequest, OTLP_BATCH_FORMAT, OTLP_MAPPING_VERSION} from '../src/otlp.mjs';
import {eventTraceIds, traceLinkTemplates, traceLinks} from '../src/trace-links.mjs';

const TRACE = '4bf92f3577b34da6a3ce929d0e0e4736';
const LANGFUSE = {name: 'Langfuse', url: 'https://cloud.langfuse.com/project/demo-project/traces/{traceId}'};
const PHOENIX = {name: 'Phoenix', url: 'https://phoenix.example/projects/UHJvamVjdDox/traces/{traceId}?selected=1'};

test('trace link templates: https, placeholder after the host, bounded, checked at start', () => {
  assert.deepEqual(traceLinkTemplates(undefined), []);
  assert.deepEqual(traceLinkTemplates([LANGFUSE, PHOENIX]).map(t => t.name), ['Langfuse', 'Phoenix']);
  for (const bad of [{}, [LANGFUSE, LANGFUSE, LANGFUSE, LANGFUSE, LANGFUSE], [{name: 'x', url: 'http://langfuse.example/{traceId}'}],
    [{name: 'x', url: 'https://langfuse.example/trace'}], [{name: 'x', url: 'https://{traceId}.example/'}], [{name: 'x', url: 'https://a.example{traceId}/'}],
    [{name: 'x', url: 'https://user:pw@langfuse.example/{traceId}'}], [{name: 'x', url: 'javascript:alert(1)//{traceId}'}],
    [{name: '<b>x</b>', url: LANGFUSE.url}], [{...LANGFUSE, extra: 1}], [{name: 'x', url: `https://a.example/${'p'.repeat(500)}{traceId}`}]])
    assert.throws(() => traceLinkTemplates(bad), /Invalid traceLinks configuration/, JSON.stringify(bad).slice(0, 80));
  const templates = traceLinkTemplates([LANGFUSE]);
  assert.deepEqual(traceLinks(templates, [TRACE, TRACE, 'not-a-trace', '0'.repeat(32), 'ABCDEF'.padEnd(32, '0')]),
    [{name: 'Langfuse', traceId: TRACE, url: `https://cloud.langfuse.com/project/demo-project/traces/${TRACE}`}]);
  assert.deepEqual(traceLinks([], [TRACE]), []);
  assert.deepEqual(eventTraceIds([{traceId: 'demo-trace'}, {traceId: 'x', aiObservation: {span: {traceId: TRACE}}}]), [TRACE]);
});

function fixture(t, traceLinksConfig) {
  mkdirSync('.test-runs', {recursive: true});
  const dir = mkdtempSync(resolve('.test-runs/trace-links-')), config = initialize(dir);
  const s = createService({dataDir: join(dir, 'data'), config, key: readFileSync(join(dir, 'signing-private.pem'), 'utf8'), traceLinks: traceLinksConfig});
  t.after(() => s.store.close());
  const principal = kind => config.principals.find(p => p.tenant === 'alpha' && (p.kind === kind || p.role === kind));
  const get = path => s.handle('GET', new URL(`http://localhost${path}`), {authorization: `Bearer ${principal('auditor').token}`});
  return {s, principal, get, dir, config};
}

test('action and trace views carry links to the same trace; none without configuration; bad configuration stops the vault', async t => {
  const {s, principal, get} = fixture(t, [LANGFUSE, PHOENIX]);
  const events = mapTraceRequest(decodeTraceRequest(readFileSync(new URL('./fixtures/otlp/sdk-genai.json', import.meta.url)), 'json')).events;
  const body = JSON.stringify({format: OTLP_BATCH_FORMAT, mapping: OTLP_MAPPING_VERSION, events});
  await s.handle('POST', new URL('http://localhost/api/ingest/otlp'), {authorization: `Bearer ${principal('otlp').token}`}, body);
  const action = await get(`/api/actions/${encodeURIComponent(`otel-trace:${TRACE}`)}`);
  assert.deepEqual(action.traceLinks.map(l => [l.name, l.url]), [['Langfuse', `https://cloud.langfuse.com/project/demo-project/traces/${TRACE}`],
    ['Phoenix', `https://phoenix.example/projects/UHJvamVjdDox/traces/${TRACE}?selected=1`]]);
  const trace = await get(`/api/events?traceId=${TRACE}`);
  assert.equal(trace.traceLinks.length, 2);
  assert.equal((await get('/api/events?traceId=x%22%3E%3Cscript%3E')).traceLinks.length, 0, 'only W3C trace ids become links');
  assert.equal((await get('/api/events')).traceLinks, undefined);
  const plain = fixture(t);
  assert.deepEqual((await plain.get(`/api/actions/${encodeURIComponent(`otel-trace:${TRACE}`)}`)).traceLinks, []);
  assert.throws(() => fixture(t, [{name: 'Langfuse', url: 'http://langfuse.internal/{traceId}'}]), /Invalid traceLinks configuration/);
});

test('UI: trace links open https targets in a new tab without referrer; #action= opens the action after sign-in', () => {
  const app = readFileSync(new URL('../public/app.js', import.meta.url), 'utf8');
  const row = app.slice(app.indexOf('function traceLinkRow'), app.indexOf('function openLinkedAction'));
  assert.match(row, /new URL\(link\.url\)\.protocol === 'https:'/);
  assert.match(row, /anchor\.rel = 'noopener noreferrer'/);
  assert.match(row, /anchor\.target = '_blank'/);
  assert.ok(!/innerHTML/.test(row));
  const linked = app.slice(app.indexOf('function openLinkedAction'), app.indexOf('async function actionDetail'));
  assert.match(linked, /if \(!match \|\| !token\) return;/, 'only after sign-in');
  assert.match(linked, /\^\[a-zA-Z0-9\._:@\/-\]\{1,120\}\$/, 'same identifier rule as the vault');
  assert.equal(app.match(/openLinkedAction\(\);/g).length, 2, 'both sign-in paths open a pending deep link');
  assert.match(app, /const traceRow = traceLinkRow\(data\.traceLinks\); if \(traceRow\) node\.append\(traceRow\);/);
});
