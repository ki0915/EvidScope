// Links from EvidScope's action and trace views to the same OTel trace in Langfuse, Phoenix or another trace UI
// (docs/observability-integration.md). The operator configures URL templates in config.json `traceLinks`; the vault only fills
// in a validated W3C trace id and never contacts the target. Example:
//   "traceLinks": [{"name": "Langfuse", "url": "https://cloud.langfuse.com/project/PROJECT_ID/traces/{traceId}"}]
export const TRACE_LINK_LIMITS = Object.freeze({templates: 4, name: 40, url: 500, traces: 10});
const PLACEHOLDER = '{traceId}', SAMPLE = '0123456789abcdef0123456789abcdef';
const otelTrace = v => typeof v === 'string' && /^[a-f0-9]{32}$/.test(v) && !/^0+$/.test(v);

// Checked when the vault starts, so a bad template fails the start instead of rendering a wrong or unsafe link.
export function traceLinkTemplates(value) {
  if (value === undefined) return Object.freeze([]);
  const bad = message => { throw Error(`Invalid traceLinks configuration: ${message}`); };
  if (!Array.isArray(value) || value.length > TRACE_LINK_LIMITS.templates) bad(`an array of at most ${TRACE_LINK_LIMITS.templates} entries`);
  return Object.freeze(value.map(entry => {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry) || Object.keys(entry).some(k => !['name', 'url'].includes(k)))
      bad('entries are {name, url}');
    const {name, url} = entry;
    if (typeof name !== 'string' || !/^[\p{L}\p{N} ._()-]{1,40}$/u.test(name)) bad('name is 1-40 letters, digits, spaces or ._()-');
    if (typeof url !== 'string' || url.length > TRACE_LINK_LIMITS.url || !url.includes(PLACEHOLDER))
      bad(`url is a template of at most ${TRACE_LINK_LIMITS.url} characters with ${PLACEHOLDER}`);
    let parsed;
    try { parsed = new URL(url.replaceAll(PLACEHOLDER, SAMPLE)); } catch { bad('url must be an absolute URL'); }
    if (parsed.protocol !== 'https:' || parsed.username || parsed.password) bad('url must be https without credentials');
    // The trace id only ever fills the path, query or fragment: the text before the first placeholder already names the origin.
    if (!url.slice(0, url.indexOf(PLACEHOLDER)).startsWith(`${parsed.origin}/`)) bad(`${PLACEHOLDER} must come after https://host/`);
    return Object.freeze({name, url});
  }));
}
// One link per configured template and OTel trace id (32 lowercase hex, not all zero) the evidence names.
export function traceLinks(templates, traceIds) {
  if (!templates.length) return [];
  const ids = [...new Set(traceIds.filter(otelTrace))].slice(0, TRACE_LINK_LIMITS.traces);
  return ids.flatMap(traceId => templates.map(t => ({name: t.name, traceId, url: t.url.replaceAll(PLACEHOLDER, traceId)})));
}
// The OTel trace ids of verified event bodies: the event's own trace id, or the span context of an OTLP observation.
export const eventTraceIds = events => events.flatMap(e => [e?.traceId, e?.aiObservation?.span?.traceId]).filter(otelTrace);
