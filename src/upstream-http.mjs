import http from 'node:http';
import https from 'node:https';

// Gateway-to-vault calls (round 6, docs/performance.md): node:http on the global keep-alive agents instead of fetch, which cost
// the ingress gateway about 0.4 ms of CPU per forwarded event. Same contract as the fetch call it replaces: redirects are never
// followed, TLS is verified against Node's default trust store, NODE_USE_ENV_PROXY applies through the global agents, and the
// deadline (timeoutMs) covers the whole exchange, response body included. Resolves {status, headers, body: Buffer}.
// agent: an http(s).Agent of the caller's own (the SDK client's keep-alive pool); the global agents otherwise.
export function upstreamRequest(url, {method = 'GET', headers = {}, body, timeoutMs, maxBytes = Infinity, agent} = {}) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const settle = (fn, value) => { if (!settled) { settled = true; fn(value); } };
    const target = url instanceof URL ? url : new URL(url);
    const transport = target.protocol === 'https:' ? https : target.protocol === 'http:' ? http : null;
    if (!transport) { reject(TypeError('Upstream URL must be http or https')); return; }
    const payload = body === undefined ? undefined : Buffer.from(body);
    const options = {method, headers: payload ? {...headers, 'content-length': payload.length} : headers, signal: AbortSignal.timeout(timeoutMs),
      ...(agent ? {agent} : {})};
    const request = transport.request(target, options, response => {
      const chunks = []; let size = 0;
      response.on('data', chunk => {
        if ((size += chunk.length) > maxBytes) { settle(reject, Error('Upstream response too large')); request.destroy(); return; }
        chunks.push(chunk);
      });
      response.on('end', () => settle(resolve, {status: response.statusCode, headers: response.headers, body: Buffer.concat(chunks)}));
      response.on('error', error => settle(reject, error));
      response.on('close', () => { if (!response.complete) settle(reject, Error('Upstream response ended early')); });
    });
    request.on('error', error => settle(reject, error));
    request.end(payload);
  });
}
