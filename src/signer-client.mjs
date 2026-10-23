// Vault side of the heads signer protocol (src/signer.mjs): JSON over HTTP on a Unix socket, a Windows named pipe, or TCP
// (loopback, or TLS with the signer's CA) with a bearer token. Every call resolves to {httpStatus, body}; only transport
// failures reject. Nothing the signer returns is trusted here: transparency.mjs re-derives and verifies every note.
import http from 'node:http';
import https from 'node:https';
import {createPublicKey, verify} from 'node:crypto';
import {readFileSync, statSync} from 'node:fs';
import {keyFingerprint} from './dsse.mjs';

// Whoever holds the token can send heads leaves in the vault's place. A token file of the reader's own user must be private
// (POSIX, as for keys); a Kubernetes Secret file (root:fsGroup 0440) is read through its group bits.
export function readSignerToken(file) {
  const st = statSync(file);
  if (process.platform !== 'win32' && st.uid === process.getuid() && (st.mode & 0o077)) {
    throw Error(`Signer token file ${file} is readable by other users (chmod 600)`);
  }
  const token = readFileSync(file, 'utf8').trim();
  if (token.length < 32 || /\s/.test(token)) throw Error(`Signer token file ${file} must hold one token of at least 32 characters`);
  return token;
}
export function createSignerClient({socket, pipe, url, token = null, ca = null, timeoutMs = 10000, maxResponseBytes = 64 * 1024 * 1024}) {
  const target = socket ?? pipe, u = target === undefined ? new URL(url) : null;
  const call = (path, body) => new Promise((resolve, reject) => {
    const data = Buffer.from(JSON.stringify(body), 'utf8');
    const options = {method: 'POST', path, agent: false, timeout: timeoutMs, headers: {'content-type': 'application/json', 'content-length': data.length,
      ...(token ? {authorization: `Bearer ${token}`} : {})}};
    if (target !== undefined) options.socketPath = target;
    else Object.assign(options, {host: u.hostname.replace(/^\[|\]$/g, ''), port: u.port || (u.protocol === 'https:' ? 443 : 80), ...(ca ? {ca} : {})});
    const req = (u?.protocol === 'https:' ? https : http).request(options, res => {
      const parts = [];
      let size = 0;
      res.on('data', chunk => {
        size += chunk.length;
        if (size > maxResponseBytes) { req.destroy(Error('heads signer answer is too large')); return; }
        parts.push(chunk);
      });
      res.on('end', () => {
        let parsed = null;
        try { parsed = JSON.parse(Buffer.concat(parts).toString('utf8')); } catch { parsed = null; }
        if (!parsed || typeof parsed !== 'object') return reject(Error(`heads signer answered HTTP ${res.statusCode} without a JSON body`));
        resolve({httpStatus: res.statusCode, body: parsed});
      });
      res.on('error', reject);
    });
    req.on('timeout', () => req.destroy(Error(`heads signer did not answer within ${timeoutMs} ms`)));
    req.on('error', error => reject(Error(`heads signer at ${target ?? url}: ${error.code || error.message}`)));
    req.end(data);
  });
  return {
    target: target ?? url,
    head: origin => call('/v1/head', {origin}),
    signHeads: request => call('/v1/sign-heads', request),
    info: () => call('/v1/info', {}),
    signStatement: message => call('/v1/sign-statement', {message: Buffer.from(message).toString('base64')}),
  };
}
// A DSSE signer (src/dsse.mjs signEnvelope) backed by a signer process started with --sign-pack-statements: the same interface as
// src/attestation-signer.mjs. publicKey is the key the caller pins; a refusal, or a signature that does not verify with it, fails.
export function statementSigner(client, publicKey) {
  const key = createPublicKey(publicKey);
  if (key.asymmetricKeyType !== 'ed25519') throw Error('The signer public key must be an Ed25519 key');
  return {keyid: keyFingerprint(key), publicKey: key, async sign(message) {
    const {httpStatus, body} = await client.signStatement(message);
    if (httpStatus !== 200 || body.status !== 'signed' || typeof body.sig !== 'string') {
      throw Error(`The signer at ${client.target} refused the statement (HTTP ${httpStatus}${body.reason ? ', ' + body.reason : ''})`
        + (typeof body.message === 'string' ? ': ' + body.message.slice(0, 300) : ''));
    }
    const sig = Buffer.from(body.sig, 'base64');
    if (sig.length !== 64 || !verify(null, message, key, sig)) {
      throw Error('The signer returned a signature that does not verify with the pinned signer public key');
    }
    return sig;
  }};
}
