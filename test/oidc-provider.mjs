import { createServer } from 'node:http';
import { createServer as createTlsServer } from 'node:https';
import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';

/**
 * In-process synthetic OIDC provider. Never use outside tests.
 *
 * const provider = await startOidcProvider();
 * const callback = await provider.authorize(loginUrl, { claims: { nonce: 'wrong' } });
 * provider.controls.keyRotation += 1; // Subsequent JWKS and tokens use the new key.
 * provider.controls.endpointFailure = { token: 503 }; // Or 'token', true, or null.
 * await provider.close();
 *
 * controls.claims (alias idTokenClaims) and the direct claim fields in overrides
 * override signed ID token claims. An undefined claim removes it. Per-call
 * overrides are bound to that authorization only, including concurrent calls.
 */
export async function startOidcProvider({
  host = '::1',
  clientId = 'evidscope-test',
  clientSecret = randomBytes(24).toString('base64url'),
  redirectUris = null,
  tls = null,
} = {}) {
  const controls = {
    claims: {},
    badSignature: false,
    omitIdToken: false,
    endpointFailure: null,
    keyRotation: 0,
    metadata: {},
  };
  Object.defineProperty(controls, 'idTokenClaims', {
    enumerable: true,
    get() { return this.claims; },
    set(value) { this.claims = value; },
  });
  const counters = { discovery: 0, authorize: 0, token: 0, jwks: 0, tokenSuccess: 0, tokenRejected: 0 };
  const codes = new Map();
  const overridesByRequest = new Map();
  const wrongKey = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey;
  let generation;
  let signingKey;
  let publicJwk;
  let issuer;

  function currentKey() {
    if (signingKey && generation === controls.keyRotation) return;
    generation = controls.keyRotation;
    const pair = generateKeyPairSync('rsa', { modulusLength: 2048 });
    signingKey = pair.privateKey;
    publicJwk = { ...pair.publicKey.export({ format: 'jwk' }), kid: randomBytes(12).toString('base64url'), alg: 'RS256', use: 'sig' };
  }

  function respond(res, status, value) {
    res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
    res.end(JSON.stringify(value));
  }

  function endpointFailure(name) {
    const failure = controls.endpointFailure;
    if (failure === true || failure === name || failure === `/${name}`) return 503;
    const status = failure && typeof failure === 'object' ? failure[name] : null;
    return status === true ? 503 : Number.isInteger(status) && status >= 400 && status <= 599 ? status : null;
  }

  function one(params, name, required = true) {
    const values = params.getAll(name);
    if (values.length > 1 || (required && (values.length !== 1 || !values[0]))) throw new Error('invalid_request');
    return values[0];
  }

  function claimOverrides(value = {}) {
    const result = { ...(value.idTokenClaims ?? {}), ...(value.claims ?? {}) };
    for (const name of ['nonce', 'iss', 'aud', 'exp', 'iat', 'auth_time', 'acr', 'sub', 'azp']) {
      if (Object.hasOwn(value, name)) result[name] = value[name];
    }
    return result;
  }

  function encodeToken(claims, badSignature) {
    currentKey();
    const header = Buffer.from(JSON.stringify({ alg: 'RS256', kid: publicJwk.kid, typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify(claims)).toString('base64url');
    const input = `${header}.${payload}`;
    return `${input}.${sign('RSA-SHA256', Buffer.from(input), badSignature ? wrongKey : signingKey).toString('base64url')}`;
  }

  async function handle(req, res) {
    const url = new URL(req.url, issuer);
    const name = url.pathname === '/.well-known/openid-configuration' ? 'discovery' : url.pathname.slice(1);
    if (!['discovery', 'authorize', 'token', 'jwks'].includes(name)) return respond(res, 404, { error: 'not_found' });
    counters[name] += 1;
    const failure = endpointFailure(name);
    if (failure) return respond(res, failure, { error: 'temporarily_unavailable' });
    if ((name === 'token' ? 'POST' : 'GET') !== req.method) return respond(res, 405, { error: 'invalid_request' });

    if (name === 'discovery') {
      return respond(res, 200, {
        issuer,
        authorization_endpoint: `${issuer}/authorize`,
        token_endpoint: `${issuer}/token`,
        jwks_uri: `${issuer}/jwks`,
        response_types_supported: ['code'],
        response_modes_supported: ['query'],
        grant_types_supported: ['authorization_code'],
        subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: ['RS256'],
        token_endpoint_auth_methods_supported: ['client_secret_post'],
        code_challenge_methods_supported: ['S256'],
        authorization_response_iss_parameter_supported: true,
        scopes_supported: ['openid', 'profile'],
        claims_supported: ['sub', 'iss', 'aud', 'exp', 'iat', 'nonce', 'auth_time', 'acr'],
        ...controls.metadata,
      });
    }
    if (name === 'jwks') {
      currentKey();
      return respond(res, 200, { keys: [publicJwk] });
    }
    if (name === 'authorize') {
      const params = url.searchParams;
      let callback;
      let challenge;
      let state;
      let nonce;
      try {
        if (one(params, 'client_id') !== clientId || one(params, 'response_type') !== 'code') throw new Error('invalid_request');
        const redirect = one(params, 'redirect_uri');
        callback = new URL(redirect);
        if (!['http:', 'https:'].includes(callback.protocol) || callback.username || callback.password || callback.hash) throw new Error('invalid_request');
        if (redirectUris && !redirectUris.includes(redirect)) throw new Error('invalid_request');
        if (!one(params, 'scope').split(' ').includes('openid')) throw new Error('invalid_request');
        if (one(params, 'code_challenge_method') !== 'S256') throw new Error('invalid_request');
        challenge = one(params, 'code_challenge');
        if (!/^[A-Za-z0-9_-]{43}$/.test(challenge)) throw new Error('invalid_request');
        state = one(params, 'state', false);
        nonce = one(params, 'nonce', false);
      } catch {
        return respond(res, 400, { error: 'invalid_request' });
      }
      const requestKey = req.headers['x-evidscope-test-authorization'];
      const overrides = overridesByRequest.get(requestKey) ?? {};
      overridesByRequest.delete(requestKey);
      const code = randomBytes(32).toString('base64url');
      codes.set(code, { redirectUri: one(params, 'redirect_uri'), challenge, nonce, issuedAt: Math.floor(Date.now() / 1000), overrides });
      callback.searchParams.set('code', code);
      if (state !== undefined) callback.searchParams.set('state', state);
      callback.searchParams.set('iss', issuer);
      for (const [key, value] of Object.entries(overrides.authorizationResponse ?? {})) {
        if (value === undefined || value === null) callback.searchParams.delete(key);
        else callback.searchParams.set(key, String(value));
      }
      res.writeHead(302, { location: callback.href, 'cache-control': 'no-store' });
      return res.end();
    }

    function tokenError(status, error) {
      counters.tokenRejected += 1;
      return respond(res, status, { error });
    }
    if (!req.headers['content-type']?.startsWith('application/x-www-form-urlencoded') || req.headers.authorization) return tokenError(400, 'invalid_request');
    const chunks = [];
    let length = 0;
    for await (const chunk of req) {
      length += chunk.length;
      if (length > 16_384) return tokenError(413, 'invalid_request');
      chunks.push(chunk);
    }
    const params = new URLSearchParams(Buffer.concat(chunks).toString('utf8'));
    let code;
    let redirectUri;
    let verifier;
    try {
      if (one(params, 'client_id') !== clientId || one(params, 'client_secret') !== clientSecret) return tokenError(401, 'invalid_client');
      if (one(params, 'grant_type') !== 'authorization_code') return tokenError(400, 'unsupported_grant_type');
      code = one(params, 'code');
      redirectUri = one(params, 'redirect_uri');
      verifier = one(params, 'code_verifier');
    } catch {
      return tokenError(400, 'invalid_request');
    }
    const authorization = codes.get(code);
    codes.delete(code);
    if (!authorization || authorization.issuedAt + 60 <= Date.now() / 1000 || authorization.redirectUri !== redirectUri
      || !/^[A-Za-z0-9._~-]{43,128}$/.test(verifier)
      || createHash('sha256').update(verifier).digest('base64url') !== authorization.challenge) return tokenError(400, 'invalid_grant');
    const now = Math.floor(Date.now() / 1000);
    const claims = {
      iss: issuer, sub: 'alice', aud: clientId, exp: now + 300, iat: now,
      auth_time: authorization.issuedAt, acr: 'urn:evidscope:test:mfa',
      ...(authorization.nonce === undefined ? {} : { nonce: authorization.nonce }),
      ...claimOverrides(controls), ...claimOverrides(authorization.overrides),
    };
    const badSignature = authorization.overrides.badSignature ?? controls.badSignature;
    const omitIdToken = authorization.overrides.omitIdToken ?? controls.omitIdToken;
    const result = { token_type: 'Bearer', access_token: randomBytes(24).toString('base64url'), expires_in: 300 };
    if (!omitIdToken) result.id_token = encodeToken(claims, badSignature);
    counters.tokenSuccess += 1;
    return respond(res, 200, result);
  }

  currentKey();
  const handler = (req, res) => {
    handle(req, res).catch(() => {
      if (!res.headersSent) respond(res, 500, { error: 'server_error' });
      else res.end();
    });
  };
  const server = tls ? createTlsServer(tls, handler) : createServer(handler);
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, host, resolve);
  });
  const address = server.address();
  issuer = `${tls ? 'https' : 'http'}://${host.includes(':') ? `[${host}]` : host}:${address.port}`;

  return {
    issuer, clientId, clientSecret, controls, counters,
    async authorize(url, overrides = {}) {
      const authorizationUrl = new URL(url);
      if (authorizationUrl.origin !== issuer || authorizationUrl.pathname !== '/authorize') throw new Error('unexpected_authorization_endpoint');
      const key = randomBytes(24).toString('base64url');
      overridesByRequest.set(key, structuredClone(overrides));
      try {
        const response = await fetch(authorizationUrl, { redirect: 'manual', headers: { 'x-evidscope-test-authorization': key } });
        const location = response.headers.get('location');
        if (response.status !== 302 || !location) throw new Error(`authorization_failed_${response.status}`);
        return new URL(location);
      } finally {
        overridesByRequest.delete(key);
      }
    },
    async close() {
      codes.clear();
      overridesByRequest.clear();
      await new Promise((resolve, reject) => {
        server.close(error => error ? reject(error) : resolve());
        server.closeAllConnections();
      });
    },
  };
}
