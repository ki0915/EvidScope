// Spec-faithful C2SP tlog-witness (add-checkpoint only) for local development and tests. Production deployments
// should use litewitness or another independently operated witness; this one shares the operator's trust boundary.
//   node scripts/witness.mjs init --dir DIR --name NAME      create key + state, print the witness vkey
//   node scripts/witness.mjs vkey --dir DIR
//   node scripts/witness.mjs add-log --dir DIR --origin ORIGIN --key LOG_VKEY      (again with another key: the origin accepts both)
//   node scripts/witness.mjs del-key --dir DIR --origin ORIGIN --key LOG_VKEY      (key rotation, as litewitness witnessctl del-key)
//   node scripts/witness.mjs list-logs --dir DIR
//   node scripts/witness.mjs serve --dir DIR [--listen 127.0.0.1:0]
import http from 'node:http';
import {createPrivateKey, generateKeyPairSync} from 'node:crypto';
import {existsSync, mkdirSync, readFileSync, writeFileSync} from 'node:fs';
import {join, resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {parseArgs} from 'node:util';
import {DatabaseSync} from 'node:sqlite';
import * as T from '../src/tlog.mjs';

const MAX_BODY = 16 * 1024;
const text = (status, message) => ({status, type: 'text/plain; charset=utf-8', body: message.endsWith('\n') ? message : message + '\n'});

export function createWitness({dir, name, now = () => Date.now()}) {
  mkdirSync(dir, {recursive: true, mode: 0o700});
  const keyFile = join(dir, 'witness-key.pem'), metaFile = join(dir, 'witness.json');
  if (!existsSync(keyFile)) {
    if (!name || !T.isValidKeyName(name)) throw Error('A valid witness name is required on first use');
    const {privateKey} = generateKeyPairSync('ed25519');
    writeFileSync(keyFile, privateKey.export({format: 'pem', type: 'pkcs8'}), {mode: 0o600, flag: 'wx'});
    writeFileSync(metaFile, JSON.stringify({format: 'evidscope-dev-witness-v1', name}) + '\n', {flag: 'wx'});
  }
  const meta = JSON.parse(readFileSync(metaFile, 'utf8'));
  if (name && name !== meta.name) throw Error('Witness directory belongs to another witness name');
  const privateKey = createPrivateKey(readFileSync(keyFile)), signer = {name: meta.name, privateKey, pub: T.ed25519RawPublic(privateKey)};
  const vkey = T.vkeyString(meta.name, T.SIG_COSIG_ED25519, signer.pub);
  const db = new DatabaseSync(join(dir, 'witness.db'));
  db.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
    CREATE TABLE IF NOT EXISTS logs(origin TEXT PRIMARY KEY, size INTEGER NOT NULL, root TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS log_keys(origin TEXT NOT NULL REFERENCES logs(origin), vkey TEXT NOT NULL, PRIMARY KEY(origin, vkey));`);
  let available = true;

  function addLog(origin, logVkey) {
    if (!origin || origin.includes('\n')) throw Error('invalid origin');
    if (logVkey !== undefined) T.noteVerifier(logVkey);
    db.prepare('INSERT OR IGNORE INTO logs VALUES(?,0,?)').run(origin, T.b64(T.EMPTY_ROOT));
    if (logVkey !== undefined) db.prepare('INSERT OR IGNORE INTO log_keys VALUES(?,?)').run(origin, logVkey);
  }
  // The origin keeps its size and root; checkpoints signed by the removed key are no longer accepted.
  const removeLogKey = (origin, logVkey) => db.prepare('DELETE FROM log_keys WHERE origin=? AND vkey=?').run(origin, logVkey).changes > 0;
  // Order follows c2sp.org/tlog-witness: parse, origin, signatures, checkpoint, old/size, conflict, proof, persist, cosign.
  function addCheckpoint(input) {
    const body = Buffer.isBuffer(input) ? input.toString('utf8') : String(input);
    if (Buffer.byteLength(body) > MAX_BODY) return text(400, 'invalid input: request too large');
    let req;
    try { req = T.parseAddCheckpointBody(body); } catch (error) { return text(400, 'invalid input: ' + error.message); }
    const origin = req.note.slice(0, Math.max(0, req.note.indexOf('\n')));
    const log = db.prepare('SELECT size,root FROM logs WHERE origin=?').get(origin);
    const keys = log ? db.prepare('SELECT vkey FROM log_keys WHERE origin=?').all(origin).map(r => T.noteVerifier(r.vkey)) : [];
    if (!log || !keys.length) return text(404, 'unknown log');
    let opened;
    try { opened = T.openNote(req.note, keys); } catch (error) {
      return text(/^malformed/.test(error.message) ? 400 : 403, 'invalid signature: ' + error.message);
    }
    let c;
    try { c = T.parseCheckpoint(opened.text); } catch (error) {
      if (/empty-tree root/.test(error.message)) return text(422, 'size 0 checkpoint must carry the empty-tree root');
      return text(400, 'invalid checkpoint: ' + error.message);
    }
    if (c.origin !== origin) return text(400, 'invalid checkpoint origin');
    if (req.old > c.size) return text(400, 'invalid input: old size exceeds checkpoint size');
    if (req.old !== log.size) return {status: 409, type: 'text/x.tlog.size', body: `${log.size}\n`};
    if (req.old === 0 && req.proof.length) return text(422, 'old 0 requires an empty consistency proof');
    const known = T.fromB64(log.root);
    if (req.old === c.size) {
      if (req.proof.length || !known.equals(c.root)) return text(422, 'checkpoint conflicts with the latest cosigned checkpoint');
    } else if (req.old > 0 && !T.verifyConsistency(req.old, c.size, known, c.root, req.proof)) return text(422, 'bad consistency proof');
    const changed = db.prepare('UPDATE logs SET size=?,root=? WHERE origin=? AND size=?').run(c.size, T.b64(c.root), origin, req.old).changes;
    if (!changed) return {status: 409, type: 'text/x.tlog.size', body: `${db.prepare('SELECT size FROM logs WHERE origin=?').get(origin).size}\n`};
    return {status: 200, type: 'text/plain; charset=utf-8', body: T.cosign(opened.text, signer, Math.floor(now() / 1000))};
  }
  function listen({port = 0, host = '127.0.0.1'} = {}) {
    if (!['127.0.0.1', '::1', 'localhost'].includes(host)) throw Error('The development witness listens on loopback only');
    const server = http.createServer(async (req, res) => {
      try {
        if (!available) return void res.writeHead(503, {'content-type': 'text/plain'}).end('temporarily unavailable\n');
        if (req.method !== 'POST' || new URL(req.url, 'http://witness').pathname !== '/add-checkpoint') return void res.writeHead(404).end('not found\n');
        const parts = [];
        let size = 0;
        for await (const chunk of req) { size += chunk.length; if (size > MAX_BODY) break; parts.push(chunk); }
        const r = size > MAX_BODY ? text(400, 'invalid input: request too large') : addCheckpoint(Buffer.concat(parts));
        res.writeHead(r.status, {'content-type': r.type}).end(r.body);
      } catch { if (!res.headersSent) res.writeHead(500).end('internal error\n'); }
    });
    server.keepAliveTimeout = 1000;
    return new Promise((done, fail) => {
      server.once('error', fail);
      server.listen(port, host, () => {
        const a = server.address(), url = `http://${a.family === 'IPv6' ? `[${a.address}]` : a.address}:${a.port}`;
        done({server, url, close: () => new Promise(r => { server.closeAllConnections?.(); server.close(() => r()); })});
      });
    });
  }
  return {
    name: meta.name, vkey, addLog, removeLogKey, addCheckpoint, listen,
    logs: () => db.prepare('SELECT origin,size,root,(SELECT COUNT(*) FROM log_keys k WHERE k.origin=logs.origin) keys FROM logs ORDER BY origin').all(),
    setAvailable(value) { available = !!value; },
    close() { db.close(); },
  };
}

async function main(argv) {
  const [command, ...rest] = argv;
  const {values} = parseArgs({args: rest, options: {dir: {type: 'string'}, name: {type: 'string'}, origin: {type: 'string'}, key: {type: 'string'},
    listen: {type: 'string', default: '127.0.0.1:0'}}});
  if (!values.dir || !['init', 'vkey', 'add-log', 'del-key', 'list-logs', 'serve'].includes(command)) {
    throw Error('Usage: node scripts/witness.mjs init|vkey|add-log|del-key|list-logs|serve --dir DIR [--name NAME] [--origin ORIGIN --key LOG_VKEY]'
      + ' [--listen HOST:PORT]');
  }
  const w = createWitness({dir: resolve(values.dir), name: values.name});
  if (command === 'init' || command === 'vkey') { console.log(w.vkey); w.close(); return; }
  if (command === 'add-log') {
    if (!values.origin || !values.key) throw Error('add-log needs --origin and --key');
    w.addLog(values.origin, values.key);
    console.log(JSON.stringify({origin: values.origin, key: values.key}));
    w.close();
    return;
  }
  if (command === 'del-key') {
    if (!values.origin || !values.key) throw Error('del-key needs --origin and --key');
    const removed = w.removeLogKey(values.origin, values.key);
    console.log(JSON.stringify({origin: values.origin, key: values.key, removed}));
    w.close();
    return;
  }
  if (command === 'list-logs') { for (const l of w.logs()) console.log(JSON.stringify(l)); w.close(); return; }
  const i = values.listen.lastIndexOf(':'), host = values.listen.slice(0, i).replace(/^\[|\]$/g, ''), port = Number(values.listen.slice(i + 1));
  const s = await w.listen({host, port});
  console.log(JSON.stringify({url: s.url, vkey: w.vkey}));
  const stop = () => s.close().then(() => { w.close(); process.exit(0); });
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main(process.argv.slice(2)).catch(error => { console.error(error.message); process.exitCode = 1; });
}
