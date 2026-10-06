// Minimal ssh-agent (draft-miller-ssh-agent) serving one Ed25519 key from a 32-byte seed, so tests can run litewitness
// without OpenSSH. Resolves with the OpenSSH SHA256 fingerprint that litewitness expects in -key.
//   node test/support/ssh-agent.mjs <socket path (<=107 bytes)> <seed hex>
import net from 'node:net';
import {createHash, sign} from 'node:crypto';
import {rmSync} from 'node:fs';
import {resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {ed25519PrivateFromSeed, ed25519RawPublic} from '../../src/tlog.mjs';

const FAILURE = 5, REQUEST_IDENTITIES = 11, IDENTITIES_ANSWER = 12, SIGN_REQUEST = 13, SIGN_RESPONSE = 14;
const str = b => { const l = Buffer.alloc(4); l.writeUInt32BE(b.length); return Buffer.concat([l, b]); };
const frame = (type, body = Buffer.alloc(0)) => str(Buffer.concat([Buffer.from([type]), body]));

export function startSshAgent(socketPath, seedHex) {
  if (Buffer.byteLength(socketPath) > 107) throw Error('ssh-agent socket path exceeds 107 bytes');
  const priv = ed25519PrivateFromSeed(Buffer.from(seedHex, 'hex')), pub = ed25519RawPublic(priv);
  const blob = Buffer.concat([str(Buffer.from('ssh-ed25519')), str(pub)]);
  const handle = msg => {
    if (msg[0] === REQUEST_IDENTITIES) {
      const n = Buffer.alloc(4);
      n.writeUInt32BE(1);
      return frame(IDENTITIES_ANSWER, Buffer.concat([n, str(blob), str(Buffer.from('evidscope-test-witness'))]));
    }
    if (msg[0] === SIGN_REQUEST) {
      let o = 1;
      const kl = msg.readUInt32BE(o), kb = msg.subarray(o + 4, o + 4 + kl);
      o += 4 + kl;
      const dl = msg.readUInt32BE(o), data = msg.subarray(o + 4, o + 4 + dl);
      if (!kb.equals(blob)) return frame(FAILURE);
      return frame(SIGN_RESPONSE, str(Buffer.concat([str(Buffer.from('ssh-ed25519')), str(sign(null, data, priv))])));
    }
    return frame(FAILURE);
  };
  rmSync(socketPath, {force: true});
  const sockets = new Set();
  const server = net.createServer(c => {
    let buf = Buffer.alloc(0);
    sockets.add(c);
    c.on('close', () => sockets.delete(c));
    c.on('error', () => {});
    c.on('data', d => {
      buf = Buffer.concat([buf, d]);
      while (buf.length >= 4) {
        const len = buf.readUInt32BE(0);
        if (buf.length < 4 + len) break;
        const m = buf.subarray(4, 4 + len);
        buf = buf.subarray(4 + len);
        c.write(handle(m));
      }
    });
  });
  const fingerprint = 'SHA256:' + createHash('sha256').update(blob).digest('base64').replace(/=+$/, '');
  return new Promise((done, fail) => {
    server.once('error', fail);
    // litewitness keeps its agent connection open, so close() destroys live connections instead of waiting for them.
    const close = () => new Promise(r => { server.close(() => { rmSync(socketPath, {force: true}); r(); }); for (const c of sockets) c.destroy(); });
    server.listen(socketPath, () => done({fingerprint, close}));
  });
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const [sock, seed] = process.argv.slice(2);
  startSshAgent(sock, seed).then(a => console.log(a.fingerprint), error => { console.error(error.message); process.exitCode = 1; });
}
