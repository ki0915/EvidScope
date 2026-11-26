// Key backends of the heads signer (src/signer.mjs). Every backend exposes {kind, publicKey, sign(message) -> 64-byte pure
// Ed25519 signature} and must pass selfTest before the signer serves:
//   file       PKCS#8 PEM private key on the signer volume
//   ssh-agent  an ssh-ed25519 key in an ssh agent (OpenSSH agent with PKCS#11, sigsum-agent, YubiKey, OS keystores), chosen
//              by its SHA256: fingerprint, over SSH_AUTH_SOCK or the Windows OpenSSH named pipe (agent protocol, RFC 9987)
//   command    an external program (a cloud KMS CLI): execFile with an argv array, message on stdin, signature on stdout
import {execFile} from 'node:child_process';
import {createHash, createPrivateKey, createPublicKey, randomBytes, sign as edSign, verify as edVerify} from 'node:crypto';
import {readFileSync, statSync} from 'node:fs';
import net from 'node:net';

export const BACKEND_KINDS = ['file', 'ssh-agent', 'command'];
export const WINDOWS_AGENT_PIPE = '\\\\.\\pipe\\openssh-ssh-agent';
const isEd25519 = key => key?.asymmetricKeyType === 'ed25519';
export function readEd25519PublicKey(file) {
  const key = createPublicKey(readFileSync(file));
  if (!isEd25519(key)) throw Error(`${file} is not an Ed25519 public key`);
  return key;
}
// As OpenSSH does on POSIX: a key file owned by the signer's user may not be readable by group or others. A file owned by
// another user is read through its group or other bits, as a Kubernetes Secret is (root, group fsGroup, mode 0440 whatever
// defaultMode says): mount that volume into the signer container only.
function privateFile(file) {
  const st = statSync(file);
  if (!st.isFile() || st.size > 64 * 1024) throw Error(`Signer key file ${file} must be a regular file of at most 64 KiB`);
  if (process.platform !== 'win32' && st.uid === process.getuid() && (st.mode & 0o077)) {
    throw Error(`Signer key file ${file} is readable by other users (chmod 600)`);
  }
  return readFileSync(file);
}

export function fileBackend({keyFile}) {
  const privateKey = createPrivateKey(privateFile(keyFile));
  if (!isEd25519(privateKey)) throw Error(`Signer key file ${keyFile} is not an Ed25519 private key`);
  return {kind: 'file', publicKey: createPublicKey(privateKey), describe: {keyFile}, async sign(message) { return edSign(null, message, privateKey); }};
}

// ---------- ssh-agent ----------
const FAILURE = 5, REQUEST_IDENTITIES = 11, IDENTITIES_ANSWER = 12, SIGN_REQUEST = 13, SIGN_RESPONSE = 14, MAX_AGENT_MESSAGE = 256 * 1024;
const sshString = buf => { const l = Buffer.alloc(4); l.writeUInt32BE(buf.length); return Buffer.concat([l, buf]); };
function reader(buf) {
  let o = 0;
  const need = n => { if (o + n > buf.length) throw Error('ssh-agent: truncated message'); };
  return {
    u8() { need(1); return buf[o++]; },
    u32() { need(4); const v = buf.readUInt32BE(o); o += 4; return v; },
    string() { const n = this.u32(); need(n); const v = buf.subarray(o, o + n); o += n; return v; },
    done: () => o === buf.length,
  };
}
export const sshFingerprint = blob => 'SHA256:' + createHash('sha256').update(blob).digest('base64').replace(/=+$/, '');
// The 32-byte key of an ssh-ed25519 public key blob; any other key type (sk-ssh-ed25519@openssh.com included, which signs a
// FIDO structure rather than the data) is refused.
export function sshEd25519Key(blob) {
  const r = reader(blob), type = r.string().toString('latin1'), pub = r.string();
  if (type !== 'ssh-ed25519' || pub.length !== 32 || !r.done()) throw Error(`ssh-agent key type ${type} is not ssh-ed25519`);
  return pub;
}
// One request per connection: an agent restart or a reconnecting hardware token never leaves a half-read stream behind.
function agentRequest(socket, payload, timeoutMs) {
  return new Promise((resolve, reject) => {
    const c = net.createConnection(socket);
    let buf = Buffer.alloc(0), settled = false;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      c.destroy();
      if (error) reject(error); else resolve(value);
    };
    const timer = setTimeout(() => finish(Error(`ssh-agent did not answer within ${timeoutMs} ms`)), timeoutMs);
    c.on('error', error => finish(Error(`ssh-agent at ${socket}: ${error.code || error.message}`)));
    c.on('connect', () => c.write(sshString(payload)));
    c.on('data', d => {
      buf = Buffer.concat([buf, d]);
      if (buf.length >= 4 && buf.readUInt32BE(0) > MAX_AGENT_MESSAGE) return finish(Error('ssh-agent answer is too large'));
      if (buf.length >= 4 && buf.length >= 4 + buf.readUInt32BE(0)) finish(null, buf.subarray(4, 4 + buf.readUInt32BE(0)));
    });
    c.on('end', () => finish(Error('ssh-agent closed the connection')));
  });
}
export async function sshAgentBackend({socket = process.env.SSH_AUTH_SOCK || (process.platform === 'win32' ? WINDOWS_AGENT_PIPE : undefined),
  fingerprint, timeoutMs = 10000}) {
  if (!socket) throw Error('ssh-agent backend needs --agent-socket or SSH_AUTH_SOCK');
  if (typeof fingerprint !== 'string' || !/^SHA256:[A-Za-z0-9+/]{43}$/.test(fingerprint)) throw Error('ssh-agent backend needs --fingerprint SHA256:...');
  const answer = reader(await agentRequest(socket, Buffer.from([REQUEST_IDENTITIES]), timeoutMs));
  if (answer.u8() !== IDENTITIES_ANSWER) throw Error('ssh-agent refused to list its keys');
  let blob = null;
  for (let n = answer.u32(); n > 0; n--) {
    const candidate = answer.string();
    answer.string();
    if (sshFingerprint(candidate) === fingerprint) blob = candidate;
  }
  if (!blob) throw Error(`ssh-agent holds no key with fingerprint ${fingerprint}`);
  const pub = sshEd25519Key(blob), publicKey = createPublicKey({key: {kty: 'OKP', crv: 'Ed25519', x: pub.toString('base64url')}, format: 'jwk'});
  return {
    kind: 'ssh-agent', publicKey, describe: {socket, fingerprint},
    async sign(message) {
      const flags = Buffer.alloc(4);
      const r = reader(await agentRequest(socket, Buffer.concat([Buffer.from([SIGN_REQUEST]), sshString(blob), sshString(message), flags]), timeoutMs));
      const type = r.u8();
      if (type === FAILURE) throw Error('ssh-agent refused to sign (key removed, locked or confirmation declined)');
      if (type !== SIGN_RESPONSE) throw Error(`ssh-agent answered message type ${type} to a sign request`);
      const sig = reader(r.string()), algorithm = sig.string().toString('latin1'), bytes = sig.string();
      if (algorithm !== 'ssh-ed25519' || bytes.length !== 64 || !sig.done()) throw Error(`ssh-agent returned a ${algorithm} signature, not ssh-ed25519`);
      return Buffer.from(bytes);
    },
  };
}

// ---------- command ----------
// The program gets the exact message on stdin and prints the 64-byte signature, raw or base64 (output 'auto' tells them apart
// by length). No shell is involved; arguments are passed as given. A non-zero exit, a timeout or anything else fails.
export function commandBackend({argv, publicKeyFile, timeoutMs = 15000, output = 'auto', env}) {
  if (!Array.isArray(argv) || !argv.length || !argv.every(a => typeof a === 'string' && a.length)) throw Error('command backend needs an argv array');
  if (!['auto', 'raw', 'base64'].includes(output)) throw Error('command backend output must be auto, raw or base64');
  if (!publicKeyFile) throw Error('command backend needs --public-key: the command only signs');
  const publicKey = readEd25519PublicKey(publicKeyFile);
  const parse = stdout => {
    if (output !== 'base64' && stdout.length === 64) return stdout;
    if (output === 'raw') throw Error(`signing command printed ${stdout.length} bytes, not a raw 64-byte signature`);
    const text = stdout.toString('latin1').trim();
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(text)) throw Error('signing command printed neither a raw nor a base64 signature');
    const sig = Buffer.from(text, 'base64');
    if (sig.length !== 64) throw Error(`signing command printed a ${sig.length}-byte signature, not 64 bytes`);
    return sig;
  };
  return {
    kind: 'command', publicKey, describe: {argv: [argv[0], `(${argv.length - 1} arguments)`]},
    sign(message) {
      return new Promise((resolve, reject) => {
        const child = execFile(argv[0], argv.slice(1), {encoding: 'buffer', timeout: timeoutMs, killSignal: 'SIGKILL', maxBuffer: 64 * 1024, windowsHide: true,
          shell: false, ...(env ? {env} : {})}, (error, stdout, stderr) => {
          if (error) {
            const why = error.killed ? `timed out after ${timeoutMs} ms` : error.code ?? error.message;
            return reject(Error(`signing command failed (${why}): ${String(stderr).trim().slice(0, 300)}`));
          }
          try { resolve(parse(stdout)); } catch (e) { reject(e); }
        });
        child.stdin.on('error', () => {});
        child.stdin.end(message);
      });
    },
  };
}

export async function createBackend(spec) {
  if (spec?.kind === 'file') return fileBackend(spec);
  if (spec?.kind === 'ssh-agent') return sshAgentBackend(spec);
  if (spec?.kind === 'command') return commandBackend(spec);
  throw Error(`Unknown signer backend ${spec?.kind}; use one of ${BACKEND_KINDS.join(', ')}`);
}
// Conformance: a fixed vector and a fresh challenge must verify as pure Ed25519 under the configured public key. This catches a
// wrong key, a prehash variant (Ed25519ph, AWS ED25519_PH_SHA_512) and a program that replays a canned signature. Neither
// message can parse as a checkpoint.
export const SELF_TEST_VECTOR = Buffer.from('evidscope-signer-self-test-v1\nfixed vector\n', 'utf8');
export async function selfTest(backend) {
  if (!isEd25519(backend.publicKey)) throw Error('Signer backend public key is not Ed25519');
  for (const message of [SELF_TEST_VECTOR, Buffer.from(`evidscope-signer-self-test-v1\n${randomBytes(16).toString('hex')}\n`, 'utf8')]) {
    let signature;
    try { signature = await backend.sign(message); } catch (error) { throw Error(`Signer backend ${backend.kind} self-test failed: ${error.message}`); }
    if (!Buffer.isBuffer(signature) || signature.length !== 64 || !edVerify(null, message, backend.publicKey, signature)) {
      throw Error(`Signer backend ${backend.kind} self-test failed: its signature does not verify as pure Ed25519 under the configured public key `
        + '(wrong key, or a prehash variant such as Ed25519ph)');
    }
  }
  return true;
}
