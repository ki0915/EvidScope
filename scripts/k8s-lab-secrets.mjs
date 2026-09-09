// Fresh synthetic credentials for a private lab; never installs Kubernetes Secrets.
import { initialize } from './init.mjs';
import { spawnSync } from 'node:child_process';
import { existsSync, lstatSync, realpathSync, mkdirSync, writeFileSync, readFileSync, chmodSync, readdirSync } from 'node:fs';
import { resolve, join, dirname, relative, basename } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { X509Certificate, createPrivateKey, createPublicKey, createHash } from 'node:crypto';

export function createLabSecrets({ out, openssl = process.env.EVIDSCOPE_TEST_OPENSSL || (process.platform === 'win32' ? 'C:\\Program Files\\Git\\usr\\bin\\openssl.exe' : 'openssl') } = {}) {
  const workspace = realpathSync(resolve(dirname(fileURLToPath(import.meta.url)), '..'));
  const localRoot = join(workspace, '.local');
  if (typeof out !== 'string' || !out.trim()) throw Error('Explicit --out is required');
  const destination = resolve(out);
  // Restrict to a single fresh directory under the actual workspace .local.
  if (relative(localRoot, dirname(destination)) !== '' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/.test(basename(destination))) throw Error('--out must be a new direct child directory of workspace .local');
  if (existsSync(localRoot) && (lstatSync(localRoot).isSymbolicLink() || !lstatSync(localRoot).isDirectory() || realpathSync(localRoot) !== localRoot)) throw Error('Workspace .local must be a real directory, not a link');
  if (existsSync(destination)) throw Error('Output already exists; refusing to overwrite or reuse it');
  const execute = (args, phase) => {
    const result = spawnSync(openssl, args, { encoding: 'utf8', timeout: 20000, windowsHide: true, maxBuffer: 1024 * 1024 });
    if (result.error || result.status !== 0) throw Error(`OpenSSL failed during ${phase}; generated material is not ready and will not be overwritten`);
    return result.stdout.trim();
  };
  const opensslVersion = execute(['version'], 'availability check');
  if (!existsSync(localRoot)) mkdirSync(localRoot, { mode: 0o700 });
  mkdirSync(destination, { mode: 0o700 }); // Atomic refusal if another process won creation.
  const output = (name, text) => writeFileSync(join(destination, name), text, { mode: 0o600, flag: 'wx' });
  const config = initialize(destination);
  const collector = config.principals.filter(p => p.tenant === 'alpha' && p.role === 'source');
  const auditors = config.principals.filter(p => p.id === 'alpha-auditor' && p.role === 'auditor');
  const worker = config.principals.find(p => p.id === 'analysis-worker' && p.role === 'worker');
  if (collector.length !== 5 || auditors.length !== 1 || !worker) throw Error('Synthetic principal separation failed');
  output('collector-config.json', JSON.stringify({ profile: 'synthetic-k8s-lab-collector', principals: collector }, null, 2) + '\n');
  output('auditor-config.json', JSON.stringify({ profile: 'synthetic-k8s-lab-auditor', principals: auditors }, null, 2) + '\n');
  output('worker-token.txt', worker.token);
  const opensslConfig = join(destination, 'openssl.cnf');
  output('openssl.cnf', '[req]\ndistinguished_name=dn\nx509_extensions=root_ca\n[dn]\n[root_ca]\nbasicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n');
  const caPath = join(destination, 'ca.crt'), caKeyPath = join(destination, 'ca.key');
  execute(['req', '-config', opensslConfig, '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-days', '7', '-subj', '/CN=EvidScope Synthetic Kubernetes Lab CA', '-keyout', caKeyPath, '-out', caPath], 'lab CA generation');
  chmodSync(caKeyPath, 0o600);
  const ca = new X509Certificate(readFileSync(caPath));
  if (!ca.ca || !ca.checkPrivateKey(createPrivateKey(readFileSync(caKeyPath))) || !ca.verify(ca.publicKey)) throw Error('CA certificate validation failed');
  const certificates = [], keyFingerprints = new Set();
  for (const [index, component] of ['vault', 'ingress', 'audit', 'worker'].entries()) {
    const key = join(destination, `${component}.key`), csr = join(destination, `${component}.csr`), cert = join(destination, `${component}.crt`);
    const hosts = ['localhost', component, `${component}.evidscope`, `${component}.evidscope.svc`, `${component}.evidscope.svc.cluster.local`];
    execute(['req', '-config', opensslConfig, '-new', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-subj', `/CN=${component}.evidscope.svc`, '-keyout', key, '-out', csr], `${component} key generation`);
    chmodSync(key, 0o600);
    output(`${component}.ext`, `basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=${hosts.map(h => `DNS:${h}`).join(',')},IP:127.0.0.1,IP:::1\n`);
    execute(['x509', '-req', '-in', csr, '-CA', caPath, '-CAkey', caKeyPath, '-set_serial', String(100 + index), '-days', '7', '-sha256', '-extfile', join(destination, `${component}.ext`), '-out', cert], `${component} certificate generation`);
    for (const host of ['localhost', `${component}.evidscope.svc`]) execute(['verify', '-CAfile', caPath, '-purpose', 'sslserver', '-verify_hostname', host, cert], `${component} CA and hostname verification`);
    execute(['verify', '-CAfile', caPath, '-purpose', 'sslserver', '-verify_ip', '127.0.0.1', cert], `${component} loopback IP verification`);
    const x509 = new X509Certificate(readFileSync(cert));
    if (x509.ca || !x509.verify(ca.publicKey) || !x509.checkPrivateKey(createPrivateKey(readFileSync(key))) || !x509.checkIP('::1')) throw Error(`${component} certificate/key validation failed`);
    if (hosts.some(host => !x509.checkHost(host))) throw Error(`${component} expected SAN validation failed`);
    if (x509.checkHost('wrong-host.invalid')) throw Error(`${component} certificate unexpectedly permits a wrong hostname`);
    keyFingerprints.add(createHash('sha256').update(x509.publicKey.export({ type: 'spki', format: 'der' })).digest('hex'));
    certificates.push({ component, file: `${component}.crt`, verifiedHosts: hosts, verifiedIPs: ['127.0.0.1', '::1'], fingerprint256: x509.fingerprint256, validFrom: x509.validFrom, validTo: x509.validTo });
  }
  if (keyFingerprints.size !== 4) throw Error('TLS keys must be independent');
  const signing = createPrivateKey(readFileSync(join(destination, 'signing-private.pem')));
  const expectedAnchor = createPublicKey(signing).export({ type: 'spki', format: 'der' });
  const actualAnchor = createPublicKey(readFileSync(join(destination, 'trust-anchor.pem'))).export({ type: 'spki', format: 'der' });
  if (signing.asymmetricKeyType !== 'ed25519' || !expectedAnchor.equals(actualAnchor)) throw Error('Signing key/trust anchor validation failed');
  const report = { ready: true, profile: 'synthetic-private-kubernetes-lab-only', outputDirectory: destination, createdAt: new Date().toISOString(), opensslVersion,
    principalCounts: { vault: config.principals.length, collector: collector.length, auditor: auditors.length, worker: 1 },
    credentialSeparation: { collector: 'alpha source principals only', auditor: 'alpha-auditor only', worker: 'worker token only; no trailing newline' },
    independentTlsKeyCount: keyFingerprints.size, caFingerprint256: ca.fingerprint256, certificates, files: readdirSync(destination).sort(),
    clusterChanged: false, productionReady: false,
    limitations: ['Synthetic credentials only; no production identity or organization PKI.', 'Keep ca.key and signing-private.pem out of collector, auditor and worker Pods.', 'Private file mode 0600 and directory mode 0700 are requested; Windows inherited ACLs require operator review.', 'This preparation verifies keys, certificate chain and hostnames, not live Kubernetes TLS or network isolation.'] };
  output('metadata.json', JSON.stringify(report, null, 2) + '\n');
  return report;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const args = process.argv.slice(2);
    if (args.length !== 2 || args[0] !== '--out') throw Error('Usage: node scripts/k8s-lab-secrets.mjs --out .local/NEW-LAB-DIRECTORY');
    console.log(JSON.stringify(createLabSecrets({ out: args[1] })));
  } catch (error) { console.error(JSON.stringify({ ready: false, error: error.message })); process.exitCode = 1; }
}
