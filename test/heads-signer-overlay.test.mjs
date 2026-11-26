// deploy/heads-signer-overlay.mjs: the heads signer never shares a volume with the vault data, its keys or its config, and the
// vault reaches it only on the socket (sidecar) or the TLS port the overlay wires up (separate Deployment).
import test from 'node:test';
import assert from 'node:assert/strict';
import {execFile} from 'node:child_process';
import {mkdtempSync, readFileSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {promisify} from 'node:util';
import {renderHeadsSignerOverlay} from '../deploy/heads-signer-overlay.mjs';

const base = JSON.parse(readFileSync(new URL('../deploy/kubernetes.json', import.meta.url), 'utf8'));
const deployment = (m, name) => m.items.find(i => i.kind === 'Deployment' && i.metadata.name === name);
// Every container (init containers too) with the volumes it mounts.
function mountsOf(d) {
  const pod = d.spec.template.spec, volumes = new Map(pod.volumes.map(v => [v.name, v]));
  return [...(pod.initContainers ?? []), ...pod.containers]
    .map(c => ({c, volumes: c.volumeMounts.map(m => ({...volumes.get(m.name), mountPath: m.mountPath}))}));
}
const claims = vs => vs.map(v => v.persistentVolumeClaim?.claimName).filter(Boolean).sort();
const secrets = vs => vs.map(v => v.secret?.secretName).filter(Boolean).sort();
const arg = (c, name) => c.command[c.command.indexOf(name) + 1];

test('sidecar overlay: the signer container shares only an in-memory socket directory with the vault', () => {
  const before = structuredClone(base), {manifest, receipt} = renderHeadsSignerOverlay({base, variant: 'sidecar'});
  assert.deepEqual(base, before, 'the base manifest is not modified');
  const vault = deployment(manifest, 'vault'), all = mountsOf(vault), pod = vault.spec.template.spec;
  assert.deepEqual([vault.spec.replicas, vault.spec.strategy.type, pod.containers.map(c => c.name), pod.initContainers.map(c => c.name)],
    [1, 'Recreate', ['vault', 'heads-signer'], ['heads-signer-init']]);
  const vaultMounts = all.find(x => x.c.name === 'vault').volumes;
  assert.deepEqual(claims(vaultMounts), ['vault-data', 'vault-transparency-pin']);
  assert.ok(!secrets(vaultMounts).includes('heads-signer-key'));
  for (const {c, volumes} of all.filter(x => x.c.name.startsWith('heads-signer'))) {
    assert.deepEqual(claims(volumes), ['heads-signer-state'], c.name);
    assert.deepEqual(secrets(volumes), ['heads-signer-key'], c.name);
    assert.deepEqual([c.securityContext.runAsUser, c.securityContext.readOnlyRootFilesystem, c.securityContext.allowPrivilegeEscalation], [1001, true, false]);
  }
  const signer = pod.containers[1], socketVolume = pod.volumes.find(v => v.name === 'heads-signer-socket');
  assert.deepEqual(socketVolume.emptyDir, {medium: 'Memory', sizeLimit: '1Mi'});
  assert.deepEqual(all.filter(x => x.c.volumeMounts.some(m => m.name === 'heads-signer-socket')).map(x => x.c.name), ['vault', 'heads-signer']);
  assert.deepEqual(signer.command.slice(0, 3), ['node', 'scripts/signer.mjs', 'serve']);
  assert.equal(arg(signer, '--socket'), receipt.transparencySigner.socket);
  const socketDir = pod.containers[0].volumeMounts.find(m => m.name === 'heads-signer-socket').mountPath;
  assert.ok(receipt.transparencySigner.socket.startsWith(socketDir + '/'));
  assert.deepEqual(pod.initContainers[0].command.slice(2), ['init', '--state-dir', '/signer-state', '--backend', 'file', '--key-file',
    '/signer-key/signer-key.pem', '--if-missing']);
  const env = Object.fromEntries(pod.containers[0].env.filter(e => 'value' in e).map(e => [e.name, e.value]));
  assert.deepEqual([env.TRANSPARENCY_CONFIG_FILE, env.TRANSPARENCY_PIN_FILE], ['/transparency/transparency.json', '/transparency-pin/pin.json']);
  assert.equal(pod.volumes.find(v => v.name === 'heads-signer-key').secret.defaultMode, 288);
  assert.deepEqual(receipt.persistentVolumeClaims, ['heads-signer-state', 'vault-transparency-pin']);
  assert.ok(manifest.items.some(i => i.kind === 'PersistentVolumeClaim' && i.metadata.name === 'heads-signer-state'));
});

test('deployment overlay: one signer replica off the vault node, TLS with a token, reachable only from the vault', () => {
  const {manifest, receipt} = renderHeadsSignerOverlay({base, variant: 'deployment'});
  const signer = deployment(manifest, 'heads-signer'), pod = signer.spec.template.spec, main = pod.containers[0];
  assert.deepEqual([signer.spec.replicas, signer.spec.strategy.type], [1, 'Recreate']);
  assert.deepEqual(pod.affinity.podAntiAffinity.requiredDuringSchedulingIgnoredDuringExecution[0],
    {labelSelector: {matchLabels: {'app.kubernetes.io/name': 'evidscope', 'app.kubernetes.io/component': 'vault'}}, topologyKey: 'kubernetes.io/hostname'});
  for (const {c, volumes} of mountsOf(signer)) {
    assert.deepEqual(claims(volumes), ['heads-signer-state'], c.name);
    assert.ok(secrets(volumes).every(s => s.startsWith('heads-signer-')), c.name);
  }
  assert.deepEqual([arg(main, '--host'), arg(main, '--port'), arg(main, '--tls-cert'), arg(main, '--token-file')],
    ['0.0.0.0', '8443', '/tls/tls.crt', '/heads-signer-token/token']);
  assert.equal(pod.automountServiceAccountToken, false);
  // Its own user and group: Secret files are readable by the pod's fsGroup.
  const ids = [pod.securityContext.runAsUser, pod.securityContext.fsGroup, main.securityContext.runAsGroup, pod.initContainers[0].securityContext.runAsGroup];
  assert.deepEqual(ids, [1001, 1001, 1001, 1001]);
  const vault = deployment(manifest, 'vault'), vaultMounts = mountsOf(vault)[0].volumes;
  assert.equal(vault.spec.template.spec.containers.length, 1);
  assert.deepEqual(secrets(vaultMounts).filter(s => s.startsWith('heads-signer')), ['heads-signer-ca', 'heads-signer-token']);
  assert.deepEqual(receipt.transparencySigner, {url: 'https://heads-signer.evidscope.svc:8443', tokenFile: '/heads-signer-token/token',
    caFile: '/heads-signer-ca/ca.crt', publicKeyFile: '/heads-signer-public/signer-public.pem'});
  const policy = name => manifest.items.find(i => i.kind === 'NetworkPolicy' && i.metadata.name === name).spec;
  assert.deepEqual(policy('heads-signer-from-vault').ingress, [{from: [{podSelector: {matchLabels: {'app.kubernetes.io/name': 'evidscope',
    'app.kubernetes.io/component': 'vault'}}}], ports: [{protocol: 'TCP', port: 8443}]}]);
  assert.equal(policy('vault-to-heads-signer').egress[0].ports[0].port, 8443);
  // The base default-deny still covers the signer: it gets no egress at all.
  assert.ok(!manifest.items.some(i => i.kind === 'NetworkPolicy' && i.spec.policyTypes.includes('Egress')
    && i.spec.podSelector.matchLabels?.['app.kubernetes.io/component'] === 'heads-signer'));
});

test('the overlay refuses a base it cannot extend safely, and the CLI writes only a new file', async t => {
  const withEnv = structuredClone(base);
  deployment(withEnv, 'vault').spec.template.spec.containers[0].env.push({name: 'TRANSPARENCY_CONFIG_FILE', value: '/x.json'});
  assert.throws(() => renderHeadsSignerOverlay({base: withEnv, variant: 'sidecar'}), /transparency_already_configured/);
  const scaled = structuredClone(base);
  deployment(scaled, 'vault').spec.replicas = 2;
  assert.throws(() => renderHeadsSignerOverlay({base: scaled, variant: 'deployment'}), /single_replica_recreate_vault_required/);
  assert.throws(() => renderHeadsSignerOverlay({base, variant: 'daemonset'}), /variant_must_be/);
  const twice = renderHeadsSignerOverlay({base, variant: 'deployment'}).manifest;
  assert.throws(() => renderHeadsSignerOverlay({base: twice, variant: 'deployment'}), /transparency_already_configured|overlay_already_present/);
  // A base whose vault pod already mounts the signer key elsewhere is refused by the separation check.
  const leaky = structuredClone(base), pod = deployment(leaky, 'vault').spec.template.spec;
  pod.volumes.push({name: 'extra', secret: {secretName: 'heads-signer-key'}});
  pod.containers[0].volumeMounts.push({name: 'extra', mountPath: '/extra'});
  assert.throws(() => renderHeadsSignerOverlay({base: leaky, variant: 'sidecar'}), /signer_key_mounted_outside_signer/);

  const dir = mkdtempSync(join(tmpdir(), 'evs-overlay-'));
  t.after(() => rmSync(dir, {recursive: true, force: true}));
  const run = args => promisify(execFile)(process.execPath, [resolve('deploy/heads-signer-overlay.mjs'), ...args]).then(r => ({code: 0, ...r}),
    error => ({code: error.code, stdout: error.stdout, stderr: error.stderr}));
  const out = join(dir, 'signer.json'), ok = await run(['--variant', 'sidecar', '--output', out]);
  assert.equal(ok.code, 0, ok.stderr);
  assert.equal(JSON.parse(ok.stdout).variant, 'sidecar');
  assert.deepEqual(JSON.parse(readFileSync(out, 'utf8')), renderHeadsSignerOverlay({base, variant: 'sidecar'}).manifest);
  writeFileSync(join(dir, 'taken.json'), '{}');
  const refused = await run(['--variant', 'sidecar', '--output', join(dir, 'taken.json')]);
  assert.deepEqual([refused.code, JSON.parse(refused.stderr).error], [1, 'new_output_file_required']);
});
