// Static overlay over deploy/kubernetes.json (docs/signer.md): turns on the transparency log with a heads signer that never mounts
// the vault data volume, the vault signing key or the data key. Not deployed or checked against a cluster.
//   node deploy/heads-signer-overlay.mjs --variant sidecar|deployment --output NEW_FILE.json [--base deploy/kubernetes.json]
// sidecar:    a heads-signer container in the vault pod with its own state PVC and key Secret. The vault reaches it on a Unix socket
//             in an in-memory emptyDir that only these two containers mount. Protects against a compromised vault container,
//             not against the node (the kubelet holds both pods' Secrets).
// deployment: a heads-signer Deployment (one replica, Recreate) that may not share a node with the vault, reached over TLS with a
//             bearer token; NetworkPolicies let only the vault pod reach it on 8443.
// The receipt names the Secrets, ConfigMap and the `signer` fragment of the vault's transparency.json the operator provides.
import {readFileSync, writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {parseArgs} from 'node:util';
import {canonical, digest} from '../src/crypto.mjs';

const NS = 'evidscope', COMPONENT = 'heads-signer', PORT = 8443, SIGNER_UID = 1001;
const labels = component => ({'app.kubernetes.io/name': NS, 'app.kubernetes.io/component': component});
const meta = name => ({name, namespace: NS});
const fail = code => { throw Object.assign(Error(code), {code}); };
export const VARIANTS = ['sidecar', 'deployment'];
// Paths inside the containers.
const P = {state: '/signer-state', key: '/signer-key', socketDir: '/run/heads-signer', tls: '/tls', token: '/heads-signer-token',
  ca: '/heads-signer-ca', publicKey: '/heads-signer-public', transparency: '/transparency', pin: '/transparency-pin'};
const BACKEND = ['--backend', 'file', '--key-file', `${P.key}/signer-key.pem`];
const VAULT_SECRETS = ['vault-signing', 'vault-data-key', 'vault-config', 'vault-transparency', 'vault-tls'];

function signerContainer(name, args, mounts, extra = {}) {
  return {name, image: 'evidscope:local', imagePullPolicy: 'IfNotPresent', command: ['node', 'scripts/signer.mjs', ...args], volumeMounts: mounts,
    resources: {requests: {cpu: '50m', memory: '64Mi'}, limits: {cpu: '500m', memory: '256Mi'}},
    securityContext: {runAsUser: SIGNER_UID, runAsGroup: 1000, allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: ['ALL']}},
    ...extra};
}
const stateMounts = [{name: 'heads-signer-state', mountPath: P.state}, {name: 'heads-signer-key', mountPath: P.key, readOnly: true}];
const stateVolumes = [{name: 'heads-signer-state', persistentVolumeClaim: {claimName: 'heads-signer-state'}},
  {name: 'heads-signer-key', secret: {secretName: 'heads-signer-key', defaultMode: 288, items: [{key: 'signer-key.pem', path: 'signer-key.pem'}]}}];
// init --if-missing creates the state on the first start and afterwards only checks that the key matches it.
const initContainer = signerContainer('heads-signer-init', ['init', '--state-dir', P.state, ...BACKEND, '--if-missing'], stateMounts);
const pvc = (name, storage) => ({apiVersion: 'v1', kind: 'PersistentVolumeClaim', metadata: meta(name),
  spec: {accessModes: ['ReadWriteOnce'], resources: {requests: {storage}}}});

function baseline(base) {
  if (base?.apiVersion !== 'v1' || base.kind !== 'List' || !Array.isArray(base.items)) fail('invalid_base_manifest');
  const vaults = base.items.filter(i => i.kind === 'Deployment' && i.metadata?.name === 'vault' && i.metadata.namespace === NS);
  if (vaults.length !== 1) fail('unique_vault_deployment_required');
  const vault = vaults[0], pod = vault.spec?.template?.spec, container = pod?.containers?.[0];
  if (vault.spec.replicas !== 1 || vault.spec.strategy?.type !== 'Recreate' || pod.containers.length !== 1 || container.name !== 'vault') {
    fail('single_replica_recreate_vault_required');
  }
  if (container.env.some(e => e.name.startsWith('TRANSPARENCY_'))) fail('transparency_already_configured');
  const names = new Set(base.items.map(i => `${i.kind}/${i.metadata?.name}`));
  for (const n of ['Deployment/heads-signer', 'PersistentVolumeClaim/heads-signer-state', 'PersistentVolumeClaim/vault-transparency-pin']) {
    if (names.has(n)) fail('overlay_already_present');
  }
  const taken = new Set([...(pod.volumes ?? []).map(v => v.name), ...(pod.initContainers ?? []).map(c => c.name)]);
  const ours = ['transparency', 'transparency-pin', 'heads-signer-public', 'heads-signer-socket', 'heads-signer-token', 'heads-signer-ca'];
  if ([...ours, ...stateVolumes.map(v => v.name)].some(n => taken.has(n))) fail('volume_name_conflict');
  const denyAll = i => i.kind === 'NetworkPolicy' && i.metadata?.name === 'deny-all' && canonical(i.spec?.podSelector) === '{}';
  if (!base.items.some(denyAll)) fail('default_deny_required');
}

// The separation the overlay exists for, checked on the rendered manifest: no signer container mounts the vault data, pin or a
// vault Secret, and no other container mounts the signer state or key.
function checkSeparation(items) {
  for (const d of items.filter(i => i.kind === 'Deployment' && i.metadata.namespace === NS)) {
    const pod = d.spec.template.spec, volumes = new Map((pod.volumes ?? []).map(v => [v.name, v]));
    for (const c of [...(pod.initContainers ?? []), ...pod.containers]) {
      const mounted = (c.volumeMounts ?? []).map(m => volumes.get(m.name) ?? {});
      if (c.name.startsWith(COMPONENT)) {
        if (mounted.some(v => ['vault-data', 'vault-transparency-pin'].includes(v.persistentVolumeClaim?.claimName)
          || VAULT_SECRETS.includes(v.secret?.secretName))) fail('signer_mounts_vault_volume');
      } else if (mounted.some(v => v.persistentVolumeClaim?.claimName === 'heads-signer-state' || v.secret?.secretName === 'heads-signer-key')) {
        fail('signer_key_mounted_outside_signer');
      }
    }
  }
}

export function renderHeadsSignerOverlay({base = JSON.parse(readFileSync(new URL('./kubernetes.json', import.meta.url), 'utf8')), variant}) {
  if (!VARIANTS.includes(variant)) fail('variant_must_be_sidecar_or_deployment');
  baseline(base);
  const manifest = structuredClone(base), items = manifest.items;
  const vault = items.find(i => i.kind === 'Deployment' && i.metadata.name === 'vault'), pod = vault.spec.template.spec, container = pod.containers[0];
  // The vault: transparency config from a Secret, the pin on its own volume (not the data PVC), the signer's public key.
  container.env.push({name: 'TRANSPARENCY_CONFIG_FILE', value: `${P.transparency}/transparency.json`},
    {name: 'TRANSPARENCY_PIN_FILE', value: `${P.pin}/pin.json`});
  pod.volumes.push({name: 'transparency', secret: {secretName: 'vault-transparency', defaultMode: 288}},
    {name: 'transparency-pin', persistentVolumeClaim: {claimName: 'vault-transparency-pin'}},
    {name: 'heads-signer-public', configMap: {name: 'heads-signer-public', items: [{key: 'signer-public.pem', path: 'signer-public.pem'}]}});
  container.volumeMounts.push({name: 'transparency', mountPath: P.transparency, readOnly: true}, {name: 'transparency-pin', mountPath: P.pin},
    {name: 'heads-signer-public', mountPath: P.publicKey, readOnly: true});
  items.push(pvc('vault-transparency-pin', '1Gi'), pvc('heads-signer-state', '1Gi'));
  const publicKeyFile = `${P.publicKey}/signer-public.pem`;
  let signer;
  if (variant === 'sidecar') {
    const socket = `${P.socketDir}/signer.sock`, socketMount = {name: 'heads-signer-socket', mountPath: P.socketDir};
    pod.volumes.push({name: 'heads-signer-socket', emptyDir: {medium: 'Memory', sizeLimit: '1Mi'}}, ...structuredClone(stateVolumes));
    container.volumeMounts.push(socketMount);
    pod.initContainers = [...(pod.initContainers ?? []), structuredClone(initContainer)];
    // Group 1000 (the vault's) may connect to the socket; nothing else of the signer is mounted into the vault container.
    pod.containers.push(signerContainer(COMPONENT, ['serve', '--state-dir', P.state, ...BACKEND, '--socket', socket, '--socket-mode', '660'],
      [...structuredClone(stateMounts), structuredClone(socketMount)]));
    signer = {socket, publicKeyFile};
  } else {
    const url = `https://${COMPONENT}.${NS}.svc:${PORT}`, selector = {matchLabels: labels(COMPONENT)};
    pod.volumes.push({name: 'heads-signer-token', secret: {secretName: 'heads-signer-token', defaultMode: 288, items: [{key: 'token', path: 'token'}]}},
      {name: 'heads-signer-ca', secret: {secretName: 'heads-signer-ca', defaultMode: 288, items: [{key: 'ca.crt', path: 'ca.crt'}]}});
    container.volumeMounts.push({name: 'heads-signer-token', mountPath: P.token, readOnly: true}, {name: 'heads-signer-ca', mountPath: P.ca, readOnly: true});
    const serve = ['serve', '--state-dir', P.state, ...BACKEND, '--host', '0.0.0.0', '--port', String(PORT), '--tls-cert', `${P.tls}/tls.crt`,
      '--tls-key', `${P.tls}/tls.key`, '--token-file', `${P.token}/token`];
    const mounts = [...structuredClone(stateMounts), {name: 'tls', mountPath: P.tls, readOnly: true},
      {name: 'heads-signer-token', mountPath: P.token, readOnly: true}];
    const probe = {tcpSocket: {port: 'https'}, periodSeconds: 10, timeoutSeconds: 3, failureThreshold: 3};
    const own = c => ({...c, securityContext: {...c.securityContext, runAsGroup: SIGNER_UID}});
    const main = own(signerContainer(COMPONENT, serve, mounts, {ports: [{name: 'https', containerPort: PORT}], readinessProbe: probe, livenessProbe: probe}));
    items.push({apiVersion: 'apps/v1', kind: 'Deployment', metadata: meta(COMPONENT), spec: {replicas: 1, strategy: {type: 'Recreate'}, selector,
      template: {metadata: {labels: labels(COMPONENT)}, spec: {automountServiceAccountToken: false, terminationGracePeriodSeconds: 30,
        // Its own group: Secret files are group-readable (fsGroup) whatever defaultMode says.
        securityContext: {...structuredClone(pod.securityContext), runAsUser: SIGNER_UID, runAsGroup: SIGNER_UID, fsGroup: SIGNER_UID},
        // Never on the vault's node: a vault host (node) compromise must not reach the signer key.
        affinity: {podAntiAffinity: {requiredDuringSchedulingIgnoredDuringExecution: [{labelSelector: {matchLabels: labels('vault')},
          topologyKey: 'kubernetes.io/hostname'}]}},
        initContainers: [own(structuredClone(initContainer))], containers: [main],
        volumes: [...structuredClone(stateVolumes), {name: 'tls', secret: {secretName: 'heads-signer-tls', defaultMode: 288}},
          {name: 'heads-signer-token', secret: {secretName: 'heads-signer-token', defaultMode: 288, items: [{key: 'token', path: 'token'}]}}]}},
      minReadySeconds: 3, progressDeadlineSeconds: 180}});
    items.push({apiVersion: 'v1', kind: 'Service', metadata: meta(COMPONENT), spec: {type: 'ClusterIP', selector: labels(COMPONENT),
      ports: [{name: 'https', port: PORT, targetPort: 'https'}], sessionAffinity: 'None', internalTrafficPolicy: 'Cluster', publishNotReadyAddresses: false}});
    const dns = {to: [{namespaceSelector: {matchLabels: {'kubernetes.io/metadata.name': 'kube-system'}}, podSelector: {matchLabels: {'k8s-app': 'kube-dns'}}}],
      ports: [{protocol: 'UDP', port: 53}, {protocol: 'TCP', port: 53}]};
    items.push({apiVersion: 'networking.k8s.io/v1', kind: 'NetworkPolicy', metadata: meta('heads-signer-from-vault'), spec: {podSelector: selector,
      policyTypes: ['Ingress'], ingress: [{from: [{podSelector: {matchLabels: labels('vault')}}], ports: [{protocol: 'TCP', port: PORT}]}]}});
    items.push({apiVersion: 'networking.k8s.io/v1', kind: 'NetworkPolicy', metadata: meta('vault-to-heads-signer'),
      spec: {podSelector: {matchLabels: labels('vault')}, policyTypes: ['Egress'],
        egress: [{to: [{podSelector: selector}], ports: [{protocol: 'TCP', port: PORT}]}, dns]}});
    signer = {url, tokenFile: `${P.token}/token`, caFile: `${P.ca}/ca.crt`, publicKeyFile};
  }
  checkSeparation(items);
  const secrets = [{name: 'heads-signer-key', keys: ['signer-key.pem'], mountedIn: [COMPONENT]},
    {name: 'vault-transparency', keys: ['transparency.json'], mountedIn: ['vault']},
    ...(variant === 'deployment' ? [{name: 'heads-signer-tls', keys: ['tls.crt', 'tls.key'], mountedIn: [COMPONENT]},
      {name: 'heads-signer-token', keys: ['token'], mountedIn: ['vault', COMPONENT]}, {name: 'heads-signer-ca', keys: ['ca.crt'], mountedIn: ['vault']}] : [])];
  const receipt = {schemaVersion: 1, variant, baseManifestSha256: digest(base), renderedManifestSha256: digest(manifest),
    secrets, configMaps: [{name: 'heads-signer-public', keys: ['signer-public.pem']}],
    persistentVolumeClaims: ['heads-signer-state', 'vault-transparency-pin'], transparencySigner: signer,
    afterFirstStart: 'kubectl -n evidscope exec deploy/' + (variant === 'sidecar' ? 'vault -c heads-signer' : COMPONENT)
      + ' -- node scripts/signer.mjs authorize-genesis --state-dir /signer-state --origin-base ORIGIN (or authorize-handover; docs/signer.md)',
    limitations: ['Static rendered manifest only; storage classes, scheduling, CNI enforcement and TLS are not verified here.',
      'The vault still needs egress to its witnesses (a NetworkPolicy like deploy/enterprise-oidc-overlay.mjs renders for OIDC).',
      variant === 'sidecar' ? 'The sidecar shares the node with the vault: a node or cluster-admin compromise reaches the signer key.'
        : 'Anti-affinity keeps the signer off the vault node; a cluster-admin or etcd compromise still reaches the signer key.']};
  return {manifest, receipt};
}

export function runHeadsSignerOverlayCli(args) {
  const {values} = parseArgs({args, options: {variant: {type: 'string'}, output: {type: 'string'}, base: {type: 'string'}}, allowPositionals: false});
  if (!values.variant || !values.output) fail('usage: --variant sidecar|deployment --output NEW_FILE.json [--base deploy/kubernetes.json]');
  const base = values.base ? JSON.parse(readFileSync(resolve(values.base), 'utf8')) : undefined;
  const {manifest, receipt} = renderHeadsSignerOverlay({...(base ? {base} : {}), variant: values.variant});
  try { writeFileSync(resolve(values.output), JSON.stringify(manifest, null, 2) + '\n', {flag: 'wx'}); } catch { fail('new_output_file_required'); }
  return receipt;
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try { console.log(JSON.stringify(runHeadsSignerOverlayCli(process.argv.slice(2)), null, 2)); } catch (error) {
    console.error(JSON.stringify({rendered: false, error: error.code || error.message}));
    process.exitCode = 1;
  }
}
