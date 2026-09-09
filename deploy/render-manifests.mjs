// Regenerate the reviewable Kubernetes JSON List: node deploy/render-manifests.mjs
import { writeFileSync } from 'node:fs';
const ns = 'evidscope';
const items = [];
const labels = component => ({ 'app.kubernetes.io/name': ns, 'app.kubernetes.io/component': component });
const meta = name => ({ name, namespace: ns });
const selector = component => ({ matchLabels: labels(component) });
const obj = (apiVersion, kind, name, spec) => ({ apiVersion, kind, metadata: meta(name), spec });
items.push({ apiVersion: 'v1', kind: 'Namespace', metadata: { name: ns, labels: { 'pod-security.kubernetes.io/enforce': 'restricted', 'pod-security.kubernetes.io/audit': 'restricted', 'pod-security.kubernetes.io/warn': 'restricted' } } });
items.push(obj('v1', 'PersistentVolumeClaim', 'vault-data', { accessModes: ['ReadWriteOnce'], resources: { requests: { storage: '10Gi' } } }));
for (const component of ['vault', 'ingress', 'audit', 'worker']) {
  const vault = component === 'vault';
  const env = [{ name: 'MODE', value: component }, { name: 'HOST', value: '0.0.0.0' }, { name: 'PORT', value: '8080' }, { name: 'TLS_CERT_FILE', value: '/tls/tls.crt' }, { name: 'TLS_KEY_FILE', value: '/tls/tls.key' }];
  const volumes = [{ name: 'tls', secret: { secretName: `${component}-tls`, defaultMode: 288 } }];
  const mounts = [{ name: 'tls', mountPath: '/tls', readOnly: true }];
  if (vault) {
    env.push({ name: 'DATA_DIR', value: '/data' }, { name: 'CONFIG_FILE', value: '/secrets/config.json' }, { name: 'SIGNING_KEY_FILE', value: '/keys/signing-private.pem' });
    volumes.push({ name: 'data', persistentVolumeClaim: { claimName: 'vault-data' } }, { name: 'config', secret: { secretName: 'vault-config', defaultMode: 288 } }, { name: 'signing', secret: { secretName: 'vault-signing', defaultMode: 288 } });
    mounts.push({ name: 'data', mountPath: '/data' }, { name: 'config', mountPath: '/secrets', readOnly: true }, { name: 'signing', mountPath: '/keys', readOnly: true });
  } else {
    env.push({ name: 'VAULT_URL', value: 'https://vault.evidscope.svc:8080' }, { name: 'NODE_EXTRA_CA_CERTS', value: '/ca/ca.crt' });
    volumes.push({ name: 'ca', secret: { secretName: 'vault-ca', defaultMode: 288 } });
    mounts.push({ name: 'ca', mountPath: '/ca', readOnly: true });
  }
  if (component === 'worker') env.push({ name: 'WORKER_TOKEN', valueFrom: { secretKeyRef: { name: 'worker-identity', key: 'token' } } });
  env.push({ name: 'POD_NAME', valueFrom: { fieldRef: { fieldPath: 'metadata.name' } } });
  const container = { name: component, image: 'evidscope:local', imagePullPolicy: 'IfNotPresent', env, ports: [{ name: 'https', containerPort: 8080 }], volumeMounts: mounts, resources: { requests: { cpu: vault ? '250m' : '100m', memory: '128Mi' }, limits: { cpu: vault ? '2000m' : '1000m', memory: vault ? '1Gi' : '512Mi' } }, securityContext: { allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: { drop: ['ALL'] } }, readinessProbe: { httpGet: { path: '/readyz', port: 'https', scheme: 'HTTPS' }, initialDelaySeconds: 3, periodSeconds: 3, timeoutSeconds: 3, failureThreshold: 2, successThreshold: 1 }, livenessProbe: { httpGet: { path: '/healthz', port: 'https', scheme: 'HTTPS' }, initialDelaySeconds: 15, periodSeconds: 10, timeoutSeconds: 3, failureThreshold: 6 }, startupProbe: { httpGet: { path: '/healthz', port: 'https', scheme: 'HTTPS' }, periodSeconds: 2, failureThreshold: 30, timeoutSeconds: 2 } };
  items.push(obj('apps/v1', 'Deployment', component, { replicas: vault ? 1 : 2, strategy: vault ? { type: 'Recreate' } : { type: 'RollingUpdate', rollingUpdate: { maxSurge: 1, maxUnavailable: 0 } }, selector: selector(component), template: { metadata: { labels: labels(component) }, spec: { automountServiceAccountToken: false, terminationGracePeriodSeconds: 30, securityContext: { runAsNonRoot: true, runAsUser: 1000, runAsGroup: 1000, fsGroup: 1000, fsGroupChangePolicy: 'OnRootMismatch', seccompProfile: { type: 'RuntimeDefault' } }, topologySpreadConstraints: [{ maxSkew: 1, topologyKey: 'kubernetes.io/hostname', whenUnsatisfiable: vault ? 'ScheduleAnyway' : 'DoNotSchedule', labelSelector: selector(component), ...(!vault ? { minDomains: 2 } : {}) }], containers: [container], volumes } }, minReadySeconds: 3, progressDeadlineSeconds: 180 }));
  if (component !== 'worker') items.push(obj('v1', 'Service', component, { type: 'ClusterIP', selector: labels(component), ports: [{ name: 'https', port: 8080, targetPort: 'https' }], sessionAffinity: 'None', internalTrafficPolicy: 'Cluster', publishNotReadyAddresses: false }));
  items.push(obj('policy/v1', 'PodDisruptionBudget', component, { minAvailable: 1, selector: selector(component) }));
  if (!vault) items.push(obj('autoscaling/v2', 'HorizontalPodAutoscaler', component, { scaleTargetRef: { apiVersion: 'apps/v1', kind: 'Deployment', name: component }, minReplicas: 2, maxReplicas: 6, metrics: [{ type: 'Resource', resource: { name: 'cpu', target: { type: 'Utilization', averageUtilization: 60 } } }], behavior: { scaleDown: { stabilizationWindowSeconds: 120 }, scaleUp: { stabilizationWindowSeconds: 15 } } }));
}
items.push(obj('networking.k8s.io/v1', 'NetworkPolicy', 'deny-all', { podSelector: {}, policyTypes: ['Ingress', 'Egress'] }));
items.push(obj('networking.k8s.io/v1', 'NetworkPolicy', 'vault-from-gateways-workers', { podSelector: selector('vault'), policyTypes: ['Ingress'], ingress: [{ from: ['ingress', 'audit', 'worker'].map(c => ({ podSelector: selector(c) })), ports: [{ protocol: 'TCP', port: 8080 }] }] }));
for (const component of ['ingress', 'audit', 'worker']) {
  items.push(obj('networking.k8s.io/v1', 'NetworkPolicy', `${component}-to-vault`, { podSelector: selector(component), policyTypes: ['Egress'], egress: [{ to: [{ podSelector: selector('vault') }], ports: [{ protocol: 'TCP', port: 8080 }] }, { to: [{ namespaceSelector: { matchLabels: { 'kubernetes.io/metadata.name': 'kube-system' } }, podSelector: { matchLabels: { 'k8s-app': 'kube-dns' } } }], ports: [{ protocol: 'UDP', port: 53 }, { protocol: 'TCP', port: 53 }] }] }));
}
// Label only approved client pods in this namespace. Namespace RBAC must reserve label changes to operators.
for (const component of ['ingress', 'audit']) {
  items.push(obj('networking.k8s.io/v1', 'NetworkPolicy', `${component}-approved-clients`, { podSelector: selector(component), policyTypes: ['Ingress'], ingress: [{ from: [{ podSelector: { matchLabels: { 'evidscope.io/client': component === 'ingress' ? 'collector' : 'auditor' } } }], ports: [{ protocol: 'TCP', port: 8080 }] }] }));
}
writeFileSync(new URL('./kubernetes.json', import.meta.url), JSON.stringify({ apiVersion: 'v1', kind: 'List', items }, null, 2) + '\n');
console.log(`Wrote ${items.length} Kubernetes resources (static configuration; not deployed).`);
