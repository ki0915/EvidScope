import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync,writeFileSync,mkdirSync,mkdtempSync} from 'node:fs';
import {join,resolve} from 'node:path';
import {renderEnterpriseOidcOverlay,validateEnterpriseOidcOverlay,runEnterpriseOidcOverlayCli} from '../deploy/enterprise-oidc-overlay.mjs';

const basePath=new URL('../deploy/kubernetes.json',import.meta.url);
const baseBytes=readFileSync(basePath),baseManifest=JSON.parse(baseBytes);
const vaultConfig={profile:'enterprise',oidc:{enabled:true,issuer:'https://id.example.org/realms/finance',publicOrigin:'https://audit.example.org',allowedEndpointOrigins:['https://keys.example.org:8443'],clientId:'evidscope',clientSecret:'PRIVATE-CLIENT-SECRET-CANARY',bindings:[{id:'reviewer',tenant:'finance',subject:'PRIVATE-SUBJECT-CANARY',role:'reviewer'}]}};
const policy={schemaVersion:1,destinations:[{origin:'https://id.example.org',addresses:['10.20.30.40']},{origin:'https://keys.example.org:8443',addresses:['2001:db8::10/128']}]};
const render=(options={})=>renderEnterpriseOidcOverlay({baseManifest,vaultConfig,policy,...options});
const copy=()=>({baseManifest:structuredClone(baseManifest),vaultConfig:structuredClone(vaultConfig),policy:structuredClone(policy)});
const findVault=manifest=>manifest.items.find(item=>item.kind==='Deployment'&&item.metadata.name==='vault');

test('overlay preserves every existing resource and permits only vault host TLS destinations plus labelled DNS',()=>{
 const before=JSON.stringify(baseManifest),{manifest,receipt}=render();assert.equal(JSON.stringify(baseManifest),before);
 assert.deepEqual(manifest.items.slice(0,-1),baseManifest.items);assert.deepEqual(readFileSync(basePath),baseBytes);
 const addition=manifest.items.at(-1);assert.equal(addition.kind,'NetworkPolicy');assert.deepEqual(addition.spec.podSelector.matchLabels,{'app.kubernetes.io/name':'evidscope','app.kubernetes.io/component':'vault'});
 assert.deepEqual(addition.spec.policyTypes,['Egress']);assert.equal(addition.spec.ingress,undefined);
 assert.deepEqual(addition.spec.egress[0],{to:[{ipBlock:{cidr:'10.20.30.40/32'}}],ports:[{protocol:'TCP',port:443}]});
 assert.deepEqual(addition.spec.egress[1],{to:[{ipBlock:{cidr:'2001:db8::10/128'}}],ports:[{protocol:'TCP',port:8443}]});
 assert.deepEqual(addition.spec.egress[2].to,[{namespaceSelector:{matchLabels:{'kubernetes.io/metadata.name':'kube-system'}},podSelector:{matchLabels:{'k8s-app':'kube-dns'}}}]);
 assert.deepEqual(addition.spec.egress[2].ports,[{protocol:'UDP',port:53},{protocol:'TCP',port:53}]);
 assert.equal(receipt.verified,true);assert.equal(receipt.runtimeConnectivityVerified,false);
 for(const secret of ['PRIVATE-CLIENT-SECRET-CANARY','PRIVATE-SUBJECT-CANARY'])assert.ok(!JSON.stringify({manifest,receipt}).includes(secret));
});

test('optional CA changes only vault and references an existing read-only secret',()=>{
 const input=copy();input.policy.privateCaSecret='finance-oidc-ca';const {manifest,receipt}=render(input);
 for(let index=0;index<baseManifest.items.length;index++)if(baseManifest.items[index].kind!=='Deployment'||baseManifest.items[index].metadata.name!=='vault')assert.deepEqual(manifest.items[index],baseManifest.items[index]);
 const pod=findVault(manifest).spec.template.spec;
 assert.deepEqual(pod.volumes.at(-1),{name:'oidc-private-ca',secret:{secretName:'finance-oidc-ca',defaultMode:288,items:[{key:'ca.crt',path:'ca.crt'}]}});
 assert.deepEqual(pod.containers[0].volumeMounts.at(-1),{name:'oidc-private-ca',mountPath:'/oidc-ca',readOnly:true});
 assert.deepEqual(pod.containers[0].env.at(-1),{name:'NODE_EXTRA_CA_CERTS',value:'/oidc-ca/ca.crt'});assert.equal(receipt.privateCaMounted,true);
 const stripped=structuredClone(findVault(manifest));stripped.spec.template.spec.volumes.pop();stripped.spec.template.spec.containers[0].volumeMounts.pop();stripped.spec.template.spec.containers[0].env.pop();assert.deepEqual(stripped,findVault(baseManifest));
});

test('HTTP, wildcards, credentials, query, discovery issuer, synthetic enterprise and missing origins fail closed',()=>{
 for(const issuer of ['http://id.example.org','https://*.example.org','https://user:pass@id.example.org','https://id.example.org?token=PRIVATE','https://id.example.org/.well-known/openid-configuration','https://id.example.org:0']){const input=copy();input.vaultConfig.oidc.issuer=issuer;assert.throws(()=>render(input));}
 for(const origin of ['https://*.example.org','http://keys.example.org','https://keys.example.org/path','https://keys.example.org/#fragment']){const input=copy();input.vaultConfig.oidc.allowedEndpointOrigins=[origin];assert.throws(()=>render(input));}
 const local=copy();local.vaultConfig.oidc.syntheticLocalIdp=true;assert.throws(()=>render(local),/enterprise_oidc_configuration_required/);
 const disabled=copy();disabled.vaultConfig.oidc.enabled=false;assert.throws(()=>render(disabled));
 const missing=copy();missing.policy.destinations.pop();assert.throws(()=>render(missing),/endpoint_origin_destination_missing/);
 const unknown=copy();unknown.policy.destinations[0].origin='https://unapproved.example.org';assert.throws(()=>render(unknown),/endpoint_origin_not_configured/);
});

test('broad CIDRs, zero or local destinations, mapped IPv6, duplicate hosts and arbitrary policy fields are rejected',()=>{
 for(const address of ['0.0.0.0/0','10.0.0.0/8','10.1.2.3/24','::/0','2001:db8::/64','0.0.0.0','127.0.0.1','169.254.169.254','224.0.0.1','::','::1','ff02::1','fe80::1','::ffff:10.1.2.3','id.example.org']){const input=copy();input.policy.destinations[0].addresses=[address];assert.throws(()=>render(input),address);}
 const duplicate=copy();duplicate.policy.destinations[0].addresses=['10.20.30.40','10.20.30.40/32'];assert.throws(()=>render(duplicate),/duplicate_destination_host/);
 const all=copy();all.policy.destinations[0].podSelector={};assert.throws(()=>render(all),/invalid_overlay_fields/);
 const injected=copy();injected.policy.component='audit';assert.throws(()=>render(injected),/invalid_overlay_fields/);
});

test('numeric endpoint origins require their matching approved host and TLS port',()=>{
 const input=copy();input.vaultConfig.oidc.issuer='https://10.20.30.40:9443/realms/finance';input.policy.destinations[0].origin='https://10.20.30.40:9443';
 assert.equal(render(input).manifest.items.at(-1).spec.egress[0].ports[0].port,9443);
 input.policy.destinations[0].addresses=['10.20.30.41'];assert.throws(()=>render(input),/literal_endpoint_destination_mismatch/);
});

test('rendered scope verifier rejects altered component selectors, extra egress, defaults or unrelated deployment changes',()=>{
 for(const mutate of [m=>{m.items.at(-1).spec.podSelector.matchLabels['app.kubernetes.io/component']='audit';},m=>{m.items.at(-1).spec.egress.push({to:[{ipBlock:{cidr:'0.0.0.0/0'}}]});},m=>{m.items.find(x=>x.kind==='NetworkPolicy'&&x.metadata.name==='deny-all').spec.policyTypes=['Ingress'];},m=>{m.items.find(x=>x.kind==='Deployment'&&x.metadata.name==='worker').spec.replicas=9;},m=>{m.items.push(structuredClone(m.items.at(-1)));}]){
  const {manifest}=render();mutate(manifest);assert.throws(()=>validateEnterpriseOidcOverlay({baseManifest,vaultConfig,policy,manifest}),/rendered_overlay_scope_mismatch/);
 }
});

test('already broad vault policy, duplicate overlay, missing default deny and CA conflicts require explicit review',()=>{
 const broad=copy();broad.baseManifest.items.push({apiVersion:'networking.k8s.io/v1',kind:'NetworkPolicy',metadata:{name:'unsafe',namespace:'evidscope'},spec:{podSelector:{},policyTypes:['Egress'],egress:[{}]}});assert.throws(()=>render(broad),/existing_vault_egress_requires_review/);
 const repeated=copy();repeated.baseManifest=render().manifest;assert.throws(()=>render(repeated),/overlay_already_present/);
 const missing=copy();missing.baseManifest.items=missing.baseManifest.items.filter(x=>x.metadata.name!=='deny-all');assert.throws(()=>render(missing),/default_deny_required/);
 const conflicting=copy();conflicting.policy.privateCaSecret='finance-ca';findVault(conflicting.baseManifest).spec.template.spec.containers[0].env.push({name:'NODE_EXTRA_CA_CERTS',value:'/other-ca/ca.crt'});assert.throws(()=>render(conflicting),/private_ca_mount_conflict/);
 for(const name of ['','*','../secret','finance/ca','UPPER','a'.repeat(64)]){const input=copy();input.policy.privateCaSecret=name;assert.throws(()=>render(input),/invalid_private_ca_secret/);}
});

test('private CA rejects normalized ancestor and descendant mounts without matching a similar prefix',()=>{
 for(const mountPath of ['/','/oidc-ca','/oidc-ca/','/oidc-ca/ca.crt','/oidc-ca/x','/oidc-ca/../oidc-ca/ca.crt','/existing/../oidc-ca','//oidc-ca///nested/./ca.crt','/existing/..']){
  const input=copy();input.policy.privateCaSecret='finance-ca';findVault(input.baseManifest).spec.template.spec.containers[0].volumeMounts.push({name:'existing-volume',mountPath,readOnly:true});assert.throws(()=>render(input),/private_ca_mount_conflict/,mountPath);
 }
 for(const mountPath of ['oidc-ca/ca.crt','','\\oidc-ca\\ca.crt','/oidc-ca\0/ca.crt']){
  const input=copy();input.policy.privateCaSecret='finance-ca';findVault(input.baseManifest).spec.template.spec.containers[0].volumeMounts.push({name:'existing-volume',mountPath,readOnly:true});assert.throws(()=>render(input),/invalid_base_mount_path/,mountPath);
 }
 for(const mountPath of ['/oidc-ca-other','/oidc-ca-other/ca.crt','/unrelated/oidc-ca','/oidc-ca/../unrelated']){
  const input=copy();input.policy.privateCaSecret='finance-ca';findVault(input.baseManifest).spec.template.spec.containers[0].volumeMounts.push({name:'existing-volume',mountPath,readOnly:true});const {manifest}=render(input);assert.equal(findVault(manifest).spec.template.spec.containers[0].volumeMounts.at(-1).mountPath,'/oidc-ca');
 }
});

test('CLI writes only a new rendered manifest, excludes vault credentials, preserves config and default manifest',()=>{
 const root=resolve('.test-runs');mkdirSync(root,{recursive:true});const directory=mkdtempSync(join(root,'enterprise-oidc-overlay-'));
 const configPath=join(directory,'vault.json'),policyPath=join(directory,'policy.json'),output=join(directory,'rendered.json');writeFileSync(configPath,JSON.stringify(vaultConfig));writeFileSync(policyPath,JSON.stringify(policy));
 const configBefore=readFileSync(configPath),receipt=runEnterpriseOidcOverlayCli(['--oidc-config',configPath,'--policy',policyPath,'--output',output]);
 assert.equal(receipt.verified,true);assert.deepEqual(JSON.parse(readFileSync(output)),render().manifest);assert.deepEqual(readFileSync(configPath),configBefore);assert.deepEqual(readFileSync(basePath),baseBytes);
 const written=readFileSync(output);assert.ok(!written.includes(Buffer.from('PRIVATE-CLIENT-SECRET-CANARY')));
 assert.throws(()=>runEnterpriseOidcOverlayCli(['--oidc-config',configPath,'--policy',policyPath,'--output',output]),/new_output_file_required/);assert.deepEqual(readFileSync(output),written);
 assert.throws(()=>runEnterpriseOidcOverlayCli(['--oidc-config',configPath,'--policy',policyPath,'--output',configPath]),/invalid_cli_arguments/);
});
