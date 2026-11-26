// Optional, static overlay over the existing renderer's JSON output. No deployment or discovery.
import {readFileSync,writeFileSync} from 'node:fs';
import {isIP} from 'node:net';
import {resolve,posix} from 'node:path';
import {pathToFileURL} from 'node:url';
import {canonical,digest} from '../src/crypto.mjs';

const selector=Object.freeze({'app.kubernetes.io/name':'evidscope','app.kubernetes.io/component':'vault'});
const policyName='vault-to-approved-oidc';
const fail=code=>{throw Object.assign(new Error(code),{code});};
const object=value=>!!value&&typeof value==='object'&&!Array.isArray(value);
function keys(value,allowed){if(!object(value)||Object.keys(value).some(key=>!allowed.includes(key)))fail('invalid_overlay_fields');}
function httpsAddress(value,{originOnly=false}={}){
 if(typeof value!=='string'||value!==value.trim()||value.length>2048)fail('invalid_oidc_address');
 let url;try{url=new URL(value);}catch{fail('invalid_oidc_address');}
 if(url.protocol!=='https:'||url.username||url.password||url.hash||url.search||!url.hostname||url.hostname.includes('*')||url.hostname==='localhost'||url.port==='0'||originOnly&&url.pathname!=='/')fail('invalid_oidc_address');
 return url;
}
function identity(vaultConfig){
 const settings=vaultConfig?.oidc;
 if(vaultConfig?.profile!=='enterprise'||!object(settings)||settings.enabled!==true||settings.syntheticLocalIdp===true)fail('enterprise_oidc_configuration_required');
 const issuer=httpsAddress(settings.issuer),publicOrigin=httpsAddress(settings.publicOrigin,{originOnly:true});
 if(settings.issuer.includes('/.well-known/'))fail('issuer_not_discovery_address');
 const extra=settings.allowedEndpointOrigins??[];
 if(!Array.isArray(extra)||extra.length>8)fail('invalid_endpoint_origins');
 const origins=[issuer.origin,...extra.map(value=>httpsAddress(value,{originOnly:true}).origin)];
 if(new Set(origins).size!==origins.length)fail('duplicate_endpoint_origin');
 // The runtime independently checks discovery issuer and every returned endpoint origin.
 return {issuer:settings.issuer,publicOrigin:publicOrigin.origin,allowedOrigins:origins.sort()};
}
function hostCidr(value){
 if(typeof value!=='string'||value!==value.trim())fail('invalid_destination_host');
 const parts=value.split('/');if(parts.length>2)fail('invalid_destination_host');
 const address=parts[0],version=isIP(address),prefix=version===4?'32':'128';
 if(!version||parts.length===2&&parts[1]!==prefix)fail('destination_must_be_single_host');
 if(version===4){const n=address.split('.').map(Number);if(n[0]===0||n[0]===127||n[0]>=224||n[0]===169&&n[1]===254)fail('invalid_destination_host');}
 else {
  const host=new URL('https://['+address+']/').hostname.slice(1,-1).toLowerCase();
  if(host==='::'||host==='::1'||host.startsWith('ff')||/^fe[89ab]/.test(host)||host.includes('::ffff:'))fail('invalid_destination_host');
  return host+'/128';
 }
 return address+'/32';
}
function connectionPolicy(policy,config){
 keys(policy,['schemaVersion','destinations','privateCaSecret']);if(policy.schemaVersion!==1||!Array.isArray(policy.destinations)||!policy.destinations.length||policy.destinations.length>9)fail('invalid_connection_policy');
 const origins=new Set(),egress=[];
 for(const destination of policy.destinations){
  keys(destination,['origin','addresses']);const url=httpsAddress(destination.origin,{originOnly:true});
  if(url.origin!==destination.origin||!config.allowedOrigins.includes(url.origin)||origins.has(url.origin))fail('endpoint_origin_not_configured');origins.add(url.origin);
  if(!Array.isArray(destination.addresses)||!destination.addresses.length||destination.addresses.length>8)fail('invalid_destination_addresses');
  const hosts=destination.addresses.map(hostCidr);if(new Set(hosts).size!==hosts.length)fail('duplicate_destination_host');
  const literal=url.hostname.replace(/^\[|\]$/g,'');if(isIP(literal)&&!hosts.includes(hostCidr(literal)))fail('literal_endpoint_destination_mismatch');
  egress.push({to:hosts.sort().map(cidr=>({ipBlock:{cidr}})),ports:[{protocol:'TCP',port:Number(url.port||443)}]});
 }
 if(config.allowedOrigins.some(origin=>!origins.has(origin)))fail('endpoint_origin_destination_missing');
 if(policy.privateCaSecret!==undefined&&(typeof policy.privateCaSecret!=='string'||policy.privateCaSecret.length>63||! /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(policy.privateCaSecret)))fail('invalid_private_ca_secret');
 egress.push({to:[{namespaceSelector:{matchLabels:{'kubernetes.io/metadata.name':'kube-system'}},podSelector:{matchLabels:{'k8s-app':'kube-dns'}}}],ports:[{protocol:'UDP',port:53},{protocol:'TCP',port:53}]});
 return egress;
}
function baseline(baseManifest){
 if(baseManifest?.apiVersion!=='v1'||baseManifest.kind!=='List'||!Array.isArray(baseManifest.items))fail('invalid_base_manifest');
 const vaults=baseManifest.items.filter(item=>item.kind==='Deployment'&&item.metadata?.name==='vault'&&item.metadata.namespace==='evidscope');if(vaults.length!==1)fail('unique_vault_deployment_required');
 const vault=vaults[0],labels=vault.spec?.template?.metadata?.labels;
 if(!object(labels)||Object.entries(selector).some(([key,value])=>labels[key]!==value)||vault.spec.template.spec.containers?.length!==1||vault.spec.template.spec.containers[0].name!=='vault')fail('invalid_vault_deployment');
 const deny=baseManifest.items.filter(item=>item.kind==='NetworkPolicy'&&item.metadata?.namespace==='evidscope'&&item.metadata.name==='deny-all');
 if(deny.length!==1||canonical(deny[0].spec.podSelector)!=='{}'||canonical([...(deny[0].spec.policyTypes||[])].sort())!==canonical(['Egress','Ingress'])||(deny[0].spec.egress||[]).length||(deny[0].spec.ingress||[]).length)fail('default_deny_required');
 const identities=new Set();for(const item of baseManifest.items){const id=canonical([item.apiVersion,item.kind,item.metadata?.namespace||'',item.metadata?.name]);if(identities.has(id))fail('duplicate_resource_identity');identities.add(id);}
 for(const item of baseManifest.items.filter(item=>item.kind==='NetworkPolicy'&&item.metadata?.namespace==='evidscope')){
  if(item.metadata.name===policyName)fail('overlay_already_present');
  const selected=item.spec?.podSelector;if(!object(selected)||selected.matchExpressions?.length)fail('unsupported_base_policy_selector');
  const matches=Object.entries(selected.matchLabels||{}).every(([key,value])=>labels[key]===value);
  if(matches&&(item.spec.egress||[]).length)fail('existing_vault_egress_requires_review');
 }
 return vault;
}
function overlapsPrivateCaMount(mount){
 const value=mount.mountPath;
 if(typeof value!=='string'||!posix.isAbsolute(value)||value.includes('\0')||value.includes('\\'))fail('invalid_base_mount_path');
 const path=posix.normalize(value).replace(/\/$/,'')||'/',target='/oidc-ca';
 return path==='/'||path===target||path.startsWith(target+'/')||target.startsWith(path+'/');
}
function expected({baseManifest,vaultConfig,policy}){
 const config=identity(vaultConfig),egress=connectionPolicy(policy,config);baseline(baseManifest);
 const manifest=structuredClone(baseManifest),vault=baseline(manifest),pod=vault.spec.template.spec;
 if(policy.privateCaSecret!==undefined){
  const container=pod.containers[0];
  if((pod.volumes||[]).some(volume=>volume.name==='oidc-private-ca')||(container.volumeMounts||[]).some(mount=>mount.name==='oidc-private-ca'||overlapsPrivateCaMount(mount))||(container.env||[]).some(env=>env.name==='NODE_EXTRA_CA_CERTS'))fail('private_ca_mount_conflict');
  pod.volumes.push({name:'oidc-private-ca',secret:{secretName:policy.privateCaSecret,defaultMode:288,items:[{key:'ca.crt',path:'ca.crt'}]}});
  container.volumeMounts.push({name:'oidc-private-ca',mountPath:'/oidc-ca',readOnly:true});
  container.env.push({name:'NODE_EXTRA_CA_CERTS',value:'/oidc-ca/ca.crt'});
 }
 manifest.items.push({apiVersion:'networking.k8s.io/v1',kind:'NetworkPolicy',metadata:{name:policyName,namespace:'evidscope'},spec:{podSelector:{matchLabels:{...selector}},policyTypes:['Egress'],egress}});
 return {manifest,config};
}
export function validateEnterpriseOidcOverlay({baseManifest,vaultConfig,policy,manifest}){
 const reference=expected({baseManifest,vaultConfig,policy});
 // Equality to the narrow patch also detects added policies, altered defaults, ports or other components.
 if(canonical(manifest)!==canonical(reference.manifest))fail('rendered_overlay_scope_mismatch');
 return {verified:true,scope:'static_vault_only_oidc_egress',runtimeConnectivityVerified:false};
}
export function renderEnterpriseOidcOverlay({baseManifest=JSON.parse(readFileSync(new URL('./kubernetes.json',import.meta.url),'utf8')),vaultConfig,policy}){
 const {manifest,config}=expected({baseManifest,vaultConfig,policy});
 const verification=validateEnterpriseOidcOverlay({baseManifest,vaultConfig,policy,manifest});
 return {manifest,receipt:{schemaVersion:1,...verification,baseManifestSha256:digest(baseManifest),renderedManifestSha256:digest(manifest),oidcConnectionIdentitySha256:digest(config),policySha256:digest(policy),privateCaMounted:policy.privateCaSecret!==undefined,limitations:['Static rendered policy only; actual CNI, DNS, TLS, IdP login and revocation require runtime verification.','NetworkPolicy permits explicit destination IPs and ports, not HTTPS hostnames or URL paths; runtime origin checks and TLS peer verification remain required.','Endpoint, DNS address, port or CA changes require a new operator-reviewed policy/config and rollout.','Standard ipBlock behavior for Service/NAT destinations varies by CNI; verify actual packet enforcement.','Private CA secret must already contain ca.crt; no secret or credential is created or printed.']}};
}
export function runEnterpriseOidcOverlayCli(args){
 const paths={};for(let index=0;index<args.length;index+=2){const name=args[index];if(!['--oidc-config','--policy','--output'].includes(name)||paths[name]||!args[index+1]||args[index+1].startsWith('--'))fail('invalid_cli_arguments');paths[name]=resolve(args[index+1]);}
 if(Object.keys(paths).length!==3||paths['--output']===paths['--policy']||paths['--output']===paths['--oidc-config'])fail('invalid_cli_arguments');
 let vaultConfig,policy;try{vaultConfig=JSON.parse(readFileSync(paths['--oidc-config'],'utf8'));policy=JSON.parse(readFileSync(paths['--policy'],'utf8'));}catch{fail('configuration_read_failed');}
 const result=renderEnterpriseOidcOverlay({vaultConfig,policy});
 try{writeFileSync(paths['--output'],JSON.stringify(result.manifest,null,2)+'\n',{flag:'wx',mode:0o600});}catch{fail('new_output_file_required');}
 return result.receipt;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
 try{console.log(JSON.stringify(runEnterpriseOidcOverlayCli(process.argv.slice(2)),null,2));}
 catch(error){console.error(JSON.stringify({rendered:false,error:error.code||'enterprise_oidc_overlay_failed'}));process.exitCode=1;}
}
