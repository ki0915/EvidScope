// Tenant shards (round 7, docs/performance.md stage 3; opt-in prototype). One tenant's ledger is one hash chain written by one
// process, so a single vault bounds the throughput of every tenant it holds. Several vault processes can each own a disjoint set
// of tenants, each with its own database, ledger, checkpoints and keys; the gateways route a request to the vault of its
// credential (VAULT_ROUTES_FILE). A tenant must never be written by two vaults, or its history would fork into two chains:
// - VAULT_TENANTS names the tenants of this vault. It serves only credentials of those tenants (the others are unknown here),
//   Store refuses to append for any other tenant, and a database that holds ledger history of another tenant does not start.
// - VAULT_TENANT_REGISTRY_DIR, shared by every vault of the deployment, holds one file per tenant naming the database that owns
//   it, created exclusively (O_EXCL). A vault whose database is not the named owner of one of its tenants does not start.
//   A vault without VAULT_TENANTS but with the registry claims every tenant of its credentials the same way.
import {createHash,randomUUID} from 'node:crypto';
import {closeSync,mkdirSync,openSync,readFileSync,writeSync} from 'node:fs';
import {join} from 'node:path';

const TENANT=/^[a-zA-Z0-9._:@/-]{1,120}$/;
export function vaultTenants(value=process.env.VAULT_TENANTS){
 if(value===undefined||value==='')return null;
 const tenants=String(value).split(',').map(tenant=>tenant.trim());
 if(tenants.some(tenant=>!TENANT.test(tenant))||new Set(tenants).size!==tenants.length)throw Error('Invalid VAULT_TENANTS');
 return new Set(tenants);
}

// The configuration this vault serves: credentials of its tenants; a worker bound to a tenants list keeps the owned part of it.
export function shardConfig(config,owned){
 if(!owned)return config;
 if(config.oidc?.enabled)throw Error('VAULT_TENANTS does not support OIDC sessions yet');
 const principals=[];
 for(const p of config.principals||[]){
  if(p.role==='worker'&&Array.isArray(p.tenants)){const tenants=p.tenants.filter(tenant=>owned.has(tenant));if(tenants.length)principals.push({...p,tenants});}
  else if(p.role==='worker'&&p.tenant==='internal'||owned.has(p.tenant))principals.push(p);
 }
 return {...config,principals};
}

// Database identity and its claims. Call before any request is served; throws when the claim conflicts.
export function claimTenants(db,{owned,claimed,registryDir}){
 db.exec(`CREATE TABLE IF NOT EXISTS vault_identity(id INTEGER PRIMARY KEY CHECK(id=1),vault TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS vault_tenants(tenant TEXT PRIMARY KEY,claimed_at TEXT NOT NULL);`);
 if(owned){
  for(const {tenant} of db.prepare('SELECT DISTINCT tenant FROM ledger').all())
   if(!owned.has(tenant))throw Error(`This database holds ledger history of tenant ${tenant}, which VAULT_TENANTS does not name`);
 }else if(!registryDir)assertNotShard(db);
 db.prepare('INSERT OR IGNORE INTO vault_identity VALUES(1,?)').run(randomUUID());
 const vault=db.prepare('SELECT vault FROM vault_identity WHERE id=1').get().vault;
 const tenants=[...(owned||claimed||[])];
 if(registryDir){
  mkdirSync(registryDir,{recursive:true,mode:0o700});
  for(const tenant of tenants){
   const file=join(registryDir,createHash('sha256').update(tenant).digest('hex')+'.owner'),record=JSON.stringify({tenant,vault})+'\n';
   try{const fd=openSync(file,'wx',0o600);try{writeSync(fd,record);}finally{closeSync(fd);}}
   catch(error){
    if(error.code!=='EEXIST')throw error;
    let owner;try{owner=JSON.parse(readFileSync(file,'utf8'));}catch{throw Error(`Tenant registry entry of ${tenant} is unreadable`);}
    if(owner.tenant!==tenant||owner.vault!==vault)throw Error(`Tenant ${tenant} is owned by another vault database (${registryDir})`);
   }
  }
 }
 const at=new Date().toISOString();for(const tenant of tenants)db.prepare('INSERT OR IGNORE INTO vault_tenants VALUES(?,?)').run(tenant,at);
 return {vault,tenants};
}

// A vault started without VAULT_TENANTS and without the registry would serve every tenant: refuse a shard's database.
export function assertNotShard(db){
 if(db.prepare("SELECT 1 FROM sqlite_schema WHERE type='table' AND name='vault_tenants'").get()&&db.prepare('SELECT 1 FROM vault_tenants LIMIT 1').get())
  throw Error('This database belongs to a tenant shard; start it with VAULT_TENANTS');
}

// Gateways: VAULT_ROUTES_FILE is {"vaults": {"<tenant>": "<vault url>"}, "credentials": {"<routeKey(token)>": "<tenant>"}}.
// The key is a labelled SHA-256 of the bearer token, so the file holds no credential. A request whose credential is not listed
// goes to VAULT_URL, which refuses what it does not serve; a vault refuses a credential of a tenant it does not own.
export const routeKey=token=>'sha256:'+createHash('sha256').update('evidscope/vault-route/v1\n').update(token).digest('hex');
export function vaultRouter(file,fallback,{allowed=()=>true}={}){
 if(!file)return ()=>fallback;
 const routes=JSON.parse(readFileSync(file,'utf8')),vaults=new Map(),credentials=new Map();
 for(const [tenant,url] of Object.entries(routes.vaults||{})){
  if(!TENANT.test(tenant)||typeof url!=='string'||!allowed(new URL(url)))throw Error('Invalid VAULT_ROUTES_FILE vault');vaults.set(tenant,url);
 }
 for(const [key,tenant] of Object.entries(routes.credentials||{})){
  if(!/^sha256:[a-f0-9]{64}$/.test(key)||!vaults.has(tenant))throw Error('Invalid VAULT_ROUTES_FILE credential');credentials.set(key,tenant);
 }
 return authorization=>{
  const token=/^Bearer (.+)$/.exec(authorization||'')?.[1];
  const tenant=token&&credentials.get(routeKey(token));return tenant?vaults.get(tenant):fallback;
 };
}
