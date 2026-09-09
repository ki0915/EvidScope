import {mkdirSync,existsSync,writeFileSync,readFileSync} from 'node:fs';
import {randomBytes,generateKeyPairSync} from 'node:crypto';
import {resolve,join} from 'node:path';
export function initialize(dir=resolve('.local')){
 mkdirSync(dir,{recursive:true});const path=join(dir,'config.json');
 if(existsSync(path))return JSON.parse(readFileSync(path,'utf8'));
 const token=()=>randomBytes(32).toString('base64url');
 const principals=[...['alpha','beta'].flatMap(tenant=>[
  ...['agent','tool','authority','safety','telemetry'].map(kind=>({id:`${tenant}-${kind}`,tenant,role:'source',kind,token:token(),hmacSecret:token()})),
  ...['auditor','reviewer','admin'].map(role=>({id:`${tenant}-${role}`,tenant,role,token:token()}))]),{id:'analysis-worker',tenant:'internal',role:'worker',token:token()}];
 const config={profile:'synthetic-local',principals};
 const {privateKey,publicKey}=generateKeyPairSync('ed25519');
 writeFileSync(join(dir,'signing-private.pem'),privateKey.export({format:'pem',type:'pkcs8'}),{mode:0o600,flag:'wx'});
 writeFileSync(join(dir,'trust-anchor.pem'),publicKey.export({format:'pem',type:'spki'}),{mode:0o644,flag:'wx'});
 writeFileSync(path,JSON.stringify(config,null,2),{mode:0o600,flag:'wx'});return config;
}
if(process.argv[1]&&resolve(process.argv[1])===resolve('scripts/init.mjs')){initialize();console.log('로컬 자격을 .local/config.json에 생성했습니다. 토큰은 출력하지 않습니다.');}
