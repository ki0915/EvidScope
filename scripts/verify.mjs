import {readFileSync} from 'node:fs';
import {parseArgs} from 'node:util';
import {verifyBundle} from '../src/crypto.mjs';
import {transparencyOptions,transparencyFlags} from './transparency-flags.mjs';
try{
 const {values,positionals}=parseArgs({allowPositionals:true,options:{...transparencyFlags,'min-checkpoint':{type:'string'}}});
 const [bundlePath,keyPath,checkpointPath]=positionals;
 if(!bundlePath||!keyPath||positionals.length>3)throw Error('Usage: node scripts/verify.mjs EXPORT.json TRUSTED_PUBLIC_KEY.pem [EXTERNAL_CHECKPOINT.json] [--witness VKEY]... [--quorum N] [--origin-base BASE] [--min-checkpoint FILE] [--max-staleness SECONDS] [--require-transparency]');
 const bundle=JSON.parse(readFileSync(bundlePath,'utf8')),transparency=transparencyOptions(values,bundle.transparency!==undefined);
 console.log(JSON.stringify(verifyBundle(bundle,readFileSync(keyPath,'utf8'),checkpointPath?JSON.parse(readFileSync(checkpointPath,'utf8')):undefined,transparency?{transparency}:{}),null,2));
}catch(e){console.error(e.message);process.exitCode=1;}
