import {readFileSync} from 'node:fs';
import {verifyBundle} from '../src/crypto.mjs';
try{
 const [bundlePath,keyPath,checkpointPath]=process.argv.slice(2);
 if(!bundlePath||!keyPath)throw Error('Usage: node scripts/verify.mjs EXPORT.json TRUSTED_PUBLIC_KEY.pem [EXTERNAL_CHECKPOINT.json]');
 console.log(JSON.stringify(verifyBundle(JSON.parse(readFileSync(bundlePath,'utf8')),readFileSync(keyPath,'utf8'),checkpointPath?JSON.parse(readFileSync(checkpointPath,'utf8')):undefined),null,2));
}catch(e){console.error(e.message);process.exitCode=1;}
