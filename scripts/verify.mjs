import {readFileSync} from 'node:fs';
import {parseArgs} from 'node:util';
import {verifyBundle} from '../src/crypto.mjs';
import {replayEvaluations} from '../src/policy-replay.mjs';
import {verifyAttestation} from '../src/receipts.mjs';
import {transparencyOptions,transparencyFlags} from './transparency-flags.mjs';
try{
 const {values,positionals}=parseArgs({allowPositionals:true,options:{...transparencyFlags,'min-checkpoint':{type:'string'},replay:{type:'boolean'},attestation:{type:'string'}}});
 const [bundlePath,keyPath,checkpointPath]=positionals;
 if(!bundlePath||!keyPath||positionals.length>3)throw Error('Usage: node scripts/verify.mjs EXPORT.json TRUSTED_PUBLIC_KEY.pem [EXTERNAL_CHECKPOINT.json] [--witness VKEY]... [--quorum N] [--origin-base BASE]'
  +' [--min-checkpoint FILE] [--replay] [--max-staleness SECONDS] [--require-transparency] [--require-tenant-witness] [--attestation EXPORT.json.intoto.json]');
 const bundle=JSON.parse(readFileSync(bundlePath,'utf8')),transparency=transparencyOptions(values,bundle.transparency!==undefined);
 const result=verifyBundle(bundle,readFileSync(keyPath,'utf8'),checkpointPath?JSON.parse(readFileSync(checkpointPath,'utf8')):undefined,transparency?{transparency}:{});
 // --replay recomputes every signed evaluation from the records before it; a mismatch fails like a broken signature.
 const replay=values.replay?replayEvaluations(bundle):undefined;
 // --attestation: the companion DSSE in-toto envelope (docs/receipts.md) must name these exact export bytes.
 const attestation=values.attestation?verifyAttestation({envelope:JSON.parse(readFileSync(values.attestation,'utf8')),subject:readFileSync(bundlePath),publicKey:readFileSync(keyPath,'utf8'),options:transparency?{transparency}:{}}):undefined;
 console.log(JSON.stringify(replay||attestation?{...result,...(replay?{replay}:{}),...(attestation?{attestation}:{})}:result,null,2));if(replay&&!replay.valid)process.exitCode=1;
}catch(e){console.error(e.message);process.exitCode=1;}
