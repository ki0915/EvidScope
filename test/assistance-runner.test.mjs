import test from 'node:test';
import assert from 'node:assert/strict';
import {runAssistance,syntheticAssistanceFixture} from '../src/assistance-runner.mjs';
import {digest} from '../src/crypto.mjs';

const credential=()=>({format:'evidscope-assistance-credential-v1',runId:'00000000-0000-4000-8000-000000000000',token:'not-a-real-secret',expiresAt:new Date(Date.now()+60000).toISOString()});

test('runner rejects DNS aliases and decorated loopback URLs before reading a credential scope',async()=>{
 for(const url of ['http://localhost:8080','https://127.0.0.1:8080','http://user:pass@127.0.0.1:8080','http://127.0.0.1:8080/path','http://127.0.0.1:8080/?next=cloud'])await assert.rejects(runAssistance({credential:credential(),baseUrl:url}),/literal HTTP loopback origin/);
});

test('runner rejects missing, malformed, and expired credential deadlines before network access',async()=>{
 for(const expiresAt of [undefined,'later',new Date(Date.now()-1).toISOString()])await assert.rejects(runAssistance({credential:{...credential(),expiresAt},baseUrl:'http://127.0.0.1:1'}),/expired or has an invalid expiresAt/);
});

test('synthetic fixture output is visibly distinct from actual model output',()=>{
 const output=syntheticAssistanceFixture({bundleHash:'a'.repeat(64),evidence:[{ref:'source/event'}]});assert.equal(output.fixture,true);assert.match(output.draft.limitations[0],/Synthetic/);assert.equal(output.providerReportedModel,'fdtn-ai/Foundation-Sec-1.1-8B-Instruct');
});

test('runner independently rejects a package whose content no longer matches its bound hash',async()=>{
 const originalFetch=globalThis.fetch,profileSnapshot={id:'evidence-organizer',version:1,instructions:['Bounded original']},profileSnapshotHash=digest(profileSnapshot),core={format:'evidscope-assistance-package-v1',caseId:'case',actionId:'action',contextHash:'a'.repeat(64),caseSnapshotHash:'b'.repeat(64),profileSnapshot,profileSnapshotHash,evidence:[{ref:'source/event'}],analysisSnapshot:{},governanceSnapshot:{},createdAt:new Date().toISOString(),createdBy:'human',limitations:['bounded']},pkg={id:'package',status:'prepared',...core,bundleHash:digest(core)},tampered=structuredClone(pkg);tampered.profileSnapshot.instructions=['FORGED INSTRUCTION'];let calls=0;
 globalThis.fetch=async url=>{calls++;if(!String(url).endsWith('/package'))throw Error('Runner reached model or result after package mismatch');return new Response(JSON.stringify({run:{id:credential().runId,packageId:pkg.id,packageHash:pkg.bundleHash,profileHash:pkg.profileSnapshotHash,expiresAt:new Date(Date.now()+60000).toISOString()},package:tampered}),{status:200,headers:{'content-type':'application/json'}});};
 try{await assert.rejects(runAssistance({credential:credential(),baseUrl:'http://127.0.0.1:1'}),/package_hash_mismatch/);assert.equal(calls,1);}finally{globalThis.fetch=originalFetch;}
});
