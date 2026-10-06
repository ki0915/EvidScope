import test from 'node:test';
import assert from 'node:assert/strict';
import {CIPHER_MODEL,SCREENING_LIMITS,languageSignals,validateLanguageSignals,screenContent,validateScreening} from '../src/content-screening.mjs';

const safe={status:'complete',safety:'safe',categories:[],processedChunks:1,totalChunks:1,model:CIPHER_MODEL,reason:'completed'};

test('script measurement samples only allowed text fields and distinguishes Unicode scripts without guessing language',()=>{
 assert.equal(languageSignals({model:'english-model',traceId:'abcdefgh',headers:{message:'private'}}).classification,'unknown');
 assert.equal(languageSignals({message:'승인되지 않은 접근입니다'}).classification,'hangul_script');
 assert.equal(languageSignals({message:'Access denied'}).classification,'latin_script');
 assert.equal(languageSignals({message:'Access denied: 승인이 없습니다 🔐'}).classification,'mixed_script');
 assert.equal(languageSignals({message:'拒否されました'}).classification,'other_script');
 assert.equal(languageSignals({message:'1234 🔐 https://sensitive.example/a?secret=yes'}).classification,'unknown');
 assert.equal(languageSignals({message:'가나'}).classification,'hangul_script');
 assert.equal(languageSignals({prompt:'한국어',response:'English'}).sampledFields,2);
 assert.throws(()=>validateLanguageSignals({...languageSignals({message:'한국어'}),classification:'latin_script'}));
 assert.throws(()=>validateLanguageSignals({...languageSignals({message:'한국어'}),rawText:'secret'}));
 const bounded=languageSignals({message:'a'.repeat(262144)+'한글'});assert.equal(bounded.complete,false);
});

test('screening is off by default, body absent is unobserved, errors preserve no input or server error',async()=>{
 const canary='DO-NOT-PERSIST-SECRET-한국어';let called=0;
 assert.equal((await screenContent({prompt:canary},{client:()=>{called++;}})).status,'off');assert.equal(called,0);
 assert.equal((await screenContent({model:'some-model'},{enabled:true,client:()=>{called++;}})).status,'unobserved');assert.equal(called,0);
 const failed=await screenContent({prompt:canary},{enabled:true,client:()=>{throw new Error(canary);}});
 assert.equal(failed.status,'error');assert.equal(failed.safety,'unknown');assert.ok(!JSON.stringify(failed).includes(canary));
 const unknown=await screenContent({prompt:canary},{enabled:true,client:async()=>({...safe,raw:canary})});assert.equal(unknown.reason,'invalid_response');assert.ok(!JSON.stringify(unknown).includes(canary));
});

test('full tail reaches the tokenizer owner and partial chunks never become a safe verdict',async()=>{
 const tail='TAIL-SENSITIVE-CANARY',prompt='English and 한글 '.repeat(400)+tail;let received;
 const result=await screenContent({prompt,authorization:'Bearer SECRET',metadata:{text:'SECRET'}},{enabled:true,client:async payload=>{received=payload;return {status:'partial',safety:'unsafe',categories:['API Key/Access Token'],processedChunks:8,totalChunks:12,model:CIPHER_MODEL,reason:'chunk_limit',maxScore:0.9};}});
 assert.equal(received.textFields.prompt,prompt);assert.ok(received.textFields.prompt.endsWith(tail));assert.deepEqual(Object.keys(received.textFields),['prompt']);
 assert.deepEqual([received.maxTokens,received.maxChunks,received.overlapTokens,received.timeoutMs],[512,8,32,10000]);
 assert.equal(result.status,'partial');assert.equal(result.safety,'unsafe');assert.ok(!JSON.stringify(result).includes(tail));
 const misleading=await screenContent({prompt},{enabled:true,client:async()=>({...safe,status:'partial',processedChunks:8,totalChunks:12})});assert.equal(misleading.status,'error');
 const tooBig=await screenContent({prompt:'x'.repeat(SCREENING_LIMITS.maxInputCharacters+1)},{enabled:true,client:()=>assert.fail('oversize input must not be submitted')});assert.equal(tooBig.status,'partial');assert.equal(tooBig.reason,'input_limit');
});

test('deadline aborts local transport and unknown differs from a safe result',async()=>{
 let signal;const result=await screenContent({text:'test'},{enabled:true,timeoutMs:10,client:async(_payload,options)=>{signal=options.signal;await new Promise(()=>{});}});
 assert.equal(result.status,'timeout');assert.equal(result.safety,'unknown');assert.equal(signal.aborted,true);
});

test('classifier metadata rejects false complete coverage, invented categories, text spans and numeric anomalies',()=>{
 for(const raw of [{...safe,totalChunks:2},{...safe,processedChunks:9,totalChunks:9},{...safe,safety:'unsafe'},{...safe,safety:'unsafe',categories:['attack_detected']},{...safe,maxScore:NaN},{...safe,spans:[]},{...safe,modelRevision:'main'},{...safe,reason:'SECRET'},{...safe,status:'off'}])assert.throws(()=>validateScreening(raw));
 assert.equal(validateScreening({...safe,modelRevision:'a'.repeat(40)}).modelRevision,'a'.repeat(40));
});

test('production transport must be injected explicitly and no host model endpoint is opened',async()=>{
 const result=await screenContent({text:'temporary'},{enabled:true});assert.equal(result.status,'error');assert.equal(result.reason,'classifier_error');assert.equal(result.totalChunks,null);
 assert.equal((await screenContent({text:'temporary'},{enabled:true,client:async()=>safe})).status,'complete');
});
