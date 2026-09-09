import test from 'node:test';
import assert from 'node:assert/strict';
import {runAssistance,syntheticAssistanceFixture} from '../src/assistance-runner.mjs';

const credential=()=>({format:'evidscope-assistance-credential-v1',runId:'00000000-0000-4000-8000-000000000000',token:'not-a-real-secret',expiresAt:new Date(Date.now()+60000).toISOString()});

test('runner rejects DNS aliases and decorated loopback URLs before reading a credential scope',async()=>{
 for(const url of ['http://localhost:8080','https://127.0.0.1:8080','http://user:pass@127.0.0.1:8080','http://127.0.0.1:8080/path','http://127.0.0.1:8080/?next=cloud'])await assert.rejects(runAssistance({credential:credential(),baseUrl:url}),/literal HTTP loopback origin/);
});

test('runner rejects missing, malformed, and expired credential deadlines before network access',async()=>{
 for(const expiresAt of [undefined,'later',new Date(Date.now()-1).toISOString()])await assert.rejects(runAssistance({credential:{...credential(),expiresAt},baseUrl:'http://127.0.0.1:1'}),/expired or has an invalid expiresAt/);
});

test('synthetic fixture output is visibly distinct from actual model output',()=>{
 const output=syntheticAssistanceFixture({bundleHash:'a'.repeat(64),evidence:[{ref:'source/event'}]});assert.equal(output.fixture,true);assert.match(output.draft.limitations[0],/Synthetic/);assert.equal(output.providerReportedModel,'qwen3:4b');
});
