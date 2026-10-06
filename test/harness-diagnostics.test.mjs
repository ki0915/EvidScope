import test from 'node:test';
import assert from 'node:assert/strict';
import {once} from 'node:events';
import {readFileSync,readdirSync} from 'node:fs';
import {dirname} from 'node:path';
import {harness} from './harness.mjs';

test('harness API failure preserves the original error and cause with private fixture diagnostics',async t=>{
 const h=await harness();t.after(()=>h.close());
 assert.equal((await h.api('/api/investigations')).status,200);
 const stopped=once(h.audit.child,'exit');h.audit.child.send('shutdown');
 const [exitCode,signal]=await stopped;assert.equal(exitCode,0);assert.equal(signal,null);
 const bodySecret='PRIVATE-BODY-NOT-FOR-DIAGNOSTICS',headerSecret='PRIVATE-HEADER-NOT-FOR-DIAGNOSTICS';
 const originalFetch=globalThis.fetch;let originalError,originalCause,fetchCalls=0;
 // Observe the actual fetch rejection; this wrapper sends the unchanged request once.
 globalThis.fetch=async(...args)=>{fetchCalls++;try{return await originalFetch(...args);}catch(error){originalError=error;originalCause=error.cause;throw error;}};
 t.after(()=>{globalThis.fetch=originalFetch;});
 let thrown;
 try{await h.api('/api/cases',{role:'reviewer',tenant:'alpha',body:{reason:bodySecret},headers:{'x-private-test':headerSecret}});}catch(error){thrown=error;}finally{globalThis.fetch=originalFetch;}
 assert.ok(thrown instanceof TypeError);assert.equal(thrown,originalError);assert.equal(thrown.cause,originalCause);assert.ok(originalCause);assert.equal(fetchCalls,1);
 const path=thrown.harnessDiagnosticPath;assert.equal(dirname(path),h.dir);assert.match(thrown.message,/Harness diagnostic:/);assert.ok(thrown.message.includes(path));
 assert.equal(readdirSync(h.dir).filter(name=>name.startsWith('harness-failure-')&&name.endsWith('.json')).length,1);
 const raw=readFileSync(path,'utf8'),diagnostic=JSON.parse(raw);
 assert.deepEqual(diagnostic.operation,{operation:'api',phase:'fetch',method:'POST',path:'/api/cases',base:h.audit.url,role:'reviewer',tenant:'alpha'});
 assert.equal(diagnostic.error.name,'TypeError');assert.equal(diagnostic.error.message,'fetch failed');assert.equal(diagnostic.error.cause.code,originalCause.code);assert.ok(diagnostic.error.stack);
 const audit=diagnostic.servers.find(server=>server.pid===h.audit.child.pid);assert.equal(audit.mode,'audit');assert.equal(audit.exitCode,0);assert.equal(audit.signalCode,null);assert.equal(audit.connected,false);assert.ok(audit.combinedLog.includes('"component":"audit"'));
 assert.equal(diagnostic.servers.length,3);assert.ok(diagnostic.servers.every(server=>Number.isInteger(server.pid)));
 for(const secret of [bodySecret,headerSecret,...h.config.principals.map(principal=>principal.token).filter(Boolean)])assert.equal(raw.includes(secret),false);
 assert.equal(Object.hasOwn(diagnostic.operation,'body'),false);assert.equal(Object.hasOwn(diagnostic.operation,'headers'),false);
 t.diagnostic(`Actual fixture failure recorded at ${path}; original cause ${originalCause.code}, audit PID ${audit.pid} exited 0; one fetch, no retry.`);
});
