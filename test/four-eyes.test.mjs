import test from 'node:test';
import assert from 'node:assert/strict';
import {harness} from './harness.mjs';
import {submit} from '../src/client.mjs';

// Regression tests for adversarial-audit finding S10: auditors keep creating cases, but whoever opened a case cannot close
// it, and an exception request only takes effect after a different reviewer approves it (once).
let h;
test.before(async()=>{
 h=await harness();
 const event={id:'four-eyes-event',actionId:'four-eyes-action',traceId:'four-eyes-trace',kind:'intent',occurredAt:new Date().toISOString()};
 assert.equal((await submit(h.ingress.url,h.principal('agent'),event)).status,202);
});
test.after(async()=>{await h?.close();});
const call=(path,body,role)=>h.api(path,{body,role});

test('S10: the principal who opened or reopened a case cannot close it',async()=>{
 const c=(await call('/api/cases',{title:'Four-eyes case',actionId:'four-eyes-action',owner:'investigator'},'auditor')).body;
 assert.equal((await call(`/api/cases/${c.id}`,{status:'closed',reason:'self close'},'auditor')).status,403,'creator cannot close');
 assert.equal((await call(`/api/cases/${c.id}`,{comment:'creator may still comment'},'auditor')).status,200);
 const closed=await call(`/api/cases/${c.id}`,{status:'closed',reason:'second person closes'},'reviewer');
 assert.equal(closed.status,200);assert.equal(closed.body.status,'closed');
 assert.equal((await call(`/api/cases/${c.id}`,{status:'open',reason:'new evidence'},'reviewer')).status,200);
 assert.equal((await call(`/api/cases/${c.id}`,{status:'closed',reason:'reopener closes'},'reviewer')).status,403,'reopener cannot close');
 assert.equal((await call(`/api/cases/${c.id}`,{status:'closed',reason:'another person closes'},'auditor')).body.status,'closed');
 const history=(await call('/api/cases',undefined,'auditor')).body.items.find(item=>item.id===c.id).history;
 assert.deepEqual(history.filter(entry=>entry.status==='closed').map(entry=>entry.by),['alpha-reviewer','alpha-auditor']);
});

test('S10: an exception request needs approval by a different reviewer, exactly once',async()=>{
 const expiresAt=new Date(Date.now()+86400000).toISOString();
 const body={ruleId:'AUTHORITY_MISSING',actionId:'four-eyes-action',owner:'risk-owner',reason:'temporary'};
 const requested=(await call('/api/exceptions',{...body,expiresAt},'auditor')).body;assert.equal(requested.status,'pending');
 assert.equal((await call(`/api/exceptions/${requested.id}/approve`,{},'auditor')).status,403,'auditor cannot approve');
 const own=(await call('/api/exceptions',{...body,expiresAt},'reviewer')).body;
 assert.equal((await call(`/api/exceptions/${own.id}/approve`,{},'reviewer')).status,403,'author cannot approve');
 assert.equal((await call(`/api/exceptions/${requested.id}/approve`,{},'reviewer')).body.status,'approved');
 assert.equal((await call(`/api/exceptions/${requested.id}/approve`,{},'admin')).status,409,'only a pending request can be approved');
 assert.equal((await call('/api/overview',undefined,'auditor')).status,200,'signed action history stays valid');
});
