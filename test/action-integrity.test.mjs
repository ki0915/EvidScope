import test from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {checkActionProjection,createActionProjectionReducer,reconstructActionProjection} from '../src/action-integrity.mjs';

function fixture(){
 const db=new DatabaseSync(':memory:');db.exec('CREATE TABLE actions(tenant TEXT,id TEXT,version INTEGER NOT NULL,analyzed INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(tenant,id))');
 const records=[],decoded=[];let seq=0;
 const add=(type,payload,tenant='alpha')=>{const row={tenant,seq:++seq,type,payload};records.push(row);return row;};
 const event=(id,keyId=`key-${seq+1}`,header=true)=>{const next=seq+1,row=add('event',{format:'evidscope-encrypted-event-v1',keyId,tenant:'alpha',seq:next,...(header?{actionId:id}:{})});return row;};
 const insert=rows=>{for(const row of rows)db.prepare('INSERT INTO actions VALUES(?,?,?,?)').run(row.tenant,row.id,row.version,row.analyzed);};
 return {db,records,decoded,add,event,insert,close:()=>db.close()};
}

test('replays event, policy, exception, evaluation and per-event retention changes',t=>{
 const h=fixture();t.after(h.close);const first=h.event('a','key-a'),second=h.event('b','key-b');
 h.add('asset',{id:'asset',version:1});h.add('asset',{id:'asset',version:2});
 h.add('rule',{id:'rule',versions:[{version:1,status:'draft'}]});
 h.add('rule',{id:'rule',versions:[{version:1,status:'draft',test:{matches:[]}}]});
 h.add('rule',{id:'rule',versions:[{version:1,status:'active'}]});
 h.add('rule',{id:'rule',versions:[{version:1,status:'active'},{version:2,status:'draft'}]});
 h.add('rule',{id:'rule',versions:[{version:1,status:'retired'},{version:2,status:'active'}]});
 h.add('exception',{id:'exception',status:'pending'});h.add('exception',{id:'exception',status:'approved'});h.add('exception',{id:'exception',status:'expired'});
 h.add('evaluation',{id:'evaluation-a',actionId:'a',version:7,status:'evaluated'});
 h.add('evaluation',{id:'quarantine-b',actionId:'b',version:7,status:'quarantined_resource_limit'});
 h.event('a','key-a-2');h.add('retention_disposition',{keyIds:['key-b'],sequences:[second.seq]});
 const expected=[{tenant:'alpha',id:'a',version:8,analyzed:7},{tenant:'alpha',id:'b',version:8,analyzed:0}];
 assert.deepEqual(reconstructActionProjection('alpha',h.records,h.decoded),expected);h.insert(expected);assert.deepEqual(checkActionProjection(h.db,'alpha',h.records,h.decoded),{valid:true,actions:2});
 assert.equal(first.seq,1);
});

test('legacy encrypted event needs authenticated decoded actionId and fails closed after erasure when unavailable',t=>{
 const h=fixture();t.after(h.close);const row=h.event('legacy','legacy-key',false),event={seq:row.seq,tenant:'alpha',actionId:'legacy'};
 assert.deepEqual(reconstructActionProjection('alpha',h.records,[event]),[{tenant:'alpha',id:'legacy',version:1,analyzed:0}]);
 assert.throws(()=>reconstructActionProjection('alpha',h.records,[]),/actionId is not replayable/);
 h.add('retention_disposition',{keyIds:['legacy-key']});
 assert.deepEqual(reconstructActionProjection('alpha',h.records,[event]),[{tenant:'alpha',id:'legacy',version:2,analyzed:0}]);
 assert.throws(()=>reconstructActionProjection('alpha',h.records,[]),/actionId is not replayable/);
});

test('rejects invalid policy transitions and evaluation versions instead of guessing action state',t=>{
 const h=fixture();t.after(h.close);h.event('a');
 h.add('exception',{id:'exception',status:'approved'});assert.throws(()=>reconstructActionProjection('alpha',h.records),/invalid exception transition/);
 h.records.pop();h.add('evaluation',{id:'evaluation',actionId:'a',version:2,status:'evaluated'});assert.throws(()=>reconstructActionProjection('alpha',h.records),/evaluated action version is not replayable/);
});

for(const mutation of ['modified','deleted','added','tenant relabeled'])test(`exact projection rejects ${mutation} action row`,t=>{
 const h=fixture();t.after(h.close);h.event('action','key-1');h.event('action','key-2');h.insert([{tenant:'alpha',id:'action',version:2,analyzed:0}]);
 if(mutation==='modified')h.db.prepare("UPDATE actions SET version=1,analyzed=1 WHERE tenant='alpha' AND id='action'").run();
 if(mutation==='deleted')h.db.prepare("DELETE FROM actions WHERE tenant='alpha' AND id='action'").run();
 if(mutation==='added')h.db.prepare("INSERT INTO actions VALUES('alpha','unsigned',1,0)").run();
 if(mutation==='tenant relabeled')h.db.prepare("UPDATE actions SET tenant='beta' WHERE tenant='alpha' AND id='action'").run();
 assert.throws(()=>checkActionProjection(h.db,'alpha',h.records,h.decoded),/Action projection differs from signed evidence/);
});

test('retention increments each disposed event and rejects unknown or duplicate sequences',t=>{
 const h=fixture();t.after(h.close);const one=h.event('a','key-1'),two=h.event('a','key-2');h.add('retention_disposition',{keyIds:['key-1','key-2'],sequences:[one.seq,two.seq]});
 assert.deepEqual(reconstructActionProjection('alpha',h.records),[{tenant:'alpha',id:'a',version:4,analyzed:0}]);
 const duplicate=structuredClone(h.records);duplicate.at(-1).payload.sequences=[one.seq,one.seq];duplicate.at(-1).payload.keyIds=['key-1','key-1'];assert.throws(()=>reconstructActionProjection('alpha',duplicate),/invalid retention event sequence/);
 const unknown=structuredClone(h.records);unknown.at(-1).payload.sequences=[999];unknown.at(-1).payload.keyIds=['missing'];assert.throws(()=>reconstructActionProjection('alpha',unknown),/retention event selection mismatch|invalid retention event sequence/);
});

test('exact comparison is independent of locale ordering for mixed-case action IDs',t=>{
 const h=fixture();t.after(h.close);h.event('Z','key-Z');h.event('a','key-a');
 h.insert([{tenant:'alpha',id:'Z',version:1,analyzed:0},{tenant:'alpha',id:'a',version:1,analyzed:0}]);
 assert.deepEqual(checkActionProjection(h.db,'alpha',h.records),{valid:true,actions:2});
});

test('incremental reducer fork matches a full replay without mutating its authenticated prefix',t=>{
 const h=fixture();t.after(h.close);const first=h.event('a','key-a'),prefix=createActionProjectionReducer('alpha');
 prefix.apply(first);assert.deepEqual(prefix.rows(),[{tenant:'alpha',id:'a',version:1,analyzed:0}]);
 const second=h.event('b','key-b'),suffix=prefix.fork();suffix.apply(second);suffix.apply(h.add('asset',{id:'asset',version:1}));
 assert.deepEqual(prefix.rows(),[{tenant:'alpha',id:'a',version:1,analyzed:0}]);
 assert.deepEqual(suffix.finish(),reconstructActionProjection('alpha',h.records));
 assert.equal(prefix.lastSequence,first.seq);assert.equal(suffix.lastSequence,h.records.at(-1).seq);
});

test('failed incremental suffix leaves the authenticated prefix unchanged',t=>{
 const h=fixture();t.after(h.close);const first=h.event('a','key-a'),prefix=createActionProjectionReducer('alpha');prefix.apply(first);
 const candidate=prefix.fork();
 assert.throws(()=>candidate.apply({tenant:'alpha',seq:first.seq+1,type:'evaluation',payload:{actionId:'a',version:2,status:'evaluated'}}),/not replayable/);
 assert.deepEqual(prefix.finish(),[{tenant:'alpha',id:'a',version:1,analyzed:0}]);
 assert.equal(prefix.lastSequence,first.seq);
});

test('incremental reducer accepts authenticated disclosure for a legacy encrypted event',t=>{
 const h=fixture();t.after(h.close);const legacy=h.event('legacy','legacy-key',false),prefix=createActionProjectionReducer('alpha');
 prefix.apply(legacy,{tenant:'alpha',actionId:'legacy'});const candidate=prefix.fork();candidate.apply(h.add('retention_disposition',{keyIds:['legacy-key']}));
 assert.deepEqual(candidate.finish([legacy.seq]),reconstructActionProjection('alpha',h.records,[{seq:legacy.seq,tenant:'alpha',actionId:'legacy'}]));
 assert.deepEqual(prefix.finish([legacy.seq]),[{tenant:'alpha',id:'legacy',version:1,analyzed:0}]);
});
