import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync} from 'node:crypto';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve,sep} from 'node:path';
import {Store} from '../src/store.mjs';
import {INVESTIGATION_ROWS_SQL} from '../src/audit-workbench.mjs';
import {SOURCE_LAST_SEEN_SQL} from '../src/monitoring.mjs';

const key=generateKeyPairSync('ed25519').privateKey;

function fixture(t){
 const dir=mkdtempSync(join(tmpdir(),'evidscope-read-index-'));let store=new Store(dir,key);
 t.after(()=>{store.close();assert.ok(resolve(dir).startsWith(resolve(tmpdir())+sep));rmSync(dir,{recursive:true,force:true});});
 const fill=()=>{
  const event=store.db.prepare('INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)'),action=store.db.prepare('INSERT OR IGNORE INTO actions VALUES(?,?,1,0)');
  for(let i=0;i<600;i++){
   event.run('alpha','source-'+(i%3),'event-'+i,'f'+i,'action-'+(i%60),'trace','result',new Date(Date.UTC(2026,0,1)+i*1000).toISOString(),'{}');
   action.run('alpha','action-'+(i%60));
  }
 };
 return {dir,get store(){return store;},fill,reopen(){store.close();store=new Store(dir,key);return store;}};
}
const plan=(store,sql,...args)=>store.db.prepare('EXPLAIN QUERY PLAN '+sql).all(...args).map(row=>row.detail);

// Without event_action_received SQLite's min/max optimisation walks event_received(tenant,received) backwards until the
// wanted action appears: O(events) per action and O(actions x events) for one /api/investigations page.
function assertInvestigationPlan(store){
 const details=plan(store,INVESTIGATION_ROWS_SQL,'alpha','','%%','%%');
 assert.ok(details.includes('SEARCH e USING COVERING INDEX event_action_received (tenant=? AND action_id=?)'),details.join('\n'));
 assert.ok(details.every(detail=>!/event_received\b/.test(detail)&&!/^SCAN e\b/.test(detail)),details.join('\n'));
}
function assertSourcePlan(store){
 assert.deepEqual(plan(store,SOURCE_LAST_SEEN_SQL,'alpha','source-1'),['SEARCH events USING COVERING INDEX event_source_received (tenant=? AND source=?)']);
}

test('investigations last-seen subquery and per-source last-seen are index probes, with and without planner statistics',t=>{
 const h=fixture(t);h.fill();
 assertInvestigationPlan(h.store);assertSourcePlan(h.store);
 h.store.db.exec('ANALYZE');
 assertInvestigationPlan(h.store);assertSourcePlan(h.store);
 const rows=h.store.db.prepare(INVESTIGATION_ROWS_SQL).all('alpha','','%%','%%');
 assert.equal(rows.length,60);assert.equal(rows[0].id,'action-59');assert.equal(rows[0].last_seen,new Date(Date.UTC(2026,0,1)+599*1000).toISOString());
 assert.equal(h.store.db.prepare(SOURCE_LAST_SEEN_SQL).get('alpha','source-2').lastSeen,new Date(Date.UTC(2026,0,1)+599*1000).toISOString());
 assert.equal(h.store.db.prepare(SOURCE_LAST_SEEN_SQL).get('alpha','never-seen').lastSeen,null);
});

test('existing databases gain the covering indexes and lose the redundant prefix index on open',t=>{
 const h=fixture(t);
 h.store.db.exec('DROP INDEX event_action_received;DROP INDEX event_source_received;CREATE INDEX event_action ON events(tenant,action_id);');h.fill();
 assert.ok(plan(h.store,INVESTIGATION_ROWS_SQL,'alpha','','%%','%%').some(detail=>/event_received\b/.test(detail)));
 const store=h.reopen();
 const indexes=store.db.prepare("SELECT name FROM sqlite_schema WHERE type='index' AND tbl_name='events' AND sql IS NOT NULL ORDER BY name").all();
 assert.deepEqual(indexes.map(row=>row.name),['event_action_received','event_received','event_source_received']);
 assertInvestigationPlan(store);assertSourcePlan(store);
});
