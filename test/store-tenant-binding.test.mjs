import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync} from 'node:crypto';
import {mkdtempSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {Store} from '../src/store.mjs';

function fixture(t){const store=new Store(mkdtempSync(join(tmpdir(),'evidscope-sql-binding-')),generateKeyPairSync('ed25519').privateKey);t.after(()=>store.close());for(const tenant of ['alpha','beta'])store.transaction(()=>store.append(tenant,'audit_access',{operation:'synthetic'},tenant+'-user'));return store;}

test('moving signed rows to another SQL tenant cannot turn valid signatures into tenant authority',t=>{
 const store=fixture(t),before=store.bundle('alpha');store.db.exec('DROP TRIGGER immutable_update');
 store.db.prepare('UPDATE ledger SET tenant=? WHERE tenant=?').run('other','beta');store.db.prepare('UPDATE checkpoints SET tenant=? WHERE tenant=?').run('other','beta');
 for(const method of ['rawBundle','bundle','ledgerEvents','checkProjection'])assert.throws(()=>store[method]('other'),/tenant/);
 assert.deepEqual(store.bundle('alpha'),before);
});

test('SQL sequence changes are detected even when record bodies and checkpoint still verify internally',t=>{
 const store=fixture(t);store.db.exec('DROP TRIGGER immutable_update');store.db.prepare('UPDATE ledger SET seq=? WHERE tenant=?').run(99,'alpha');assert.throws(()=>store.bundle('alpha'),/sequence/);assert.equal(store.bundle('beta').checkpoint.count,1);
});

test('an empty tenant cannot inherit another tenant checkpoint',t=>{
 const store=fixture(t),cp=store.db.prepare('SELECT body FROM checkpoints WHERE tenant=?').get('alpha').body;
 store.db.prepare('INSERT INTO checkpoints VALUES(?,?)').run('empty',cp);assert.throws(()=>store.rawBundle('empty'),/tenant/);
});
