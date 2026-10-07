// Round 3 re-audit: a database writer (no keys) must not reach the event keystore. The first move from database mode marks
// itself in evidence.db (event_keystore_usage.moved_at), which that writer can clear; the keystore then imported planted epoch
// rows on the next start: a known secret for a future epoch (its events readable from any copy of evidence.db, even after the
// epoch is destroyed) and a tombstone that destroyed a live epoch in the keystore (its events lost in every backup).
import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {existsSync,readdirSync} from 'node:fs';
import {join} from 'node:path';
import {DatabaseSync} from 'node:sqlite';
import {createKeyring,generateDataKeyFile,readDataKeyFile} from '../src/data-keys.mjs';
import {createEventKeystore,dataKeySealer,openEventKeystore} from '../src/event-keystore.mjs';
import {tempDir} from './temp-dir.mjs';
import {vault} from './event-key-vault.mjs';

const TAG=/^fp2:(\d{4}-(?:0[1-9]|1[0-2])):[a-f0-9]{64}$/;
const event=id=>({id,actionId:id,traceId:'planted',kind:'intent',occurredAt:new Date().toISOString(),note:`note of ${id}`});

test('epoch rows planted in evidence.db after the first move never reach the event keystore, even with moved_at cleared',async t=>{
 const root=tempDir('evidscope-planted-'),dataDir=join(root,'data'),keystoreDir=join(root,'keystore'),keyFile=join(root,'data.key');
 generateDataKeyFile(keyFile);createEventKeystore(keystoreDir);
 const options={dataKey:readDataKeyFile(keyFile),eventKeystoreDir:keystoreDir};
 const keystore=()=>openEventKeystore({dir:keystoreDir,sealer:dataKeySealer(createKeyring({dataKey:options.dataKey})),dataDir});
 const v=vault(t,{dir:dataDir,options,cleanup:false});
 assert.equal((await v.ingest(event('live-1'))).status,202);
 const receipt=v.store.bundle('alpha').records.find(row=>row.type==='event_receipt').payload,live=TAG.exec(receipt.fingerprint)[1];
 v.store.close();
 // The database writer: forget the completed move, plant a known secret for a future month and a tombstone for the live epoch.
 const known=randomBytes(32),future='2099-12',db=new DatabaseSync(join(dataDir,'evidence.db'));
 db.prepare('UPDATE event_keystore_usage SET moved_at=NULL').run();
 db.prepare('INSERT INTO event_key_epochs VALUES(?,?,?,?)').run('alpha',future,known,new Date().toISOString());
 db.prepare('INSERT INTO event_key_epoch_tombstones VALUES(?,?,?,?)').run('alpha',live,new Date().toISOString(),'database');
 db.close();
 const again=vault(t,{dir:dataDir,key:v.key,options,cleanup:false});
 assert.deepEqual([again.service.eventKeystore.importedEpochs,again.service.eventKeystore.importedTombstones],[0,0]);
 const ks=keystore();
 assert.equal(ks.destroyed('alpha',live),false,'a planted tombstone destroyed a live epoch in the keystore');
 assert.equal(ks.present('alpha',live),true);
 assert.equal(ks.available('alpha',future),false,'a planted known secret became a keystore epoch');
 assert.deepEqual(again.store.ledgerEvents('alpha').map(item=>item.note),['note of live-1']);
 // The planted rows stay where they are and the integrity check names them for review.
 const integrity=(await again.call('/api/integrity','alpha-reviewer')).body;
 assert.equal(integrity.valid,false);assert.match(integrity.error,/epoch row\(s\) beside its event keystore/);
 assert.equal(existsSync(join(keystoreDir,'moved.json')),true);
 assert.ok(readdirSync(join(keystoreDir,'epochs'),{recursive:true}).filter(name=>name.endsWith('.json')).length===1);
});
