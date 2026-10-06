const receiptKey=(source,id)=>JSON.stringify([source,id]);
const digest=/^[a-f0-9]{64}$/;

function receiptEntries(tenant,records,events){
 const eventRows=new Map(records.filter(row=>row.type==='event').map(row=>[row.seq,row]));
 const disposedAt=new Map();
 for(const row of records.filter(row=>row.type==='retention_disposition'))for(const keyId of row.payload?.keyIds||[])if(!disposedAt.has(keyId))disposedAt.set(keyId,row.seq);
 const retainedBySequence=new Map(events.map(event=>[event.seq,event]));
 const entries=new Map(),coveredSequences=new Set();
 let signedReceipts=0,legacyRetainedReceipts=0;
 for(const row of records){
  if(row.type!=='event_receipt')continue;
  const value=row.payload||{},event=eventRows.get(value.eventSeq);
  if(value.format!=='evidscope-event-receipt-v1'||typeof value.source!=='string'||!value.source||typeof value.id!=='string'||!value.id||!digest.test(value.fingerprint||'')||!Number.isSafeInteger(value.eventSeq)||value.eventSeq<1||!digest.test(value.eventHash||'')||!event||event.hash!==value.eventHash||row.seq<=value.eventSeq)throw Error('Receipt signed history is invalid');
  const dispositionSeq=disposedAt.get(event.payload?.keyId);if(dispositionSeq!==undefined&&row.seq>=dispositionSeq)throw Error('Receipt was not preserved before event disposition');
  if(value.basis!==undefined&&!['source_ingest','verified_before_retention'].includes(value.basis))throw Error('Receipt signed history has an invalid basis');
  if(value.basis==='source_ingest'&&row.principal!==value.source)throw Error('Receipt source attestation principal differs');
  if(value.basis==='verified_before_retention'&&value.attestedBy!==row.principal)throw Error('Receipt retention attestation principal differs');
  const key=receiptKey(value.source,value.id);
  if(entries.has(key)||coveredSequences.has(value.eventSeq))throw Error('Receipt signed history is duplicated');
  const retained=retainedBySequence.get(value.eventSeq);
  if(retained&&(retained.source!==value.source||retained.id!==value.id||retained.fingerprint!==value.fingerprint))throw Error('Receipt signed history differs from retained event');
  entries.set(key,{source:value.source,id:value.id,fingerprint:value.fingerprint,eventSeq:value.eventSeq,eventHash:value.eventHash,signed:true});
  coveredSequences.add(value.eventSeq);signedReceipts++;
 }
 for(const event of events){
  const key=receiptKey(event.source,event.id),existing=entries.get(key);
  if(existing){if(existing.eventSeq!==event.seq||existing.eventHash!==event.hash||existing.fingerprint!==event.fingerprint)throw Error('Receipt signed history differs from retained event');continue;}
  if(coveredSequences.has(event.seq)||typeof event.fingerprint!=='string'||!event.fingerprint)throw Error('Receipt retained event identity is invalid');
  entries.set(key,{source:event.source,id:event.id,fingerprint:event.fingerprint,eventSeq:event.seq,eventHash:event.hash,signed:false});
  coveredSequences.add(event.seq);legacyRetainedReceipts++;
 }
 for(const row of eventRows.values())if(!coveredSequences.has(row.seq))throw Error('Receipt history is missing for disposed legacy event');
 return {entries,signedReceipts,legacyRetainedReceipts};
}

export function expectedReceiptProjection(tenant,records,events){
 if(typeof tenant!=='string'||!Array.isArray(records)||!Array.isArray(events))throw Error('Receipt verification input is invalid');
 return receiptEntries(tenant,records,events);
}

export function checkReceiptProjection(db,tenant,records,events){
 const expected=receiptEntries(tenant,records,events),rows=db.prepare('SELECT source,id,fingerprint FROM receipts WHERE tenant=? ORDER BY source,id').all(tenant);
 if(rows.length!==expected.entries.size)throw Error('Receipt projection count differs from signed history');
 for(const row of rows){const value=expected.entries.get(receiptKey(row.source,row.id));if(!value||value.fingerprint!==row.fingerprint)throw Error('Receipt projection differs from signed history');}
 return {valid:true,receipts:rows.length,signedReceipts:expected.signedReceipts,legacyRetainedReceipts:expected.legacyRetainedReceipts,unverifiableLegacyDisposedReceipts:0};
}
