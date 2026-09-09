import {randomBytes,randomUUID,createCipheriv,createDecipheriv} from 'node:crypto';
import {canonical,digest} from './crypto.mjs';
export function encryptEvent(event,tenant,seq,policy) {
 const key=randomBytes(32),iv=randomBytes(12),keyId=randomUUID();
 const header={format:'evidscope-encrypted-event-v1',keyId,tenant,seq,actionId:event.actionId,policyVersion:policy.version,retainUntil:new Date(Date.parse(event.receivedAt)+policy.retentionSeconds*1000).toISOString()};
 const cipher=createCipheriv('aes-256-gcm',key,iv);cipher.setAAD(Buffer.from(canonical(header)));
 const plaintext=canonical(event),ciphertext=Buffer.concat([cipher.update(plaintext,'utf8'),cipher.final()]);
 return {key,keyId,payload:{...header,iv:iv.toString('base64'),ciphertext:ciphertext.toString('base64'),tag:cipher.getAuthTag().toString('base64'),payloadHash:digest(plaintext)}};
}
export function decryptEvent(payload,key){
 const {format,keyId,tenant,seq,policyVersion,retainUntil}=payload;
 const header={format,keyId,tenant,seq,policyVersion,retainUntil};if(Object.hasOwn(payload,'actionId'))header.actionId=payload.actionId;
 const decipher=createDecipheriv('aes-256-gcm',key,Buffer.from(payload.iv,'base64'));decipher.setAAD(Buffer.from(canonical(header)));decipher.setAuthTag(Buffer.from(payload.tag,'base64'));
 const plaintext=Buffer.concat([decipher.update(Buffer.from(payload.ciphertext,'base64')),decipher.final()]).toString('utf8');if(digest(plaintext)!==payload.payloadHash)throw Error('Event plaintext commitment mismatch');const event=JSON.parse(plaintext);if(Object.hasOwn(payload,'actionId')&&event.actionId!==payload.actionId)throw Error('Event action header mismatch');return event;
}
