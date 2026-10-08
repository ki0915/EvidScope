import {randomBytes,randomUUID,createCipheriv,createDecipheriv} from 'node:crypto';
import {canonical,digest,payloadCommitment,secretKey,ENCRYPTED_EVENT_V1,ENCRYPTED_EVENT_V2,PAYLOAD_COMMITMENT_V2,COMMITMENT_SALT_BYTES} from './crypto.mjs';
export const EVENT_KEY_BYTES=32;
// Key material of an event: v1 is the 32-byte AES key; v2 is key || 32-byte commitment salt (one secret, erased together).
export const eventKeyMaterialBytes=payload=>payload?.format===ENCRYPTED_EVENT_V2?EVENT_KEY_BYTES+COMMITMENT_SALT_BYTES:EVENT_KEY_BYTES;
// v2 pads the canonical JSON with spaces (JSON whitespace) to a multiple of 64 bytes, so the ciphertext shows the length of
// an event only in 64-byte steps. openEvent parses either form; the commitment covers the event, not the padding.
const PADDING_BYTES=64,padded=text=>text+' '.repeat((PADDING_BYTES-Buffer.byteLength(text)%PADDING_BYTES)%PADDING_BYTES);
// retention: {policy, retainUntil, keyEpoch} from Store.eventRetention. Writes v2 only; v1 stays readable.
export function encryptEvent(event,tenant,seq,{policy,retainUntil,keyEpoch}) {
 const key=randomBytes(EVENT_KEY_BYTES),salt=randomBytes(COMMITMENT_SALT_BYTES),iv=randomBytes(12),keyId=randomUUID();
 const header={format:ENCRYPTED_EVENT_V2,keyId,tenant,seq,actionId:event.actionId,policyVersion:policy.version,retainUntil,keyEpoch,commitmentAlg:PAYLOAD_COMMITMENT_V2};
 const cipher=createCipheriv('aes-256-gcm',secretKey(key),iv);cipher.setAAD(Buffer.from(canonical(header)));
 const text=canonical(event),plaintext=padded(text),ciphertext=Buffer.concat([cipher.update(plaintext,'utf8'),cipher.final()]);
// text: the canonical plaintext, for a writer that keeps what it just sealed (Store._advanceVerifiedStates); not stored.
 return {material:Buffer.concat([key,salt]),keyId,text,payload:{...header,iv:iv.toString('base64'),ciphertext:ciphertext.toString('base64'),
  tag:cipher.getAuthTag().toString('base64'),payloadCommitment:payloadCommitment(salt,event,text)}};
}
// Returns {event, salt}; salt is null for v1. Throws unless the plaintext matches the ledger commitment.
export function openEvent(payload,material){
 const v2=payload.format===ENCRYPTED_EVENT_V2;
 if(!v2&&payload.format!==ENCRYPTED_EVENT_V1)throw Error('Unsupported event envelope');
 const bytes=Buffer.from(material);if(bytes.length!==eventKeyMaterialBytes(payload))throw Error('Event key material has the wrong length');
 const {format,keyId,tenant,seq,policyVersion,retainUntil}=payload;
 const header={format,keyId,tenant,seq,policyVersion,retainUntil};
 if(v2)Object.assign(header,{actionId:payload.actionId,keyEpoch:payload.keyEpoch,commitmentAlg:payload.commitmentAlg});
 else if(Object.hasOwn(payload,'actionId'))header.actionId=payload.actionId;
 if(v2&&payload.commitmentAlg!==PAYLOAD_COMMITMENT_V2)throw Error('Unsupported payload commitment');
 const decipher=createDecipheriv('aes-256-gcm',secretKey(bytes.subarray(0,EVENT_KEY_BYTES)),Buffer.from(payload.iv,'base64'));
 decipher.setAAD(Buffer.from(canonical(header)));decipher.setAuthTag(Buffer.from(payload.tag,'base64'));
 const plaintext=Buffer.concat([decipher.update(Buffer.from(payload.ciphertext,'base64')),decipher.final()]).toString('utf8');
 let event,salt=null;
 if(v2){salt=bytes.subarray(EVENT_KEY_BYTES);event=JSON.parse(plaintext);if(payloadCommitment(salt,event)!==payload.payloadCommitment)throw Error('Event plaintext commitment mismatch');}
 else{if(digest(plaintext)!==payload.payloadHash)throw Error('Event plaintext commitment mismatch');event=JSON.parse(plaintext);}
 if(Object.hasOwn(payload,'actionId')&&event.actionId!==payload.actionId)throw Error('Event action header mismatch');
 return {event,salt};
}
export const decryptEvent=(payload,key)=>openEvent(payload,key).event;
