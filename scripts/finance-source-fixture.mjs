import {randomUUID} from 'node:crypto';
import {mac} from '../src/crypto.mjs';
// Synthetic independent producer. Credentials arrive over IPC, never command-line arguments.
process.once('message',({principal,events})=>{
 const records=events.map(event=>{const body=JSON.stringify(event),timestamp=String(Date.now()),nonce=randomUUID();return {body,headers:{authorization:'Bearer '+principal.token,'x-evid-timestamp':timestamp,'x-evid-nonce':nonce,'x-evid-signature':mac(principal.hmacSecret,timestamp,nonce,body)}};});
 process.send({pid:process.pid,source:principal.id,records},()=>process.disconnect());
});
