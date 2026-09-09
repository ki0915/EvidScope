import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
export const guideTool={type:'function',function:{name:'read_product_guide',description:'Read the synthetic product guide from a local fixture. Use the returned id, version and content to answer.',parameters:{type:'object',properties:{version:{type:'string',enum:['1','2']}},required:['version'],additionalProperties:false}}};
export function readGuide(call){
 const fn=call?.function,args=fn?.arguments;
 if(fn?.name!=='read_product_guide'||!args||Array.isArray(args)||Object.keys(args).length!==1||!['1','2'].includes(args.version))throw Error('Unsupported tool or guide version');
 const file=`data/synthetic-knowledge-v${args.version}.json`,raw=readFileSync(file),guide=JSON.parse(raw);
 return {guide,reference:{id:guide.id,kind:'document',role:'retrieved',version:guide.version,hash:hash(raw),locator:'workspace:'+file,description:'Local tool read of a synthetic fixture; real model inference is tested separately'}};
}
export function modelReference(content){
 try{const answer=JSON.parse(content);if(answer.reference?.id!=='product-guide'||!['1','2'].includes(answer.reference.version))return null;return {id:answer.reference.id,version:answer.reference.version,kind:'document',role:'retrieved',description:'Reference explicitly named by the local model; actual use is not proven'};}catch{return null;}
}
export async function localChat(body){
 // Fixed loopback only; model text never controls a URL, file path, credential or shell.
 const response=await fetch('http://127.0.0.1:11434/api/chat',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body),redirect:'error',signal:AbortSignal.timeout(120000)});
 if(!response.ok){await response.body?.cancel();throw Error('Local model HTTP '+response.status);}
 const parts=[];let bytes=0;for await(const part of response.body){bytes+=part.length;if(bytes>1024*1024)throw Error('Local model response limit');parts.push(part);}
 return JSON.parse(Buffer.concat(parts).toString('utf8'));
}
