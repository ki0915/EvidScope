// Only explicitly supplied text is inspected in memory. No source text is returned.
export const CIPHER_MODEL = 'smartm2m-bdg/CipherGuard-V5.0-XLM-RoBERTa';
export const TEXT_FIELDS = Object.freeze(['prompt','response','message','text']);
export const SCREENING_LIMITS = Object.freeze({maxTokens:512,maxChunks:8,overlapTokens:32,timeoutMs:10000,maxInputCharacters:262144});
export const PRIVACY_CATEGORIES = Object.freeze(['PII','Financial Information','Credential/Secret','Location/Device Information','Health/Biometric Information','API Key/Access Token','Account Information','HR/Payroll Information','Internal Document','Legal Information','Organization/Project Information','Real Estate Information']);
const statuses = ['complete','partial','timeout','error','unobserved','off'];
const safetyLabels = ['safe','unsafe','controversial','unknown'];
const reasons = ['completed','chunk_limit','input_limit','deadline','classifier_error','invalid_response','body_unavailable','disabled','no_text'];
function invalid(){const error=new Error('Invalid screening metadata');error.status=400;throw error;}
function only(raw,keys){if(!raw||Array.isArray(raw)||typeof raw!=='object'||Object.keys(raw).some(k=>!keys.includes(k)))invalid();}
function count(value,max=Number.MAX_SAFE_INTEGER){if(!Number.isSafeInteger(value)||value<0||value>max)invalid();return value;}
function fieldsOnly(raw){const result={};if(!raw||typeof raw!=='object'||Array.isArray(raw))return result;for(const field of TEXT_FIELDS)if(typeof raw[field]==='string'&&raw[field].length)result[field]=raw[field];return result;}

export function languageSignals(raw){
 const fields=Object.values(fieldsOnly(raw));let remaining=SCREENING_LIMITS.maxInputCharacters,hangulLetters=0,latinLetters=0,otherLetters=0,complete=true;
 for(const source of fields){if(source.length>remaining)complete=false;const selected=source.slice(0,remaining);remaining-=selected.length;
  // Remove opaque tokens inside allowed text fields; JSON keys and IDs are never sampled.
  const text=selected.replace(/https?:\/\/\S+|\b[A-Fa-f0-9]{16,}\b|\b[A-Za-z0-9_-]{24,}\b|\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/gu,'');
  for(const char of text){if(/\p{Script=Hangul}/u.test(char))hangulLetters++;else if(/\p{Script=Latin}/u.test(char))latinLetters++;else if(/\p{Letter}/u.test(char))otherLetters++;}
 }
 const classification=hangulLetters&&latinLetters?'mixed_script':hangulLetters?'hangul_script':latinLetters?'latin_script':otherLetters?'other_script':'unknown';
 return {classification,hangulLetters,latinLetters,otherLetters,sampledFields:fields.length,complete};
}

export function validateLanguageSignals(raw){
 only(raw,['classification','hangulLetters','latinLetters','otherLetters','sampledFields','complete']);
 if(!['mixed_script','hangul_script','latin_script','other_script','unknown'].includes(raw.classification)||typeof raw.complete!=='boolean')invalid();
 const result={classification:raw.classification,hangulLetters:count(raw.hangulLetters,262144),latinLetters:count(raw.latinLetters,262144),otherLetters:count(raw.otherLetters,262144),sampledFields:count(raw.sampledFields,4),complete:raw.complete};
 const expected=result.hangulLetters&&result.latinLetters?'mixed_script':result.hangulLetters?'hangul_script':result.latinLetters?'latin_script':result.otherLetters?'other_script':'unknown';
 if(expected!==result.classification||result.hangulLetters+result.latinLetters+result.otherLetters>262144)invalid();return result;
}

export function screeningUnavailable(status='off',reason='disabled'){
 return validateScreening({status,safety:'unknown',categories:[],processedChunks:0,totalChunks:null,model:CIPHER_MODEL,reason});
}

export function validateScreening(raw){
 only(raw,['status','safety','categories','processedChunks','totalChunks','model','modelRevision','maxScore','reason']);
 if(!statuses.includes(raw.status)||!safetyLabels.includes(raw.safety)||!Array.isArray(raw.categories)||raw.categories.length>12||raw.categories.some(v=>!PRIVACY_CATEGORIES.includes(v))||new Set(raw.categories).size!==raw.categories.length)invalid();
 const processedChunks=count(raw.processedChunks,8),totalChunks=raw.totalChunks===null?null:count(raw.totalChunks);
 if((totalChunks===null?processedChunks!==0:processedChunks>totalChunks)||raw.model!==CIPHER_MODEL||(raw.reason!==undefined&&!reasons.includes(raw.reason)))invalid();
 if(raw.status==='complete'&&(processedChunks===0||processedChunks!==totalChunks||raw.safety==='unknown'))invalid();
 if(['off','unobserved','error','timeout'].includes(raw.status)&&(raw.safety!=='unknown'||raw.categories.length))invalid();
 if(raw.safety==='safe'&&raw.categories.length)invalid();
 if(['unsafe','controversial'].includes(raw.safety)&&(!raw.categories.length||!processedChunks))invalid();
 if(raw.status==='partial'&&raw.safety==='safe')invalid();
 const result={status:raw.status,safety:raw.safety,categories:[...raw.categories],processedChunks,totalChunks,model:CIPHER_MODEL};
 if(raw.modelRevision!==undefined){if(typeof raw.modelRevision!=='string'||!/^[a-f0-9]{40,64}$/.test(raw.modelRevision))invalid();result.modelRevision=raw.modelRevision;}
 if(raw.maxScore!==undefined){if(typeof raw.maxScore!=='number'||!Number.isFinite(raw.maxScore)||raw.maxScore<0||raw.maxScore>1)invalid();result.maxScore=raw.maxScore;}
 if(raw.reason!==undefined)result.reason=raw.reason;return result;
}

export async function screenContent(raw,{enabled=false,client,timeoutMs=SCREENING_LIMITS.timeoutMs}={}){
 if(!enabled)return screeningUnavailable();const textFields=fieldsOnly(raw);
 if(!Object.keys(textFields).length)return screeningUnavailable('unobserved','no_text');
 if(Object.values(textFields).reduce((n,text)=>n+text.length,0)>SCREENING_LIMITS.maxInputCharacters)return screeningUnavailable('partial','input_limit');
 if(typeof client!=='function')return screeningUnavailable('error','classifier_error');
 const limit=Math.min(SCREENING_LIMITS.timeoutMs,Math.max(1,Number.isFinite(timeoutMs)?timeoutMs:SCREENING_LIMITS.timeoutMs));
 const controller=new AbortController();let timer;const timeout=Symbol('timeout');
 try{
  const result=await Promise.race([Promise.resolve().then(()=>client({textFields,maxTokens:512,maxChunks:8,overlapTokens:32,timeoutMs:limit},{signal:controller.signal})),new Promise(resolve=>{timer=setTimeout(()=>{controller.abort();resolve(timeout);},limit);})]);
  if(result===timeout)return screeningUnavailable('timeout','deadline');
  try{return validateScreening(result);}catch{return screeningUnavailable('error','invalid_response');}
 }catch{return screeningUnavailable('error','classifier_error');}finally{clearTimeout(timer);controller.abort();}
}
