import {cleanText,date,fail} from './model.mjs';

const object=value=>value&&typeof value==='object'&&!Array.isArray(value);
const fields=(value,names)=>object(value)&&Object.keys(value).every(name=>names.includes(name));
const nonempty=(value,max)=>{const text=cleanText(value,max).trim();if(!text)fail(400,'공급사 출처·검토 근거를 입력해야 합니다');return text;};
export function normalizeSupplierProvenance(synthetic,value){
 if(typeof synthetic!=='boolean')fail(400,'증빙 synthetic은 true 또는 false로 명시해야 합니다');
 if(value===undefined&&synthetic)return undefined;
 if(!fields(value,['channel','reference','suppliedAt'])||!['supplier_portal','email','contract_attachment','manual_upload'].includes(value.channel))fail(400,'실제 공급사 증빙에는 수신 경로·참조 provenance가 필요합니다');
 return {channel:value.channel,reference:nonempty(value.reference,1000),...(value.suppliedAt===undefined?{}:{suppliedAt:date(value.suppliedAt)})};
}

export function normalizeSupplierProvenanceReview(input,bundle){
 const checks=['supplierIdentityChecked','deliveryReferenceChecked','modelPurposeScopeChecked'];
 if(!fields(input,['bundleHash','decision','reason','checks'])||!['verified','unverified','rejected'].includes(input.decision))fail(400,'출처 검토 결정·근거·확인 항목이 필요합니다');
 if(!/^[a-f0-9]{64}$/.test(input.bundleHash||'')||input.bundleHash!==bundle.contentHash)fail(409,'현재 공급사 증빙 해시와 검토 대상이 다릅니다');
 if(!fields(input.checks,checks)||checks.some(name=>typeof input.checks[name]!=='boolean'))fail(400,'출처 확인 항목은 각각 true 또는 false로 명시해야 합니다');
 if(input.decision==='verified'&&checks.some(name=>input.checks[name]!==true))fail(400,'출처 확인 검토에는 공급사·수신 참조·모델 목적 범위 확인이 모두 필요합니다');
 return {decision:input.decision,reason:nonempty(input.reason,2000),checks:Object.fromEntries(checks.map(name=>[name,input.checks[name]]))};
}
