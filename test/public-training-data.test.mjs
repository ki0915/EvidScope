import test from 'node:test';
import assert from 'node:assert/strict';
import {normalizeKlue,partitionKlue} from '../scripts/prepare-public-training-data.mjs';

const revision='a'.repeat(40);
const dataset=(qas,context='가😀나',title='문서')=>({version:'1.1',data:[{title,source:'wikipedia',paragraphs:[{context,qas}]}]});
const qa=(guid='q1')=>({guid,question:'마지막 글자는?',answers:[{text:'나',answer_start:2}],is_impossible:false,question_type:1});
const normalize=(d,upstreamSplit='train')=>normalizeKlue(d,{upstreamSplit,revision});
const row=(id,title,context='가😀나',upstreamSplit='train')=>normalize(dataset([qa(id)],context,title),upstreamSplit)[0];

test('KLUE normalization uses Unicode code points, preserves originals and never claims local human approval',()=>{
 const original=dataset([qa()]);const normalized=normalize(original)[0];
 assert.equal(normalized.context,'가😀나');
 assert.deepEqual(normalized.answers,[{text:'나',answer_start:2}]);
 assert.deepEqual(normalized.originalQa,original.data[0].paragraphs[0].qas[0]);
 assert.equal(normalized.upstreamAnnotation.localHumanReviewPerformed,false);
 assert.equal(Object.hasOwn(normalized,'humanReviewed'),false);
 assert.equal(Object.hasOwn(normalized,'approvedOutput'),false);
 assert.equal(normalized.machineValidation.privacyStatus,'not_reviewed');
 const utf16=dataset([{...qa(),answers:[{text:'나',answer_start:3}]}]);
 assert.throws(()=>normalize(utf16),/answer_span_invalid/);
});

test('KLUE malformed QA, duplicate identity and inconsistent unanswerable labels fail closed',()=>{
 assert.throws(()=>normalize(dataset([qa(),qa()])),/duplicate_id/);
 assert.throws(()=>normalize(dataset([{...qa(),answers:[]}])),/unanswerable_marker/);
 assert.throws(()=>normalize(dataset([{...qa(),is_impossible:true,question_type:3}])),/unanswerable_marker/);
 assert.throws(()=>normalize(dataset([{...qa(),question_type:3}])),/unanswerable_marker/);
 assert.throws(()=>normalize(dataset([{...qa(),answers:[{text:'없음',answer_start:2}]}])),/answer_span_invalid/);
 const impossible={...qa(),answers:[],is_impossible:true,question_type:3,plausible_answers:[{text:'나',answer_start:2}]};
 assert.deepEqual(normalize(dataset([impossible]))[0].answers,[]);
 assert.deepEqual(normalize(dataset([])),[]); // Upstream includes contexts with zero QA rows.
});

test('document/context components cannot cross derived splits or touch official heldout',()=>{
 const train=[];
 for(let index=0;index<30;index++)train.push(row('train'+index,'문서'+index,'가😀나 '+index));
 train.push({...train[0],id:'duplicate-content'});
 train.push(row('linked-context','새 제목',train[1].context));
 train.push(row('linked-title',train[1].title,'가😀나 다른 문장'));
 const heldout=[row('heldout','보존할 공식 문서',train[0].context,'dev')];
 const result=partitionKlue(train,heldout);
 assert.equal(result.heldout.length,1);
 assert.equal(result.heldout[0].context,heldout[0].context);
 assert.deepEqual(result.heldout[0].originalQa,heldout[0].originalQa);
 assert.equal(result.excluded.filter(v=>v.reason==='family_overlaps_official_dev').length,2);
 const familySplits=new Map();
 for(const split of ['train','validation','heldout'])for(const r of result[split]){
  assert.ok(!familySplits.has(r.familyId)||familySplits.get(r.familyId)===split);
  familySplits.set(r.familyId,split);
 }
 const linked=[...result.train,...result.validation].filter(r=>['train1','linked-title','linked-context'].includes(r.id));
 assert.equal(new Set(linked.map(r=>r.familyId)).size,1);
 assert.equal(new Set(linked.map(r=>r.split)).size,1);
 assert.ok(result.train.length>0&&result.validation.length>0);
 assert.deepEqual(partitionKlue(train,heldout),result);
 assert.throws(()=>partitionKlue([train[0]],[{...train[0],upstreamSplit:'dev'}]),/duplicate_id/);
});

test('duplicate training questions are excluded while distinct questions remain in the same family',()=>{
 const first=row('original','제목');
 const duplicate={...first,id:'duplicate'};
 const distinct={...first,id:'different',question:'답은 무엇인가요?'};
 const result=partitionKlue([first,duplicate,distinct],[]);
 assert.deepEqual(result.excluded,[{id:'duplicate',reason:'duplicate_context_question'}]);
 assert.equal(result.train.length+result.validation.length,2);
});
