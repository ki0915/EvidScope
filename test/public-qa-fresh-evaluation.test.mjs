import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,mkdirSync,readFileSync,rmSync} from 'node:fs';
import {join,resolve,sep} from 'node:path';
import {createHash} from 'node:crypto';
import {selectFreshEvaluation,writeFrozenEvaluation} from '../scripts/prepare-public-qa-fresh-evaluation.mjs';
import {revision} from '../scripts/prepare-public-qa-run.mjs';

const sha=value=>createHash('sha256').update(value).digest('hex');
function row(id,isImpossible=false){
 const context=`한국의 공개 자료 ${id}에는 답이 서울이라고 쓰여 있다.`,question=isImpossible?'자료에 없는 설립자는?':'자료의 답은?';
 const answers=isImpossible?[]:[{text:'서울',answer_start:Array.from(context.slice(0,context.indexOf('서울'))).length}];
 return {id,familyId:'family-'+id,contextSha256:sha(context),context,question,answers,isImpossible,split:'heldout',upstreamSplit:'dev',
  upstreamRevision:revision,language:'ko',sourceLicense:'CC-BY-SA-4.0',upstreamAnnotation:{kind:'human_authored_question_answer_spans'},
  originalQa:{question,answers:structuredClone(answers),is_impossible:isImpossible}};
}
const pool=()=>[...Array.from({length:8},(_,i)=>row('positive'+i)),...Array.from({length:8},(_,i)=>row('negative'+i,true))];

test('fresh heldout selection excludes prior IDs, families and contexts, preserves human labels and unique passages',()=>{
 const source=pool(),exposed=[{id:source[0].id,familyId:'other',contextSha256:'other'},
  {id:'other',familyId:source[1].familyId,contextSha256:'other'},
  {id:'other',familyId:'other',contextSha256:source[2].contextSha256}];
 const selected=selectFreshEvaluation(source,exposed,{perLabel:2});
 assert.equal(selected.sufficient,true);assert.equal(selected.excluded.previousExposure,3);
 assert.deepEqual(selected.counts,{answerable:2,impossible:2});assert.equal(selected.uniqueSelectedFamilies,4);assert.equal(selected.uniqueSelectedContexts,4);
 for(const chosen of selected.rows){
  const original=source.find(item=>item.id===chosen.id);
  for(const key of ['question','context','answers','originalQa','isImpossible','contextSha256','upstreamAnnotation'])assert.deepEqual(chosen[key],original[key]);
  assert.ok(!exposed.some(prior=>['id','familyId','contextSha256'].some(key=>prior[key]===chosen[key])));
 }
 assert.deepEqual(selectFreshEvaluation(source.slice().reverse(),exposed,{perLabel:2}).rows,selected.rows);
});

test('modified human answers, incorrect Unicode spans and duplicate source IDs fail rather than creating labels',()=>{
 const source=pool(),changed=structuredClone(source);changed[0].answers[0].text='한국';
 assert.throws(()=>selectFreshEvaluation(changed,[],{perLabel:2}),/original_changed/);
 const span=structuredClone(source);span[0].answers[0].answer_start++;
 span[0].originalQa.answers=structuredClone(span[0].answers);
 assert.throws(()=>selectFreshEvaluation(span,[],{perLabel:2}),/answer_span_invalid/);
 assert.throws(()=>selectFreshEvaluation([...source,source[0]],[],{perLabel:2}),/duplicate_source_id/);
 const wrong=structuredClone(source);wrong[0].upstreamSplit='train';
 assert.throws(()=>selectFreshEvaluation(wrong,[],{perLabel:2}),/original_provenance_invalid/);
});

test('long original passages and privacy patterns are counted; insufficient classes never emit partial evaluation rows',()=>{
 const source=pool();source[0].context+=' 원문'.repeat(300);source[0].contextSha256=sha(source[0].context);
 source[1].context+=' example@example.org';source[1].contextSha256=sha(source[1].context);
 const selected=selectFreshEvaluation(source,[],{perLabel:2});
 assert.equal(selected.excluded.contextTooLong,1);assert.equal(selected.excluded.privacyPattern,1);
 const missing=selectFreshEvaluation(source.filter(item=>!item.isImpossible),[],{perLabel:2});
 assert.equal(missing.sufficient,false);assert.deepEqual(missing.rows,[]);assert.equal(missing.availableCounts.impossible,0);
});

test('frozen evaluation cannot be replaced even with identical content; existing data remains byte-identical',t=>{
 const scratch=resolve('.test-runs');mkdirSync(scratch,{recursive:true});const directory=mkdtempSync(join(scratch,'fresh-evaluation-cpu-'));
 t.after(()=>{assert.ok(resolve(directory).startsWith(scratch+sep));rmSync(directory,{recursive:true,force:true});});
 const output=join(directory,'frozen'),rows=selectFreshEvaluation(pool(),[],{perLabel:2}).rows;
 const bytes=Buffer.from(rows.map(item=>JSON.stringify(item)).join('\n')+'\n'),manifest={datasetSha256:sha(bytes)};
 const result=writeFrozenEvaluation(output,rows,manifest),before=readFileSync(result.data);
 assert.throws(()=>writeFrozenEvaluation(output,rows,manifest),/already_exists/);
 assert.deepEqual(readFileSync(result.data),before);
 assert.equal(sha(readFileSync(result.data)),result.datasetSha256);
 assert.throws(()=>writeFrozenEvaluation(join(directory,'wrong'),rows,{datasetSha256:'0'.repeat(64)}),/digest_mismatch/);
});
