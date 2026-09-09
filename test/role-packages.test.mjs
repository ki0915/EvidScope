import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {ROLE_IDS,loadRolePackages,buildRoleExecution} from '../src/role-packages.mjs';
import {scoreRoleOutput,evaluateRoleSet,evaluateLoraAdmission} from '../src/role-evaluation.mjs';

const readJsonl=path=>readFileSync(path,'utf8').trim().split(/\r?\n/).map(JSON.parse);
test('four versioned role packages have distinct runner instructions and 30/10/20 isolated unreviewed fixtures',()=>{
 const root=resolve('.'),packs=loadRolePackages({root});assert.deepEqual(packs.map(p=>p.id),ROLE_IDS);assert.equal(new Set(packs.map(p=>p.instructions)).size,4);
 for(const pack of packs){const run=buildRoleExecution(pack.id,{root,request:'bounded task',contextRefs:['alpha/ref-1']});assert.equal(run.roleVersion,'1.0.0');assert.ok(run.systemInstructions);const sets=Object.fromEntries(pack.evalSets.map(path=>[path.split('/').at(-1).replace('.jsonl',''),readJsonl(resolve(path))]));assert.deepEqual(Object.fromEntries(Object.entries(sets).map(([k,v])=>[k,v.length])),{tune:30,validation:10,test:20});const all=Object.values(sets).flat();assert.ok(all.every(v=>v.reviewStatus==='UNREVIEWED'&&v.humanReviewed===false&&v.truth.labels.length));const family=new Map();for(const item of all){if(!family.has(item.familyId))family.set(item.familyId,new Set());family.get(item.familyId).add(item.split);}assert.ok([...family.values()].every(s=>s.size===1));}
});

test('deterministic scorer checks citations, unknown, relations and safety; LoRA gate blocks current corpus',()=>{
 const example=readJsonl(resolve('data/role-evals/evidence-reconciler/v1/test.jsonl')).find(v=>v.truth.labels.includes('adverse_evidence')),refs=example.truth.requiredRefs;
 const good={findings:[{claim:'reported success',evidenceRefs:[refs[0]],relation:'supports',confidence:'low'},{claim:'independent conflict',evidenceRefs:[refs[1]],relation:'contradicts',confidence:'high'}],uncertainties:['conflict unresolved'],limitations:[],recommendedFollowUps:[],abstained:true};assert.equal(scoreRoleOutput(example,good).passed,true);
 const perfectSynthetic=evaluateRoleSet([example],{[example.id]:good});assert.equal(example.humanReviewed,false);assert.equal(perfectSynthetic.passRate,1);assert.equal(perfectSynthetic.fixtureAssertionsPassed,true);assert.equal(perfectSynthetic.qualityClaimAllowed,false);assert.match(perfectSynthetic.qualityClaimRequirement,/reviewed real-world evaluation/);
 const empty=evaluateRoleSet([],{});assert.equal(empty.passRate,null);assert.equal(empty.fixtureAssertionsPassed,false);assert.equal(empty.qualityClaimAllowed,false);
 const bad={...good,findings:[{claim:'made up',evidenceRefs:['made-up-citation'],relation:'supports'}],uncertainties:[],abstained:false};const result=scoreRoleOutput(example,bad);assert.equal(result.passed,false);assert.equal(result.citationValidity.onlyKnown,false);assert.equal(result.unknownCorrect,false);
 const records=ROLE_IDS.flatMap(role=>['tune','validation','test'].flatMap(split=>readJsonl(resolve(`data/role-evals/${role}/v1/${split}.jsonl`))));const gate=evaluateLoraAdmission(records);assert.equal(gate.admitted,false);assert.equal(gate.trainingRunAllowed,false);assert.equal(gate.qualityClaimAllowed,false);assert.deepEqual(gate.counts,{tune:0,validation:0,test:0});
});
