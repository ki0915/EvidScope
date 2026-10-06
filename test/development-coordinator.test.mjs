import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,mkdirSync,writeFileSync} from 'node:fs';
import {resolve,join} from 'node:path';
import {execFileSync} from 'node:child_process';
import {createDevelopmentCoordinator} from '../src/development-coordinator.mjs';

const git=(cwd,...args)=>execFileSync('git',args,{cwd,encoding:'utf8',windowsHide:true}).trim();
test('coordinator enforces linked worktrees, fixed model, global slots, lease reconciliation, handoff scope and review cap',()=>{
 mkdirSync('.test-runs',{recursive:true});const root=mkdtempSync(resolve('.test-runs/coordinator-')),main=join(root,'main'),one=join(root,'one'),two=join(root,'two'),three=join(root,'three'),coord=join(root,'coord');mkdirSync(main);git(main,'init');git(main,'config','user.email','test@example.invalid');git(main,'config','user.name','test');writeFileSync(join(main,'README.md'),'base\n');git(main,'add','README.md');git(main,'commit','-m','base');const base=git(main,'rev-parse','HEAD');git(main,'worktree','add','-b','task-one',one,base);git(main,'worktree','add','-b','task-two',two,base);git(main,'worktree','add','-b','task-three',three,base);mkdirSync(coord);
 const task=(taskId,worktree)=>({taskId,teamId:'team',roleId:'core',parentRunId:'root',model:'gpt-5.6-sol',reasoningEffort:'high',worktree,baseCommit:base,allowedPaths:['allowed.txt'],completionCriteria:['implementation','tests'],depth:1,maxReviewRounds:2,noFallback:true});writeFileSync(join(coord,'team-manifest.json'),JSON.stringify({schemaVersion:1,teamId:'team',coordinatorWorktree:main,maxConcurrentIncludingCoordinator:3,maxDepth:1,tasks:[task('one',one),task('two',two),task('three',three)]}));let current=1000;const coordinator=createDevelopmentCoordinator(coord,{clock:()=>current,lockTimeoutMs:10});
 assert.throws(()=>coordinator.claim('one',{agentId:'a',model:'gpt-5.6-luna',reasoningEffort:'low'}),e=>e.code==='COORDINATOR_MODEL');coordinator.claim('one',{agentId:'a',model:'gpt-5.6-sol',reasoningEffort:'high',leaseMs:60000});coordinator.claim('two',{agentId:'b',model:'gpt-5.6-sol',reasoningEffort:'high',leaseMs:60000});assert.throws(()=>coordinator.claim('three',{agentId:'c',model:'gpt-5.6-sol',reasoningEffort:'high'}),e=>e.code==='COORDINATOR_CAPACITY');
 current+=60001;const status=coordinator.status();assert.equal(status.active,2);assert.equal(status.state.claims.one.status,'reconciliation_required');assert.throws(()=>coordinator.release('one',{agentId:'a'}),e=>e.code==='COORDINATOR_RECONCILE');coordinator.release('one',{agentId:'a',reconciled:true,reason:'process confirmed stopped'});coordinator.claim('three',{agentId:'c',model:'gpt-5.6-sol',reasoningEffort:'high'});
 writeFileSync(join(two,'allowed.txt'),'done\n');git(two,'add','allowed.txt');git(two,'commit','-m','allowed change');const changed=git(two,'rev-parse','HEAD');const handoff=coordinator.complete('two',{agentId:'b',reconciled:true,changedCommit:changed,testResults:[{command:'node --test targeted',status:'passed',exitCode:0}],unresolved:[],criteria:[{criterion:'implementation',status:'met'},{criterion:'tests',status:'met'}],artifacts:['allowed.txt']});assert.deepEqual(handoff.changedPaths,['allowed.txt']);assert.equal(coordinator.review('two',{reviewerAgentId:'reviewer-1',reviewerRole:'adversarial',outcome:'needs_changes',notes:['bounded issue']}).round,1);assert.equal(coordinator.review('two',{reviewerAgentId:'reviewer-2',reviewerRole:'design-review',outcome:'accepted',notes:[]}).round,2);assert.throws(()=>coordinator.review('two',{reviewerAgentId:'reviewer-3',reviewerRole:'adversarial',outcome:'accepted'}),e=>e.code==='COORDINATOR_REVIEW_LIMIT');
});

test('Windows coordinator completes a linked worktree under a long installation path without changing Git configuration',{skip:process.platform!=='win32'},()=>{
 mkdirSync('.test-runs',{recursive:true});const fixtureRoot=mkdtempSync(resolve('.test-runs/cl-'));let root=fixtureRoot;
 while(join(root,'one').length<190)root=join(root,'path');
 mkdirSync(root,{recursive:true});const main=join(fixtureRoot,'main'),one=join(root,'one'),coord=join(fixtureRoot,'coord');mkdirSync(main);mkdirSync(coord);
 const fixtureGit=(cwd,...args)=>git(cwd,'-c','core.longpaths=true',...args);
 fixtureGit(main,'init');fixtureGit(main,'config','user.email','test@example.invalid');fixtureGit(main,'config','user.name','test');fixtureGit(main,'config','core.longpaths','false');
 writeFileSync(join(main,'README.md'),'base\n');fixtureGit(main,'add','README.md');fixtureGit(main,'commit','-m','base');const base=fixtureGit(main,'rev-parse','HEAD');fixtureGit(main,'worktree','add','-b','long-task',one,base);
 writeFileSync(join(one,'allowed.txt'),'done\n');fixtureGit(one,'add','allowed.txt');fixtureGit(one,'commit','-m','allowed change');const changed=fixtureGit(one,'rev-parse','HEAD');
 assert.ok(join(one,`${base}..${changed}`).length>260);
 assert.throws(()=>git(one,'diff','--name-only',`${base}..${changed}`),error=>/Filename too long/.test(String(error.stderr)));
 const task={taskId:'long-task',roleId:'core',model:'gpt-5.6-sol',reasoningEffort:'high',worktree:one,baseCommit:base,allowedPaths:['allowed.txt'],completionCriteria:['implementation'],depth:1,maxReviewRounds:2,noFallback:true};
 writeFileSync(join(coord,'team-manifest.json'),JSON.stringify({schemaVersion:1,coordinatorWorktree:main,maxConcurrentIncludingCoordinator:3,maxDepth:1,tasks:[task]}));
 const coordinator=createDevelopmentCoordinator(coord);coordinator.claim(task.taskId,{agentId:'long-agent',model:task.model,reasoningEffort:task.reasoningEffort});
 const handoff=coordinator.complete(task.taskId,{agentId:'long-agent',changedCommit:changed,testResults:[{command:'synthetic fixture check',status:'passed',exitCode:0}],unresolved:[],criteria:[{criterion:'implementation',status:'met'}]});
 assert.deepEqual(handoff.changedPaths,['allowed.txt']);assert.equal(coordinator.status().state.claims[task.taskId].status,'completed');assert.equal(fixtureGit(main,'config','--local','core.longpaths'),'false');
});
