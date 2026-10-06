import test from 'node:test';
import assert from 'node:assert/strict';
import {execFileSync,spawnSync} from 'node:child_process';
import {copyFileSync,mkdirSync,readFileSync,writeFileSync} from 'node:fs';
import {join,resolve} from 'node:path';
import {tempDir} from './temp-dir.mjs';

const dense='export const dense='+JSON.stringify('x'.repeat(400))+';\n';
function repository(){
 const root=tempDir('evidscope-check-source-');execFileSync('git',['init','-q',root],{windowsHide:true});
 for(const directory of ['scripts','src','test'])mkdirSync(join(root,directory));
 copyFileSync(resolve('scripts/check-source.mjs'),join(root,'scripts','check-source.mjs'));
 writeFileSync(join(root,'src','dense.mjs'),dense);writeFileSync(join(root,'src','clean.mjs'),'export const clean=1;\n');
 const env={...process.env,GITHUB_ACTIONS:''};
 const check=(...args)=>spawnSync(process.execPath,['scripts/check-source.mjs',...args],{cwd:root,encoding:'utf8',env,timeout:30000,windowsHide:true});
 assert.equal(check().status,0,'the first run records the baseline');
 const baseline=()=>JSON.parse(readFileSync(join(root,'scripts','line-length-baseline.json'),'utf8'));
 return {root,check,baseline,write:(path,text)=>writeFileSync(join(root,path),text)};
}

test('source check keeps existing dense files at their baseline and new files under 160 characters',()=>{
 const r=repository();assert.equal(r.baseline()['src/dense.mjs'],1);
 r.write('src/dense.mjs',dense+dense.replace('dense=','again='));
 const grown=r.check();assert.equal(grown.status,1);assert.match(grown.stderr,/src\/dense\.mjs:1: 2 lines longer than 300 characters; baseline allows 1/);
 r.write('src/dense.mjs',dense.replace('x'.repeat(400),'y'.repeat(400)));assert.equal(r.check().status,0,'editing a dense line in place is allowed');
 r.write('src/new.mjs',`export const fresh='${'z'.repeat(150)}';\n`);
 const fresh=r.check();assert.equal(fresh.status,1);
 assert.match(fresh.stderr,/src\/new\.mjs:1: line has 172 characters; files new since the baseline allow 160/);
 r.write('src/new.mjs','export const fresh=1;\n');r.write('src/dense.mjs',dense+dense.replace('dense=','again='));
 assert.equal(r.check('--update-baseline').status,0);assert.equal(r.baseline()['src/dense.mjs'],2);assert.equal('src/new.mjs' in r.baseline(),false);
});

test('source check rejects syntax errors, BOM, CR, trailing whitespace and committed .only',()=>{
 const r=repository();
 for(const [path,text,problem] of [
  ['src/broken.mjs','export const broken=;\n',/src\/broken\.mjs:1: node --check failed/],
  ['src/bom.mjs','﻿export const bom=1;\n',/src\/bom\.mjs:1: UTF-8 BOM/],
  ['src/cr.mjs','export const cr=1;\r\n',/src\/cr\.mjs:1: CR line ending/],
  ['src/space.mjs','export const space=1; \n',/src\/space\.mjs:1: trailing whitespace/],
  ['test/focus.test.mjs',"import test from 'node:test';\ntest.only('focus',()=>{});\n",/test\/focus\.test\.mjs:2: committed \.only/],
 ]){
  r.write(path,text);const result=r.check();assert.equal(result.status,1,path);assert.match(result.stderr,problem);
  r.write(path,'export const fixed=1;\n');
 }
 assert.equal(r.check().status,0);
});
