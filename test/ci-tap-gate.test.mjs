import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';

const tap=(lines,{tests=2,pass=2,fail=0,cancelled=0,skipped=0,todo=0}={})=>[
 'TAP version 13',...lines,`1..${lines.length}`,`# tests ${tests}`,'# suites 0',`# pass ${pass}`,`# fail ${fail}`,
 `# cancelled ${cancelled}`,`# skipped ${skipped}`,`# todo ${todo}`,'# duration_ms 1',''].join('\n');
const gate=input=>{
 const env={...process.env};delete env.GITHUB_STEP_SUMMARY;
 return spawnSync(process.execPath,['scripts/ci-tap-gate.mjs','-'],{input,encoding:'utf8',env,timeout:10000,windowsHide:true});
};

test('TAP gate passes a clean log and skips whose reasons name their opt-in gate',()=>{
 const result=gate(tap(['ok 1 - a','ok 2 - research # SKIP unshipped research artifacts absent (.local/x); set EVIDSCOPE_REQUIRE_RESEARCH_ARTIFACTS=1',
  '    ok 1 - interop # SKIP set EVIDSCOPE_EXAMPLE_BIN to run the interop check','ok 3 - win # SKIP Windows-only: path check'],{tests:4,pass:1,skipped:3}));
 assert.equal(result.status,0,result.stdout+result.stderr);assert.match(result.stdout,/node:test passed/);assert.match(result.stdout,/^ok 1 - a$/m);
});

test('TAP gate fails failures, cancellations, todo, unexplained skips and missing summaries',()=>{
 for(const [input,problem] of [
  [tap(['ok 1 - a','not ok 2 - b'],{pass:1,fail:1}),/fail=1/],
  [tap(['ok 1 - a','not ok 2 - test/hung.test.mjs'],{pass:1,cancelled:1}),/cancelled=1/],
  [tap(['ok 1 - a','ok 2 - later # TODO'],{pass:1,todo:1}),/todo=1/],
  [tap(['ok 1 - a','ok 2 - quiet # SKIP'],{pass:1,skipped:1}),/unapproved skip: "quiet" \(reason: none\)/],
  [tap(['ok 1 - a','ok 2 - flaky # SKIP flaky on CI'],{pass:1,skipped:1}),/unapproved skip: "flaky"/],
  [tap([],{tests:0,pass:0}),/no tests ran/],
  ['TAP version 13\nok 1 - a\n',/summary line "# tests" found 0 times/],
 ]){
  const result=gate(input);assert.equal(result.status,1,result.stdout);assert.match(result.stdout,problem);assert.match(result.stdout,/node:test FAILED/);
 }
});
