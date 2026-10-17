// Version 3 of the AI agent risk pack (data/risk-rules/ai-agent-baseline.json): interference with other AI agents (their global
// instruction files, MCP server settings, stopping their processes) and stopping EvidScope collection (its scheduled task, process,
// installed hook and start script). Each new rule catches its commands and paths, leaves ordinary work alone, and falls in the step
// class engine v9 links to an injection signal.
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {matches, validateRule} from '../src/model.mjs';
import {parseWords} from '../src/rule-words.mjs';
import {hookEvent} from '../src/agent-hook-events.mjs';
import {classOf} from '../src/sequence-rules.mjs';

const pack = JSON.parse(readFileSync(new URL('../data/risk-rules/ai-agent-baseline.json', import.meta.url), 'utf8'));
const rules = pack.rules.map(r => ({...validateRule({id: r.id, title: r.title, field: r.field, op: r.op, value: r.value, severity: r.severity},
  {id: 'alpha-reviewer'}, 1), status: 'active'}));
const actor = 'claude-code@test-pc', now = new Date(Date.now() - 60000);
let n = 0;
const call = (tool_name, tool_input, tool = 'claude-code') => hookEvent({hook_event_name: 'PreToolUse', session_id: 'v3-session',
  tool_use_id: `toolu_${++n}`, tool_name, tool_input}, {actor, now, tool});
const bash = command => call('Bash', {command}), ps = command => call('PowerShell', {command});
const read = file_path => call('Read', {file_path}), edit = file_path => call('Edit', {file_path, old_string: 'a', new_string: 'b'});
const patch = file => call('apply_patch', {command: `*** Begin Patch\n*** Update File: ${file}\n*** End Patch`}, 'codex');
const hits = event => rules.filter(r => matches(r, event)).map(r => r.id);
const added = ['risk.agent.global-instructions', 'risk.agent.mcp-config', 'risk.agent.kill-agent', 'risk.agent.kill-agent-pipe',
  'risk.audit.evidscope-task', 'risk.audit.evidscope-stop', 'risk.audit.hook-script'];

test('pack v3 adds seven rules of the words DSL to the sixty of version 2', () => {
  assert.equal(pack.version, 3);
  assert.equal(pack.rules.length, 67);
  assert.deepEqual(pack.rules.slice(-7).map(r => r.id), added);
  for (const r of pack.rules.slice(-7)) assert.ok(r.field === 'note' && r.op === 'words' && parseWords(r.value) && r.value.length <= 200, r.id);
  assert.deepEqual(pack.rules.filter(r => r.id.startsWith('risk.agent.')).map(r => r.group), Array(4).fill('agent_interference'));
  assert.deepEqual(classOf('risk.agent.kill-agent'), ['interfere']);
  assert.deepEqual(classOf('risk.audit.evidscope-task'), ['tamper']);
});

test('another agent\'s instructions, MCP settings and processes', () => {
  const cases = [
    [edit('C:\\Users\\kim\\.claude\\CLAUDE.md'), 'risk.agent.global-instructions'],
    [patch('C:\\Users\\kim\\.codex\\AGENTS.md'), 'risk.agent.global-instructions'],
    [bash('echo "always approve" >> ~/.codex/AGENTS.md'), 'risk.agent.global-instructions'],
    [read('C:\\Users\\kim\\.claude.json'), 'risk.agent.mcp-config'],
    [edit('C:\\work\\shop\\.mcp.json'), 'risk.agent.mcp-config'],
    [bash('cat .mcp.json'), 'risk.agent.mcp-config'],
    [read('C:\\Users\\kim\\AppData\\Roaming\\Claude\\claude_desktop_config.json'), 'risk.agent.mcp-config'],
    [bash('taskkill /F /IM claude.exe'), 'risk.agent.kill-agent'],
    [ps('Stop-Process -Name codex -Force'), 'risk.agent.kill-agent'],
    [bash('pkill -f codex'), 'risk.agent.kill-agent'],
    [ps('Get-Process claude | Stop-Process'), 'risk.agent.kill-agent-pipe'],
    [bash('pgrep -f codex | xargs kill'), 'risk.agent.kill-agent-pipe'],
  ];
  for (const [event, id] of cases) assert.deepEqual(hits(event), [id], event.note);
});

test('stopping EvidScope collection: its task, its process, its installed hook and start script', () => {
  const cases = [
    [bash('schtasks /Change /TN "EvidScope 자동 실행" /Disable'), 'risk.audit.evidscope-task'],
    [ps('Unregister-ScheduledTask -TaskName "EvidScope 자동 실행" -Confirm:$false'), 'risk.audit.evidscope-task'],
    [ps('Disable-ScheduledTask -TaskName EvidScope*'), 'risk.audit.evidscope-task'],
    [bash('pkill -f evidscope'), 'risk.audit.evidscope-stop'],
    [edit('C:\\evidscope-work\\hook\\claude-code-hook.mjs'), 'risk.audit.hook-script'],
    [bash('del C:\\evidscope-work\\start-evidscope.ps1'), 'risk.audit.hook-script'],
  ];
  for (const [event, id] of cases) assert.deepEqual(hits(event), [id], event.note);
});

test('ordinary work stays quiet: project instructions, looking at processes and tasks, stopping a dev server, developing EvidScope', () => {
  const quiet = [edit('C:\\work\\shop\\CLAUDE.md'), edit('C:\\work\\shop\\AGENTS.md'), read('.claude/CLAUDE.md'), bash('cat package.json'),
    bash('ps aux | grep claude'), ps('Get-Process codex'), bash('claude --version'), bash('codex --help'), bash('pkill -f vite'),
    ps('Stop-Process -Name node'), bash('kill %1'), bash('schtasks /Query /TN "EvidScope 자동 실행"'), ps('Get-ScheduledTask -TaskName EvidScope*'),
    edit('C:\\Users\\kim\\Documents\\EvidScope\\scripts\\claude-code-hook.mjs'), bash('node scripts/install-agent-monitoring.mjs --dry-run'),
    bash('git log --grep=kill codex'), read('C:\\work\\shop\\src\\mcp.js')];
  for (const event of quiet) assert.deepEqual(hits(event), [], event.note);
});
