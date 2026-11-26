// The pre-execution guard of the AI agent hook (docs/agent-monitoring.md, "확실한 위협 차단"): before a tool call runs, the hook
// checks its intent against the risk pack (data/risk-rules/ai-agent-baseline.json) and denies the few kinds of call that are a problem
// whatever the context: touching the audit and collection set-up (EvidScope's hook credentials, the agents' hook settings, the
// installed hook, the scheduled task, the EvidScope process), clearing the event log, switching a defence off (antivirus,
// firewall, iptables, SELinux), and one command that both reads a credential and sends data out. Everything else stays a finding for
// review. The intent of a denied call is still sent, with the guard:denied category, so the ledger records what was stopped.
// Only ./rule-words.mjs is imported: the installer copies this module next to the hook.
// v2 (security review 2026-10-22): the rules are matched against the command's words as the shell reads them (matchesCommand:
// quotes removed, a program by path or .exe also by its bare name, a relative path after cd also under that directory), and a
// shell call counts as a read only without any chain operator, substitution or an option of a showing command that writes or runs.
import {matchesCommand, programName} from './rule-words.mjs';

export const GUARD_VERSION = 'agent-guard-v2';
export const GUARD_DENIED = 'guard:denied';
// Rule id prefixes the guard stops. reads: reading the file is let through (reading a settings file is not changing it; EvidScope's own
// hook settings hold its credentials, so reading them is stopped too); unless: a word that makes the call a query (netsh advfirewall show).
export const GUARD_RULES = Object.freeze([
  {prefix: 'risk.audit.evidscope-config'},
  {prefix: 'risk.audit.claude-settings', reads: true},
  {prefix: 'risk.audit.codex-hooks', reads: true},
  {prefix: 'risk.audit.codex-config', reads: true},
  {prefix: 'risk.audit.hook-script', reads: true},
  {prefix: 'risk.audit.evidscope-task'},
  {prefix: 'risk.audit.evidscope-stop'},
  {prefix: 'risk.defense.clear-eventlog'},
  {prefix: 'risk.defense.defender'},
  {prefix: 'risk.defense.firewall', unless: 'show'},
  {prefix: 'risk.defense.iptables-flush'},
  {prefix: 'risk.defense.selinux-off'},
].map(Object.freeze));

// Commands that only show something. A shell call reads when every piped part starts with one of them (by bare name: sort.exe,
// /usr/bin/sort) and nothing is redirected, chained (also with one &, the cmd and PowerShell chain), substituted ($( ), `, <( ), >( ))
// or written or run by an option of the showing command (WRITES: sort -o FILE and --compress-program=PROG, rg --pre=PROG, less -o FILE).
const SHOW = new Set(['cat', 'type', 'get-content', 'gc', 'head', 'tail', 'less', 'more', 'grep', 'rg', 'findstr', 'select-string', 'sls', 'jq',
  'ls', 'dir', 'get-childitem', 'gci', 'get-item', 'gi', 'test-path', 'stat', 'wc', 'sort', 'convertfrom-json', 'select-object', 'format-list',
  'out-string']);
const WRITES = {sort: /^(?:-[a-zA-Z]*[oT]|--(?:output|compress-program|temporary-directory))/, rg: /^--pre/i, less: /^(?:-[a-z]*o|--log-file)/i};
const CHAINED = /[>;`\n&]|\|\||\$\(|<\(/;
export function readOnlyCommand(note) {
  const command = String(note).replace(/^\[[^\]]*\]\s*/, '');
  if (!command.trim() || CHAINED.test(command)) return false;
  return command.split('|').every(part => {
    const words = part.trim().replace(/["']/g, '').replace(/\\/g, '/').split(/\s+/), name = (programName(words[0]) ?? words[0]).toLowerCase();
    return SHOW.has(name) && !words.slice(1).some(w => WRITES[name]?.test(w));
  });
}
const reads = event => ['file_read', 'file_search'].includes(event.action) || (event.action === 'shell_exec' && readOnlyCommand(event.note));
const noteRule = r => r && typeof r.id === 'string' && r.field === 'note' && r.op === 'words' && typeof r.value === 'string';
const hit = (r, note) => { try { return matchesCommand(r.value, note); } catch { return false; } };

// The decision for one intent of the hook (src/agent-hook-events.mjs hookEvent) against the rules of the pack: null to let it run, or
// {rules, reason} to deny it. Only words rules on the note are read, as the vault does for the pack.
export function guardDecision(event, rules) {
  if (!event || event.kind !== 'intent' || typeof event.note !== 'string' || !Array.isArray(rules)) return null;
  const matched = rules.filter(noteRule).filter(r => hit(r, event.note));
  const stopped = matched.filter(r => GUARD_RULES.some(g => r.id.startsWith(g.prefix) && !(g.reads && reads(event))
    && !(g.unless && matchesCommand(g.unless, event.note))));
  const exfil = matched.some(r => r.id.startsWith('risk.cred.')) && matched.some(r => r.id.startsWith('risk.out.'))
    ? matched.filter(r => r.id.startsWith('risk.cred.') || r.id.startsWith('risk.out.')) : [];
  const deny = [...new Set([...stopped, ...exfil])];
  if (!deny.length) return null;
  const titles = [...new Set(deny.map(r => r.title).filter(t => typeof t === 'string'))].slice(0, 3).join('; ');
  return {rules: deny.map(r => r.id),
    reason: `EvidScope가 실행 전에 막았습니다: ${titles}. 감사·수집 설정 조작, 보안 기능 끄기, 비밀을 읽어 바로 외부로 보내는 명령은 `
      + 'AI가 실행할 수 없습니다. 꼭 필요한 작업이면 사용자가 직접 실행하세요.'};
}

// The hook's answer that denies the call (Claude Code PreToolUse JSON output: https://code.claude.com/docs/en/hooks).
export const denyOutput = reason => JSON.stringify({hookSpecificOutput: {hookEventName: 'PreToolUse', permissionDecision: 'deny',
  permissionDecisionReason: reason}});
