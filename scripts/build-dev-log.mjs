// Builds the development log from its structured records. docs/dev-log/data/*.json is the source of truth: one array of
// entries per track, a skill/enum vocabulary and the project card. This script validates the records and renders
//   docs/dev-log/01..04-*.md     one readable page per track (generated, do not edit by hand)
//   docs/dev-log/reflection.md   open questions, what-ifs and the owner's notes, grouped by track
//   docs/dev-log/entries.jsonl   one entry per line for resume tools and crawlers
//   docs/dev-log/career-profile.json  project card plus skills, tech, metrics and resume lines aggregated with entry ids
// Usage: node scripts/build-dev-log.mjs [--check]   (--check renders in memory and fails when a file is stale)
import {existsSync, readFileSync, writeFileSync} from 'node:fs';
import {dirname, join} from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const DIR = join(ROOT, 'docs', 'dev-log');
export const TRACKS = [
  {key: 'evidence-layer', code: 'EL', file: '01-evidence-layer.md'},
  {key: 'agent-monitoring', code: 'AM', file: '02-agent-monitoring.md'},
  {key: 'judge-models', code: 'JM', file: '03-judge-models.md'},
  {key: 'ui-ux', code: 'UX', file: '04-ui-ux.md'},
];
const KEYS = ['id', 'track', 'date_start', 'date_end', 'status', 'title', 'title_en', 'summary', 'context', 'trigger', 'problem',
  'constraints', 'options', 'decision', 'actions', 'tech', 'skills', 'metrics', 'result', 'tradeoffs', 'lessons', 'reflection',
  'resume', 'interview', 'evidence', 'related', 'uncertain', 'owner_notes'];
const DATE = /^\d{4}-\d{2}-\d{2}$/;

export function loadData(dir = DIR) {
  const read = name => JSON.parse(readFileSync(join(dir, 'data', name), 'utf8'));
  return {
    vocabulary: read('vocabulary.json'),
    project: read('project.json'),
    entries: TRACKS.flatMap(t => read(`${t.key}.json`)),
  };
}

export function validateEntries(entries, vocabulary) {
  const errors = [], ids = new Set(entries.map(e => e.id));
  const str = v => typeof v === 'string' && v.trim() !== '';
  const list = v => Array.isArray(v) && v.every(str);
  if (ids.size !== entries.length) errors.push('duplicate entry ids');
  for (const e of entries) {
    const at = msg => errors.push(`${e.id ?? '?'}: ${msg}`);
    const extra = Object.keys(e).filter(k => !KEYS.includes(k)), missing = KEYS.filter(k => !(k in e));
    if (extra.length) at(`unknown keys ${extra.join(', ')}`);
    if (missing.length) at(`missing keys ${missing.join(', ')}`);
    const track = TRACKS.find(t => t.key === e.track);
    if (!track) at(`unknown track ${e.track}`);
    else if (!new RegExp(`^${track.code}-\\d{2}$`).test(e.id)) at(`id does not match track code ${track.code}`);
    if (!DATE.test(e.date_start ?? '')) at('date_start is not YYYY-MM-DD');
    if (e.date_end !== null && !DATE.test(e.date_end ?? '')) at('date_end is not YYYY-MM-DD or null');
    if (e.date_end && e.date_end < e.date_start) at('date_end is before date_start');
    if (!(e.status in vocabulary.status)) at(`unknown status ${e.status}`);
    for (const k of ['title', 'title_en', 'summary', 'context', 'problem', 'result']) if (!str(e[k])) at(`${k} is empty`);
    for (const k of ['constraints', 'actions', 'tech', 'tradeoffs', 'lessons', 'related', 'uncertain']) {
      if (!Array.isArray(e[k]) || !e[k].every(str)) at(`${k} must be a list of strings`);
    }
    if (!e.trigger || !(e.trigger.type in vocabulary.trigger) || !str(e.trigger.detail)) at('trigger needs a known type and a detail');
    if (!Array.isArray(e.options) || !e.options.length || !e.options.some(o => o.chosen === true)) at('options need one chosen');
    if (!e.decision || !str(e.decision.what) || !(e.decision.decided_by in vocabulary.decided_by)) at('decision is incomplete');
    if (!Array.isArray(e.skills) || !e.skills.length) at('skills are empty');
    for (const s of e.skills ?? []) if (!(s in vocabulary.skills)) at(`unknown skill ${s}`);
    for (const m of e.metrics ?? []) if (!str(m.name) || !str(m.after) || !str(m.source)) at('a metric needs name, after and source');
    const r = e.reflection ?? {};
    if (!list(r.open_questions) || !r.open_questions.length || !list(r.what_if ?? [])) at('reflection needs open questions');
    // Planned work has nothing to claim yet, so only its resume lines may be empty.
    const need = e.status === 'planned' ? 0 : 1;
    if (!list(e.resume?.ko ?? []) || e.resume.ko.length < need || !list(e.resume?.en ?? []) || e.resume.en.length < need) {
      at('resume needs ko and en lines');
    }
    for (const id of e.related ?? []) if (!ids.has(id)) at(`related id ${id} does not exist`);
    if (typeof e.owner_notes !== 'string') at('owner_notes must be a string');
  }
  return errors;
}

const cell = v => (v === null || v === undefined || v === '' ? '' : String(v).replace(/\|/g, '\\|').replace(/\s*\n\s*/g, ' '));
const fileOf = id => TRACKS.find(t => id.startsWith(`${t.code}-`)).file;
const anchor = id => id.toLowerCase();
const period = e => (e.date_end && e.date_end !== e.date_start ? `${e.date_start} → ${e.date_end}` : e.date_start);
// Repository paths become links relative to docs/dev-log when the file exists; anything else stays as code text.
function docLink(path) {
  const file = path.split('#')[0];
  if (!/^(docs|reports)\//.test(file) || !existsSync(join(ROOT, file))) return `\`${path}\``;
  return `[${path}](${file.startsWith('docs/') ? `../${path.slice(5)}` : `../../${path}`})`;
}
const entryLink = (id, here) => `[${id}](${fileOf(id) === here ? '' : fileOf(id)}#${anchor(id)})`;
const bullets = items => items.map(x => `- ${x}`).join('\n');

function renderEntry(e, v, here) {
  const out = [];
  const head = [`\`${period(e)}\``, `상태: ${v.status[e.status]}`, `계기: ${v.trigger[e.trigger.type]}`,
    `결정: ${v.decided_by[e.decision.decided_by]}`];
  out.push(`<a id="${anchor(e.id)}"></a>`, `### ${e.id} · ${e.title}`, '', `${head.join(' · ')}  `, `*${e.title_en}*`, '');
  out.push(`**요약.** ${e.summary}`, '', `**배경.** ${e.context}`, '');
  out.push(`**계기.** ${e.trigger.detail}`);
  if (e.trigger.quote) out.push('', `> "${e.trigger.quote}"`);
  out.push('', `**문제.** ${e.problem}`, '');
  if (e.constraints.length) out.push('**당시 제약**', '', bullets(e.constraints), '');
  out.push('**검토한 대안**', '', '| 대안 | 장점 | 단점 | 선택 | 이유 |', '|---|---|---|---|---|');
  for (const o of e.options) out.push(`| ${cell(o.option)} | ${cell(o.pros)} | ${cell(o.cons)} | ${o.chosen ? '선택' : ''} | ${cell(o.reason)} |`);
  out.push('', `**결정.** ${e.decision.what}${e.decision.why ? ` 이유: ${e.decision.why}` : ''}`, '');
  out.push('**한 일**', '', e.actions.map((a, i) => `${i + 1}. ${a}`).join('\n'), '');
  out.push(`**결과.** ${e.result}`, '');
  if (e.metrics.length) {
    out.push('| 지표 | 전 | 후 | 단위 | 범위 | 출처 |', '|---|---|---|---|---|---|');
    for (const m of e.metrics) out.push(`| ${cell(m.name)} | ${cell(m.before)} | ${cell(m.after)} | ${cell(m.unit)} | ${cell(m.scope)} | ${cell(m.source)} |`);
    out.push('');
  }
  if (e.tradeoffs.length) out.push('**트레이드오프와 남은 한계**', '', bullets(e.tradeoffs), '');
  if (e.lessons.length) out.push('**배운 점**', '', bullets(e.lessons), '');
  out.push('**다시 생각해 볼 질문**', '', bullets(e.reflection.open_questions), '');
  if (e.reflection.what_if?.length) out.push('**다른 선택을 했다면**', '', bullets(e.reflection.what_if), '');
  if (e.reflection.revisit_when) out.push(`**다시 볼 시점.** ${e.reflection.revisit_when}`, '');
  const resume = [...e.resume.ko, ...e.resume.en.map(x => `(EN) ${x}`)];
  if (resume.length) out.push('**이력서 문장**', '', bullets(resume), '');
  if (e.interview?.length) {
    out.push('**예상 면접 질문**', '');
    for (const q of e.interview) out.push(`- Q. ${q.q}`, ...(q.a_points ?? []).map(a => `  - ${a}`));
    out.push('');
  }
  const ev = e.evidence ?? {};
  const sources = [...(ev.commits ?? []).map(c => `커밋 \`${c}\``), ...(ev.docs ?? []).map(d => docLink(d)), ...(ev.notes ?? [])];
  out.push(`**기술.** ${e.tech.join(', ')}  `, `**역량.** ${e.skills.map(s => v.skills[s]).join(', ')}  `);
  if (sources.length) out.push(`**근거.** ${sources.join(', ')}  `);
  if (e.related.length) out.push(`**관련 항목.** ${e.related.map(id => entryLink(id, here)).join(', ')}  `);
  out.push('');
  if (e.uncertain.length) out.push('**확인하지 못한 것**', '', bullets(e.uncertain), '');
  out.push(`**내 메모.** ${e.owner_notes.trim() || '_(비어 있음: data의 owner_notes에 적으면 여기와 회고 노트에 나타납니다)_'}`, '');
  return out.join('\n');
}

function renderTrack(track, entries, v) {
  const list = entries.filter(e => e.track === track.key);
  const first = list[0]?.date_start, last = list.map(e => e.date_end ?? e.date_start).sort().at(-1);
  const out = [`# 개발 기록 · ${v.tracks[track.key]} (${first} → ${last})`, '',
    `[개발 기록 목차](README.md) · [회고 노트](reflection.md) · 항목 ${list.length}개`, '',
    `> 이 문서는 \`docs/dev-log/data/${track.key}.json\`에서 \`node scripts/build-dev-log.mjs\`로 만든다. 내용을 고칠 때는 data를 고치고 다시 실행한다.`,
    '> 숫자에는 출처를 붙였고, 출처 없이 짐작한 것은 "(추정)"이나 "확인하지 못한 것"에 적었다.', '',
    '| ID | 기간 | 제목 | 상태 | 계기 |', '|---|---|---|---|---|'];
  for (const e of list) {
    out.push(`| [${e.id}](#${anchor(e.id)}) | ${period(e)} | ${cell(e.title)} | ${v.status[e.status]} | ${v.trigger[e.trigger.type]} |`);
  }
  out.push('', '---', '');
  for (const e of list) out.push(renderEntry(e, v, track.file), '---', '');
  return `${out.join('\n').trimEnd()}\n`;
}

function renderReflection(entries, v) {
  const out = ['# 회고 노트', '', '[개발 기록 목차](README.md)', '',
    '나중에 다시 생각해 볼 질문, 다른 선택을 했다면 어땠을지, 그 결정을 다시 볼 시점을 항목별로 모았다. "내 메모"는 오너의 생각을 적는 칸이다.',
    '메모는 `docs/dev-log/data/<분야>.json`의 해당 항목 `owner_notes`에 적고 `node scripts/build-dev-log.mjs`를 실행하면 이 문서와 각 기록에 함께 나타난다.', ''];
  for (const t of TRACKS) {
    out.push(`## ${v.tracks[t.key]}`, '');
    for (const e of entries.filter(x => x.track === t.key)) {
      out.push(`### [${e.id}](${t.file}#${anchor(e.id)}) · ${e.title}`, '', `\`${period(e)}\` · ${v.status[e.status]}`, '');
      out.push('**다시 생각해 볼 질문**', '', bullets(e.reflection.open_questions), '');
      if (e.reflection.what_if?.length) out.push('**다른 선택을 했다면**', '', bullets(e.reflection.what_if), '');
      if (e.reflection.revisit_when) out.push(`**다시 볼 시점.** ${e.reflection.revisit_when}`, '');
      out.push(`**내 메모.** ${e.owner_notes.trim() || '_(비어 있음)_'}`, '');
    }
  }
  return `${out.join('\n').trimEnd()}\n`;
}

function enrich(e, v) {
  const t = TRACKS.find(x => x.key === e.track);
  return {...e, track_name: v.tracks[e.track], status_name: v.status[e.status], skills_ko: e.skills.map(s => v.skills[s]),
    record: `docs/dev-log/${t.file}#${anchor(e.id)}`};
}

function renderProfile(entries, v, project) {
  const tally = (pick, label) => {
    const map = new Map();
    for (const e of entries) for (const k of pick(e)) map.set(k, [...(map.get(k) ?? []), e.id]);
    return [...map].map(([k, ids]) => ({...label(k), count: ids.length, entries: ids}))
      .sort((a, b) => b.count - a.count || JSON.stringify(a).localeCompare(JSON.stringify(b)));
  };
  const asOf = entries.map(e => e.date_end ?? e.date_start).sort().at(-1);
  return {
    schema: 'evidscope-career-profile/1',
    as_of: asOf,
    project,
    tracks: TRACKS.map(t => {
      const list = entries.filter(e => e.track === t.key);
      return {key: t.key, name: v.tracks[t.key], entries: list.length, from: list[0]?.date_start,
        to: list.map(e => e.date_end ?? e.date_start).sort().at(-1), record: `docs/dev-log/${t.file}`};
    }),
    status_counts: Object.fromEntries(Object.keys(v.status).map(s => [s, entries.filter(e => e.status === s).length])),
    skills: tally(e => e.skills, k => ({key: k, name: v.skills[k]})),
    tech: tally(e => [...new Set(e.tech)], k => ({name: k})),
    achievements: entries.filter(e => e.status !== 'invalidated' && e.status !== 'planned')
      .map(e => ({id: e.id, date: e.date_end ?? e.date_start, title: e.title, title_en: e.title_en, ko: e.resume.ko, en: e.resume.en})),
    metrics: entries.flatMap(e => e.metrics.map(m => ({id: e.id, ...m}))),
    decisions: entries.map(e => ({id: e.id, what: e.decision.what, why: e.decision.why, decided_by: e.decision.decided_by})),
    lessons: entries.flatMap(e => e.lessons.map(text => ({id: e.id, text}))),
    open_questions: entries.flatMap(e => e.reflection.open_questions.map(text => ({id: e.id, text}))),
  };
}

export function renderAll({vocabulary: v, project, entries}) {
  const sorted = TRACKS.flatMap(t => entries.filter(e => e.track === t.key));
  const files = {};
  for (const t of TRACKS) files[t.file] = renderTrack(t, sorted, v);
  files['reflection.md'] = renderReflection(sorted, v);
  files['entries.jsonl'] = sorted.map(e => JSON.stringify(enrich(e, v))).join('\n') + '\n';
  files['career-profile.json'] = `${JSON.stringify(renderProfile(sorted, v, project), null, 2)}\n`;
  return files;
}

function main() {
  const data = loadData(), errors = validateEntries(data.entries, data.vocabulary);
  if (errors.length) {
    console.error(errors.join('\n'));
    process.exit(1);
  }
  const files = renderAll(data), check = process.argv.includes('--check'), stale = [];
  for (const [name, text] of Object.entries(files)) {
    const path = join(DIR, name);
    if (check) {
      if (!existsSync(path) || readFileSync(path, 'utf8') !== text) stale.push(name);
    } else writeFileSync(path, text);
  }
  if (stale.length) {
    console.error(`stale: ${stale.join(', ')} (run node scripts/build-dev-log.mjs)`);
    process.exit(1);
  }
  console.log(JSON.stringify({entries: data.entries.length, files: Object.keys(files).length, check}));
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) main();
