// Content signals of what enters an AI coding agent's context (docs/agent-monitoring.md, "LLM 보안 신호"): the user's prompt
// (UserPromptSubmit) and what a tool handed back to the model (PostToolUse tool_response: a web page, a file, an MCP answer, command
// output). The hook (src/agent-hook-events.mjs) reads that text in memory and keeps only which kinds of signal it found and how
// often, how many characters it read, and the SHA-256 of the text; the text itself never leaves the hook. The patterns are
// deterministic and need no model: an article about prompt injection quotes the same phrases, so each one is a signal for review,
// and evaluation engine v9 (src/content-rules.mjs) turns them into findings and links an injection signal to the risky calls that
// follow it in the same session.
// Only node built-ins are imported: the installer copies this module next to the hook (scripts/install-agent-monitoring.mjs).
import {createHash} from 'node:crypto';

export const CONTENT_SIGNALS_VERSION = 'content-signals-v1';
// Where the text came from: the user's prompt, or a tool's answer that the model reads next.
export const CONTENT_SOURCES = Object.freeze(['prompt', 'tool_result']);
// injection_cue: wording that tries to replace the agent's instructions, addresses the AI reading a page and asks it to act, asks it
// to hide something from the user, or asks for its system prompt. role_marker: chat-template or fake role markers. hidden_text:
// invisible characters (Unicode tag characters, bidi controls, runs of zero-width characters). secret_value: well-known secret
// formats (private key blocks, cloud and service tokens). unique_id: Korean resident or foreigner registration numbers and driver's
// licence numbers (PIPA art. 24 unique identifiers). card_number: a grouped card number that passes the Luhn check. contact_bulk:
// many distinct phone numbers or e-mail addresses in one text.
export const CONTENT_SIGNALS = Object.freeze(['injection_cue', 'role_marker', 'hidden_text', 'secret_value', 'unique_id', 'card_number',
  'contact_bulk']);
// chars: the most characters read from one prompt or tool answer; depth: how deep a JSON answer is walked; count: the cap of one
// count; contacts: distinct phone numbers and e-mail addresses that make contact_bulk; zeroWidth: zero-width characters that make
// hidden_text (one alone is common in pasted text).
export const CONTENT_LIMITS = Object.freeze({chars: 262144, depth: 8, count: 999, contacts: 20, zeroWidth: 3});

// The text of a prompt or tool answer: every string in it (a tool answer is any JSON), in order, up to the character limit.
export function contentText(value) {
  const parts = [];
  let left = CONTENT_LIMITS.chars, truncated = false;
  const walk = (v, depth) => {
    if (typeof v === 'string') {
      if (!v) return;
      if (v.length > left) truncated = true;
      if (left <= 0) return;
      parts.push(v.slice(0, left)); left -= Math.min(v.length, left);
      return;
    }
    if (!v || typeof v !== 'object' || depth >= CONTENT_LIMITS.depth) return;
    for (const x of Array.isArray(v) ? v : Object.values(v)) walk(x, depth + 1);
  };
  walk(value, 0);
  return {text: parts.join('\n'), truncated};
}

// Gaps are bounded character runs that stop at a full stop or line end, so a phrase is matched within one sentence and the scan stays
// linear on long minified text.
const INJECTION = [
  new RegExp(/\b(?:ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}?\b(?:previous|prior|above|earlier|preceding|all|any|your|system|developer)\b/.source
    + /[^.\n]{0,24}?\b(?:instructions?|prompts?|rules|directives?|guidelines|guardrails)\b/.source, 'gi'),
  /\b(?:new|updated|real|actual|true)\s+(?:system\s+)?(?:instructions?|directives?)\s*:/gi,
  /\bif\s+you\s+are\s+(?:an?\s+)?(?:AI|LLM|large\s+language\s+model|language\s+model|AI\s+assistant|AI\s+agent|coding\s+agent|chatbot)\b/gi,
  /\b(?:do\s+not|don't|never)\s+(?:tell|inform|notify|mention|reveal|show|alert)\b[^.\n]{0,24}?\b(?:the\s+)?(?:user|human|operator)\b/gi,
  /\b(?:reveal|print|show|output|repeat|leak|dump)\b[^.\n]{0,24}?\b(?:your|the)\s+(?:system|initial|hidden)\s+prompt\b/gi,
  /\b(?:DAN|jailbreak|god)\s+mode\s+(?:enabled|activated|on)\b/gi,
  /(?:이전|앞의|위의|기존|모든|원래)\s*(?:의\s*)?(?:지시|지침|명령|규칙|프롬프트)[^.\n]{0,20}?(?:무시|잊어|잊고|따르지\s*말)/gu,
  /(?:사용자|유저|운영자)에게[^.\n]{0,12}?(?:알리지\s*말|말하지\s*말|보여\s*주지\s*말|언급하지\s*말|숨기)/gu,
  /(?:AI|LLM|에이전트|어시스턴트|인공지능|언어\s*모델)(?:이)?라면[^.\n]{0,30}?(?:실행|전송|보내|업로드|삭제|읽어|무시)/gu,
  /시스템\s*프롬프트[^.\n]{0,16}?(?:출력|공개|보여|알려|유출)/gu,
];
const ROLE_MARKERS = [
  /<\|(?:im_start|im_end|system|assistant|user|endoftext|start_header_id|end_header_id|eot_id)\|>/g,
  /\[\/?INST\]|<<\/?SYS>>/g,
  /<\/?(?:system[-_]prompt|system[-_]instructions?)>/gi,
];
const TAG_CHARACTERS = /[\u{E0000}-\u{E007F}]/gu, BIDI_CONTROLS = /[\u202A-\u202E\u2066-\u2069]/g;
// U+200D (zero-width joiner) is left out: it joins emoji sequences.
const ZERO_WIDTH = /[\u200B\u200C\u2060\u180E]|(?<!^)\uFEFF/g;
const SECRETS = [
  /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----/g,
  /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
  /\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{40,}/g,
  /\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{32,}/g,
  /\bxox[abprs]-[A-Za-z0-9-]{10,}/g,
  /\bhf_[A-Za-z0-9]{30,}\b/g,
  /\bAIza[0-9A-Za-z_-]{35}\b/g,
  /\bglpat-[A-Za-z0-9_-]{20,}/g,
  /\bnpm_[A-Za-z0-9]{36}\b/g,
  /\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b/g,
  /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
];
// YYMMDD-Gnnnnnn with a real month and day and G 1-8 (resident 1-4, foreigner 5-8); NN-NN-NNNNNN-NN driver's licence numbers.
const UNIQUE_IDS = [/(?<![\d-])\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\s?-\s?[1-8]\d{6}(?![\d-])/g, /(?<![\d-])\d{2}-\d{2}-\d{6}-\d{2}(?![\d-])/g];
const CARD = /(?<![\d-])(?:\d{4}([- ])\d{4}\1\d{4}\1\d{4}|\d{4}([- ])\d{6}\2\d{5})(?![\d-])/g;
const PHONE = /(?<!\d)01[016789][-. ]?\d{3,4}[-. ]?\d{4}(?!\d)/g;
const EMAIL = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
// Addresses that name no person: placeholders, and the no-reply addresses of commit metadata.
const NO_PERSON = /@(?:example\.(?:com|org|net)|users\.noreply\.github\.com|noreply\.github\.com)$|^(?:no-?reply|noreply\+[^@]*)@/i;

const count = (text, patterns) => patterns.reduce((n, p) => n + (text.match(p)?.length ?? 0), 0);
function luhn(digits) {
  let sum = 0;
  for (let i = 0; i < digits.length; i++) {
    let d = digits.charCodeAt(digits.length - 1 - i) - 48;
    if (i % 2) { d *= 2; if (d > 9) d -= 9; }
    sum += d;
  }
  return sum % 10 === 0;
}

// The signals of one text: {label: count} for the labels found, in CONTENT_SIGNALS order.
export function scanText(text) {
  const s = String(text ?? '');
  const zeroWidth = s.match(ZERO_WIDTH)?.length ?? 0;
  const contacts = new Set([...(s.match(PHONE) || []).map(p => p.replace(/\D/g, '')),
    ...(s.match(EMAIL) || []).map(e => e.toLowerCase()).filter(e => !NO_PERSON.test(e))]);
  const found = {
    injection_cue: count(s, INJECTION),
    role_marker: count(s, ROLE_MARKERS),
    hidden_text: count(s, [TAG_CHARACTERS, BIDI_CONTROLS]) + (zeroWidth >= CONTENT_LIMITS.zeroWidth ? zeroWidth : 0),
    secret_value: count(s, SECRETS),
    unique_id: count(s, UNIQUE_IDS),
    card_number: (s.match(CARD) || []).filter(c => luhn(c.replace(/\D/g, ''))).length,
    contact_bulk: contacts.size >= CONTENT_LIMITS.contacts ? contacts.size : 0,
  };
  return Object.fromEntries(CONTENT_SIGNALS.filter(k => found[k]).map(k => [k, Math.min(found[k], CONTENT_LIMITS.count)]));
}

// One prompt or tool answer: its signals, how many characters were read, whether it was cut at the limit, and the SHA-256 of the
// text read (the hash lets a reviewer check a copy of the content they hold; it does not reveal the text).
export function contentSignals(value) {
  const {text, truncated} = contentText(value);
  return {signals: scanText(text), chars: text.length, truncated, sha256: createHash('sha256').update(text).digest('hex')};
}

// The record fields of one screened text (src/agent-hook-events.mjs puts them on the content record): dataCategories name the source
// and each signal with its count ("content:tool_result", "signal:injection_cue:2"), and one dataRef carries the hash.
export function contentFields(source, found) {
  if (!CONTENT_SOURCES.includes(source)) throw Error('content_source_unknown');
  const prompt = source === 'prompt';
  return {
    dataCategories: [`content:${source}`, ...Object.entries(found.signals).map(([k, n]) => `signal:${k}:${n}`)],
    dataRefs: [{id: `content.${found.sha256.slice(0, 16)}`, kind: prompt ? 'record' : 'retrieval', role: prompt ? 'input' : 'retrieved',
      version: CONTENT_SIGNALS_VERSION, hash: found.sha256,
      description: `screened in the hook, text not stored: ${found.chars} characters${found.truncated ? ' (cut at the limit)' : ''}`}],
  };
}

// The signals a record's fields name, or null when the record carries no content screening. Read by evaluation engine v9; only labels
// of this version and well-formed counts count.
export function recordContent(event) {
  const ref = (event?.dataRefs || []).find(r => r?.version === CONTENT_SIGNALS_VERSION && typeof r.id === 'string' && r.id.startsWith('content.'));
  const categories = Array.isArray(event?.dataCategories) ? event.dataCategories : [];
  const source = CONTENT_SOURCES.find(s => categories.includes(`content:${s}`));
  if (!ref || !source) return null;
  const signals = {};
  for (const c of categories) {
    const m = /^signal:([a-z_]+):([1-9]\d{0,2})$/.exec(c);
    if (m && CONTENT_SIGNALS.includes(m[1]) && !signals[m[1]]) signals[m[1]] = Number(m[2]);
  }
  return {source, signals, hash: ref.hash};
}
