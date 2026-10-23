// The `words` operator of the rule DSL (src/model.mjs, evaluation engine v6): matches the words of a command or path in order, so a
// rule can name the parts of a command an AI agent runs without depending on flag order or spacing ("curl -s -X POST -d @f" is
// "curl ... -d"). Linear in the text: no regular expression is built from a rule, so a tenant rule cannot stall the analysis.
// Pattern: terms separated by single spaces. A term is one or more alternatives separated by |. An alternative is a glob in which
// * stands for any characters, or a "quoted" word compared literally (rm -rf "/*"). Positive terms must match words of the text in
// that order (other words may come between); a term starting with ! must match no word anywhere. Case: an alternative with an
// upper-case letter matches case-sensitively (curl -F is not curl -f), any other one ignores case. In the text, backslashes read as
// forward slashes, and words are split at whitespace, quotes, parentheses, brackets, braces, commas and the shell separators ; | & < >.
export const WORDS_LIMITS = Object.freeze({terms: 12, alternatives: 16, alternativeChars: 64});
const SPLIT = /[\s"'`()[\]{},;|&<>]+/u;

const validAlternative = a => a && a.length <= WORDS_LIMITS.alternativeChars && !a.startsWith('!') && !/^\*+$/u.test(a)
  && (!a.includes('"') || /^"[^"]+"$/u.test(a));

// The parsed pattern, or null when the value is not a valid words pattern.
export function parseWords(value) {
  if (typeof value !== 'string' || !value || value !== value.trim() || / {2}|[^\S ]/u.test(value)) return null;
  const terms = value.split(' ').map(raw => {
    const negative = raw.startsWith('!');
    return {negative, alternatives: (negative ? raw.slice(1) : raw).split('|')};
  });
  if (terms.length > WORDS_LIMITS.terms || !terms.some(t => !t.negative)) return null;
  if (terms.some(t => t.alternatives.length > WORDS_LIMITS.alternatives || !t.alternatives.every(validAlternative))) return null;
  return terms.map(t => ({negative: t.negative, alternatives: t.alternatives.map(a => {
    const literal = a.startsWith('"'), word = (literal ? a.slice(1, -1) : a).replace(/\\/g, '/');
    const exact = /\p{Lu}/u.test(word), text = exact ? word : word.toLowerCase();
    return {parts: literal ? [text] : text.split('*'), exact};
  })}));
}

// Glob match of one word: the parts in order, the first anchored at the start and the last at the end (greedy, linear per part).
function globMatch(word, parts) {
  if (parts.length === 1) return word === parts[0];
  const first = parts[0], last = parts.at(-1);
  if (word.length < first.length + last.length || !word.startsWith(first) || !word.endsWith(last)) return false;
  let at = first.length;
  const end = word.length - last.length;
  for (const part of parts.slice(1, -1)) {
    const found = word.indexOf(part, at);
    if (found < 0 || found + part.length > end) return false;
    at = found + part.length;
  }
  return true;
}

export const textWords = text => String(text).replace(/\\/g, '/').split(SPLIT).filter(Boolean);

// The words of a command as the shell reads them, for the hook's guard (src/agent-hook-guard.mjs; security review 2026-10-22: a
// guard that read the text as it is let the same call through with an .exe suffix, a path before the program, a cd before a
// relative path, a quote inside a word). Quotes are removed instead of splitting (~/.evid"scope"/x is ~/.evidscope/x); a program
// named by path or with a Windows extension is also its bare name (C:/Windows/System32/schtasks.exe is also schtasks); after cd
// (also chdir, pushd, Set-Location, cd /d) a relative word of a later command is also the path under that directory. Each added
// word follows the word it comes from, so the order a pattern asks for still holds. The vault's engine v6 (matchesWords) keeps
// reading the text as it is: changing it would change signed evaluations. A shell variable, glob or encoded command is not resolved.
const COMMAND_SPLIT = /[\s()[\]{},<>]+/u, SEGMENTS = /\s*(?:\|\||&&|[;|&\n])\s*/u;
const PROGRAM_EXT = /\.(?:exe|com|cmd|bat)$/i, OPTION_OR_ROOT = /^(?:[a-z]:|[/~$%-])/i, CD = new Set(['cd', 'chdir', 'pushd', 'set-location', 'sl']);
// The bare name of a program given by path or with a Windows extension, else null (a lone /option is not a path, a dot name is a
// directory or a dot file).
export function programName(word) {
  const base = word.slice(word.lastIndexOf('/') + 1).replace(PROGRAM_EXT, '');
  return base && base !== word && !base.startsWith('.') && (PROGRAM_EXT.test(word) || !/^\/[^/]*$/.test(word)) ? base : null;
}
export function commandWords(text) {
  // The hook's note starts with the tool in brackets ("[Bash] cd ..."): kept as a word, apart from the first command.
  const tool = /^\s*\[([^\]]*)\]/.exec(String(text)), out = tool ? tool[1].split(COMMAND_SPLIT).filter(Boolean) : [];
  let cwd = null;
  for (const segment of String(text).slice(tool ? tool[0].length : 0).replace(/\\/g, '/').replace(/["'`]/g, '').split(SEGMENTS)) {
    const words = segment.split(COMMAND_SPLIT).filter(Boolean);
    if (!words.length) continue;
    out.push(...words.flatMap((word, i) => {
      const program = programName(word), under = cwd && i > 0 && !OPTION_OR_ROOT.test(word) ? cwd + '/' + word : null;
      return [word, ...(program ? [program] : []), ...(under ? [under] : [])];
    }));
    if (CD.has(words[0].toLowerCase())) {
      const target = words[1]?.toLowerCase() === '/d' ? words[2] : words[1];
      cwd = !target ? null : !cwd || OPTION_OR_ROOT.test(target) ? target : cwd + '/' + target;
    }
  }
  return out;
}

const termMatches = (term, word, lower) => term.alternatives.some(a => globMatch(a.exact ? word : lower, a.parts));

// Parsed patterns by value: every snapshot evaluates the same tenant rules against each event.
const parsed = new Map();
const cachedWords = value => {
  if (!parsed.has(value)) { if (parsed.size >= 1024) parsed.clear(); parsed.set(value, parseWords(value)); }
  return parsed.get(value);
};

function matchList(terms, words) {
  const lowered = words.map(w => w.toLowerCase());
  if (terms.some(t => t.negative && words.some((w, i) => termMatches(t, w, lowered[i])))) return false;
  let i = 0;
  for (const term of terms.filter(t => !t.negative)) {
    while (i < words.length && !termMatches(term, words[i], lowered[i])) i++;
    if (i === words.length) return false;
    i++;
  }
  return true;
}

export function matchesWords(pattern, text) {
  const terms = typeof pattern === 'string' ? cachedWords(pattern) : pattern;
  return terms ? matchList(terms, textWords(text)) : false;
}

// The pattern against the command's words as the shell reads them (commandWords); the hook's guard uses it.
export function matchesCommand(pattern, text) {
  const terms = typeof pattern === 'string' ? cachedWords(pattern) : pattern;
  return terms ? matchList(terms, commandWords(text)) : false;
}
