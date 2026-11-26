// Builds public/theme-dark-base.css from the console's light stylesheets: every rule that paints a light surface, dark text or a
// light border gets a dark counterpart under :root[data-theme="dark"] (light surfaces become dark panels, dark text becomes light,
// saturated accents keep their hue at a lightness readable on a dark panel). public/theme-dark.css adds the hand-written layout and
// component styles on top. Rerun after changing a light stylesheet: node scripts/build-dark-theme.mjs
import {readFileSync, writeFileSync} from 'node:fs';
import {dirname, join} from 'node:path';
import {fileURLToPath} from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', 'public');
const SOURCES = ['style.css', 'graphs.css', 'k8s-evidence.css', 'team-support.css', 'console.css'];
const COLOR = /#(?:[0-9a-fA-F]{3,4}){1,2}\b|rgba?\([^)]*\)|\bwhite\b|\bblack\b/g;

function parseColor(text) {
  if (text === 'white') return [255, 255, 255, 1];
  if (text === 'black') return [0, 0, 0, 1];
  if (text.startsWith('#')) {
    let h = text.slice(1);
    if (h.length <= 4) h = [...h].map(c => c + c).join('');
    const n = [0, 2, 4, 6].map(i => parseInt(h.slice(i, i + 2) || 'ff', 16));
    return [n[0], n[1], n[2], n[3] / 255];
  }
  const parts = text
    .slice(text.indexOf('(') + 1, -1)
    .split(/[\s,/]+/)
    .filter(Boolean)
    .map(Number);
  return [parts[0], parts[1], parts[2], parts.length > 3 ? parts[3] : 1];
}
function toHsl([r, g, b]) {
  r /= 255;
  g /= 255;
  b /= 255;
  const max = Math.max(r, g, b),
    min = Math.min(r, g, b),
    l = (max + min) / 2;
  if (max === min) return [0, 0, l];
  const d = max - min,
    s = l > 0.5 ? d / (2 - max - min) : d / (max + min);
  const h = max === r ? (g - b) / d + (g < b ? 6 : 0) : max === g ? (b - r) / d + 2 : (r - g) / d + 4;
  return [h * 60, s, l];
}
const fmt = (h, s, l, a) =>
  a >= 1
    ? `hsl(${Math.round(h)} ${Math.round(s * 100)}% ${Math.round(l * 100)}%)`
    : `hsl(${Math.round(h)} ${Math.round(s * 100)}% ${Math.round(l * 100)}% / ${Math.round(a * 100) / 100})`;

// role: 'bg' | 'fg' | 'border'. Returns null when the light value already works on a dark page.
function darken(text, role) {
  const rgba = parseColor(text),
    [h, s, l] = toHsl(rgba),
    a = rgba[3];
  if (role === 'bg') {
    if (l >= 0.86) return fmt(h, Math.min(s, 0.18), 0.09 + (1 - l) * 0.35, a); // white and pale tints -> dark panels, tint kept faint
    if (l >= 0.6) return fmt(h, Math.min(s, 0.45), 0.2, a); // light tinted chips -> deep tinted chips
    if (l <= 0.25 && s < 0.5) return fmt(h, s, Math.max(0.07, l * 0.6), a); // navy/ink surfaces -> near-black
    return null; // saturated accents (buttons, bars) keep their colour
  }
  if (role === 'fg') {
    if (l <= 0.5) return fmt(h, Math.min(s, 0.75), s > 0.3 ? 0.72 : 0.82 - l * 0.3, a); // dark text -> light text, accents -> light accents
    if (l >= 0.9) return null; // white text on accent surfaces stays white
    return fmt(h, s, Math.max(l, 0.7), a);
  }
  if (l >= 0.7) return fmt(h, Math.min(s, 0.2), 0.22, a); // light borders -> dark hairlines
  if (l <= 0.4 && s > 0.3) return fmt(h, s, 0.55, a);
  return null;
}
const ROLES = {
  background: 'bg',
  'background-color': 'bg',
  color: 'fg',
  border: 'border',
  'border-color': 'border',
  'border-top': 'border',
  'border-bottom': 'border',
  'border-left': 'border',
  'border-right': 'border',
  outline: 'border',
  'box-shadow': 'border',
  fill: 'bg',
  stroke: 'border',
};

function declarations(body) {
  const out = [];
  for (const decl of body.split(';')) {
    const i = decl.indexOf(':');
    if (i < 0) continue;
    const prop = decl.slice(0, i).trim().toLowerCase(),
      value = decl.slice(i + 1).trim(),
      role = ROLES[prop];
    if (!role || !COLOR.test(value)) {
      COLOR.lastIndex = 0;
      continue;
    }
    COLOR.lastIndex = 0;
    let changed = false;
    const next = value.replace(COLOR, c => {
      const d = darken(c, prop === 'box-shadow' && /inset/.test(value) ? 'border' : role);
      if (d) changed = true;
      return d || c;
    });
    if (changed) out.push(`${prop}:${next}`);
  }
  return out;
}
const scope = selectors =>
  selectors
    .split(',')
    .map(s => s.trim())
    .filter(Boolean)
    .map(s =>
      /^(:root|html)\b/.test(s)
        ? s.replace(/^(:root|html)/, ':root[data-theme="dark"]')
        : /^body\b/.test(s)
          ? `:root[data-theme="dark"] ${s}`
          : `:root[data-theme="dark"] ${s}`,
    )
    .join(',');

// A small brace walker: top-level rules and one level of @media; @keyframes are skipped.
function transform(css) {
  css = css.replace(/\/\*[\s\S]*?\*\//g, '');
  const out = [];
  let i = 0;
  while (i < css.length) {
    const open = css.indexOf('{', i);
    if (open < 0) break;
    const head = css.slice(i, open).trim();
    if (head.startsWith('@')) {
      let depth = 1,
        j = open + 1;
      while (j < css.length && depth) {
        if (css[j] === '{') depth++;
        else if (css[j] === '}') depth--;
        j++;
      }
      if (head.startsWith('@media')) {
        const inner = transform(css.slice(open + 1, j - 1));
        if (inner) out.push(`${head}{${inner}}`);
      }
      i = j;
      continue;
    }
    const close = css.indexOf('}', open);
    const decls = declarations(css.slice(open + 1, close));
    if (decls.length && head) out.push(`${scope(head)}{${decls.join(';')}}`);
    i = close + 1;
  }
  return out.join('\n');
}

const parts = SOURCES.map(name => `/* from ${name} */\n${transform(readFileSync(join(root, name), 'utf8'))}`);
writeFileSync(
  join(root, 'theme-dark-base.css'),
  `/* Generated by scripts/build-dark-theme.mjs from the light stylesheets. Do not edit by hand. */\n${parts.join('\n')}\n`,
);
console.log('theme-dark-base.css written');
