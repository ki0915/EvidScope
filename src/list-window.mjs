// Time windows and cursors for console lists (docs/feature-guide.md): newest first, since/until on the list's own time and an
// opaque cursor for "load older". A list read without these parameters keeps its earlier order and paging. Nothing is deleted.
import {fail} from './model.mjs';

export const LIST_WINDOW_PARAMS = ['since', 'until', 'cursor', 'order'];
export const encodeCursor = parts => Buffer.from(JSON.stringify(parts)).toString('base64url');
export function decodeCursor(value) {
  let parts;
  try { parts = JSON.parse(Buffer.from(String(value).slice(0, 2000), 'base64url').toString('utf8')); } catch { fail(400, 'cursor 형식 오류'); }
  if (!Array.isArray(parts) || !parts.length || parts.length > 4 || parts.some(v => typeof v !== 'string' || v.length > 600)) fail(400, 'cursor 형식 오류');
  return parts;
}
// null when the request names none of the window parameters (the list's previous behaviour).
export function listWindow(params, {maxLimit = 500, defaultLimit = 100, parts = 2} = {}) {
  if (!LIST_WINDOW_PARAMS.some(k => params.has(k))) return null;
  if (params.has('order') && params.get('order') !== 'desc') fail(400, 'order는 desc만 지원합니다');
  const time = k => {
    const v = params.get(k);if (v === null || v === '') return null;
    if (v.length > 40 || !Number.isFinite(Date.parse(v))) fail(400, `${k}는 ISO 8601 시각입니다`);
    return new Date(Date.parse(v)).toISOString();
  };
  const since = time('since'), until = time('until');
  if (since && until && since >= until) fail(400, 'since는 until보다 앞서야 합니다');
  const limit = Math.max(1, Math.min(maxLimit, Math.floor(Number(params.get('limit'))) || defaultLimit));
  const cursor = params.get('cursor') ? decodeCursor(params.get('cursor')) : null;
  if (cursor && cursor.length !== parts) fail(400, 'cursor 형식 오류');
  return {since, until, limit, cursor};
}
const compare = (a, b) => { for (let i = 0; i < a.length; i++) { if (a[i] < b[i]) return -1;if (a[i] > b[i]) return 1; } return 0; };
// In-memory lists (alerts, cases): newest first by [time, id]; windowTotal counts the window without the cursor.
export function pageNewestFirst(items, {since, until, limit, cursor}, keyOf) {
  const inWindow = items.filter(x => { const t = keyOf(x)[0];return (!since || t >= since) && (!until || t < until); });
  const older = (cursor ? inWindow.filter(x => compare(keyOf(x), cursor) < 0) : inWindow).sort((a, b) => compare(keyOf(b), keyOf(a)));
  const page = older.slice(0, limit), more = older.length > limit;
  return {items: page, windowTotal: inWindow.length, hasMore: more, nextCursor: more ? encodeCursor(keyOf(page.at(-1))) : null,
    window: {since, until, order: 'desc'}};
}
