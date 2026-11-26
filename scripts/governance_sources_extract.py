#!/usr/bin/env python3
"""Source tables for governance-mapping derivation (src/governance-mapping-sources.mjs) from the official documents.

  governance_sources_extract.py kisa --pdf PDF --xlsx XLSX --out kisa-isms-p-guide-2023-11.json [--pdf-text TXT]
      KISA ISMS-P 인증기준 안내서 (2023.11.23) + 세부점검항목 (2023.10.31) -> per item: criterion, check items (xlsx),
      evidence examples and defect cases (guide). KOGL type 4: the output stays local (.local/governance-tables/).
      Without --pdf-text the guide is read with `pdftotext -layout -x 0 -y 0 -W 560 -H 842` (poppler), which crops the
      right-margin tabs; --pdf-text takes the output of that same command.
  governance_sources_extract.py eu --html OJ_HTML --retrieved YYYY-MM-DD --out eu-ai-act-2024-1689-text.json
      EUR-Lex OJ L 2024/1689 HTML -> Articles 9-15, 17, 19, 26, 72 and Annex IV as paragraph/point units.
  governance_sources_extract.py kr --law LAW_XML --decree DECREE_XML --retrieved YYYY-MM-DD --out kr-ai-basic-act-2026-text.json
      law.go.kr DRF XML (file names carry MST<number>) of the AI Basic Act and its decree -> article/paragraph/item units.

Standard library only; the same inputs give the same bytes, so the table hash the dataset rows carry (derivation.tableSha256)
is reproducible on any machine that holds the documents. Each table records its sources' sha256 and licence.
"""
import argparse
import collections
import hashlib
import html
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
import zipfile


def sha256_file(path):
    with open(path, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()


def dump(table, out):
    with open(out, 'w', encoding='utf-8') as f:
        json.dump(table, f, ensure_ascii=False, indent=1)


# ---------- KISA ISMS-P guide (PDF) ----------
ITEM = re.compile(r'^\s*항 목\s+(\d\.\d{1,2}\.\d)\s+(.+?)\s*$')
FOOTER = re.compile(r'^\s*(\d{1,3}|정보보호 및 개인정보보호 관리체계 인증제도 안내서|제\d장 .*인증기준 설명)\s*$')
CHECK_BULLET, LIST_BULLET = '', ''  # private-use glyphs of the guide's bullet font


def clean(s):
    return re.sub(r'\s+', ' ', s.replace('\x0c', '')).strip()


def kisa_guide_items(text):
    """Item blocks of the cropped pdftotext output: criterion, check items, evidence examples (증거자료 예시), defect cases (결함사례)."""
    lines = text.split('\n')
    starts = [i for i, l in enumerate(lines) if ITEM.match(l.replace('\x0c', ''))]
    items = []
    for n, i in enumerate(starts):
        j = starts[n + 1] if n + 1 < len(starts) else len(lines)
        blk = [l.replace('\x0c', '') for l in lines[i:j]]
        m = ITEM.match(blk[0])
        number, title = m.group(1), clean(m.group(2))

        def find(pred, start=0):
            for k in range(start, len(blk)):
                if pred(blk[k]):
                    return k
            return None
        kc = find(lambda l: l.strip() == '주요 확인사항')
        kl = find(lambda l: l.strip() in ('관련 법규', '관련법규') or l.strip().startswith('관련 법규'))
        kd = find(lambda l: l.strip() in ('세부 설명', '세부설명'))
        ke = find(lambda l: l.strip() == '증거자료')
        kf = find(lambda l: l.strip() == '결함사례', ke or 0)
        crit = []
        for l in blk[1:(kc if kc else 1)]:
            s = l.strip()
            if not s or s.startswith(CHECK_BULLET) or s.startswith(LIST_BULLET):
                if s.startswith(CHECK_BULLET) or s.startswith(LIST_BULLET):
                    break
                continue
            crit.append(re.sub(r'^인증기준\s*', '', s))
        checks, cur = [], None
        for l in blk[1:(kl if kl else (kd if kd else len(blk)))]:
            s = l.strip()
            if s == '주요 확인사항' or not s or s.startswith('인증기준'):
                continue
            if s.startswith(CHECK_BULLET):
                if cur:
                    checks.append(clean(cur))
                cur = s[1:].strip()
            elif cur is not None and l.startswith(' ' * 8):
                cur += ' ' + s
        if cur:
            checks.append(clean(cur))

        def bullets(start, stop):
            out, cur = [], None
            for l in blk[start:stop]:
                s = l.strip()
                if not s or s == '예시' or FOOTER.match(l):
                    continue
                if s.startswith(LIST_BULLET):
                    if cur:
                        out.append(clean(cur))
                    cur = s[1:].strip()
                elif cur is not None:
                    cur += ' ' + s
            if cur:
                out.append(clean(cur))
            return out
        evidence = bullets(ke + 1, kf if kf is not None else len(blk)) if ke is not None else []
        defects = [re.sub(r'^사례\s*\d+\s*[:：]\s*', '', d) for d in bullets(kf + 1, len(blk))] if kf is not None else []
        items.append({'number': number, 'title': title, 'criterion': clean(' '.join(crit)), 'checkItems': checks,
                      'evidenceExamples': evidence, 'defectCases': defects})
    return items


# ---------- KISA detailed check items (xlsx) ----------
def kisa_check_items(path):
    """Sheets 1-3, columns D (항목) E (명칭) F (상세내용) G (주요 확인사항); a row without D continues the item above."""
    z = zipfile.ZipFile(path)
    ss = z.read('xl/sharedStrings.xml').decode()
    strings = [html.unescape(re.sub(r'<[^>]+>', '', m)) for m in re.findall(r'<si>(.*?)</si>', ss, flags=re.S)]

    def rows(sheet):
        d = z.read(sheet).decode()
        out = []
        for r in re.findall(r'<row [^>]*>(.*?)</row>', d, flags=re.S):
            cells = {}
            for ref, typ, inner in re.findall(r'<c r="([A-Z]+)\d+"(?: s="\d+")?(?: t="(\w+)")?[^>]*?(?:/>|>(.*?)</c>)', r, flags=re.S):
                v = re.search(r'<v>(.*?)</v>', inner or '', flags=re.S)
                if not v:
                    continue
                val = v.group(1)
                if typ == 's':
                    val = strings[int(val)]
                cells[ref] = re.sub(r'\s+', ' ', val).strip()
            out.append(cells)
        return out
    items, cur = [], None
    for sh in ['sheet1', 'sheet2', 'sheet3']:
        for r in rows('xl/worksheets/%s.xml' % sh):
            if re.fullmatch(r'\d\.\d{1,2}\.\d', r.get('D', '')):
                cur = {'number': r['D'], 'title': r.get('E', ''), 'detail': r.get('F', ''), 'checkItems': []}
                items.append(cur)
                if r.get('G'):
                    cur['checkItems'].append(r['G'])
            elif cur and r.get('G') and not r.get('D'):
                cur['checkItems'].append(r['G'])
    return items


def kisa_table(pdf, xlsx, pdf_text=None):
    if pdf_text is None:
        if not shutil.which('pdftotext'):
            sys.exit('pdftotext (poppler) is not installed; pass --pdf-text with its output instead')
        with tempfile.TemporaryDirectory() as d:
            tmp = os.path.join(d, 'guide.txt')
            subprocess.run(['pdftotext', '-layout', '-x', '0', '-y', '0', '-W', '560', '-H', '842', pdf, tmp], check=True)
            with open(tmp, encoding='utf-8') as f:
                text = f.read()
    else:
        with open(pdf_text, encoding='utf-8') as f:
            text = f.read()
    guide = kisa_guide_items(text)
    checks = {i['number']: i for i in kisa_check_items(xlsx)}
    items = []
    for it in guide:
        x = checks.get(it['number'], {})
        # Title and criterion come from the spreadsheet (명칭, 상세내용) where it has the item; the guide's copies differ in
        # bullet characters and a few words.
        items.append({'number': it['number'], 'title': x.get('title') or it['title'], 'criterion': x.get('detail') or it['criterion'],
                      'checkItems': x.get('checkItems') or it['checkItems'], 'evidenceExamples': it['evidenceExamples'],
                      'defectCases': it['defectCases']})
    return {'schemaVersion': 1, 'id': 'kisa-isms-p-guide-2023-11',
            'title': 'ISMS-P 인증기준 안내서(2023.11.23) 항목별 주요 확인사항·증거자료 예시·결함사례',
            'licence': {'name': 'KOGL Type 4 (공공누리 제4유형: 출처표시, 상업적 이용금지, 변경금지)',
                        'use': 'local-only; never shipped in the repository or a release; commercial use needs KISA permission'},
            'sources': [{'file': os.path.basename(pdf), 'sha256': sha256_file(pdf), 'bytes': os.path.getsize(pdf),
                         'publisher': '한국인터넷진흥원(KISA)·개인정보보호위원회',
                         'extraction': 'pdftotext -layout -W 560 (right margin tabs cropped), bullets \\uf09f under 증거자료 예시 / 결함사례'},
                        {'file': os.path.basename(xlsx), 'sha256': sha256_file(xlsx), 'bytes': os.path.getsize(xlsx), 'publisher': 'KISA',
                         'extraction': 'xlsx sheets 1-3, columns D (항목) E (명칭) F (상세내용) G (주요 확인사항)'}],
            'items': items}


# ---------- EU AI Act (EUR-Lex OJ HTML) ----------
EU_ARTICLES = [(12, 13), (14, 15), (19, 20), (26, 27), (72, 73), (11, 12), (13, 14), (15, 16), (17, 18), (9, 10), (10, 11)]


def eu_table(path, retrieved):
    with open(path, encoding='utf-8') as f:
        t = f.read()

    def text(h):
        return html.unescape(re.sub(r'\s+', ' ', re.sub(r'<[^>]+>', ' ', h))).strip()

    def segment(start, ends):
        s = t.index('id="%s"' % start)
        s = t.rfind('<', 0, s)
        e = min([t.find('id="%s"' % x, s + 10) for x in ends if t.find('id="%s"' % x, s + 10) > 0] + [len(t)])
        return t[s:e]

    def units(seg):
        """oj-normal paragraphs: '1.' starts a paragraph, '(a)' a point under it; table rows hold points as two cells."""
        flat = []
        for m in re.finditer(r'<p class="oj-normal">(.*?)</p>|<tr>(.*?)</tr>', seg, flags=re.S):
            if m.group(1) is not None:
                flat.append(text(m.group(1)))
            else:
                cells = [c for c in (text(c) for c in re.findall(r'<td[^>]*>(.*?)</td>', m.group(2), flags=re.S)) if c]
                if cells:
                    flat.append(' '.join(cells))
        out, cur = [], None
        for s in flat:
            if not s:
                continue
            m = re.match(r'^(\d+)\.\s+(.*)$', s)
            if m:
                cur = {'paragraph': m.group(1), 'text': m.group(2), 'points': []}
                out.append(cur)
                continue
            m = re.match(r'^\(([a-z]{1,2})\)\s+(.*)$', s)
            if m and cur is not None:
                cur['points'].append({'point': m.group(1), 'text': m.group(2)})
                continue
            if cur is None:
                out.append({'paragraph': None, 'text': s, 'points': []})
                cur = out[-1]
            else:
                cur['text'] += ' ' + s
        return out
    articles = []
    for n, nxt in EU_ARTICLES:
        seg = segment('art_%d' % n, ['art_%d' % nxt])
        title = text(re.search(r'<p class="oj-sti-art">(.*?)</p>', seg, flags=re.S).group(1))
        articles.append({'article': n, 'title': title, 'units': units(seg)})
    anx = segment('anx_IV', ['anx_V'])
    titles = [text(x) for x in re.findall(r'<p class="oj-doc-ti">(.*?)</p>', anx, flags=re.S)]
    annex = {'annex': 'IV', 'title': ' '.join(titles[:2]) or 'ANNEX IV Technical documentation referred to in Article 11(1)', 'units': units(anx)}
    return {'schemaVersion': 1, 'id': 'eu-ai-act-2024-1689-text',
            'title': 'Regulation (EU) 2024/1689 (AI Act): Articles 9-15, 17, 19, 26, 72 and Annex IV as paragraph/point units',
            'licence': {'name': 'EUR-Lex reuse (Commission Decision 2011/833/EU): reuse allowed with source acknowledgement',
                        'use': 'shipped in the repository with this notice'},
            'sources': [{'file': os.path.basename(path), 'sha256': sha256_file(path), 'bytes': os.path.getsize(path),
                         'url': 'https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=OJ:L_202401689', 'retrieved': retrieved}],
            'articles': articles, 'annexes': [annex]}


# ---------- Korean AI Basic Act and decree (law.go.kr DRF XML) ----------
CIRCLED = {c: i + 1 for i, c in enumerate('①②③④⑤⑥⑦⑧⑨⑩⑪⑫⑬⑭⑮⑯⑰⑱⑲⑳')}


def kr_clean(s):
    return re.sub(r'\s+', ' ', (s or '').replace('ㆍ', '·')).strip()


def strip_lead(s, pat):
    return re.sub(pat, '', s, count=1).strip()


def kr_doc(path, kind):
    r = ET.parse(path).getroot()
    info = r.find('기본정보')
    doc = {'kind': kind, 'name': kr_clean(info.findtext('법령명_한글')), 'lawId': info.findtext('법령ID'),
           'mst': re.search(r'MST(\d+)', os.path.basename(path)).group(1), 'promulgated': info.findtext('공포일자'),
           'effective': info.findtext('시행일자'), 'articles': []}
    for a in r.findall('./조문/조문단위'):
        if (a.findtext('조문여부') or '') != '조문':
            continue
        num, branch = (a.findtext('조문번호') or '').strip(), (a.findtext('조문가지번호') or '').strip()
        art = {'article': num + ('의' + branch if branch else ''), 'title': kr_clean(a.findtext('조문제목')), 'text': '', 'paragraphs': []}
        body = re.sub(r'<[^>]*>', '', strip_lead(kr_clean(a.findtext('조문내용')), r'^제\d+조(의\d+)?\([^)]*\)\s*')).strip()
        hs = a.findall('항')
        if not hs or (body and not re.fullmatch(r'제\d+조.*', body)):
            art['text'] = body
        for h in hs:
            hn = (h.findtext('항번호') or '').strip()
            ht = re.sub(r'<[^>]*>', '', strip_lead(kr_clean(h.findtext('항내용')), r'^[①-⑳]\s*')).strip()
            p = {'paragraph': str(CIRCLED.get(hn, hn)), 'text': ht, 'items': []}
            for ho in h.findall('호'):
                ot = re.sub(r'<[^>]*>', '', strip_lead(kr_clean(ho.findtext('호내용')), r'^\d+\.\s*')).strip()
                p['items'].append({'item': kr_clean(ho.findtext('호번호')).rstrip('.'), 'text': ot})
            art['paragraphs'].append(p)
        doc['articles'].append(art)
    return doc


def kr_table(law, decree, retrieved):
    def source(path, mst):
        return {'file': os.path.basename(path), 'sha256': sha256_file(path), 'bytes': os.path.getsize(path),
                'url': 'https://www.law.go.kr/DRF/lawService.do?OC=test&target=law&MST=%s&type=XML' % mst, 'retrieved': retrieved}
    law_doc, decree_doc = kr_doc(law, 'law'), kr_doc(decree, 'decree')
    return {'schemaVersion': 1, 'id': 'kr-ai-basic-act-2026-text',
            'title': '인공지능 발전과 신뢰 기반 조성 등에 관한 기본법(법률, 시행 2026-01-22)과 시행령(시행 2026-08-20)의 조·항·호',
            'licence': {'name': '법령 본문: 저작권법 제7조제1호(보호받지 못하는 저작물)', 'use': 'shipped in the repository; source law.go.kr DRF'},
            'sources': [source(law, law_doc['mst']), source(decree, decree_doc['mst'])], 'law': law_doc, 'decree': decree_doc}


def main(argv):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest='command', required=True)
    k = sub.add_parser('kisa')
    k.add_argument('--pdf', required=True)
    k.add_argument('--xlsx', required=True)
    k.add_argument('--pdf-text')
    k.add_argument('--out', required=True)
    e = sub.add_parser('eu')
    e.add_argument('--html', required=True)
    e.add_argument('--retrieved', required=True)
    e.add_argument('--out', required=True)
    r = sub.add_parser('kr')
    r.add_argument('--law', required=True)
    r.add_argument('--decree', required=True)
    r.add_argument('--retrieved', required=True)
    r.add_argument('--out', required=True)
    a = p.parse_args(argv)
    if a.command == 'kisa':
        table = kisa_table(a.pdf, a.xlsx, a.pdf_text)
        c = collections.Counter()
        for it in table['items']:
            c['items'] += 1
            c['check'] += len(it['checkItems'])
            c['evidence'] += len(it['evidenceExamples'])
            c['defect'] += len(it['defectCases'])
        summary = dict(c)
    elif a.command == 'eu':
        table = eu_table(a.html, a.retrieved)
        summary = {'articles': len(table['articles']), 'paragraphs': sum(len(x['units']) for x in table['articles']),
                   'annexUnits': len(table['annexes'][0]['units'])}
    else:
        table = kr_table(a.law, a.decree, a.retrieved)
        summary = {d: {'articles': len(table[d]['articles']), 'paragraphs': sum(len(x['paragraphs']) for x in table[d]['articles'])}
                   for d in ('law', 'decree')}
    dump(table, a.out)
    print(json.dumps({'out': a.out, 'sha256': sha256_file(a.out), 'bytes': os.path.getsize(a.out), **summary}, ensure_ascii=False))


if __name__ == '__main__':
    main(sys.argv[1:])
