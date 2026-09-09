"""Build the first development report and portfolio from a fixed evidence snapshot.

Uses bundled Python + reportlab. No model calls, credentials, or network access.
Source snapshot: 300c07f, with reports collected through 2026-09-09 19:00 KST.
Later security fixes and development-operation integration require a new revision.
"""
from pathlib import Path
from xml.sax.saxutils import escape
import json
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak, KeepTogether
from reportlab.graphics.shapes import Drawing, Rect, String, Line, Polygon
from reportlab.graphics import renderSVG

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'output/pdf'
ASSETS = ROOT / 'docs/assets/portfolio'
OUT.mkdir(parents=True, exist_ok=True)
ASSETS.mkdir(parents=True, exist_ok=True)
pdfmetrics.registerFont(TTFont('KR', 'C:/Windows/Fonts/malgun.ttf'))
pdfmetrics.registerFont(TTFont('KRB', 'C:/Windows/Fonts/malgunbd.ttf'))
pdfmetrics.registerFontFamily('KR', normal='KR', bold='KRB', italic='KR', boldItalic='KRB')
INK = '#172C3C'; NAVY = '#163B4C'; TEAL = '#147F79'; MUTED = '#536774'; PALE = '#F1F6F8'; LINE = '#D9D9D9'; AMBER = '#98621B'
styles = {
 'body': ParagraphStyle('body', fontName='KR', fontSize=10, leading=16, textColor=colors.HexColor(INK), wordWrap='CJK', spaceAfter=9),
 'small': ParagraphStyle('small', fontName='KR', fontSize=8, leading=12, textColor=colors.HexColor(MUTED), wordWrap='CJK', spaceAfter=6),
 'title': ParagraphStyle('title', fontName='KRB', fontSize=25, leading=34, textColor=colors.black, wordWrap='CJK', spaceAfter=12),
 'h1': ParagraphStyle('h1', fontName='KRB', fontSize=19, leading=26, textColor=colors.black, wordWrap='CJK', spaceAfter=12),
 'h2': ParagraphStyle('h2', fontName='KRB', fontSize=12, leading=18, textColor=colors.black, wordWrap='CJK', spaceBefore=9, spaceAfter=6),
 'cell': ParagraphStyle('cell', fontName='KR', fontSize=8.4, leading=13, textColor=colors.HexColor(INK), wordWrap='CJK'),
 'th': ParagraphStyle('th', fontName='KRB', fontSize=8.5, leading=13, textColor=colors.white, wordWrap='CJK'),
}

def p(s, style='body'):
 return Paragraph(escape(s).replace('\n','<br/>'), styles[style])

def table(headers, rows, widths):
 data = [[p(v,'th') for v in headers]] + [[p(str(v),'cell') for v in row] for row in rows]
 t = Table(data, colWidths=widths, repeatRows=1, hAlign='LEFT')
 t.setStyle(TableStyle([
  ('BACKGROUND',(0,0),(-1,0),colors.HexColor(NAVY)),
  ('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.white,colors.HexColor(PALE)]),
  ('GRID',(0,0),(-1,-1),.45,colors.HexColor(LINE)),
  ('VALIGN',(0,0),(-1,-1),'MIDDLE'),
  ('LEFTPADDING',(0,0),(-1,-1),9),('RIGHTPADDING',(0,0),(-1,-1),9),
  ('TOPPADDING',(0,0),(-1,-1),7),('BOTTOMPADDING',(0,0),(-1,-1),7),
 ]))
 return t

def arch():
 d=Drawing(510,224)
 def label(x,y,s,size=10,bold=False,color=INK):
  d.add(String(x,y,s,fontName='KRB' if bold else 'KR',fontSize=size,fillColor=colors.HexColor(color)))
 def box(x,y,w,h,title,sub,fill=PALE):
  d.add(Rect(x,y,w,h,rx=6,fillColor=colors.HexColor(fill),strokeColor=colors.HexColor(LINE)))
  label(x+10,y+h-19,title,10,True);label(x+10,y+12,sub,8,color=MUTED)
 def arr(x1,y1,x2,y2):
  d.add(Line(x1,y1,x2,y2,strokeColor=colors.HexColor(TEAL),strokeWidth=1.6))
  dx=x2-x1;dy=y2-y1;n=(dx*dx+dy*dy)**.5;ux=dx/n;uy=dy/n
  d.add(Polygon([x2,y2,x2-6*ux+3*uy,y2-6*uy-3*ux,x2-6*ux-3*uy,y2-6*uy+3*ux],fillColor=colors.HexColor(TEAL),strokeColor=None))
 label(0,211,'관측 경로',9,True,TEAL)
 box(0,139,124,54,'업무 AI와 도구','출처별 행동과 참고자료')
 box(156,139,124,54,'수집 gateway','출처 인증과 접수')
 box(314,139,192,54,'Vault와 분석 worker','서명 원장 · 규칙 · 사건 기록')
 arr(124,166,156,166);arr(280,166,314,166)
 label(156,109,'사람이 요청하는 로컬 AI 지원',9,True,TEAL)
 box(0,34,124,54,'사람의 자료 선택','사건과 역할 범위 확인')
 box(156,34,124,54,'로컬 실행기','작업 자격 하나 · Qwen 4B')
 box(314,34,192,54,'AI 초안과 인간 검토','채택 · 수정 · 반려를 따로 보존')
 arr(124,61,156,61);arr(280,61,314,61)
 d.add(Line(410,139,410,121,strokeColor=colors.HexColor(TEAL),strokeWidth=1.6))
 d.add(Line(410,121,62,121,strokeColor=colors.HexColor(TEAL),strokeWidth=1.6))
 arr(62,121,62,88)
 label(0,8,'AI 실행기에 Vault DB · 서명키 · 인간 감사자 토큰을 제공하지 않는 설계',8,color=MUTED)
 d.hAlign='CENTER'
 return d

def distribution():
 d=Drawing(510,130)
 for y,label,a,b in [(91,'수집 Service',27,33),(38,'감사 Service',33,27)]:
  d.add(String(0,y+12,label,fontName='KRB',fontSize=10,fillColor=colors.HexColor(INK)))
  x=110; scale=5.45
  for count,c in [(a,TEAL),(b,NAVY)]:
   d.add(Rect(x,y,count*scale,30,fillColor=colors.HexColor(c),strokeColor=None))
   d.add(String(x+count*scale/2,y+10,str(count),fontName='KRB',fontSize=11,textAnchor='middle',fillColor=colors.white));x+=count*scale
  d.add(String(449,y+10,'60 / 60',fontName='KRB',fontSize=10,fillColor=colors.HexColor(INK)))
 d.add(String(110,2,'두 색은 각 Service의 서로 다른 처리 Pod를 나타냅니다',fontName='KR',fontSize=8,fillColor=colors.HexColor(MUTED)))
 return d

def shot(name,width):
 from PIL import Image as PILImage
 path=ASSETS/name
 with PILImage.open(path) as img:w,h=img.size
 return Image(str(path),width=width,height=width*h/w,hAlign='CENTER')

def footer(kind):
 def draw(c,doc):
  w,h=doc.pagesize
  c.setFont('KRB',8);c.setFillColor(colors.HexColor(TEAL));c.drawString(42,h-29,'EVIDSCOPE')
  c.setFont('KR',8);c.setFillColor(colors.HexColor(MUTED));c.drawRightString(w-42,h-29,kind+'  /  1차 초본')
  c.setStrokeColor(colors.HexColor(LINE));c.setLineWidth(.5);c.line(42,37,w-42,37)
  c.setFont('KR',7);c.drawString(42,24,'2026.09.09 19:00 KST 기준  ·  검증 기준 300c07f  ·  합성 데이터 파일럿')
  c.drawRightString(w-42,24,f'{doc.page:02d}')
 return draw

class Publication:
 def __init__(self,title,filename,mdpath,pagesize=A4):
  self.title=title;self.filename=filename;self.mdpath=mdpath;self.story=[];self.md=['# '+title,'','기준 시점: 2026-09-09 19:00 KST · 검증 기준 커밋 `300c07f` · 1차 초본',''];self.pagesize=pagesize
 def heading(self,s,title=False):self.story.append(p(s,'title' if title else 'h1'));self.md+=['## '+s,'']
 def sub(self,s):self.story.append(p(s,'h2'));self.md+=['### '+s,'']
 def para(self,s,small=False):self.story.append(p(s,'small' if small else 'body'));self.md+=[s,'']
 def grid(self,heads,rows,widths):
  self.story += [table(heads,rows,widths),Spacer(1,10)]
  self.md += ['| '+' | '.join(heads)+' |','| '+' | '.join(['---']*len(heads))+' |']
  self.md += ['| '+' | '.join(str(v).replace('\n','<br>') for v in row)+' |' for row in rows];self.md+=['']
 def image(self,name,width,caption):
  self.story += [shot(name,width),Spacer(1,8)];self.para(caption,True)
  self.md += [f'![{caption}](../docs/assets/portfolio/{name})',''] if self.mdpath.startswith('reports/') else [f'![{caption}](assets/portfolio/{name})','']
 def diagram(self):self.story +=[arch(),Spacer(1,8)];self.md+=['```mermaid','flowchart LR','  W[업무 AI와 도구] --> I[수집 gateway] --> V[Vault와 규칙 분석]','  V --> H[사람의 자료 선택] --> L[로컬 실행기] --> D[AI 검토 초안] --> R[인간 검토 기록]','```','']
 def page(self):self.story.append(PageBreak());self.md+=['---','']
 def build(self):
  doc=SimpleDocTemplate(str(OUT/self.filename),pagesize=self.pagesize,rightMargin=42,leftMargin=42,topMargin=52,bottomMargin=49,title=self.title,author='EvidScope',subject='사용자 주도 AI 협업 개발의 실제 구현과 검증 현황')
  doc.build(self.story,onFirstPage=footer('개발 보고서' if self.pagesize==A4 else '프로젝트 포트폴리오'),onLaterPages=footer('개발 보고서' if self.pagesize==A4 else '프로젝트 포트폴리오'))
  (ROOT/self.mdpath).write_text('\n'.join(self.md),encoding='utf-8')

R=Publication('EvidScope 1차 개발 보고서','evidscope-first-development-report.pdf','reports/first-development-report-20260909.md')
R.heading('EvidScope 1차 개발 보고서',True)
R.para('AI 행동과 참고자료를 근거로 사람이 검토하는 감사 지원 서비스')
R.para('현재 결과물은 실행 가능한 로컬 파일럿이다. 에이전트별 행동·정책 평가와 사건 검토를 제공하며, 선택한 사건 자료를 실제 로컬 모델에 전달해 초안을 만들고 별도 검토 기록을 남기는 흐름을 확인했다. 운영 배포를 승인할 단계는 아니며, 독립 감사에서 재현한 결함과 모델의 인용 오류를 후속 작업으로 관리한다.')
R.sub('해결하려는 실무 문제')
R.para('AI가 작업을 성공했다고 보고해도 도구 실행 결과, 당시 권한, 사용한 자료의 버전이 서로 다를 수 있다. EvidScope는 이 기록들을 한 행동으로 연결하고, 확인되지 않은 부분을 드러내어 보안 담당자와 감사자가 판단 근거를 남기도록 한다.')
R.grid(['기능 묶음','1차 상태','현재 확인 범위'],[
 ['행동과 참고자료 가시성','구현','출처별 기록 대조, 행동 연결도, 검색과 시간축'],
 ['에이전트별 지표','구현','정책 준수율과 평가 범위, 미확인과 재검토 구분'],
 ['사건과 거버넌스','구현','인간 검토, 규칙 버전, 근거 연결, 서명 보고서'],
 ['로컬 AI 검토 지원','실제 추론 확인','Qwen3 4B의 초안과 합성 검토 API 및 화면 흐름'],
 ['다중 개발 에이전트 운영','통합 진행','역할 패키지, 실행 이벤트, 협업 상한과 인수인계'],
 ['운영 승격','미완료','보안 수정 재검증, 모델 품질, SSO와 저장소 HA'],
],[125,90,296])
R.sub('이 보고서의 기준')
R.para('검증 기준은 300c07f와 2026년 9월 9일 19시까지 확보한 원자료다. 이후 진행 중인 보안 수정과 별도 작업 브랜치의 결과는 완료 성과로 포함하지 않는다. Kubernetes 수치는 9월 8일 이전 구현의 실험이며 최신 AI 지원 기능의 배포 결과와 구분한다.',True)
R.para('사용자 역할은 목표·우선순위·비용·모델 배치 결정이며, 코드와 문서는 AI 협업으로 작성되었다. 개인의 직접 작성 비율, 고객 도입 실적, 업무 시간 절감률은 측정하지 않았다.',True)
R.sub('시험 외에는 실행 자원을 중지')
R.para('후속 운영 지시를 반영해 19시 14분에 유휴 로컬 모델 컨테이너, 전용 Kubernetes 시험 클러스터와 로컬 시험 서버를 중지하고 관련 포트가 닫힌 것을 확인했다. 테스트를 명시적으로 시작할 때만 자원을 켜고 종료·실패 시 정리하는 도구는 추가 구현 중이다. 데이터와 볼륨은 보존했다.',True)

R.page();R.heading('시스템 구조와 판단의 경계')
R.para('업무 실행의 관측 경로와 선택적 AI 검토 경로를 분리했다. 로컬 모델의 실패가 원본 증거의 수집·규칙 평가·인간 검토를 대체하거나 중단시키지 않도록 구성한다.')
R.diagram()
R.grid(['구성요소','책임','선택한 이유'],[
 ['Node API와 정적 UI','수집·감사 gateway와 조사 화면','기존 구조 확장, 프레임워크 전환 비용 억제'],
 ['Vault와 SQLite','증거·사건·서명 원장 소유','신뢰 영역 축소와 독립 내보내기 검증'],
 ['규칙 worker','관측 사실과 정책 대조','상시 추론 비용 없이 반복 평가'],
 ['로컬 실행기와 Ollama','선별 묶음으로 AI 초안 생성','원본 저장소 자격과 추론 권한 분리'],
],[119,179,213])
R.sub('기록 무결성과 내용의 진실성을 구별')
R.para('서명은 기록이 바뀌었는지 확인하는 수단이다. 서명된 자기보고가 사실인지, 인용한 자료가 주장을 뒷받침하는지는 별도 검토가 필요하다. 해시와 자료 참조만으로 실제 사용 여부나 모델 내부 사고 과정을 입증하지 않는다.')
R.para('작업 자격은 특정 실행 하나에만 묶는다. 실행기에는 Vault DB·서명키·인간 감사자 토큰을 전달하지 않는다. 단, 현재 호스트 CLI와 같은 PC의 컨테이너 배치는 호스트 관리자 침해에 대한 독립 격리를 보장하지 않는다. 저장 사본과 서명 원본의 일치 검증 누락은 별도 감사에서 확인해 수정 중이다.',True)

R.page();R.heading('에이전트별 가시성과 조사 화면')
R.para('수치를 클릭해 행동과 근거로 이동한다. 지표의 분모와 관측 범위를 함께 보여 주며, 기록이 없거나 판단할 수 없는 경우를 통과로 계산하지 않는다.')
R.image('agents-20260909.jpg',511,'실제 실행 화면 2026-09-09. 합성 support-agent와 로컬 Qwen 0.6B 연결 시험 기록이 표시된다. 이 목록의 0.6B는 별도 감사 지원 후보인 4B와 다른 실행이다.')
R.sub('준수율과 평가 범위')
R.para('관측 정책 준수율 = 충족 행동 ÷ (충족 행동 + 위반 신호 행동). 미확인·분석 대기·예외는 분모에서 제외하고 평가 범위를 따로 표시한다. 판정 가능한 행동이 0개이면 산정 불가다. 이는 법적 준수율이나 모델의 전반적 신뢰 점수가 아니다.')
R.grid(['사용 목적','조회 구간','집계 단위','화면 갱신'],[
 ['상세 조사','최근 10분','30초','30초'],['운영 모니터링','최근 1시간','1분','1분'],['일간 추세','최근 24시간','5분','5분'],['주간 검토','최근 7일','1시간','15분'],
],[145,126,120,120])
R.para('확대·축소, 시간축 이동, 최신 따라가기와 일시정지를 지원한다. 화면 조회 주기는 이벤트 수집·탐지 주기와 별개다. 정책 준수율, 역할 시험 성적, 실제 인간 채택률은 서로 다른 지표로 유지한다.',True)

R.page();R.heading('실제 로컬 AI 실행과 품질 관찰')
R.para('RTX 3080 12GB와 RAM 32GB 환경에서 Ollama의 Qwen3 4B Q4_K_M을 실행했다. 아래 두 회차는 합성 자료를 사용한 개별 기능 시험이며 평균 지연·정확도·실무 품질 벤치마크가 아니다.')
R.grid(['시험','실행 결과','입력 / 출력 토큰','공급자 보고 시간'],[
 ['API 연결 회차','completed · 주장 3개','1,207 / 478','10.90초'],['화면 연계 회차','abstained · 주장 5개','3,501 / 592','46.04초'],
],[112,146,128,125])
R.image('advisory-review-20260909.jpg',460,'실제 Qwen3 4B 결과를 조회한 화면. 오른쪽 반려 기록은 자동화가 합성 감사자 자격으로 남긴 시험 기록이며 실제 사람의 내용 검수나 법적 판단이 아니다.')
R.sub('인용이 존재해도 주장을 뒷받침하지 않을 수 있다')
R.para('화면 연계 회차에서는 도구 실패와 AI 자기보고의 모순을 제시했지만, 참고자료 충돌·수집 공백 주장 일부는 선택된 인용만으로 입증되지 않았다. 사건 전체 규칙 평가를 선택 근거의 직접 증거처럼 사용한 문제가 있어 초안을 시험상 반려했다. 품질 승격 승인은 하지 않았다.')
R.para('개선 방향은 사건 전체 참고 평가와 선택 증거의 지지 범위를 구분하고, 근거가 없는 주장은 유보하도록 역할 지침과 평가 사례를 강화하는 것이다. 모델명·digest·토큰·시간은 공급자가 보고한 메타데이터이며 독립 인증 값이 아니다. [E1, E2]',True)

R.page();R.heading('적대적 감사와 검증에서 확인한 문제')
R.para('구현 문맥과 분리된 GPT-6 Astra high 세션이 요구사항·코드·시험을 검토하고 실제 HTTP 및 함수 재현 검사를 수행했다. 검토 모델의 동의와 시험 통과를 동일시하지 않는다.')
R.grid(['ID와 수준','재현 결과','기준 시점 상태'],[
 ['A1 조건부 P1','조회용 DB 사본을 바꾸면 고정 묶음과 위조 초안을 원본 검증 없이 사용','Sol 수정 중'],
 ['A2 P2','사건 담당자·상태 등 변경 후에도 이전 초안이 최신으로 표시','Sol 수정 중'],
 ['A3 P2','만료 응답은 거부되지만 timeout 원장 기록이 롤백됨','Sol 수정 중'],
 ['A4 P2','전송 전 미리보기에서 governance 입력이 누락','Claude UI 수정 보류'],
 ['A5 P2','사람이 수정해 채택한 본문이 재조회 화면에서 누락','Claude UI 수정 보류'],
],[91,302,118])
R.para('A1은 조회용 DB 사본의 쓰기 권한이나 손상을 전제로 한다. 작업 자격만으로 DB에 접근하거나 다른 tenant를 침해한 결과는 아니다. 전체 호스트 관리자 침해도 이 시험의 보장 범위 밖이다. [E3]',True)
R.sub('통과한 검사와 남은 회귀')
R.para('기존 AI 지원 시험 8개는 통과했지만, 추가 감사는 위 결함을 재현했다. 다른 tenant의 묶음 조회 거부, 작업 자격의 인간 판단 API 접근 거부, AI 초안 채택 후 기존 사건 판단이 바뀌지 않는 경계는 확인했다. 최신 통합본의 전체 회귀와 수정 후 독립 재검증은 아직 완료 성과로 집계하지 않는다.')
R.para('9월 8일 별도 Linux 회귀 70/70 통과는 이전 구현의 결과다. 같은 날 Windows 회귀는 서버 listen EFAULT로 56 통과·10 실패였다. 운영체제와 Node 버전이 달라 원인을 OS 하나로 확정하지 않았다. 통과한 이전 결과를 최신 수정본의 통과로 대체하지 않는다. [E4]',True)
R.sub('법규 지원의 범위')
R.para('한국 AI 기본법 중심으로 공식 원문, 적용 조건, 통제, 증거와 인간 검토를 연결하는 매핑 초안을 제공한다. 원문 버전·시행일·확인일·검토 상태를 구분하며, 법적 적용성·예외·대외 준수 주장은 인간 검토자가 확정한다. 현재 매핑은 법률 검토 전이며 인증 결과가 아니다. 상세 출처는 docs/legal-sources.md에 있다.')

R.page();R.heading('Kubernetes 분산과 복구 실험')
R.para('9월 8일 전용 k3d 클러스터에서 내부 Service 분산, HPA 증감과 Pod 교체를 시험했다. 서버 1개와 에이전트 2개는 같은 PC 위의 컨테이너 노드다. 아래 결과는 새 AI 지원 기능 배포 전 버전의 실험이다.')
R.story += [distribution(),Spacer(1,10)]
R.grid(['시험','실측','해석'],[
 ['정상 수집과 감사','각 60/60 성공 · 각 2개 Pod 처리','내부 Service 경유 분산 확인'],
 ['수집 Pod 종료 중','300건 중 297 성공 · 3 실패','남은 Pod 처리 확인, 무오류 실패'],
 ['감사 HPA 부하','5,203 시도 · 5,195 성공 · 8 timeout','actual replica 2 → 3 → 2 관측'],
 ['확장 후 새 Pod 참여','60/60 성공 · Pod별 18 / 23 / 19','부하 종료 후 새 Pod의 처리 확인'],
 ['Vault Pod 재생성','성공접수 515건과 이전 checkpoint 보존','같은 PVC의 Pod 복구 확인'],
],[115,215,181])
R.sub('확인되지 않은 운영 보장')
R.para('HPA 시험은 목표 80회/초에 대해 실제 43.36회/초를 전송했고 전체 p95는 778.57ms였다. 목표 처리량 달성과 확장 중 무오류는 입증하지 못했다. 새 Pod가 부하 중에는 준비되지 않아 처리량 개선 효과도 분리 측정하지 못했다.')
R.para('외부 LoadBalancer, 조직 접근 경로와 운영 SSO, 저장소 HA·키관리, 노드 분실·정전 복구, GPU 실행기의 Kubernetes 격리와 최신 기능 재배포는 남은 과제다. 네트워크 거부 응답만으로 정책 차단의 인과성이 확인된 것은 아니어서 네트워크 시험의 엄격한 실패 상태를 보존했다. [E4]',True)

R.page();R.heading('개발 협업과 다음 완료 조건')
R.grid(['담당','배치','책임'],[
 ['설계와 개선 감사','GPT-6 Astra high','요구사항·신뢰 경계·우선순위·별도 검토'],
 ['핵심 구현과 통합','GPT-5.6 Sol','API·저장·실행기·테스트와 통합'],
 ['UI','Claude Sonnet 5','화면 초안 구현 · 추가 수정은 보류'],
 ['적대적 감사','별도 Astra high','공격 조건·재현·영향과 회귀 공백'],
],[114,159,238])
R.para('등록된 협업 작업은 root를 포함해 최대 3개, 위임은 1단계로 제한한다. 코드 수정자는 worktree를 분리하고 요구사항·허용 파일·기준 커밋·시험 결과로 인수인계한다. 추가 API 지출 상한은 0원이며 구독 한도 소진 시 대기한다. 전력·기존 구독료·사람의 검수 시간까지 0원이라는 뜻은 아니다.')
R.sub('역할 전문화와 학습의 순서')
R.para('증거 정리, 근거 대조, 거버넌스 지원, 보고서 초안의 네 역할을 구분한다. 먼저 지침·도구·지식·출력 계약·평가를 버전 관리한다. 역할별 60개 합성 사례는 초기 평가 설계이며, AI 생성 사례를 사람이 검수한 정답으로 취급하지 않는다.')
R.para('LoRA는 증거 정리 역할부터 검토한다. 사람 검수 학습 300개·검증 50개·별도 시험 100개를 확보한 뒤 같은 조건에서 비교한다. 주요 오류 상대 20% 감소와 필수 안전 시험 비악화를 초기 채택 기준으로 둔다. 현재 가중치 학습·배포 승인·품질 개선 실측은 완료하지 않았다.',True)
R.grid(['우선순위','다음 완료 조건'],[
 ['1 보안과 통합','A1~A3 수정 후 독립 재현 검사, 개발 실행 수집 API와 역할 패키지 연결'],
 ['2 근거 품질','선택 근거와 사건 전체 평가 구분, 인용 타당성과 유보 감지 평가'],
 ['3 화면 보완','전체 입력 미리보기, 수정 채택본 표시, 접근성 재검증'],
 ['4 운영 실증','최신 전체 회귀, 실행기 실패 복구, Kubernetes 재배포와 격리 확인'],
],[118,393])
R.sub('결과를 확인할 원자료')
for s in [
 'E1 reports/assistance-local-20260909.json — 실제 API 연계 Qwen3 4B 실행',
 'E2 reports/assistance-ui-local-20260909.json — 실제 화면 연계 실행과 인용 오류',
 'E3 reports/astra-adversarial-20260909.md — 별도 감사의 5개 재현 결과',
 'E4 reports/kubernetes-runtime-20260908.md — 분산·HPA·복구·이전 회귀와 실패',
 '설계 docs/multi-agent-development.md · docs/adr/0004-local-advisory-boundary.md',
 '추가 명세 docs/assistance-contract.md · docs/legal-sources.md · docs/product-reference.md',
]:R.para(s,True)
R.build()

P=Publication('EvidScope 프로젝트 포트폴리오','evidscope-portfolio.pdf','docs/portfolio.md',landscape(A4))
P.heading('EvidScope 프로젝트 포트폴리오',True)
P.para('AI 행동과 참고자료를 연결하는 감사 지원 서비스')
P.para('업무 AI의 자기보고, 도구 결과, 권한과 참고자료를 대조하고 사람이 검토 근거를 남기는 로컬 파일럿이다. 보안·플랫폼 개발 관점에서 관측 가능한 사실, AI 검토 의견, 인간 판단의 경계를 설계했다.')
P.diagram()
P.grid(['프로젝트 성격','주요 기술','현재 단계'],[
 ['사용자 주도 AI 협업 개발','Node.js 24 · SQLite · 정적 JavaScript UI','실행 가능한 1차 파일럿'],
 ['행동 가시성과 감사 지원','서명 원장 · Docker · Kubernetes · Ollama','실제 로컬 추론 확인 · 보안 보완 중'],
],[202,345,211])
P.para('공개 운영·고객 도입·법률 인증·학습 완료를 주장하지 않는다. 실제 실험의 실패와 미확인 사항도 결과에 포함한다.',True)

P.page();P.heading('수치를 근거까지 따라갈 수 있는 화면')
P.image('agents-20260909.jpg',625,'실제 에이전트 목록. 합성·로컬 시험 기록이며, 미확인은 산정 불가로 표시한다. 화면에 표시된 비율은 관측된 행동의 정책 평가이며 법적 준수율이 아니다.')
P.para('설계 선택은 분모를 드러내는 것이다. 준수율 옆에 평가 범위를 표시하고, 각 행동의 자료·권한·결과로 이동하게 했다. 주식형 시간축은 확대·이동·최신 따라가기를 제공하며, 상세 조사와 주간 검토의 집계 간격을 구분한다.',True)

P.page();P.heading('실험으로 확인한 결과와 개선 사례')
P.grid(['관점','실제로 확인한 결과','해석의 범위'],[
 ['로컬 AI 지원','Qwen3 4B 실제 실행 10.90초 / 46.04초','서로 다른 합성 입력 2회, 평균 성능 아님'],
 ['품질 문제 발견','참고자료 충돌·수집 공백 주장 일부의 인용 불충분','초안 시험상 반려, 실무 품질 승인 보류'],
 ['내부 Service 분산','수집 60/60, 감사 60/60 · 각 2개 Pod','9월 8일 이전 구현, 외부 LB 시험 아님'],
 ['HPA와 복구','replica 2 → 3 → 2, 성공접수 515건 보존','8 timeout 발생, 단일 PVC의 Pod 복구'],
 ['적대적 감사','기존 지원 시험 8개 통과 후 추가 결함 5개 재현','조건부 P1 1개, P2 4개 · 수정 재검증 중'],
],[109,320,329])
P.sub('인용 ID 검증만으로 충분하지 않았던 사례')
P.para('로컬 모델은 존재하는 기록을 인용했지만, 그 기록이 해당 주장을 지지하지 않는 경우가 있었다. 이 결과를 성공으로 포장하지 않고 반려 기록과 원본 초안을 함께 보존했다. 다음 조치는 선택 근거와 사건 전체 규칙 평가를 분리하고, 역할 평가에 인용 타당성과 근거 부족 감지를 추가하는 것이다.')
P.para('두 AI 검토 기록은 자동화가 합성 인간 역할 자격으로 API·화면 경계를 검증한 결과다. 실제 사람의 내용 검수나 채택률 자료가 아니다. 성능·정확도 향상과 업무 시간 절감률은 아직 측정하지 않았다.',True)
P.para('근거: reports/assistance-local-20260909.json · reports/assistance-ui-local-20260909.json · reports/astra-adversarial-20260909.md · reports/kubernetes-runtime-20260908.md',True)

P.page();P.heading('역할 분담과 포트폴리오 소개 문안')
P.para('사용자는 사람이 판단할 수 있는 가시성을 우선 목표로 정하고, 로컬 모델 실증·Kubernetes 분산·역할별 에이전트·추가 API 비용 0원이라는 조건을 결정했다. 설계와 감사에는 Astra, 핵심 구현에는 Sol, UI에는 Claude를 배치한 AI 협업 프로젝트다. 아래와 같이 기획·판단과 구현 기여를 구분한다.')
P.grid(['구분','산출물과 책임'],[
 ['사용자','문제 정의, 우선순위·모델·비용 조건 결정, 최종 검토와 공개 판단'],
 ['Astra','아키텍처·개선 방향·독립 적대적 감사와 문서 정리'],
 ['Sol','수집·API·저장·로컬 실행기·검증 및 통합 구현'],
 ['Claude','팀·AI 지원 UI 초안 구현. 추가 UI 수정은 구독 한도로 보류'],
],[117,641])
P.sub('소개 글에 사용할 수 있는 문안')
P.para('EvidScope는 AI 행동·도구 결과·권한·참고자료를 연결하는 감사 지원 파일럿입니다. 근거가 부족한 상태를 준수로 계산하지 않고, 실제 로컬 모델이 작성한 초안을 별도 검토 기록으로 관리하도록 구성했습니다. AI 협업 개발에서 설계·구현·UI·적대적 감사를 분리했으며, Kubernetes 분산·복구와 로컬 추론 시험에서 확인한 성과와 실패를 원자료로 남겼습니다.')
P.sub('다음 단계')
P.para('보안 결함 수정과 재감사 → 개발 실행 이벤트와 역할 패키지 통합 → 인용 품질 평가 → UI 보완 → 최신 Kubernetes 및 격리 재검증 순으로 진행한다. 선택적 LoRA는 사람 검수 데이터와 평가 기준을 충족한 이후에 검토한다.',True)
P.para('저장소 공개 주소와 실서비스 주소는 미확정이다. GitHub 업로드 완료나 고객 운영 실적으로 표기하지 않는다. 상세 구현 보고서는 함께 제공하는 EvidScope 1차 개발 보고서를 참조한다.',True)
P.para('운영 원칙 추가: 테스트 외에는 모델·시험 워커를 중지한다. 19시 14분에 전용 모델·클러스터·로컬 시험 서버의 중지를 확인했으며, 자동 정리 도구는 구현 중이다.',True)
P.build()

manifest={'format':'evidscope-publication-snapshot-v1','cutoff':'2026-09-09T19:00:00+09:00','reviewedCommit':'300c07f','outputs':[R.filename,P.filename],'pendingChangesExcluded':True,'humanAuthorshipShareUnmeasured':True,'sources':['reports/assistance-local-20260909.json','reports/assistance-ui-local-20260909.json','reports/astra-adversarial-20260909.md','reports/kubernetes-runtime-20260908.md']}
(ROOT/'reports/first-draft-publication-manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps(manifest,ensure_ascii=False))
