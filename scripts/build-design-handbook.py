"""Rebuild the visual documentation. Requires reportlab and a Korean TrueType font.
EVIDSCOPE_DOC_FONT and EVIDSCOPE_DOC_FONT_BOLD override the Windows defaults.
No network, model API, database, or credentials are used.
"""
import os
import re
from pathlib import Path
from xml.sax.saxutils import escape
from reportlab.pdfgen import canvas
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib.colors import HexColor, Color
from reportlab.platypus import Paragraph
from reportlab.lib.styles import ParagraphStyle
from reportlab.graphics.shapes import Drawing, Rect, String, Line, Polygon, Circle
from reportlab.graphics import renderPDF, renderSVG

ROOT=Path(__file__).resolve().parents[1]
ASSETS=ROOT/'docs/assets'; OUT=ROOT/'output/pdf'; ASSETS.mkdir(parents=True,exist_ok=True); OUT.mkdir(parents=True,exist_ok=True)
pdfmetrics.registerFont(TTFont('KR',os.environ.get('EVIDSCOPE_DOC_FONT','C:/Windows/Fonts/malgun.ttf')))
pdfmetrics.registerFont(TTFont('KRB',os.environ.get('EVIDSCOPE_DOC_FONT_BOLD','C:/Windows/Fonts/malgunbd.ttf')))
NAVY='#10283F'; TEAL='#087F79'; MINT='#DDF2EC'; WHITE='#FFFFFF'; INK='#183348'; MUTED='#5C7181'; LINE='#DCE5EB'; PAPER='#F4F7F9'; AMBER='#A56C22'; SAND='#FFF3DB'

def shape_text(d,x,y,text,size=20,color=INK,bold=False):
 d.add(String(x,y,text,fontName='KRB' if bold else 'KR',fontSize=size,fillColor=HexColor(color)))

def box(d,x,y,w,h,title,sub='',dark=False):
 d.add(Rect(x,y,w,h,rx=12,ry=12,fillColor=HexColor(NAVY if dark else WHITE),strokeColor=HexColor(NAVY if dark else LINE),strokeWidth=1.4))
 shape_text(d,x+20,y+h-35,title,22,WHITE if dark else INK,True)
 if sub:shape_text(d,x+20,y+23,sub,17,'#B9DAD9' if dark else MUTED)

def arrow(d,points,color=TEAL,dashed=False):
 for a,b in zip(points,points[1:]):
  ln=Line(*a,*b,strokeColor=HexColor(color),strokeWidth=2.4)
  if dashed:ln.strokeDashArray=[7,5]
  d.add(ln)
 a,b=points[-2:];dx=b[0]-a[0];dy=b[1]-a[1];norm=(dx*dx+dy*dy)**.5;ux=dx/norm;uy=dy/norm
 d.add(Polygon([b[0],b[1],b[0]-10*ux+4*uy,b[1]-10*uy-4*ux,b[0]-10*ux-4*uy,b[1]-10*uy+4*ux],fillColor=HexColor(color),strokeColor=None))

def architecture():
 d=Drawing(1160,625)
 d.add(Rect(0,0,1160,625,fillColor=HexColor(PAPER),strokeColor=None,rx=18,ry=18))
 for x,w,title in [(20,265,'01  업무 실행'),(310,525,'02  관측 및 감사'),(860,280,'03  사람의 검토')]:
  shape_text(d,x+15,582,title,20,TEAL,True)
 box(d,40,422,225,110,'업무 AI / 에이전트','로컬 모델 시험 완료')
 box(d,40,222,225,110,'업무 도구 / API','독립 출처의 실행·결과')
 arrow(d,[(150,422),(150,332)],MUTED);shape_text(d,165,369,'업무 실행',17,MUTED)
 box(d,335,422,220,110,'수집 gateway','이벤트 제출 전용')
 box(d,600,422,210,110,'감사 gateway','인간 인증 / 조회')
 box(d,470,222,250,110,'Vault','인증 · 서명 · 저장',True)
 box(d,335,50,210,100,'분석 worker','규칙 기반 분석')
 box(d,600,50,210,100,'SQLite / 키','단일 vault가 소유')
 box(d,885,422,235,110,'인간 감사자','근거 대조 / 판단 / 과제')
 box(d,885,222,235,110,'서명 보고서','사건·원장 내보내기')
 box(d,885,50,235,100,'독립 검증기','별도 공개키 / checkpoint')
 arrow(d,[(265,477),(335,477)],dashed=True)
 arrow(d,[(265,277),(300,277),(300,440),(335,440)],dashed=True)
 arrow(d,[(445,422),(445,365),(525,365),(525,332)])
 arrow(d,[(705,422),(705,365),(660,365),(660,332)])
 arrow(d,[(885,477),(810,477)],MUTED)
 arrow(d,[(440,150),(440,185),(525,185),(525,222)])
 arrow(d,[(665,222),(665,150)])
 arrow(d,[(720,277),(885,277)])
 arrow(d,[(1002,222),(1002,150)])
 shape_text(d,30,12,'점선: 비동기 관측   /   실선: 업무 실행 또는 서비스 요청   /   Vault는 높은 신뢰 영역',15,MUTED)
 return d

def svg_export(d,name,title,description):
 path=ASSETS/name;renderSVG.drawToFile(d,str(path))
 svg=path.read_text(encoding='utf-8')
 svg=re.sub(r'<!DOCTYPE[\s\S]*?>','',svg)
 svg=svg.replace('<title>...</title>','<title>'+escape(title)+'</title>').replace('<desc>...</desc>','<desc>'+escape(description)+'</desc>')
 svg=svg.replace('font-family: KRB;',"font-family: 'Malgun Gothic', 'Apple SD Gothic Neo', sans-serif; font-weight: 700;").replace('font-family: KR;',"font-family: 'Malgun Gothic', 'Apple SD Gothic Neo', sans-serif;")
 path.write_text(svg,encoding='utf-8')

def banner(title,subtitle,name):
 d=Drawing(1200,300);d.add(Rect(0,0,1200,300,rx=20,ry=20,fillColor=HexColor(NAVY),strokeColor=None))
 for i in range(4):d.add(Circle(1110,150,72+i*38,fillColor=None,strokeColor=HexColor('#234558'),strokeWidth=1))
 d.add(Rect(48,211,42,42,rx=9,ry=9,fillColor=HexColor('#41B8A6'),strokeColor=None));shape_text(d,59,219,'E',27,NAVY,True)
 shape_text(d,107,222,'EvidScope',31,WHITE,True);shape_text(d,51,130,title,43,WHITE,True)
 shape_text(d,52,81,subtitle,21,'#BDCED9');shape_text(d,52,37,'DESIGN DRAFT  /  0.1  /  2026.09.09',15,'#79C9BA')
 svg_export(d,name,title,subtitle)

banner('Architecture & Engineering','AI 행동의 근거를 연결하고, 최종 판단은 사람에게.','document-cover.svg')
banner('Architecture Draft','구성 · 데이터 흐름 · 신뢰 경계 · 배포 설계','architecture-cover.svg')
banner('Developer Handbook','실행 · 모듈 · API · 검증 · 변경 인수 기준','development-cover.svg')
diagram=architecture();svg_export(diagram,'system-architecture.svg','EvidScope 시스템 구성','업무 실행, 관측 및 감사, 사람의 검토와 독립 검증을 연결한 구성도')

W,H=842,595
c=canvas.Canvas(str(OUT/'evidscope-design-handbook.pdf'),pagesize=(W,H))
c.setTitle('EvidScope | Architecture & Developer Handbook');c.setAuthor('EvidScope');c.setSubject('설계 초안 및 개발 안내 / 2026-09-09')
styles={}
def text(x,y,value,size=11,color=INK,bold=False):
 c.setFont('KRB' if bold else 'KR',size);c.setFillColor(HexColor(color));c.drawString(x,H-y,value)
def para(x,y,value,width,size=11,color=INK,leading=None):
 style=ParagraphStyle('p',fontName='KR',fontSize=size,leading=leading or size*1.6,textColor=HexColor(color),wordWrap='CJK')
 p=Paragraph(escape(value).replace('\n','<br/>'),style);_,h=p.wrap(width,700);p.drawOn(c,x,H-y-h);return h
def rect(x,y,w,h,fill=PAPER,stroke=None,r=10):
 c.setFillColor(HexColor(fill));c.setStrokeColor(HexColor(stroke or fill));c.roundRect(x,H-y-h,w,h,r,stroke=bool(stroke),fill=1)
def line(x,y,x2,y2,color=LINE):
 c.setStrokeColor(HexColor(color));c.setLineWidth(.8);c.line(x,H-y,x2,H-y2)
def header(n,kicker,title,description):
 c.setFillColor(HexColor(WHITE));c.rect(0,0,W,H,fill=1,stroke=0)
 text(44,35,'EVIDSCOPE',10,TEAL,True);text(574,35,'ARCHITECTURE / ENGINEERING',9,MUTED)
 line(44,48,798,48);text(44,79,kicker,10,TEAL,True);text(44,113,title,26,INK,True)
 para(44,128,description,750,10.5,MUTED)
 line(44,552,798,552);text(44,572,'설계 초안 0.1  ·  2026.09.09  ·  상세 명세는 저장소 docs/ 참조',8,MUTED);text(771,572,f'{n:02d}',10,TEAL,True)
def finish():c.showPage()
def card(x,y,w,h,kicker,title,body,tint=PAPER):
 rect(x,y,w,h,tint);text(x+18,y+28,kicker,9,TEAL,True);text(x+18,y+56,title,16,INK,True);para(x+18,y+73,body,w-36,10.5)
def row(y,label,body):
 text(60,y+22,label,11,INK,True);para(259,y+7,body,514,10.5);line(60,y+54,782,y+54)

# 01 - Editorial cover.
c.setFillColor(HexColor(NAVY));c.rect(0,0,W,H,fill=1,stroke=0)
for i in range(7):
 c.setStrokeColor(HexColor('#224257'));c.setLineWidth(.7);c.circle(730,340,65+i*38,stroke=1,fill=0)
rect(48,45,40,40,'#41B8A6',r=9);text(59,74,'E',25,NAVY,True);text(104,73,'EvidScope',26,WHITE,True)
text(49,149,'ARCHITECTURE & ENGINEERING',12,'#79C9BA',True)
text(47,218,'관측에서',47,WHITE,True);text(47,278,'사람의 판단까지.',47,WHITE,True)
para(50,307,'AI 행동·권한 가시성과 독립 증적\n아키텍처 초안 및 개발 안내',460,16,'#C2D6E0',26)
rect(49,414,742,103,'#1B374D',r=12)
for x,k,v in [(70,'DESIGN STATUS','실행 가능한 파일럿'),(324,'OPERATING PRINCIPLE','근거 우선 · 인간 검토'),(578,'COST PRINCIPLE','상시 AI 호출 없음')]:
 text(x,444,k,8.5,'#79C9BA',True);text(x,477,v,15,WHITE,True)
text(50,555,'VERSION 0.1   /   2026.09.09',10,'#A7C4D3');text(561,555,'운영 인증·법적 준수 확정 문서 아님',9,'#A7C4D3');finish()

# 02 - Architecture.
header(2,'01 / SYSTEM MAP','서비스 구조와 신뢰 경계','업무 실행과 감사 서비스를 분리하고, 인증·저장·서명 책임을 vault에 모읍니다.')
c.saveState();c.translate(93,65);c.scale(.565,.565);renderPDF.draw(diagram,c,0,0);c.restoreState();finish()

# 03 - Evidence lifecycle.
header(3,'02 / EVIDENCE LIFECYCLE','접수와 판단 사이의 네 단계','서로 다른 보장을 같은 성공 상태로 합치지 않습니다. 새로운 근거는 새로운 평가와 재검토를 만듭니다.')
steps=[('01','관측 제출','출처별 서명·nonce와 허용된 최소 필드. 프롬프트·응답 원문은 기본 미수집.'),('02','지속성 접수','원장·조회 사본·행동 버전·체크포인트를 함께 저장한 뒤 202 응답.'),('03','규칙 분석','worker가 배정받은 자료를 분석. 작업 임대·버전이 유효한 결과만 저장.'),('04','인간 검토','실행·권한·참조 근거를 대조하고 판단·과제·재검토 기한과 보고서를 남김.')]
for i,(k,t,b) in enumerate(steps):card(44+i*191,180,181,205,k,t,b)
rect(44,408,754,105,MINT);text(62,436,'반드시 구분할 세 가지',12,TEAL,True)
for x,t,b in [(62,'출처 인증','누가 제출했는가'),(307,'외부 효과 확인','어떤 결과가 기록됐는가'),(552,'증적 무결성','보관 후 변조가 없는가')]:text(x,466,t,12,INK,True);text(x,490,b,10,MUTED)
finish()

# 04 - trust & data.
header(4,'03 / TRUST & DATA','권한과 데이터의 소유권','에이전트가 자신의 감사 결과를 바꾸지 못하도록 제출·분석·인간 검토의 권한을 구분합니다.')
rect(44,176,754,59,NAVY);text(60,202,'SUBJECT',9,'#79C9BA',True);text(259,202,'허용 범위와 제한',11,WHITE,True)
row(239,'업무 source','허용된 유형의 이벤트 제출만 가능. 원본·검색·export·룰·서명키 조회 불가.')
row(296,'분석 worker','배정된 자료의 규칙 분석. 인간 감사 판단·법률 판정·업무 실행 승인 불가.')
row(353,'인간 감사자 / 검토자','자신의 tenant 조사와 검토. 룰·예외·파기는 역할 및 작성자 분리 조건 적용.')
row(410,'Vault / 운영 관리자','DB·서명키를 가진 높은 신뢰 주체. 동일 관리자·호스트 침해는 별도 통제 필요.')
para(60,483,'원장 → 조회 사본 → 평가 이력 → 인간 의견을 구분합니다. 정당한 파기는 승인된 키·사본 제거로 기록하며 기존 export·백업까지 지웠다고 주장하지 않습니다.',720,10.5,MUTED)
finish()

# 05 - Developer start.
header(5,'04 / DEVELOPER START','처음 실행하고, 수정할 위치 찾기','Node.js 24.15 이상 25 미만. 외부 npm 런타임 패키지나 유료 AI 계정 없이 일반 서비스를 실행합니다.')
rect(44,180,320,217,NAVY)
text(63,211,'LOCAL QUICKSTART',10,'#79C9BA',True)
for y,s in [(246,'npm run init'),(274,'npm start'),(316,'# 별도 터미널'),(345,'npm run demo')]:text(64,y,s,14,'#D7ECEF')
text(64,378,'감사 UI   http://127.0.0.1:8082',10,'#79C9BA')
rect(44,414,320,104,SAND);para(62,429,'.local의 토큰·DB·서명키는 Git에 포함하지 않습니다. 9082 UI fixture는 별도 합성 시험 환경입니다.',283,10.5,AMBER)
mods=[('HTTP / 역할 경계','src/server.mjs · service.mjs'),('수집 계약 / 정책 대조','src/model.mjs · client.mjs'),('저장 / 무결성 / 보존','store.mjs · crypto.mjs · retention.mjs'),('분석 / 에이전트 지표','analysis.mjs · agent-inventory.mjs'),('인간 조사 / 화면','audit-workbench.mjs · public/')]
for i,(a,b) in enumerate(mods):
 y=182+i*67;text(395,y+18,a,12,INK,True);text(395,y+40,b,9.5,MUTED);line(395,y+54,796,y+54)
finish()

# 06 - actual boundaries.
header(6,'05 / VALIDATION STATUS','구현과 검증을 분리해서 읽기','아래는 2026-09-08에 기록한 범위입니다. 문서 작성일이 최신 소스 전체의 재검증일을 뜻하지 않습니다.')
card(44,180,240,195,'LOCAL AI','실제 도구 호출 확인','Qwen3 0.6B + 합성 안내 자료. 요청·실행·결과·자기보고 4개 기록을 서명 원장과 대조했습니다.',MINT)
card(301,180,240,195,'OPERATIONS UI','집계 / 조사 검증','에이전트 운영 관련 7개 테스트 통과. 실제 API에서 목록·상세·추이 합계와 source 조회 거부를 확인했습니다.',MINT)
card(558,180,240,195,'KUBERNETES','분산 / 복구 관측','Service 분산, HPA 증감, Pod 복구를 실험했습니다. 장애 중 실패와 부하 timeout이 남았습니다.',SAND)
text(45,414,'미완료 범위',13,INK,True)
para(45,432,'Codex 실제 수집기 · 운영 SSO와 키 회전 · 외부 checkpoint 운영 · 저장소 HA · 최신 UI의 Kubernetes 재배포 · 운영 적합성 및 법률 검토',748,12,MUTED)
para(45,489,'실측 근거: reports/service-improvement-stage1.md / local-ai-audit-verification.json / kubernetes-runtime-20260908.md',748,9,MUTED)
finish()

# 07 - roadmap and reading.
header(7,'06 / DELIVERY ROADMAP','비용을 통제하며 단계적으로 확장','수집·그래프·정책 점검은 일반 코드로 처리하고, AI는 필요한 시험 작업에서만 실행합니다.')
road=[('01','운영 현황과 조사','1차 반영','기간·필터·추이·전체 행동 조회'),('02','에이전트 관리','후속 개발','소유자·목적·외부 정책·변경 이력'),('03','실제 연동 검증','후속 개발','로컬 격리·Codex 수집·누락 시험'),('04','감사와 운영 배포','후속 검증','보고서·복구·부하·저장소 HA')]
for i,(num,title,status,desc) in enumerate(road):
 y=178+i*67;rect(44,y,754,55,MINT if i==0 else PAPER);text(60,y+34,num,17,TEAL,True);text(111,y+24,title,12,INK,True);text(111,y+44,desc,9.5,MUTED);text(684,y+33,status,10,TEAL if i==0 else MUTED)
para(45,467,'로컬 모델도 CPU·메모리·전력·유지보수 비용이 듭니다. 유료 API나 서버 증설은 필요성을 실측하고 별도 결정합니다.',750,10.5,MUTED)
text(45,518,'자세히 읽기  →  docs/README.md  ·  architecture-draft.md  ·  development-guide.md',10,TEAL,True)
finish();c.save()
print('Created 4 SVG assets and output/pdf/evidscope-design-handbook.pdf (7 pages).')
