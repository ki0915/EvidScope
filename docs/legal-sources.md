# 법적 출처·범위와 인간 검토 상태

한국 법률·시행령 출처 및 구현 목록 대조일: **2026-10-06**. 전체 매핑 상태: `draft_requires_human_review`. 공식 원문에 근거한 한국어 요약과 EvidScope의 증거 연결 해석을 구분한다. 현재 `data/requirements.json`의 31개 레코드는 한국 18개, NIST 6개, EU 6개, ISO 준비 기록 1개다. 이번 확인은 아래 한국 조문과 공식 가이드의 명시된 쪽을 대상으로 하며 국제 기준의 최신성을 재확인한 결과가 아니다. 이 목록은 AI사업자·공공 이용자의 주요 거버넌스 의무에 집중한다. 국가·기관의 산업 진흥 의무, AI 기본법 전체, 타법 전체, EU AI Act 전체 또는 ISO 인증을 포괄하지 않는다. 기술 검증 완료를 법률상 준수 인증으로 표시하지 않는다.

## 한국 법률과 시행령

국가법령정보센터의 현행 법률 표제는 **법률 제21311호, 2026-01-20 일부개정, 2026-07-21 시행**이다. 제2~5조·제27~36조·제40조·제43조의 관련 내용을 대조했다. 제30~34조·제36조·제40조의 이 문서 사용 조항은 2026-01-22부터 시행된 내용을 확인했다. 제35조제1항의 취약계층 특성 반영 후단은 2026-07-21부터 시행한다. 조문별 기존 효력일을 출처 재확인일로 바꾸지 않는다. [현행 법률](https://www.law.go.kr/LSW/lsInfoP.do?lsiSeq=282791), [현행 제35조](https://www.law.go.kr/LSW/lsSideInfoP.do?docCls=jo&joBrNo=00&joNo=0035&lsiSeq=282791&urlMode=lsScJoRltInfoR)

현행 시행령은 **대통령령 제36580호, 2026-08-18 타법개정, 2026-08-20 시행**으로 확인했다. 과거 검색 결과의 제36053호 제정본이나 행정예고안만으로 현행을 단정하지 않았다. 확인 범위는 제1조의2·제2조·제23~25조·제27~29조·별표1이다. [현행 시행령](https://www.law.go.kr/LSW/lsInfoP.do?lsiSeq=288781), [현행 시행령 제24조](https://www.law.go.kr/LSW/lsSideInfoP.do?docCls=jo&joBrNo=00&joNo=0024&lsiSeq=288781&urlMode=lsScJoRltInfoR)

법 제4조제1항은 국외 행위라도 국내 시장 또는 이용자에게 영향을 미치는 경우 적용한다. 제4조제2항의 제외는 국방·국가안보 **전용 목적**이고 시행령 제2조의 지정업무에 해당하는 근거를 함께 검토한다. 국내 영향이 없다는 입력, 단순 사용기관이라는 입력, 국방 목적이라는 입력을 기계적인 최종 적용 제외로 처리하지 않는다. 시스템 사실관계 schema 4는 국내 영향, 실제 AI사업자 여부, 전용 목적·지정업무, 제공 시작일을 별도 보관한다. 기존 기록에 없던 값은 `unknown`으로 이관하고 재검토 대상으로 남긴다. [법 제4조](https://www.law.go.kr/LSW/lsSideInfoP.do?docCls=jo&joBrNo=00&joNo=0004&lsiSeq=282791&urlMode=lsScJoRltInfoR), [시행령 제2조](https://www.law.go.kr/LSW/lsSideInfoP.do?docCls=jo&joBrNo=00&joNo=0002&lsiSeq=288781&urlMode=lsScJoRltInfoR)

| 매핑 범위 | 규범 내용의 구분 | 근거와 조건 |
|---|---|---|
| KR-30-EFFORT/PUBLIC | 사업자의 제공 전 검·인증 노력의무와 공공 이용자의 검·인증 제품 우선 고려 의무 | [법 제30조제3·4항](https://www.law.go.kr/LSW/lsSideInfoP.do?docCls=jo&joBrNo=00&joNo=0030&lsiSeq=282791&urlMode=lsScJoRltInfoR). 검·인증 취득의 일반적 강제 의무나 인증 제품만 조달하는 의무가 아님 |
| KR-31-1/2/3 | AI 사용 사전 고지, 생성형 결과물 표시, 사실적인 합성물 고지·표시를 분리 | [법 제31조](https://www.law.go.kr/LSW/lsSideInfoP.do?docCls=jo&joBrNo=00&joNo=0031&lsiSeq=282791&urlMode=lsScJoRltInfoR), [시행령 제23조](https://www.law.go.kr/LSW/lsSideInfoP.do?docCls=jo&joBrNo=00&joNo=0023&lsiSeq=288781&urlMode=lsScJoRltInfoR) |
| KR-32-RISK/MONITOR/SUBMIT | 수명주기 위험관리, 안전사고 체계, 결과 제출을 분리 | [법 제32조](https://www.law.go.kr/LSW/lsSideInfoP.do?docCls=jo&joBrNo=00&joNo=0032&lsiSeq=282791&urlMode=lsScJoRltInfoR), [시행령 제24조](https://www.law.go.kr/LSW/lsSideInfoP.do?docCls=jo&joBrNo=00&joNo=0024&lsiSeq=288781&urlMode=lsScJoRltInfoR) |
| KR-33 | 제공 전 검토는 의무, 장관 확인 요청은 선택 | [법 제33조](https://law.go.kr/LSW/lsLinkCommonInfo.do?chrClsCd=010202&lsJoLnkSeq=1031810895), [확인 절차 제25조](https://www.law.go.kr/LSW/lsSideInfoP.do?docCls=jo&joBrNo=00&joNo=0025&lsiSeq=288781&urlMode=lsScJoRltInfoR) |
| KR-34-* | 위험관리·설명·보호·인간 감독·문서를 구분 | [법 제34조](https://www.law.go.kr/LSW/lsSideInfoP.do?docCls=jo&joBrNo=00&joNo=0034&lsiSeq=282791&urlMode=lsScJoRltInfoR), [시행령 제27조](https://www.law.go.kr/LSW/lsSideInfoP.do?docCls=jo&joBrNo=00&joNo=0027&lsiSeq=288781&urlMode=lsScJoRltInfoR) |
| KR-35-IMPACT/PUBLIC | 영향평가 노력의무와 공공 이용 시 평가 제품 우선 고려 의무를 구분 | [법 제35조](https://www.law.go.kr/lsLinkCommonInfo.do?chrClsCd=010202&lsJoLnkSeq=1031810855), [시행령 제28조](https://www.law.go.kr/LSW/lsSideInfoP.do?docCls=jo&joBrNo=00&joNo=0028&lsiSeq=288781&urlMode=lsScJoRltInfoR) |
| KR-36-REPRESENTATIVE | 국내 주소·영업소가 없는 일정 규모 등의 AI사업자의 국내대리인 지정·서면 위임·신고 및 대리 업무 | [법 제36조](https://www.law.go.kr/LSW/lsSideInfoP.do?docCls=jo&joBrNo=00&joNo=0036&lsiSeq=282791&urlMode=lsScJoRltInfoR), [시행령 제29조](https://www.law.go.kr/LSW/lsSideInfoP.do?docCls=jo&joBrNo=00&joNo=0029&lsiSeq=288781&urlMode=lsScJoRltInfoR) |
| KR-40-ORDER | 실제 사실조사·중지 또는 시정명령의 대상·기한·이행 증거 대조 | [법 제40조](https://www.law.go.kr/LSW/lsSideInfoP.do?docCls=jo&joBrNo=00&joNo=0040&lsiSeq=282791&urlMode=lsScJoRltInfoR), [법 제43조](https://www.law.go.kr/LSW/lsSideInfoP.do?docCls=jo&joBrNo=00&joNo=0043&lsiSeq=282791&urlMode=lsScJoRltInfoR). 내부 차단 로그만으로 실제 중지명령 이행을 확정하지 않음 |

시행령 제23조는 명백성, 사업자 내부 업무 등에서 전부 또는 일부 예외를 허용한다. 기계 판독 방식의 생성형 표시는 생성 사실을 1회 이상 안내해야 한다. 예외를 자동 적용하지 않고 대상·근거·검토자를 기록한다. [시행령 제23조](https://www.law.go.kr/LSW/lsSideInfoP.do?docCls=jo&joBrNo=00&joNo=0023&lsiSeq=288781&urlMode=lsScJoRltInfoR)

제31조제1항은 고영향 또는 생성형 AI 이용 제품·서비스의 사전 고지, 제2항은 생성형 결과 표시, 제3항은 AI시스템으로 만든 사실적인 가상 음향·이미지·영상 등의 고지·표시다. 제3항을 생성형 여부에만 종속시키지 않는다. 예술적·창의적 표현물에는 향유를 저해하지 않는 방식을 허용하지만 고지·표시를 전부 면제하는 조건이 아니다. 주된 이용자의 연령과 신체적·사회적 조건에 맞는 접근성도 검토한다. [법 제31조](https://www.law.go.kr/LSW/lsSideInfoP.do?docCls=jo&joBrNo=00&joNo=0031&lsiSeq=282791&urlMode=lsScJoRltInfoR), [시행령 제23조](https://www.law.go.kr/LSW/lsSideInfoP.do?docCls=jo&joBrNo=00&joNo=0023&lsiSeq=288781&urlMode=lsScJoRltInfoR)

제32조 대상은 누적 학습 연산량 10^26 FLOPs 이상, 최첨단 기술 사용, 광범위하고 중대한 위험 우려의 **세 기준을 모두** 충족해야 한다. 연산량이 알려지지 않은 API 이용 서비스에 이를 임의 추정하지 않는다. [시행령 제24조](https://www.law.go.kr/LSW/lsSideInfoP.do?docCls=jo&joBrNo=00&joNo=0024&lsiSeq=288781&urlMode=lsScJoRltInfoR)

제33조의 사전 고영향 검토는 활용 영역과 사람의 생명·신체 안전 또는 기본권에 대한 중대한 영향·위험을 함께 살핀다. 금융업 또는 AI 사용만으로 고영향을 확정하지 않는다. 장관 확인 요청은 선택이며 시스템 설명·이용자·피영향자·영역·위험 등 지정 서류를 제출한다. 통상 답변은 30일 이내이며 부득이한 경우 한 번의 30일 연장과 서면 사유·기간 안내가 가능하다. 결과 통지를 받은 후 10일 내 재확인을 요청할 수 있고 재확인 답변은 30일 이내다. 접수나 지연 자체를 고영향 여부의 결정으로 대체하지 않는다. [법 제2조·제33조](https://www.law.go.kr/LSW/lsInfoP.do?lsiSeq=282791), [시행령 제25조](https://www.law.go.kr/LSW/lsSideInfoP.do?docCls=jo&joBrNo=00&joNo=0025&lsiSeq=288781&urlMode=lsScJoRltInfoR)

제34조의 조치 근거 문서 5년 보관과 게시 의무를 연결한다. 5년을 모든 prompt·개인정보·원본 로그의 기본 보존기간으로 확대하지 않는다. 사업자 간 기존 조치 인정은 중대한 기능 변경 여부와 제1~3호 범위를, 다른 법령의 인정은 별표1을 별도로 검토해야 한다. 영업비밀 게시 제외는 원본 삭제 권한을 뜻하지 않는다. [시행령 제27조](https://www.law.go.kr/LSW/lsSideInfoP.do?docCls=jo&joBrNo=00&joNo=0027&lsiSeq=288781&urlMode=lsScJoRltInfoR)

게시 대상은 제27조제1항의 4항목이다: 위험관리정책·조직체계 등 주요 내용, 설명 방안 주요 내용, 이용자 보호 방안, 관리·감독하는 사람의 성명과 연락처. 영업비밀에 해당하는 사항만 게시에서 제외하며, 게시의 전면 면제나 문서 보관 면제로 확대하지 않는다. 보관은 제2항, 공급사 조치 활용은 제3항, 자료 요청·협력 노력은 제4항, 타법 인정은 제5항이다. 공급사 조치는 본래 목적·용도 등을 포함한 중대한 기능 변경이 없을 때 **공급사가 실제 이행한 제34조제1항제1~3호의 전부 또는 일부**에 대응한다. 사람 감독(제4호)·문서 보관(제5호)까지 자동 승계하지 않는다. 사람 감독을 모든 실행의 사전 승인으로 치환하지 않고 당시 조직 정책의 건별 승인 요구와 구분한다. [법 제34조](https://www.law.go.kr/LSW/lsSideInfoP.do?docCls=jo&joBrNo=00&joNo=0034&lsiSeq=282791&urlMode=lsScJoRltInfoR), [시행령 제27조](https://www.law.go.kr/LSW/lsSideInfoP.do?docCls=jo&joBrNo=00&joNo=0027&lsiSeq=288781&urlMode=lsScJoRltInfoR)

금융권의 타법 인정은 개별 조치에 한정한다. 시행령 별표1 제2호다목은 대출심사에 대해 신용정보법 제35조의2 설명 의무와 제36조의2제1항 설명 절차를 **모두** 이행한 경우 설명 방안(제34조제1항제2호)에 대응한다. 별표1 제3호나목은 금융소비자보호법 제10조 의무를 **모두** 이행한 경우 이용자 보호(제3호)에 대응한다. 별표1 제7호의 개인정보보호법 조치 인정은 개인정보 처리·보호에 상응하는 범위이며 전체 AI 위험·감독의 일괄 면제가 아니다. 실제 타법 의무 이행, 대상 업무와 인정 범위를 사람이 판단한다. 공식 [별표1 PDF](https://www.law.go.kr/LSW/flDownload.do?gubun=&flSeq=168105389&bylClsCd=110201)의 4쪽 본문을 확인했으며 SHA-256은 `8d25709613ecb05ead23c517f58b39c1e681a6f3d4bd47a8ba0edd09cc880ec8`이다.

영향평가 실시를 모든 사업자의 동일한 강제 의무로 표현하지 않는다. 평가를 수행하는 경우 취약계층을 포함한 영향 집단, 기본권, 사회경제 영향, 사용 행태, 지표·산출 방식, 위험 예방·완화·복구, 개선 계획을 확인한다. 행동 로그가 평가서나 전문가 의견을 대체하지 않는다. [현행 법 제35조](https://www.law.go.kr/lsLinkCommonInfo.do?chrClsCd=010202&lsJoLnkSeq=1031810855), [시행령 제28조](https://www.law.go.kr/LSW/lsSideInfoP.do?docCls=jo&joBrNo=00&joNo=0028&lsiSeq=288781&urlMode=lsScJoRltInfoR)

제28조제1항의 내용 7항목은 영향 가능 개인·집단과 취약계층 특성, 기본권 유형, 사회경제 영향의 내용·범위, AI 사용 행태, 정량·정성 지표·산출 방식, 위험 예방·완화·손실 복구, 필요한 개선 이행계획이다. 직접 또는 제3자 평가가 가능하다. 현행 취약계층 정의는 **시행령 제1조의2**이며 행정예고안의 제2조의2를 재사용하지 않는다. 현재 10개 범주는 구직 수급자격자, 기초생활 수급권자·차상위, 농어업인등, 다문화가족 구성원, 북한이탈주민, 경력보유여성등, 장애인, 한부모가족 지원대상자, 65세 이상, 중앙행정기관장 또는 지방자치단체장이 AI 이용의 어려움을 인정한 사람이다. 제품·서비스 성격에 따른 특성을 실제 평가에서 반영했는지는 담당자가 검토한다. [현행 시행령](https://www.law.go.kr/LSW/lsInfoP.do?lsiSeq=288781), [제28조](https://www.law.go.kr/LSW/lsSideInfoP.do?docCls=jo&joBrNo=00&joNo=0028&lsiSeq=288781&urlMode=lsScJoRltInfoR)

국내대리인 후보는 국내 영향·AI사업자 범위·적용 제외를 검토한 후 국내 주소 또는 영업소가 **없음**과 다음 기준 중 **하나 이상**을 결합한다: 전년도 전체 매출액 1조 원 이상, 전년도 AI 제품·서비스 관련 매출액 100억 원 이상, 전년도 말 기준 직전 3개월간 일평균 국내 이용자 100만 명 이상, 법 제43조제1항제3호 명령 위반 과태료 이력. 외화 매출은 전년도 연평균 환율에 따른 원화 환산 근거를 확인한다. 단순 해외 소재, 모든 기준의 동시 충족, 기관 제출용 보고서 생성만으로 지정·신고 완료를 판정하지 않는다. [법 제36조](https://www.law.go.kr/LSW/lsSideInfoP.do?docCls=jo&joBrNo=00&joNo=0036&lsiSeq=282791&urlMode=lsScJoRltInfoR), [시행령 제29조](https://www.law.go.kr/LSW/lsSideInfoP.do?docCls=jo&joBrNo=00&joNo=0029&lsiSeq=288781&urlMode=lsScJoRltInfoR)

제40조 사실조사의 특정 대상은 제31조제2·3항, 제32조제1·2항, 제34조제1항 위반 의심 또는 신고 등이다. 제31조제1항 고지 누락만으로 이 목록을 확장하지 않는다. 과태료 제43조제1항은 제31조제1항 고지, 제36조제1항 국내대리인, 제40조제3항 명령 위반을 각각 정하고 있으므로 모든 제31조 결과 표시 누락을 동일한 직접 과태료 사유로 표시하지 않는다. 실제 조사·명령과 법정 절차는 별도 확인한다. [법 제40·43조](https://www.law.go.kr/LSW/lsInfoP.do?lsiSeq=282791)

법 제3조의 의미 있는 설명 관련 원칙, 제27~29조의 국가 윤리기준·민간 자율 윤리위원회·정책 책무도 확인했다. 이를 모든 AI사업자의 의무적 위원회 설치나 고영향 조치와 별개의 동일한 제재 의무로 만들지 않았다. 제34조제1항제6호 위원회 심의·의결 추가 사항은 실제 현행 결정 원문을 확보한 후 별도 반영해야 한다.

## 공식 가이드의 역할과 버전

NIA의 [공식 배포 페이지](https://www.nia.or.kr/site/nia_kor/ex/bbs/View.do?bcIdx=28987&cbIdx=99835&parentSeq=28987)에서 2026-01-22 배포 및 이후 정오표·파일 교체를 확인했다. 가이드의 권고·예시는 법률·시행령에 추가한 독립적인 강제 의무로 취급하지 않는다. 게시 당시 인용된 초안 또는 과거 법령은 현행 원문으로 다시 대조한다. 다음 해시는 2026-10-06에 받은 파일 바이트에 대한 무결성 식별자이며 내용의 진실성이나 공식 법적 인증을 보증하지 않는다.

| 가이드 파일 | 이번 확인 범위 | SHA-256 |
|---|---|---|
| [투명성, 260126](https://www.nia.or.kr/common/board/Download.do?bcIdx=28987&cbIdx=99835&fileNo=14) | PDF 33쪽; 8~9쪽 표시 방식·접근성·예술 표현, 12~13쪽 서비스 내 제공·외부 반출의 예시 구분 확인 | `f3c9206fc9e8b33d1ac7cf973bb00422efd2b0296347fa0346456bd807ef020d` |
| [안전성, 260122](https://www.nia.or.kr/common/board/Download.do?bcIdx=28987&cbIdx=99835&fileNo=15) | PDF 71쪽의 파일 수신·해시 확인. 글꼴의 문자 추출 오류가 있어 본문의 조문별 가이드 대조는 완료로 기록하지 않음 | `c49c4fa002e60d21a4964fbea992e1ae2f3554063db6e5da262b1d74aeb32dd5` |
| [고영향 판단, 260429](https://www.nia.or.kr/common/board/Download.do?bcIdx=28987&cbIdx=99835&fileNo=27) | PDF 216쪽; 10쪽 확인·자문 효력, 17쪽 대출심사 역할 도식, 20쪽 영역·위험의 두 단계, 80쪽 대출심사 범위 확인 | `c67782a5b61bbcc4753925c6fea47dbca8a522d67c0966aa8ea32782a2da005c` |
| [고영향 사업자 책무, 260122](https://www.nia.or.kr/common/board/Download.do?bcIdx=28987&cbIdx=99835&fileNo=23) | PDF 111쪽; 4쪽 가이드 자체의 구속력 한계, 13·16쪽 게시·시행령 연결, 60쪽 문서 관리 안내 확인 | `cbbd8a304563f879b2a584860481255cfb7b7e2d990fb13916404e306eea104e` |
| [영향평가, 260122](https://www.nia.or.kr/common/board/Download.do?bcIdx=28987&cbIdx=99835&fileNo=24) | PDF 39쪽; 4~8쪽 노력의무·제공자·당시 시행령안, 37쪽 재평가 권고 확인. 7월 취약계층 개정은 현행 법·시행령을 우선 | `a67ce99e960511d53f537a759aaeba6049faed220e430cc5ee1ff8817c39ea47` |

특히 **고영향 판단 가이드 PDF 17쪽**의 대출심사 도식은 신용예측 모델 개발자를 AI개발사업자, AI 대출심사 시스템 공급업체를 AI이용사업자, 이를 사용하는 은행 등 금융기관을 AI이용자로 예시한다. **80쪽**은 대출 승인·조건 결정에 직접 쓰이는 심사와 부수 상담·본인 확인·서류·사후처리 등을 구별한다. 금융기관이라는 이유만으로 이용사업자 또는 고영향을 확정하지 않는다. 개별 은행이 실제로 AI 제품·서비스를 개발·제공하면 그 역할을 다시 검토해야 하며, 이 도식을 모든 은행의 일괄 면제 근거로 쓰지 않는다. 공공기관 AI 이용 시 제30조제4항·제35조제2항의 우선 고려는 AI사업자 해당성과 별도로 유지한다. [공식 페이지](https://www.nia.or.kr/site/nia_kor/ex/bbs/View.do?bcIdx=28987&cbIdx=99835&parentSeq=28987), [확인한 PDF](https://www.nia.or.kr/common/board/Download.do?bcIdx=28987&cbIdx=99835&fileNo=27)

## 고시와 해석 보조자료의 확인 한계

과기정통부 공식 게시물에서 고영향 사업자 책무 고시 **제정안 행정예고**를 확인했다. 제목에 “고시 제2026-125호”가 들어가지만 본문은 “공고 제2026-125호” 및 행정예고로 명시하므로 이를 확정 고시로 취급하지 않았다. [2026-03-12 행정예고](https://www.msit.go.kr/bbs/view.do?bbsSeqNo=84&mId=109&mPid=103&nttSeqNo=3186336&pageIndex=&sCode=user&searchOpt=ALL&searchTxt=)

안전성 이행 고시도 추가 행정예고를 가리키는 공식 게시물을 찾았으나 최종 고시의 번호·공포일·본문을 확인하지 못했다. 투명성 추가 예외, 영향평가 세부 고시의 최종 현행본 역시 이번 확인에서 확보하지 못했다. “없음”이라는 판정이 아닌 **미확인**이다. 법률·시행령에서 직접 확인한 요구사항은 제공하되 최종 세부 고시 지원 완료로 보고하지 않는다. 법 제34조제2항에 따른 세부 고시·권고와 법률상 조치 의무의 성격도 동일시하지 않는다.

해소 과제: 법무 담당자가 관보·과기정통부 소관 고시 목록에서 최종본을 확보하고 법률·시행령 위임 범위 및 조문별 구속력을 검토한다. 출처 URL, 공포번호, 효력일, 확인일, 검토자와 변경 요약을 새 버전으로 저장한다. 기존 버전과 평가를 유지한 채 영향받는 통제에 재검토 과제를 연결한다. 공식 안내의 계도·규제 유예 표현을 법률 시행일 자체의 변경으로 해석하지 않는다.

## 국제 기준의 제한된 묶음

**NIST AI RMF 1.0 (2023)**: GOVERN·MAP·MEASURE·MANAGE를 책임, 맥락, 평가, 위험 처리에 연결했다. 자율 프레임워크이며 순서가 고정된 체크리스트가 아니다. 이번에 읽은 공식 페이지는 1.0 업데이트 진행 중임을 알린다. 아직 확인하지 않은 차기 버전의 조항으로 대체하지 않는다. [NIST 공식 Core](https://airc.nist.gov/airmf-resources/airmf/5-sec-core/)

**EU AI Act 구현 범위**: 현재 목록에는 `EU-50-1`, `EU-50-2`, `EU-50-3`, `EU-50-4-MEDIA`, `EU-50-4-TEXT`, `EU-50-5`가 등록되어 있고 `src/governance-policy.mjs`가 제출된 관할·역할·기능 사실에서 적용 후보를 제시한다. 이는 Article 50 전체의 법률 검토 완료를 뜻하지 않는다. Article 2 관할, 실제 provider/deployer 역할, 출시일, 예외를 검토해야 한다. 한국 고영향 후보 분류가 EU 고위험 분류를 확정하지 않는다. 전체 고위험 의무·GPAI·금지행위 적합성 평가는 이 묶음 밖이며 외부 절차로 남는다. 법적 원문 출처: [2024/1689 공식 원문](https://eur-lex.europa.eu/eli/reg/2024/1689/oj).

**변경을 반영한 EU 적용일**: Regulation (EU) 2026/1744의 2026-07-27 효력 및 Article 111(4), 113 변경을 확인했다. Article 50 일반 적용은 2026-08-02이며 2026-08-02 이전 출시한 합성 콘텐츠 생성 시스템 provider의 50(2) 전환 기한은 2026-12-02다. Chapter III Sections 1~3의 Annex III 고위험은 2027-12-02, Annex I 고위험은 2028-08-02로 변경되었다. 고위험 전환·기존 시스템의 설계 변경 등 예외를 일괄 판정하지 않는다. [2026/1744 공포 원문](https://eur-lex.europa.eu/legal-content/EN/ALL/?uri=CELEX%3A32026R1744), [집행위원회 일정 안내](https://ai-act-service-desk.ec.europa.eu/en/ai-act/eu-ai-act-implementation-timeline)

**ISO/IEC 42001:2023**: 공식 소개 페이지의 표준명·범위만 확인했다. 정당하게 확보한 유료 전체 본문이 없으므로 세부 조항 매핑은 제공하지 않는다. 인증 보장·문서 재배포도 하지 않는다. [ISO 공식 소개](https://www.iso.org/standard/42001)

## 증거와 평가를 연결하는 방법

`data/requirements.json`은 현재 31개 요구사항·준비 기록의 기준 목록이다. 개별 레코드의 출처·조항·구속력·조건·필요 증거·한계·확인일·효력일을 확인해야 한다. ISO 준비 기록을 법률상 의무나 유료 표준 본문의 세부 조항으로 세지 않는다. `data/governance-examples.json`은 생성형 고객안내와 고영향 후보 대출심사의 사실관계, 통제 연결, 합성 문서, 누락, 담당자·기한, 출처 변경 예제를 제공한다.

증거 존재는 충분성 판정이 아니다. 기술 결과, 증거 충분성, 법적 적용성, 인간 평가를 분리한다. “통지 이벤트 있음”은 실제 표시·읽음·이해를 확정하지 않으며 “사람 검토 기록 있음”은 감독 체계 전체를 충족시키지 않는다. 각 문서·시험 증거의 버전과 적용 기간이 시스템·정책 버전과 맞는지도 검토한다.

두 사례는 모두 합성이고 법률 검토 전이다. 고영향 미확정·안전성 대상 미확인은 미충족과도 구별한다. 설명 방안·이용자 보호·영향평가·기관 제출처럼 로그 외 자료가 필요한 통제는 외부 절차를 명시한다. 실제 기관 제출·법률 의견·인증은 자동 발급하지 않는다.

