# 법적 출처·범위와 인간 검토 상태

확인일: 2026-09-08. 전체 매핑 상태: `draft_requires_human_review`. 공식 원문을 읽고 작성한 한국어 요약과 EvidScope의 증거 연결 해석을 구분한다. 요구사항 20개는 한국 14개, NIST 4개, EU 2개로 구성한다. 다른 법령·전체 AI 기본법·전체 EU AI Act·ISO 인증을 포괄하지 않는다.

## 한국 법률과 시행령

국가법령정보센터의 현행 법률 표제는 **법률 제21311호, 2026-01-20 일부개정, 2026-07-21 시행**이다. 제31~34조의 이 문서 사용 조항은 2026-01-22부터 시행된 내용을 확인했다. 제35조제1항의 취약계층 특성 반영 후단은 2026-07-21부터 시행한다. [현행 법률](https://www.law.go.kr/LSW/lsInfoP.do?lsId=014820), [현행 제35조](https://www.law.go.kr/lsLinkCommonInfo.do?chrClsCd=010202&lsJoLnkSeq=1031810855)

현행 시행령은 **대통령령 제36580호, 2026-08-18 타법개정, 2026-08-20 시행**으로 확인했다. 과거 검색 결과의 제36053호 제정본만으로 현행을 단정하지 않았다. 확인 범위는 제23~25조·제27~28조이며 전체 개정 영향 분석은 아니다. [현행 시행령 제24조](https://www.law.go.kr/LSW/lsSideInfoP.do?docCls=jo&joBrNo=00&joNo=0024&lsiSeq=288781&urlMode=lsScJoRltInfoR)

| 매핑 범위 | 규범 내용의 구분 | 근거와 조건 |
|---|---|---|
| KR-31-1/2/3 | AI 사용 사전 고지, 생성형 결과물 표시, 사실적인 합성물 고지·표시를 분리 | [법 제31조](https://www.law.go.kr/LSW/lsSideInfoP.do?docCls=jo&joBrNo=00&joNo=0031&lsiSeq=282791&urlMode=lsScJoRltInfoR), [시행령 제23조](https://www.law.go.kr/LSW/lsSideInfoP.do?docCls=jo&joBrNo=00&joNo=0023&lsiSeq=288781&urlMode=lsScJoRltInfoR) |
| KR-32-RISK/MONITOR/SUBMIT | 수명주기 위험관리, 안전사고 체계, 결과 제출을 분리 | [법 제32조](https://www.law.go.kr/LSW/lsSideInfoP.do?docCls=jo&joBrNo=00&joNo=0032&lsiSeq=282791&urlMode=lsScJoRltInfoR), [시행령 제24조](https://www.law.go.kr/LSW/lsSideInfoP.do?docCls=jo&joBrNo=00&joNo=0024&lsiSeq=288781&urlMode=lsScJoRltInfoR) |
| KR-33 | 제공 전 검토는 의무, 장관 확인 요청은 선택 | [법 제33조](https://law.go.kr/LSW/lsLinkCommonInfo.do?chrClsCd=010202&lsJoLnkSeq=1031810895), [확인 절차 제25조](https://www.law.go.kr/LSW/lsSideInfoP.do?docCls=jo&joBrNo=00&joNo=0025&lsiSeq=288781&urlMode=lsScJoRltInfoR) |
| KR-34-* | 위험관리·설명·보호·인간 감독·문서를 구분 | [법 제34조](https://www.law.go.kr/LSW/lsSideInfoP.do?docCls=jo&joBrNo=00&joNo=0034&lsiSeq=282791&urlMode=lsScJoRltInfoR), [시행령 제27조](https://www.law.go.kr/LSW/lsSideInfoP.do?docCls=jo&joBrNo=00&joNo=0027&lsiSeq=288781&urlMode=lsScJoRltInfoR) |
| KR-35-IMPACT/PUBLIC | 영향평가 노력의무와 공공 이용 시 평가 제품 우선 고려 의무를 구분 | [법 제35조](https://www.law.go.kr/lsLinkCommonInfo.do?chrClsCd=010202&lsJoLnkSeq=1031810855), [시행령 제28조](https://www.law.go.kr/LSW/lsSideInfoP.do?docCls=jo&joBrNo=00&joNo=0028&lsiSeq=288781&urlMode=lsScJoRltInfoR) |

시행령 제23조는 명백성, 사업자 내부 업무 등에서 전부 또는 일부 예외를 허용한다. 기계 판독 방식의 생성형 표시는 생성 사실을 1회 이상 안내해야 한다. 예외를 자동 적용하지 않고 대상·근거·검토자를 기록한다. [시행령 제23조](https://www.law.go.kr/LSW/lsSideInfoP.do?docCls=jo&joBrNo=00&joNo=0023&lsiSeq=288781&urlMode=lsScJoRltInfoR)

제32조 대상은 누적 학습 연산량 10^26 FLOPs 이상, 최첨단 기술 사용, 광범위하고 중대한 위험 우려의 **세 기준을 모두** 충족해야 한다. 연산량이 알려지지 않은 API 이용 서비스에 이를 임의 추정하지 않는다. [시행령 제24조](https://www.law.go.kr/LSW/lsSideInfoP.do?docCls=jo&joBrNo=00&joNo=0024&lsiSeq=288781&urlMode=lsScJoRltInfoR)

제34조의 조치 근거 문서 5년 보관과 게시 의무를 연결한다. 5년을 모든 prompt·개인정보·원본 로그의 기본 보존기간으로 확대하지 않는다. 사업자 간 기존 조치 인정은 중대한 기능 변경 여부와 제1~3호 범위를, 다른 법령의 인정은 별표1을 별도로 검토해야 한다. 영업비밀 게시 제외는 원본 삭제 권한을 뜻하지 않는다. [시행령 제27조](https://www.law.go.kr/LSW/lsSideInfoP.do?docCls=jo&joBrNo=00&joNo=0027&lsiSeq=288781&urlMode=lsScJoRltInfoR)

영향평가 실시를 모든 사업자의 동일한 강제 의무로 표현하지 않는다. 평가를 수행하는 경우 취약계층을 포함한 영향 집단, 기본권, 사회경제 영향, 사용 행태, 지표·산출 방식, 위험 예방·완화·복구, 개선 계획을 확인한다. 행동 로그가 평가서나 전문가 의견을 대체하지 않는다. [현행 법 제35조](https://www.law.go.kr/lsLinkCommonInfo.do?chrClsCd=010202&lsJoLnkSeq=1031810855), [시행령 제28조](https://www.law.go.kr/LSW/lsSideInfoP.do?docCls=jo&joBrNo=00&joNo=0028&lsiSeq=288781&urlMode=lsScJoRltInfoR)

## 고시와 해석 보조자료의 확인 한계

과기정통부 공식 게시물에서 고영향 사업자 책무 고시 **제정안 행정예고**를 확인했다. 제목에 “고시 제2026-125호”가 들어가지만 본문은 “공고 제2026-125호” 및 행정예고로 명시하므로 이를 확정 고시로 취급하지 않았다. [2026-03-12 행정예고](https://www.msit.go.kr/bbs/view.do?bbsSeqNo=84&mId=109&mPid=103&nttSeqNo=3186336&pageIndex=&sCode=user&searchOpt=ALL&searchTxt=)

안전성 이행 고시도 추가 행정예고를 가리키는 공식 게시물을 찾았으나 최종 고시의 번호·공포일·본문을 확인하지 못했다. 투명성 추가 예외, 영향평가 세부 고시의 최종 현행본 역시 이번 확인에서 확보하지 못했다. “없음”이라는 판정이 아닌 **미확인**이다. 법률·시행령에서 직접 확인한 요구사항은 제공하되 최종 세부 고시 지원 완료로 보고하지 않는다. 법 제34조제2항에 따른 세부 고시·권고와 법률상 조치 의무의 성격도 동일시하지 않는다.

해소 과제: 법무 담당자가 관보·과기정통부 소관 고시 목록에서 최종본을 확보하고 법률·시행령 위임 범위 및 조문별 구속력을 검토한다. 출처 URL, 공포번호, 효력일, 확인일, 검토자와 변경 요약을 새 버전으로 저장한다. 기존 버전과 평가를 유지한 채 영향받는 통제에 재검토 과제를 연결한다. 공식 안내의 계도·규제 유예 표현을 법률 시행일 자체의 변경으로 해석하지 않는다.

## 국제 기준의 제한된 묶음

**NIST AI RMF 1.0 (2023)**: GOVERN·MAP·MEASURE·MANAGE를 책임, 맥락, 평가, 위험 처리에 연결했다. 자율 프레임워크이며 순서가 고정된 체크리스트가 아니다. 이번에 읽은 공식 페이지는 1.0 업데이트 진행 중임을 알린다. 아직 확인하지 않은 차기 버전의 조항으로 대체하지 않는다. [NIST 공식 Core](https://airc.nist.gov/airmf-resources/airmf/5-sec-core/)

**EU AI Act**: 현재 묶음은 Article 50(1) 직접 상호작용 고지와 50(2) 합성물 기계 판독 표시의 provider 의무만 구현한다. Article 2 관할, 실제 provider/deployer 역할, 출시일, 예외를 검토해야 한다. 한국 고영향 후보 분류가 EU 고위험 분류를 확정하지 않는다. 50(3)/(4) deployer 의무, 전체 고위험 의무·GPAI·금지행위 적합성 평가는 이 묶음 밖이며 외부 절차로 남는다. [2024/1689 공식 원문](https://eur-lex.europa.eu/eli/reg/2024/1689/oj)

**변경을 반영한 EU 적용일**: Regulation (EU) 2026/1744의 2026-07-27 효력 및 Article 111(4), 113 변경을 확인했다. Article 50 일반 적용은 2026-08-02이며 2026-08-02 이전 출시한 합성 콘텐츠 생성 시스템 provider의 50(2) 전환 기한은 2026-12-02다. Chapter III Sections 1~3의 Annex III 고위험은 2027-12-02, Annex I 고위험은 2028-08-02로 변경되었다. 고위험 전환·기존 시스템의 설계 변경 등 예외를 일괄 판정하지 않는다. [2026/1744 공포 원문](https://eur-lex.europa.eu/legal-content/EN/ALL/?uri=CELEX%3A32026R1744), [집행위원회 일정 안내](https://ai-act-service-desk.ec.europa.eu/en/ai-act/eu-ai-act-implementation-timeline)

**ISO/IEC 42001:2023**: 공식 소개 페이지의 표준명·범위만 확인했다. 정당하게 확보한 유료 전체 본문이 없으므로 세부 조항 매핑은 제공하지 않는다. 인증 보장·문서 재배포도 하지 않는다. [ISO 공식 소개](https://www.iso.org/standard/42001)

## 증거와 평가를 연결하는 방법

`data/requirements.json`은 출처·조항·구속력·조건·필요 증거·한계·확인일·효력일을 가진 20개 레코드다. `data/governance-examples.json`은 생성형 고객안내와 고영향 후보 대출심사의 사실관계, 통제 연결, 합성 문서, 누락, 담당자·기한, 출처 변경 예제를 제공한다.

증거 존재는 충분성 판정이 아니다. 기술 결과, 증거 충분성, 법적 적용성, 인간 평가를 분리한다. “통지 이벤트 있음”은 실제 표시·읽음·이해를 확정하지 않으며 “사람 검토 기록 있음”은 감독 체계 전체를 충족시키지 않는다. 각 문서·시험 증거의 버전과 적용 기간이 시스템·정책 버전과 맞는지도 검토한다.

두 사례는 모두 합성이고 법률 검토 전이다. 고영향 미확정·안전성 대상 미확인은 미충족과도 구별한다. 설명 방안·이용자 보호·영향평가·기관 제출처럼 로그 외 자료가 필요한 통제는 외부 절차를 명시한다. 실제 기관 제출·법률 의견·인증은 자동 발급하지 않는다.

