# ISMS-P 인증기준 참고 정렬

> 2026-10-07 개선 2라운드에서 항목 단위로 다시 정렬한 참고 자료입니다. 인증 심사·판정이나 법률 의견이 아니며 상태는
> `draft_requires_human_review`입니다. 원본 데이터는 [`data/isms-p-alignment.json`](../data/isms-p-alignment.json)이고, 표가 출처·코드와
> 어긋나지 않는지는 [`test/isms-p-alignment.test.mjs`](../test/isms-p-alignment.test.mjs)가 확인합니다.

## 무엇을 위한 표인가

EvidScope는 ISMS-P 인증을 받는 관리체계가 아니라, 인증 범위에 AI 에이전트를 둔 조직이 일부 통제를 보일 때 꺼낼 수 있는
**증거의 출처**입니다. 이 표는 인증기준 101개 항목마다 EvidScope의 기록·API·검증 결과가 어느 확인사항의 참고 증거가 될 수 있는지,
무엇이 여전히 사람과 조직의 일인지 나눕니다. 27개 항목을 정렬했고 74개 항목은 이유를 적어 제외했습니다.

- **증거가 있다는 것은 기준을 충족했다는 판정이 아닙니다.** 인증 여부, 결함 여부, 기준 충족 여부를 판정하지 않습니다
  (`certificationClaim:false`, `criterionAssessment:"not_performed"`). 심사에서 보는 정책·절차·운영 기록은 조직이 따로 갖춥니다.
- 엄격하게 정렬했습니다. EvidScope 기록·API·검증 결과가 그 항목의 확인사항 가운데 적어도 하나에 대해 **실제 증거**가 될 때만
  정렬했고, 입력 자료일 뿐인 경우는 제외하고 이유를 적었습니다. 중심은 AI 에이전트에 고유한 부분입니다. 에이전트 식별과 권한, 도구·모델
  호출, 사람 승인, 정책 판단, 증거 저장소 자체의 조회 기록, 보존과 파기, 공급사 자료가 여기에 해당합니다.
- 고시의 상세 내용과 KISA 주요 확인사항 문구를 옮기지 않습니다. 항목 번호·짧은 명칭과 확인사항의 위치(①②…)만 쓰고, 증거가 보여 주는
  것은 짧게 풀어 씁니다. 기준의 내용은 아래 원문을 직접 읽어야 합니다.

## 출처와 확인 수준

| 구분 | 내용 |
|---|---|
| 법적 출처 | 「정보보호 및 개인정보보호 관리체계 인증 등에 관한 고시」 [별표 7] 인증기준(제23조 관련). 개인정보보호위원회 고시 제2024-8호·과학기술정보통신부 고시 제2024-30호, 2024-07-24 일부개정·2024-07-24 시행, DRF `현행여부` Y |
| 법적 출처 파일 | 국가법령정보 Open API(DRF) 행정규칙 본문 XML, 행정규칙일련번호 2100000244750, 434,490바이트, SHA-256 `1f791301caf2b1135be1b353bddc98a31a2656e1988cb073bb8cafa64a3b09f1`. 사람이 읽는 화면: [국가법령정보센터](https://www.law.go.kr/LSW/admRulLsInfoP.do?admRulSeq=2100000244750) |
| 해설 자료 1 | KISA ISMS-P 인증기준 세부점검항목(2023.10.31), 자료실 게시물 RCSRMID_000000010066(게시일 2023-10-31), xlsx 52,947바이트, SHA-256 `ab99cad99473eb8873d0000be42be4f13f098b26515c45a8a141d4625ff4bf2d` |
| 해설 자료 2 | KISA 정보보호 및 개인정보보호 관리체계(ISMS-P) 인증기준 안내서(2023. 11.), 자료실 게시물 RCSRMID_000000010105(게시일 2023-11-23), PDF 262쪽 8,504,805바이트, SHA-256 `cf80d3bb191f325583e7410840d8016b50ffcf28f9fc5a4d044e4ef600f90a9b` |
| 자료실 | [ISMS-P 누리집 자료실](https://isms-p.or.kr/ntcn/rcsrm/selectGnrlRcsrmList.do). 게시물 본문은 양식 POST로만 열립니다 |
| 구성 | 가. 관리체계 수립 및 운영 16개(주요 확인사항 42개), 나. 보호대책 요구사항 64개(주요 확인사항 195개), 다. 개인정보 처리 단계별 요구사항 21개(주요 확인사항 91개). 제23조제1항에 따라 ISMS-P 인증은 가목부터 다목까지, ISMS 인증은 가목과 나목을 적용합니다 |
| 읽은 날 | 2026-10-07. 작업 컨테이너에서 law.go.kr와 isms-p.or.kr가 열리지 않아, 리드가 국내 망에서 받은 파일을 읽었습니다 |
| 확인 수준 | `item_numbers_and_titles_verified_against_notice_check_items_from_kisa_workbook`: 항목 번호·명칭은 고시 원문과 대조했고, 주요 확인사항은 KISA 엑셀에서 읽었습니다 |

확인한 방법은 다음과 같습니다.

1. 고시 XML의 [별표 7] 표를 직접 구문 분석해 101개 항목의 번호·명칭을 뽑고, 리드의 구문 분석 결과(TSV)와 같은지 대조했습니다.
   줄바꿈된 명칭은 공백 하나로 이었습니다. 분야 명칭도 고시 원문을 따릅니다(예: 2.1 정책, 조직, 자산 관리).
2. KISA 세부점검항목 엑셀의 101개 항목 번호·명칭과 상세내용이 현행 고시 [별표 7]과 같은지 대조했습니다. 공백과 가운뎃점 표기
   (`ㆍ`와 `∙`) 차이만 있었습니다.
3. 주요 확인사항 328개(영역별 42·195·91개)는 엑셀에서 읽었습니다. 안내서도 101개 항목 모두 같은 확인사항을 같은 순서로 싣고 있음을
   대조했습니다(한 문장만 표기 차이). KISA 자료에는 확인사항 번호가 없으므로, 이 표의 ①②…는 항목 안의 순서를 가리키려고 붙인 것입니다.
4. 시험은 항목 목록(번호·명칭·확인사항 수)의 SHA-256을 고정합니다. 목록을 고치려면 출처를 다시 읽고 시험의 값을 함께 바꿔야 합니다.

주의할 점도 그대로 적습니다.

- 과학기술정보통신부 고시 번호(제2024-30호)는 리드가 전달한 값입니다. DRF XML의 발령번호에는 개인정보보호위원회 고시 제2024-8호만
  있어 이 번호는 대조하지 못했습니다.
- 제23조제2항에 따라 인증범위·업무특성·기업규모를 고려한 구체적인 확인사항이 따로 공고될 수 있습니다. 이 표는 반영하지 않습니다.
- 제23조제3항·제4항의 특례 대상자에게 적용하는 완화된 기준인 [별표 7의2]·[별표 7의3]은 정렬하지 않았습니다.
- XML에 있는 담당자 정보는 저장소에 옮기지 않았습니다.

### 2024-07-24 개정과 [별표 7]

안내서는 2023. 11.판이고 고시는 2024-07-24에 일부개정되었습니다. 고시 원문에서 확인한 결과, **이 개정은 [별표 7]을 바꾼 것으로
보이지 않습니다.**

- 2024-07-24 개정이유의 주요내용은 인증심사 일부 생략 대상(제20조), 특례 대상자 수수료 감면(제21조), 특례 대상자의 완화된 기준
  (제23조, 별표 7의2, 별표 7의3)만 듭니다. [별표 7]은 들지 않습니다.
- 현행 [별표 7]의 101개 항목 번호·명칭·상세내용이 2023-10-31 KISA 세부점검항목과 같습니다.
- 안내서 머리말은 2023년 고시(과학기술정보통신부고시 제2023-33호, 개인정보보호위원회고시 제2023-8호)를 설명한다고 적습니다.

다만 개정 전 고시 원문과 직접 비교하지는 않았고, [별표 7] 머리에는 날짜 없는 `<전문개정>` 표시만 있습니다.

## 항목별 정렬

27개 항목입니다. "확인사항"은 증거가 닿는 주요 확인사항의 위치입니다. 증거 이름은 API(`메서드 경로`), 원장 기록 종류,
발견사항 코드, 출처별 이벤트 규칙, 시험·스크립트 파일입니다. `{id}`는 경로의 식별자 자리입니다.

| 항목 | 확인사항 | EvidScope 증거가 보여 주는 것 | 사람·조직이 할 일 |
|---|---|---|---|
| 1.2.1 정보자산 식별 | ①③ | ① AI 에이전트·도구 조합을 자산으로 등록한 서명 목록(소유자·목적·허용 목적지·정책 버전·유효기간). 증거: `POST /api/assets`, `GET /api/assets`, `asset`. ③ 관측된 행동에서 등록되지 않은 에이전트·도구·AI 자산을 찾아 목록을 고칠 대상을 알림. 증거: `GET /api/agents`, `GET /api/ai-visibility`, `UNREGISTERED_ASSET`, `AI_UNREGISTERED_ASSET`. | ① 분류기준 수립과 범위 내 전체 정보자산 식별(AI 에이전트·도구 밖의 자산); ② 중요도 결정과 보안등급 부여; ③ 정기 조사의 수행. 관측 목록에 없다는 것이 존재하지 않는다는 뜻은 아니다 |
| 1.4.1 법적 요구사항 준수 검토 | ①② | ① AI 관련 요구사항 카탈로그와 각 법령 출처의 확인 범위·확인일을 데이터로 유지. 증거: `GET /api/governance`의 `legalSourceCoverage`, `catalog`, [legal-sources.md](legal-sources.md). ② 요구사항별 평가, 평가 작성자가 아닌 검토자의 법률 검토 확인, 출처·정책 변경 때 생기는 재검토 과제. 증거: `POST /api/governance/assessments`, `assessment`, `POST /api/governance/assessments/{id}/legal-review`, `governance_legal_review`, `GET /api/governance/report`, `governance_task`. | 카탈로그는 AI 관련 요구사항만 담는다. 정보통신망법·개인정보 보호법 등 정보보호·개인정보보호 법규 전체의 파악은 조직의 일이다; 법률 적용성·충분성 판단과 정기 검토 주기의 결정 |
| 2.1.3 정보자산 관리 | ② | ② AI 에이전트·도구 자산마다 소유자 항목을 함께 서명 기록으로 남김. 증거: `POST /api/assets`, `asset`. | ① 보안등급별 취급절차와 보호대책; 소유자 지정의 적절성 확인과 AI 자산 밖 정보자산의 책임자 지정 |
| 2.2.2 직무 분리 | ①② | ① 승인 행위의 직무 분리를 코드로 강제: 룰·예외·파기 계획은 작성자가 승인할 수 없고, 사건은 연 사람이 종결할 수 없으며, 사람 승인은 authority 출처만 기록. 증거: `POST /api/rules/{id}/approve`, `POST /api/exceptions/{id}/approve`, `POST /api/retention/plans/{id}/approve`, `POST /api/cases/{id}`, `human_approval`(authority 출처만), [`test/four-eyes.test.mjs`](../test/four-eyes.test.mjs). ② 작성자와 승인자·종결자가 서명 기록에 남아 상호 검토의 책임추적 근거가 됨. 증거: `rule`, `exception`, `retention_plan`, `governance_legal_review`, `case`. | 직무 분리 기준 수립과 조직 전체의 역할 배정·겸직 검토; EvidScope 밖 시스템의 직무 분리 |
| 2.2.5 퇴직 및 직무변경 관리 | ② | ② OIDC 모드에서 퇴직·직무변경자의 EvidScope 접근 중지·재개·세션 회수와 사유를 서명 기록으로 남김. 증거: `POST /api/access/subjects/{id}`(OIDC), `GET /api/access`(OIDC), `identity_access`, [oidc-authentication.md](oidc-authentication.md). | ① 인사변경 내용의 부서 간 공유; IdP와 대상 시스템 계정의 회수, bearer 토큰 계정의 회수와 결과 확인. 이 증거는 EvidScope 자신의 접근만 다룬다 |
| 2.3.1 외부자 현황 관리 | ① | ① 에이전트가 실제로 호출한 외부 AI 모델 서비스(제공자·모델·목적지)를 관측해 외부 서비스 이용 현황 식별 자료로 씀. 증거: `POST /api/ingest/otlp`, `GET /api/ai-visibility`, `notice`(otlp·telemetry 출처만). | ② 법적 요구사항·위험 파악과 보호대책; OTLP를 보내지 않는 경로의 외부 서비스 이용과 업무 위탁 현황 |
| 2.3.3 외부자 보안 이행 관리 | ① | ① 모델·서비스 공급사 자료를 해시로 고정해 등록하고, 출처 검토와 공급사 조치 활용 검토를 서명 기록으로 남김. 증거: `POST /api/governance/bundles`, `POST /api/governance/bundles/{id}/provenance-reviews`, `supplier_bundle`, `supplier_provenance_review`, `supplier_risk_reliance`(authority 출처만), [kr-supplier-reliance.md](kr-supplier-reliance.md). | 계약서·협정서 요구사항과의 대조와 주기적 점검·감사 계획; ② 개선계획 수립·이행, ③ 재위탁 동의; 공급사 자료 내용의 진실성 검증 |
| 2.5.1 사용자 계정 관리 | ①② | ① 에이전트 행동 권한의 부여·회수는 authority 출처만 기록하고, OIDC 계정의 접근 변경은 사유와 함께 서명 기록. 증거: `grant`(authority 출처만), `revoke`(authority 출처만), `identity_access`. ② 권한이 행동·대상 범위로 기록되어 최소 권한 검토의 자료가 되고, 권한 증거가 없거나 범위와 맞지 않는 행동을 표시. 증거: `AUTHORITY_MISSING`, `AUTHORITY_MISMATCH`. | 계정·권한 등록·변경·삭제 절차와 직무별 권한 분류 체계 수립; 부여한 범위가 최소한인지의 판단; ③ 보안책임 인식; IdP와 대상 시스템의 계정 관리 |
| 2.5.2 사용자 식별 | ① | ① 에이전트 행동을 인증된 수집 출처와 에이전트 식별자에 귀속하고, 식별자에 귀속하지 못한 행동 수를 보고. 증거: `GET /api/agents`, `intent`(agent 출처만). | 에이전트 식별자의 유일한 부여는 배포 조직의 일이다(EvidScope는 받은 식별자를 기록한다); ② 공유 식별자 사용 사유 검토와 승인 |
| 2.5.3 사용자 인증 | ① | ① 수집 출처는 HMAC 서명·시각·nonce로 인증되고, OIDC 사람 로그인·로그아웃은 세션 기록으로 남음. 증거: `POST /api/ingest`, `identity_session`, [oidc-authentication.md](oidc-authentication.md). | 로그인 횟수 제한·불법 로그인 경고 등은 IdP와 배포 환경의 설정; ② 외부 접속 시 안전한 인증수단; 에이전트가 대상 시스템에 인증하는 방식 |
| 2.5.5 특수 계정 및 권한 관리 | ①② | ① 사람 승인이 필요한 자산의 고위험 행동에 authority 출처 승인 기록을 요구하고, 없거나 맞지 않는 승인과 확인되지 않은 위임을 표시. 증거: `human_approval`(authority 출처만), `HUMAN_APPROVAL_MISSING`, `APPROVAL_MISMATCH`, `DELEGATION_UNVERIFIED`. ② AI 에이전트를 특수 목적 계정으로 보아 등록 자산 목록(소유자·목적·승인 필요 여부)으로 따로 관리. 증거: `GET /api/assets`, `asset`, `GET /api/agents`. | 관리자 권한 등 특수권한의 신청·승인 절차와 최소 인원 부여; AI 에이전트를 특수 계정으로 볼지의 판단 |
| 2.5.6 접근권한 검토 | ① | ① 에이전트 권한의 부여·회수와 도구 실행, OIDC 계정의 접근 변경과 세션 이력이 서명 원장에 남음. 증거: `grant`(authority 출처만), `revoke`(authority 출처만), `execution`(tool 출처만), `identity_access`, `identity_session`. | ② 정기 검토의 기준·주체·방법·주기 수립과 이행; ③ 문제 발견 시 조치 절차; 대상 시스템의 계정·권한 이력 |
| 2.6.3 응용프로그램 접근 | ① | ① EvidScope 자신의 역할별 API 권한(감사자·검토자·관리자)과 tenant 경계, 조회 기록 열람 제한. 증거: `GET /api/access`(OIDC), `GET /api/audit/reads`, [`test/governance-authorization.test.mjs`](../test/governance-authorization.test.mjs), [`test/store-tenant-binding.test.mjs`](../test/store-tenant-binding.test.mjs). | ②~⑤ 세션 시간·동시 세션 제한, 관리 화면 접근, 표시제한 기준은 배포 설정과 조직 기준; 에이전트가 쓰는 대상 응용프로그램의 접근권한 |
| 2.6.7 인터넷 접속 통제 | ② | ② 에이전트·도구의 외부 목적지를 등록 허용 목록과 비교해 정책 밖 접속을 발견사항으로 표시(탐지만 하며 차단하지 않음). 증거: `asset`, `DESTINATION_OUTSIDE_POLICY`, `AI_DESTINATION_OUTSIDE_POLICY`, `POLICY_CONTEXT_UNVERIFIED`. | 실제 접속 차단(방화벽·프록시); ① 업무용 PC의 인터넷 접속 통제; ③ 인터넷망 차단 의무 대상 식별과 조치 |
| 2.7.1 암호정책 적용 | ② | ② 데이터 키를 설정하면 거버넌스·금융 문서와 vault 백업을 서명키와 분리한 키로 암호화하고, 분리 상태를 무결성 검사가 보고. 증거: `GET /api/integrity`의 `keySeparation`, [data-key-separation.md](data-key-separation.md). | ① 암호정책 수립; 이벤트 키는 같은 DB에 감싸지 않은 채 있어 DB를 읽는 사람에게 기밀성이 없고 조회 사본은 평문이다(keySeparation.eventKeys); 전송 구간 암호화(TLS)는 배포 설정 |
| 2.7.2 암호키 관리 | ① | ① 데이터 키의 생성·식별·재암호화 도구와, 파기 때 삭제한 이벤트 키 ID의 서명 기록. 증거: [`scripts/data-key.mjs`](../scripts/data-key.mjs), `retention_disposition`, `GET /api/integrity`의 `keySeparation`. | 키 관리 절차 수립과 책임자 지정; ② 키 백업의 별도 안전 보관과 접근 최소화(HSM·KMS 연동 없음) |
| 2.8.5 소스 프로그램 관리 | ③ | ③ 개발 에이전트 실행이 만든 산출물의 경로·해시와 도구 사용 범주를 서명 기록으로 남김(원문·명령·도구 인자는 받지 않음). 증거: `POST /api/development-runs/events`, `GET /api/development-runs`, `development_run_event`, [development-agent-operations.md](development-agent-operations.md). | 변경이력의 원본은 형상관리 도구(git 등)다; ① 소스 접근 통제, ② 운영환경 밖 보관 |
| 2.9.1 변경관리 | ① | ① 에이전트·도구 자산의 버전·정책 버전·유효기간 변경이 서명 이력으로 남고, 행동 시점 정책을 확정할 수 없으면 표시. 증거: `asset`, `POLICY_CONTEXT_UNVERIFIED`, `GET /api/ai-visibility`. | 변경 절차 수립과 변경 승인; ② 변경 전 성능·보안 영향 분석 |
| 2.9.2 성능 및 장애관리 | ③ | ③ 등록 출처의 수신 상태(미연결·지연·수신), 도구 실행 실패 추이, 수집 공백 보고로 수집 경로와 도구 실행의 장애를 알림. 증거: `GET /api/overview`, `GET /api/monitoring`, `gap`(telemetry 출처만), `COLLECTION_GAP`. | ①② 성능·용량 감시와 임계치 대응; ④ 장애조치 기록, ⑤ 원인분석과 재발방지; EvidScope vault 자체의 가용성 감시 |
| 2.9.3 백업 및 복구관리 | ①② | ① vault 백업 생성·복구 도구와 절차. 증거: [`scripts/vault-backup.mjs`](../scripts/vault-backup.mjs), [vault-recovery.md](vault-recovery.md). ② 복구한 vault를 검증한 뒤 복구 결과와 아카이브 해시를 원장에 남기고, 복구 시험을 회귀 시험에 포함. 증거: `recovery_restore`, [`test/vault-recovery.test.mjs`](../test/vault-recovery.test.mjs). | 백업 대상·주기 결정과 정기 복구 테스트의 수행; ③ 원격지 소산 |
| 2.9.4 로그 및 접속기록 관리 | ①② | ① 에이전트 의도·도구 실행·모델 호출 기록을 출처 인증 뒤 서명 원장에 보관하고 보존기간을 정책으로 정함. 증거: `intent`(agent 출처만), `execution`(tool 출처만), `POST /api/ingest/otlp`, `retention_policy`. ② 원장 위변조를 서명·해시 체인·위트니스 체크포인트로 탐지하고, 원장 조회 행위를 봉인된 조회 기록으로 남기며 그 열람을 감사자·관리자로 제한. 증거: [`scripts/verify.mjs`](../scripts/verify.mjs), `/api/integrity`의 `signed_ledger`, `/api/integrity`의 `access_log`, `audit_access_batch`, `integrity_failure`, `GET /api/audit/reads`, `GET /api/audit/reads/proof`, [transparency-log.md](transparency-log.md). | ③ 개인정보처리시스템 접속기록의 법정 항목·보관기간은 대상 시스템 기록으로 판단한다. EvidScope 조회 기록에는 접속지·정보주체 항목이 없다; 로그관리 절차 수립과 보관 매체의 도난·분실 방지; 위변조는 막지 않고 탐지한다. 서명키를 가진 vault 호스트 공격자는 외부 체크포인트 없이 되돌리기를 숨길 수 있다 |
| 2.9.5 로그 및 접속기록 점검 | ①② | ① 에이전트 행동을 정해진 규칙으로 평가해 권한 없음·결과 상충·참고 자료 불일치 등을 발견사항으로 남기고, 평가를 오프라인에서 재계산. 증거: `evaluation`, `CONTRADICTING_RESULT`, `REFERENCE_METADATA_CONFLICT`, `GET /api/alerts`, [`scripts/replay-findings.mjs`](../scripts/replay-findings.mjs). ② 발견사항을 사건으로 열고 사람 판단을 서명 기록으로 남김. 증거: `POST /api/cases`, `case`, `POST /api/cases/{id}/decisions`, `case_decision`. | 로그 검토 주기·대상·방법과 책임자 보고 절차; ③ 법정 주기의 접속기록 점검 |
| 2.10.1 보안시스템 운영 | ③④ | ③ 탐지 룰의 신규·변경을 버전으로 추가하고, 시험한 초안만 작성자가 아닌 사람이 승인. 증거: `POST /api/rules`, `POST /api/rules/{id}/test`, `POST /api/rules/{id}/approve`, `rule`. ④ 예외는 작성자·소유자가 아닌 사람이 최대 90일로 승인하고, 예외로 억제된 발견사항도 기록에 남음. 증거: `POST /api/exceptions`, `POST /api/exceptions/{id}/approve`, `exception`. | EvidScope 탐지 룰을 보안시스템 정책으로 볼지의 판단; ①② 운영절차와 관리자 최소화; ⑤ 정책 타당성의 정기 검토; ⑥ 법령이 정한 기능의 보안시스템 |
| 2.11.3 이상행위 분석 및 모니터링 | ①② | ① 에이전트의 모델 호출·도구 실행·목적지 기록을 모아 정책 밖 목적지와 로그 주입 신호를 분석. 증거: `POST /api/ingest/otlp`, `GET /api/ai-visibility`, `DESTINATION_OUTSIDE_POLICY`, `AI_DESTINATION_OUTSIDE_POLICY`, `LOG_INJECTION_SIGNAL`. ② 판단 기준을 승인된 룰로 정하고 경보·조사 화면과 SIEM용 내보내기로 후속 조치에 넘김. 증거: `rule`, `GET /api/alerts`, `GET /api/investigations`, `GET /api/export/ocsf`. | 네트워크 트래픽·보안시스템 이벤트 등 에이전트 밖 이상행위 분석; 기준·임계치의 적정성과 후속 조치의 적시성 |
| 2.11.5 사고 대응 및 복구 | ①③ | ① 에이전트 중지·차단 요청과 확인을 safety 출처로 기록하고, 확인이 없거나 중지 뒤 실행이 있으면 표시하며, 사람 판단을 사건 기록에 남김. 증거: `stop_requested`(safety 출처만), `stop_confirmed`(safety 출처만), `STOP_UNCONFIRMED`, `EXECUTION_AFTER_STOP_REQUEST`, `BLOCK_SUCCESS_CONFLICT`, `POST /api/cases/{id}/decisions`, `case_decision`. ③ 사건 결과를 서명 보고서로 내보내 오프라인 검증 뒤 공유. 증거: `GET /api/cases/{id}/report`, [`scripts/verify-case-report.mjs`](../scripts/verify-case-report.mjs). | 침해사고 대응절차와 보고 체계; ② 정보주체 통지·관계기관 신고와 법정 기한; ④ 재발방지 대책; 실제 차단 효력의 확인 |
| 3.1.2 개인정보 수집 제한 | ① | ① 증거 계층 자신이 받는 값을 허용 필드로 제한하고 원문(prompt 등)·예약 필드를 거부하며, 이벤트에 최소 수집 표시를 남김. 증거: `POST /api/ingest`, `POST /api/ingest/otlp`, `event`, [`test/integration.test.mjs`](../test/integration.test.mjs). | 원 서비스의 수집 목적과 최소 수집 판단; ②③ 동의 관련 고지와 서비스 거부 금지; 수집기가 본문을 실제로 지우는지 확인 |
| 3.4.1 개인정보 파기 | ①②③④ | ① 새 이벤트에 적용할 보존기간을 목적·사유와 함께 서명 기록으로 정함. 증거: `POST /api/retention/policy`, `retention_policy`. ② 보존기간이 지난 기록을 보여 주고 hold와 파기 계획을 거쳐 처리(자동 파기는 없음). 증거: `GET /api/retention`, `retention_plan`, `retention_hold`. ③ 이벤트 키 삭제와 조회 사본 제거로 파기하고, 파기 뒤 DB·WAL 잔여를 시험하며, 검증기가 파기한 본문의 공개를 거부. 증거: `retention_disposition`, [`test/erasure-remnants.test.mjs`](../test/erasure-remnants.test.mjs), [`scripts/verify.mjs`](../scripts/verify.mjs). ④ 다른 사람이 승인한 계획만 관리자가 실행하고, 실행 기록에 승인자·실행자·대상 키를 남김. 증거: `POST /api/retention/plans/{id}/execute`, `retention_disposition`. | 법정 보유기간 결정(기본 30일은 공학적 기본값)과 지체 없는 파기의 판단; EvidScope 밖 사본(수집기·백업·SIEM·이전 내보내기)의 파기; 물리 매체 파기는 확인하지 않는다 |

## 정렬하지 않은 항목

74개 항목입니다. 이유별로 묶었습니다.

| 이유 | 설명 | 항목 |
|---|---|---|
| 관리 행위(`management`) | 관리체계의 수립·운영·점검은 조직의 관리 행위다. EvidScope 기록은 입력 자료일 수 있으나 그 행위의 증거가 아니다. | 1.1.1 경영진의 참여, 1.1.2 최고책임자의 지정, 1.1.3 조직 구성, 1.1.4 범위 설정, 1.1.5 정책 수립, 1.1.6 자원 할당, 1.2.2 현황 및 흐름분석, 1.2.3 위험 평가, 1.2.4 보호대책 선정, 1.3.1 보호대책 구현, 1.3.2 보호대책 공유, 1.3.3 운영현황 관리, 1.4.2 관리체계 점검, 1.4.3 관리체계 개선, 2.1.1 정책의 유지관리, 2.1.2 조직의 유지관리 |
| 인적 보안(`people`) | 인적 보안(지정·서약·교육·징계)은 사람과 조직의 일이다. | 2.2.1 주요 직무자 지정 및 관리, 2.2.3 보안 서약, 2.2.4 인식제고 및 교육훈련, 2.2.6 보안 위반 시 조치 |
| 계약(`contract`) | 계약·협정과 계약 변경·종료 절차는 조직 문서로 확인한다. | 2.3.2 외부자 계약 시 보안, 2.3.4 외부자 계약 변경 및 만료 시 보안 |
| 물리·매체(`physical`) | 물리 보호구역·설비·저장매체는 범위 밖이다. | 2.4.1 보호구역 지정, 2.4.2 출입통제, 2.4.3 정보시스템 보호, 2.4.4 보호설비 운영, 2.4.5 보호구역 내 작업, 2.4.6 반출입 기기 통제, 2.4.7 업무환경 보안, 2.9.7 정보자산의 재사용 및 폐기, 2.10.7 보조저장매체 관리 |
| IdP 설정(`identity_provider`) | 비밀번호와 인증수단 규칙은 조직 IdP의 설정이다. EvidScope는 비밀번호를 다루지 않는다. | 2.5.4 비밀번호 관리 |
| 배포 환경(`infrastructure`) | 네트워크·서버·DB·클라우드·단말·패치·악성코드 통제는 배포 환경의 일이다. EvidScope는 그 설정을 기록하지 않는다. | 2.6.1 네트워크 접근, 2.6.2 정보시스템 접근, 2.6.4 데이터베이스 접근, 2.6.5 무선 네트워크 접근, 2.6.6 원격접근 통제, 2.9.6 시간 동기화, 2.10.2 클라우드 보안, 2.10.3 공개서버 보안, 2.10.4 전자거래 및 핀테크 보안, 2.10.5 정보전송 보안, 2.10.6 업무용 단말기기 보안, 2.10.8 패치관리, 2.10.9 악성코드 통제 |
| 조직 시스템 개발(`development`) | 조직 정보시스템의 보안 요구사항·시험·이관 절차다. EvidScope의 출시 검증은 EvidScope 자신에 관한 것이다. | 2.8.1 보안 요구사항 정의, 2.8.2 보안 요구사항 검토 및 시험, 2.8.3 시험과 운영 환경 분리, 2.8.4 시험 데이터 보안, 2.8.6 운영환경 이관 |
| 사고 대응 프로그램(`incident_program`) | 사고 대응 체계·취약점 점검·훈련은 조직 프로그램이다. | 2.11.1 사고 예방 및 대응체계 구축, 2.11.2 취약점 점검 및 조치, 2.11.4 사고 대응 훈련 및 개선 |
| 재해복구(`continuity`) | 재해복구 계획과 시험은 조직의 일이다. vault 백업·복구는 2.9.3에서 다룬다. | 2.12.1 재해ㆍ재난 대비 안전조치, 2.12.2 재해 복구 시험 및 개선 |
| 원 서비스의 개인정보 처리(`privacy_lifecycle`) | 원 서비스의 개인정보 처리 단계 요구사항이다. EvidScope는 원 서비스의 개인정보 처리를 기록하지 않는다. | 3.1.1 개인정보 수집ㆍ이용, 3.1.3 주민등록번호 처리 제한, 3.1.4 민감정보 및 고유식별정보의 처리 제한, 3.1.5 개인정보 간접수집, 3.1.6 영상정보처리기기 설치ㆍ운영, 3.1.7 마케팅 목적의 개인정보 수집ㆍ이용, 3.2.1 개인정보 현황관리, 3.2.2 개인정보 품질보장, 3.2.3 이용자 단말기 접근 보호, 3.2.4 개인정보 목적 외 이용 및 제공, 3.2.5 가명정보 처리, 3.3.1 개인정보 제3자 제공, 3.3.2 개인정보 처리 업무 위탁, 3.3.3 영업의 양도 등에 따른 개인정보 이전, 3.3.4 개인정보 국외이전, 3.4.2 처리목적 달성 후 보유 시 조치 |
| 정보주체 권리(`data_subject`) | 원 서비스의 정보주체 권리보호 요구사항이다. | 3.5.1 개인정보 처리방침 공개, 3.5.2 정보주체 권리보장, 3.5.3 정보주체에 대한 통지 |

일부 항목은 EvidScope 기록과 가까워 보여도 제외한 까닭을 따로 적습니다.

| 항목 | 보충 설명 |
|---|---|
| 1.2.2 현황 및 흐름분석 | 에이전트 관측 흐름과 AI 시스템 사실관계는 흐름도 작성의 입력일 뿐 현황·흐름 문서가 아니다. |
| 1.2.3 위험 평가 | AI 관련 요구사항 평가(/api/governance/assessments)는 위험평가 방법·계획을 대신하지 않는다. |
| 1.4.2 관리체계 점검 | 평가·법률 검토 기록은 1.4.1에서 본다. 독립 점검 인력과 점검 계획은 조직의 일이다. |
| 1.4.3 관리체계 개선 | 재검토 과제(governance_task)는 후속 작업 추적일 뿐 근본 원인 분석이 아니다. |
| 2.1.1 정책의 유지관리 | 보관 문서 기능에 정책 문서를 올리면 해시 이력이 남지만 정책 검토·승인의 증거는 아니다. |
| 2.2.6 보안 위반 시 조치 | 사건 기록은 위반 조사 자료가 될 수 있으나 징계 규정과 조치는 조직의 일이다. |
| 2.6.4 데이터베이스 접근 | EvidScope 자신의 SQLite 파일 접근 통제도 배포 호스트의 일이다. tenant 바인딩 시험은 서명 행 바꿔치기 탐지일 뿐이다. |
| 2.8.2 보안 요구사항 검토 및 시험 | scripts/release-verify.mjs와 check-source는 EvidScope 자신의 시험이다. |
| 2.8.6 운영환경 이관 | 개발 에이전트 실행 기록은 2.8.5에서 본다. 운영 이관 통제는 조직 절차다. |
| 2.9.6 시간 동기화 | EvidScope는 출처가 밝힌 시각 오차로 순서 불확실(CLOCK_ORDER_UNCERTAIN)을 표시할 뿐 시간 동기화를 하거나 점검하지 않는다. |
| 2.9.7 정보자산의 재사용 및 폐기 | 파기 기록은 physicalMediaErasure를 not_verified로 적는다. 매체 재사용·폐기는 확인하지 않는다. |
| 2.10.5 정보전송 보안 | 수집 출처의 HMAC 서명은 메시지 인증이다. 외부 조직과의 전송 정책·협약과 TLS는 조직과 배포 환경의 일이다. |
| 3.2.1 개인정보 현황관리 | EvidScope가 보관하는 이벤트에도 개인정보가 담길 수 있으므로 그 현황은 조직이 따로 관리해야 한다. |
| 3.3.1 개인정보 제3자 제공 | 에이전트의 외부 목적지 관측(2.6.7)은 제3자 제공 여부를 판단하지 않는다. |
| 3.3.4 개인정보 국외이전 | 모델 호출 목적지 관측은 국외이전 검토의 입력일 수 있으나 이전 근거·고지·계약은 조직의 일이다. |
| 3.4.2 처리목적 달성 후 보유 시 조치 | 보존 hold는 파기를 멈추는 기록일 뿐 분리 보관과 그 접근 제한을 다루지 않는다. |

## 내보내기로 항목별 증거 목록 만들기

[`scripts/isms-p-report.mjs`](../scripts/isms-p-report.mjs)는 서명된 내보내기(`GET /api/export`)를 기존 오프라인 검증기와 같은
코드(`verifyBundle`, 선택 시 `replayEvaluations`)로 먼저 검증하고, 정렬한 항목마다 표에 적은 증거 종류가 그 내보내기에 실제로
몇 건, 어느 기간에 있는지 나열합니다. 새 암호 처리는 없습니다.

```bash
node scripts/isms-p-report.mjs export.json trust-anchor.pem [external-checkpoint.json] [--replay] [--markdown]
```

- 검증에 실패하면(서명·해시 체인·체크포인트 불일치, 공개 본문 변조, `--replay`의 재계산 불일치) 보고서를 만들지 않고 종료 코드 1로 끝납니다.
  위트니스 관련 선택지는 `scripts/verify.mjs`와 같습니다(`--witness`, `--quorum`, `--require-transparency` 등).
- 기록(`record`)은 원장 기록 종류별로, 이벤트 종류(`eventKind`)는 공개된 이벤트 본문에서 출처 자격까지 맞는 것만, 발견사항(`finding`)은
  행동별 마지막 서명 평가에서, 측정 종류(`checkType`)는 `governance_check` 이벤트에서 셉니다. 기간은 vault가 서명한 `recordedAt`이고,
  이벤트의 `occurredAt`은 출처가 주장한 시각으로 따로 적습니다.
- API 응답, 저장소 파일, `/api/integrity`의 검사 결과는 내보내기에 들어 있지 않으므로 `not_in_export`로 적습니다. 서명 원장 검사
  (`signed_ledger`)만 이 보고서의 오프라인 검증으로 대신합니다. 0건은 `none_recorded`이며, 통제가 없다는 뜻이 아닙니다.
- 파기한 이벤트는 본문이 없어 종류를 알 수 없으므로 건수만 따로 적습니다.
- JSON(`evidscope-isms-p-evidence-report-v1`)과 한국어 Markdown 모두 첫머리에 **증거가 있다는 것은 기준 충족 판정이 아니다**는
  문구와 `criterionAssessment:"not_performed"`를 담습니다. 외부 체크포인트나 위트니스 없이 검증하면 되돌리기(rollback)를 배제하지
  못했다고 함께 적습니다.
- [`test/isms-p-report.test.mjs`](../test/isms-p-report.test.mjs)는 데모 내보내기로 건수가 원장과 같은지 보고, 기록·공개 본문 변조,
  다른 공개키, 고정 체크포인트보다 짧은 재서명 내보내기를 거부하는지, vault 키로 재서명한 발견사항 변경을 `--replay`가 거부하는지
  확인합니다.

## 표가 출처·코드와 어긋나지 않게 하는 방법

`test/isms-p-alignment.test.mjs`는 전체 시험에 포함되어 다음을 확인합니다.

1. 상태가 `draft_requires_human_review`이고 인증 주장과 판정이 없는지, 세 출처 파일의 SHA-256과 주소가 기록과 같은지 확인합니다.
2. 항목이 101개이고 번호가 겹치지 않으며, 영역별 16·64·21개(주요 확인사항 42·195·91개), 분야 번호가 실제로 있는 분야인지,
   분야 안 번호가 빠짐없이 이어지는지 확인합니다. 항목 목록의 SHA-256도 고정합니다.
3. 모든 항목이 정렬 또는 제외 가운데 정확히 한 곳에만 있는지, 데이터와 이 문서에 나오는 세 자리 항목 번호가 모두 공식 목록에
   있는지 확인합니다.
4. 정렬한 항목이 확인사항 위치를 그 항목의 확인사항 수 안에서 인용하는지, KISA 확인 질문(의문문)을 옮기지 않았는지,
   기준을 충족한다고 말하는 문장이 없는지 확인합니다.
5. 표의 API가 실제 라우터에 있는지 봅니다. 임시 vault를 관리자 계정으로 호출해, 없는 경로가 받는 마지막 404
   (`지원하지 않는 경로 또는 메서드`)가 나오지 않아야 합니다. OIDC 전용 API는 OIDC 설정에서만 처리되는지 따로 봅니다.
6. 기록 종류(서명 객체이거나 원장에 append되는 종류), 서명 평가에서 나오는 발견사항 코드, 출처별 이벤트 허용 규칙(허용 출처는 통과하고
   나머지 출처는 모두 403), 한국법 측정 종류와 `authorityOnly`, `/api/integrity` 검사 이름, 파일 경로가 실제로 있는지 확인합니다.
7. 이 문서가 데이터와 같은 상태·확인일·출처 해시를 적고, 정렬한 항목과 제외한 항목을 모두 싣는지 확인합니다.

기능 이름을 바꾸거나 지우면 이 시험이 실패하므로, 표를 함께 고치거나 해당 증거를 빼야 합니다.

## 한계와 다음 단계

- 사람이 검토해야 합니다. 특히 어떤 확인사항에 어떤 증거가 닿는지는 이 저장소의 판단이며, 인증심사원이나 법률 전문가의 검토를
  거치지 않았습니다.
- 주요 확인사항은 KISA 해설 자료(2023)에서 읽었습니다. 고시가 바뀌거나 KISA가 새 안내서를 내면 출처를 다시 읽고 시험의 고정값을
  바꿔야 합니다. 2024-07-24 개정은 위에서 본 대로 [별표 7]을 바꾸지 않은 것으로 보입니다.
- EvidScope가 기록하는 것은 등록된 출처가 보낸 최소 메타데이터입니다. 서명은 vault가 받은 기록을 인증할 뿐 출처 주장의 진실을
  보증하지 않으며, 외부 체크포인트나 위트니스가 없으면 서명 키를 가진 호스트 공격자의 되돌리기를 배제하지 못합니다.
- 인증 대상 조직의 정책·절차·운영 증적과 심사 대응은 EvidScope가 대신하지 않습니다. EvidScope를 배포한 호스트·DB·네트워크의
  통제도 배포 조직의 몫입니다.
- ISMS-P 누리집에는 AI 서비스 기업을 위한 관리체계 고려사항 카드뉴스(2025-07-08 게시)가 있습니다. 제목만 확인했고 이 표의
  근거로 쓰지 않았습니다.
- AI 기본법 하위 고시의 확인 상태는 [법령 확인 범위](legal-sources.md)를 보세요.
