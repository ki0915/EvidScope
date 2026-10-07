# ISMS-P 인증기준 참고 정렬

> 2026-10-07 개선 2라운드에서 추가한 참고 자료입니다. 인증 심사·판정이나 법률 의견이 아니며 상태는 `draft_requires_human_review`입니다.
> 원본 데이터는 [`data/isms-p-alignment.json`](../data/isms-p-alignment.json)이고, 표가 코드와 어긋나지 않는지는
> [`test/isms-p-alignment.test.mjs`](../test/isms-p-alignment.test.mjs)가 확인합니다.

## 무엇을 위한 표인가

EvidScope는 ISMS-P 인증을 받는 관리체계가 아니라, 인증 범위에 AI 에이전트를 둔 조직이 일부 통제를 보일 때 꺼낼 수 있는
**증거의 출처**입니다. 이 표는 인증기준의 분야마다 EvidScope의 기록·API·검증 결과 중 무엇을 참고 증거로 쓸 수 있는지,
무엇이 여전히 사람과 조직의 일인지 나눕니다.

- 인증 여부, 결함 여부, 기준 충족 여부를 판정하지 않습니다(`certificationClaim:false`).
- 인증기준 문구를 옮기지 않고 번호와 짧은 명칭만 씁니다. 기준의 내용은 아래 공식 안내서를 직접 읽어야 합니다.
- 증거가 있다는 것이 그 분야의 통제가 **충분하다**는 뜻은 아닙니다. 심사에서 보는 정책·절차·운영 기록은 조직이 따로 갖춥니다.

## 출처와 확인 수준

| 항목 | 내용 |
|---|---|
| 기준 | 정보보호 및 개인정보보호 관리체계(ISMS-P) 인증기준 101개: 관리체계 수립 및 운영 16, 보호대책 요구사항 64, 개인정보 처리단계 요구사항 21 |
| 현행판 판단 | ISMS-P 인증기준 안내서(2023.11), 2023-11-23 수정게시. 세부점검항목 공지 2023-10-31 |
| 근거 법령(누리집 기재) | 「정보보호 및 개인정보보호 관리체계 인증 등에 관한 고시」, 정보통신망법 제47조·시행령 제47조~제54조·시행규칙 제3조, 개인정보 보호법 제32조의2·시행령 제34조의2~제34조의8 |
| 읽은 곳 | KISA ISMS-P 누리집의 [인증기준 소개](https://isms-p.or.kr/sysm/intro/selectSysmCertDetail.do)와 [자료실 목록](https://isms-p.or.kr/ntcn/rcsrm/selectGnrlRcsrmList.do), 2026-10-07 |
| 확인 수준 | 영역·분야 번호와 명칭, 영역별 기준 수(`verifiedLevel:"area_and_domain_titles_and_counts"`) |

확인하지 못한 것도 그대로 적습니다.

1. **항목 수준(분야 아래 세 번째 자리 번호)은 대조하지 않았습니다.** 자료실 게시물 본문이 스크립트 POST로만 열려 안내서 파일을
   받지 못했습니다. 그래서 표는 분야 단위로만 정렬하고, 시험은 확인하지 않은 항목 번호가 데이터에 들어오는 것을 막습니다.
2. **원본 파일의 SHA-256이 없습니다.** 누리집 화면을 작업 환경의 텍스트 변환 도구로 읽었고 파일 바이트를 받지 못했습니다
   (`sourceSha256:"not_captured"`).
3. **2023.11판이 현행이라는 판단**은 자료실 목록(2026-05-12 게시물까지)에 더 새로운 인증기준 안내서가 없다는 데 근거합니다.
   인증 고시 원문(국가법령정보센터 행정규칙)은 이 작업 환경에서 열리지 않아 대조하지 못했습니다.
4. KISA 대표 누리집(`www.kisa.or.kr`)은 인증서 검증 실패로, `isms.kisa.or.kr`는 이름 해석 실패로 열리지 않았습니다. 검색 결과에
   나온 공공데이터포털의 안내서·세부점검항목 데이터셋(15105394, 15106188) 페이지도 열지 못했습니다.

## 분야별 정렬

괄호 안은 API·기록·발견사항·시험 파일 이름입니다. `{id}`는 경로의 식별자 자리입니다.

| 분야 | EvidScope 증거·통제 | 사람·조직이 할 일 |
|---|---|---|
| 1.2 위험 관리 | 관측 에이전트와 귀속 불명 행동(`GET /api/agents`), 자산·허용 목적지·정책 버전 등록(`POST /api/assets`), OTLP 모델 호출·목적지(`GET /api/ai-visibility`), AI 시스템 사실관계(`POST /api/governance/systems`), 발견사항 `UNREGISTERED_ASSET`·`DESTINATION_OUTSIDE_POLICY` | 위험 평가 방법·위험 수용·자산 중요도 결정. 목록에 없다는 것이 존재하지 않는다는 뜻은 아닙니다 |
| 1.4 관리체계 점검 및 개선 | 법률 출처 확인 범위(`GET /api/governance`의 `legalSourceCoverage`, `wholeLawComplete:false`), 평가와 작성자 아닌 검토자의 법률 검토 확인(`governance_legal_review`), 재검토 과제(`GET /api/governance/report`, `POST /api/governance/tasks/{id}`), [법령 확인 범위](legal-sources.md) | 법률 적용성·충분성 판단, 내부 감사와 경영진 검토 |
| 2.2 인적 보안 | 직무 분리: 예외·룰·파기 계획의 자기 승인 거부, 사건을 열거나 다시 연 사람의 종결 거부(`test/four-eyes.test.mjs`) | 서약·교육·퇴직 관리, 역할 배정과 겸직 검토 |
| 2.3 외부자 보안 | 공급사 묶음(`supplier_bundle`, 문서 해시 목록과 대상·범위의 contentHash)과 출처 검토(`supplier_provenance_review`), 묶음 내보내기, authority 출처 전용 측정 `supplier_risk_reliance`, [공급사 조치 활용](kr-supplier-reliance.md) | 계약의 보안 요구사항과 위탁 관계, 외부자 점검과 계약 종료 시 회수, 공급사 자료 내용의 진실성 |
| 2.5 인증 및 권한관리 | 출처 HMAC·시각·nonce 검사(`POST /api/ingest`), `human_approval`은 `authority` 출처만(에이전트·도구·OTLP 거부), OIDC 모드의 접근 중지·세션 회수(`GET /api/access`, `POST /api/access/subjects/{id}`, `identity_access`, `identity_session`), [OIDC 안내](oidc-authentication.md) | IdP 계정 생명주기·다중 인증, 정기 권한 검토와 특수 권한 승인, bearer 토큰 계정의 발급·회수 |
| 2.6 접근통제 | 역할별 API 권한과 tenant 경계(`test/governance-authorization.test.mjs`, `test/store-tenant-binding.test.mjs`), 감사자·관리자만 보는 조회 기록(`GET /api/audit/reads`) | 네트워크·DB·서버·원격 접근 통제, 인터넷 접속 통제 |
| 2.7 암호화 적용 | 서명키와 데이터 암호화 키 분리(`GET /api/integrity`의 `keySeparation`), 키 생성·식별·재암호화(`scripts/data-key.mjs`), [키 분리 안내](data-key-separation.md) | 암호 정책과 키 관리 책임자, HSM·KMS 연동(미지원), 키 백업 보관 |
| 2.8 정보시스템 도입 및 개발보안 | 탐지 룰 버전과 시험 후 승인(`POST /api/rules`, `POST /api/rules/{id}/test`), 개발 에이전트 실행 기록(`POST /api/development-runs/events`, `development_run_event`), 출시 전 반복 시험(`scripts/release-verify.mjs`), 소스 검사(`scripts/check-source.mjs`) | 조직 시스템의 보안 요구사항·코드 검토·시험과 운영 분리, 운영 이관 승인 |
| 2.9 시스템 및 서비스 운영관리 | 서명 원장 내보내기(`GET /api/export`)와 오프라인 검증(`scripts/verify.mjs`, `--replay`), `/api/integrity`의 `signed_ledger`·`access_log` 검사, 조회 기록 봉인(`audit_access_batch`, `GET /api/audit/reads/proof`), [위트니스 체크포인트](transparency-log.md), 수신 집계(`GET /api/monitoring`), OCSF 내보내기(`GET /api/export/ocsf`), 발견사항 `CLOCK_ORDER_UNCERTAIN`·`COLLECTION_GAP`, 백업(`scripts/vault-backup.mjs`), 문서 원본 복구 | 법정 접속기록 보관기간·점검 주기·결과 보고, 호스트 시간 동기화, EvidScope로 보내지 않은 시스템 자체의 접속기록 |
| 2.11 사고 예방 및 대응 | 경보(`GET /api/alerts`)와 조사(`GET /api/investigations`), 사건과 사람 판단(`POST /api/cases`, `POST /api/cases/{id}/decisions`), 서명 사건 보고서(`GET /api/cases/{id}/report`, `scripts/verify-case-report.mjs`), `stop_confirmed`는 `safety` 출처만, 발견사항 `STOP_UNCONFIRMED`·`EXECUTION_AFTER_STOP_REQUEST`·`LOG_INJECTION_SIGNAL`, 무결성 실패 기록(`integrity_failure`), 오프라인 재계산(`scripts/replay-findings.mjs`) | 침해사고 신고와 법정 기한, 대응 조직·훈련·외부 공조, 실제 차단 효력 확인 |
| 2.12 재해복구 | vault 백업·복구(`scripts/vault-backup.mjs`, `recovery_restore`), [복구 절차](vault-recovery.md), 복구 시험(`test/vault-recovery.test.mjs`) | 재해복구 계획·목표 복구 시간·원격지 보관, 정기 복구 훈련 |
| 3.1 개인정보 수집 시 보호 조치 | 증거 계층 자신의 최소 수집: 허용 필드 밖 값과 예약 필드 거부(`POST /api/ingest`), 참고 데이터는 참조 메타데이터만, 원문 필드 거부 시험(`test/integration.test.mjs`) | 원 서비스의 수집 근거·동의·고지, 수집기가 실제로 본문을 지우는지 확인 |
| 3.4 개인정보 파기 시 보호조치 | 보존기간·hold·파기 계획(`/api/retention`), 작성자 아닌 승인 뒤 관리자 실행(`POST /api/retention/plans/{id}/execute`), 파기 기록(`retention_disposition`), 파기 후 잔여 데이터 시험(`test/erasure-remnants.test.mjs`) | 법정 보존기간 결정(기본 30일은 공학적 기본값), 수집기·백업·SIEM 등 EvidScope 밖 사본의 파기, 파기 결과 확인 |

## 정렬하지 않은 분야

| 분야 | 이유 |
|---|---|
| 1.1 관리체계 기반 마련 | 경영진 참여·책임자 지정·조직·범위·정책 수립은 조직의 관리 행위입니다. |
| 1.3 관리체계 운영 | 보호대책 구현·공유·운영현황 관리는 조직 절차입니다. EvidScope 기록은 입력 자료일 뿐입니다. |
| 2.1 정책, 조직, 자산관리 | 정책·조직 문서와 전체 정보자산 관리는 조직 산출물입니다. AI 자산 목록은 1.2의 증거를 봅니다. |
| 2.4 물리 보안 | 범위 밖입니다. |
| 2.10 시스템 및 서비스 보안관리 | 보안시스템·패치·악성코드·단말 관리는 배포 환경의 책임입니다. OCSF 내보내기는 SIEM 연동일 뿐입니다. |
| 3.2 개인정보 보유 및 이용 시 보호조치 | 원 서비스의 개인정보 보유·이용 단계 요구사항입니다. |
| 3.3 개인정보 제공 시 보호조치 | 원 서비스의 개인정보 제공 단계 요구사항입니다. |
| 3.5 정보주체 권리보호 | 원 서비스의 정보주체 권리보호 요구사항입니다. |

## 표가 코드와 어긋나지 않게 하는 방법

`test/isms-p-alignment.test.mjs`는 전체 시험에 포함되어 다음을 확인합니다.

1. 21개 분야가 정렬 또는 제외 사유 중 정확히 한 곳에만 있고, 영역별 기준 수가 16·64·21(합계 101)인지 확인합니다.
2. 표의 API가 실제 라우터에 있는지 봅니다. 임시 vault를 관리자 계정으로 호출해, 없는 경로가 받는 마지막 404
   (`지원하지 않는 경로 또는 메서드`)가 나오지 않아야 합니다. 대조용 가짜 경로는 반드시 그 404를 받습니다. OIDC 전용 API는
   기본 모드에서는 404이고 OIDC 설정에서만 처리되는지 따로 봅니다. `field`가 적힌 API는 응답에 그 항목이 있어야 합니다.
3. 기록 종류(서명 객체이거나 원장에 append되는 종류), 발견사항 코드, 출처별 이벤트 허용 규칙(허용 출처는 통과하고 거부 출처는
   403), 한국법 측정 종류와 `authorityOnly`, `/api/integrity` 검사 이름, 파일 경로가 실제로 있는지 확인합니다.
4. 상태가 `draft_requires_human_review`이고 인증 주장이 없으며, 확인하지 않은 항목 번호(세 자리)가 들어가지 않았는지 확인합니다.
5. 이 문서가 데이터와 같은 상태·확인일·안내서판·분야를 적는지 확인합니다.

기능 이름을 바꾸거나 지우면 이 시험이 실패하므로, 표를 함께 고치거나 해당 증거를 빼야 합니다.

## 한계와 다음 단계

- 분야 단위 정렬이라 개별 인증기준 항목의 충족 범위를 말하지 않습니다. 공식 안내서(2023.11) 파일을 직접 받아 SHA-256을 기록한
  뒤 항목 단위로 다시 정렬하고, 사람이 검토해야 합니다.
- 인증 대상 조직의 정책·절차·운영 증적과 심사 대응은 EvidScope가 대신하지 않습니다. EvidScope를 배포한 호스트·DB·네트워크의
  통제도 배포 조직의 몫입니다.
- ISMS-P 누리집에는 AI 서비스 기업을 위한 관리체계 고려사항 카드뉴스(2025-07-08 게시)가 있습니다. 제목만 확인했고 이 표의
  근거로 쓰지 않았습니다.
- AI 기본법 하위 고시의 확인 상태는 [법령 확인 범위](legal-sources.md)를 보세요.
