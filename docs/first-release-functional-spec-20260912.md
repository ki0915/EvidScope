# EvidScope 1차 기능 명세서

작성일: 2026-09-12 · 상태: 코드 1차 구현, 실제 모델 실행과 운영 승격 대기

## 사용자와 권한

| 사용자 | 읽기 | 변경 |
|---|---|---|
| 감사자 | 현황, 자산, 증거, 조사, 거버넌스, AI 초안 | 사건 의견·사람 판단 |
| 검토자 | 감사자 범위 | 자산·룰·평가·보존 계획·AI profile |
| 관리자 | 전체 감사 화면 | 분리 승인이 필요한 작업, 명시적 보존 실행 |
| 수집 출처 | 없음 | 자신의 서명 이벤트만 제출 |
| 분석 worker | 내부 claim/result | 인간 API 접근 불가 |
| 모델 Pod | 선택된 고정 증거 묶음 | 한 번의 advisory JSON 반환만 가능 |

## 화면 구조

1. **현황**: 수집 건수, 미관측·검사 미완료, 조사 대기, 연결 상태를 본다.
2. **AI 자산·수집**: 등록 여부, 소유자, 공급자·모델, 수집기, 본문 관측 범위, 언어 신호와 근거를 확인한다.
3. **탐색·조사**: 이벤트·경보·행동·사건을 검색하고 출처→행동→결과→사람 검토를 대조한다.
4. **거버넌스**: 시스템 사실, KR/EU/NIST/ISO 요구사항, 부족한 사실, 증거와 재검토 과제를 관리한다.
5. **AI 검토실**: 최대 3개 요구사항과 선택 증거의 전체 frozen package를 확인하고 AI 초안·사람 수정본·이력을 구분한다.
6. **운영·설정**: 룰·예외·보존과 모델/학습의 기본 OFF, 현재 관측, 종료 확인, 데이터 준비 상태를 본다.

Datadog의 필터·행 선택 상세와 Grafana의 시간 범위·drilldown 방식을 참고했다. 모든 상태는 색 외에 글자로 표시하고, 빈 결과·미수집·오류·stale을 서로 다르게 보여준다.

## 기능 요구사항

| ID | 요구사항 | 완료 증거 |
|---|---|---|
| F-01 | SDK/local/HTTP/OTLP/Zeek AI 관측을 엄격한 v2 스키마로 수집 | `src/ai-observations.mjs`, adapter 시험 |
| F-02 | 원문 prompt/response·자격·HTTP body를 중앙에 저장하지 않음 | 허용 목록, canary 통합 시험 |
| F-03 | 명시적으로 켠 수집 지점에서만 CipherGuard 일시 검사 | `content-screening.mjs`, 기본 off와 실패 상태 시험 |
| F-04 | 본문 관측/미관측, 검사 완료/미완료, 한글/라틴/혼합/미확인을 집계 | `/api/ai-visibility`, UI 상태 시험 |
| F-05 | 미등록, 목적지 범위, DLP, injection, 권한, 수집 공백, 증거 충돌, 중단 미확인 신호 제공 | 조사 finding과 evidenceRefs |
| F-06 | 현재 기간 호출 급증과 새 모델 관측을 제한된 후보 신호로 표시 | `ai-visibility.mjs`, 미확정 문구 |
| F-07 | AI 기본법·EU AI Act·NIST·ISO 준비 요구를 출처·버전·증거와 연결 | 27개 catalog, 적용성 정책 시험 |
| F-08 | 적용성·준수·법적 판단과 AI 초안을 사람이 승인 | `human_review_required`, advisory boundary |
| F-09 | 감사 모델은 독립 Pod·mTLS·고정 내부 주소·무도구·무업무파일로 실행 | 배포 템플릿, 클라이언트·수명주기 시험 |
| F-10 | 모델은 기본 OFF이고 오류·취소·완료·timeout 뒤 종료를 확인 | UID delete, orphan reconcile, STOP_UNCONFIRMED 시험 |
| F-11 | 학습 자료의 검토·분할·hash·동의·PII 확인을 강제 | admission/import 시험 |
| F-12 | 사용자 PC가 유휴하고 자원이 충분할 때만 학습 후보 시작 | 호스트 영수증과 resource guard 시험 |
| F-13 | 사람이 PC를 다시 쓰면 학습을 멈추고 종료를 확인 | idle guard 중단·미확인 실패 시험 |
| F-14 | 6개 주 메뉴와 기존 기능 목적지를 유지 | DOM/UI 회귀 시험 |

## 주요 API

| API | 반환/동작 |
|---|---|
| `POST /api/ingest` | HMAC·시각·nonce를 검증하고 최소 이벤트를 durable commit |
| `GET /api/ai-visibility?range=1h|24h|7d&q=&assetRef=` | 자산, 관측 범위, 검사·언어 집계, 조사 신호, 모델 상태 |
| `GET/POST /api/assets` | 관리 AI 자산과 당시 정책 범위 |
| `GET/POST /api/governance/systems` | tri-state 시스템 사실과 역할·시장·버전 |
| `GET /api/governance/report?systemId=` | 요구사항별 적용성 후보, 부족한 사실, 증거·법률 검토 상태 |
| `GET /api/assistance/requirements` | AI 검토에 선택 가능한 요구사항, 최대 3개 |
| `POST /api/assistance/packages` | 선택 증거·질문·요구사항을 고정하고 hash 서명 |
| `POST /api/assistance/packages/:id/dispatch` | 6분 만료 단일 실행 자격 발급 |
| `GET /api/model-runtime` | 기본 정책과 30초 이내 Kubernetes 관측 상태; 없으면 unavailable |

## 데이터와 상태 규칙

- source와 tenant는 payload가 아니라 인증 자격에서 결정한다.
- 수집 실패에도 `unobserved` 또는 `COLLECTION_GAP` 최소 이벤트를 남기며 성공으로 바꾸지 않는다.
- `contentObserved=0`은 안전 또는 AI 미사용을 뜻하지 않는다.
- `DLP_SENSITIVE_CONTENT`는 분류기 신호이며 실제 외부 유출 확정이 아니다.
- `STOP_UNCONFIRMED`는 종료 증거 부족이며 실행 중이라고 단정하지 않는다.
- 법률 catalog 변경, 시스템 사실 변경, 새 증거, 검토 기한 만료는 기존 판단을 stale로 만든다.
- 합성·미검토 자료는 모델 품질이나 법률 준수 근거가 아니다.

## 학습 시작 조건

다음 조건을 모두 만족하지 않으면 Job을 만들지 않는다.

1. 사용자가 모델을 선택하고 artifact revision·hash·license를 승인했다.
2. 학습 300, 검증 50, 시험 100개 이상의 사람이 검토한 자료가 admission을 통과했다.
3. base와 training image가 digest로 고정됐다.
4. 실제 CNI 격리와 파일 미접근, mTLS, 프로세스 종료 probe가 통과했다.
5. 동일 공유 Lease에 추론/학습 작업이 없다.
6. 5초 이내 호스트 영수증이 유휴·자원 조건을 충족한다.
7. `--execute-isolated-model`과 같은 명시적 실행 의사가 전달됐다.

같은 GPU를 쓰는 동안 다른 화면 앱에 영향이 전혀 없다는 보장은 승인 기준으로 삼을 수 없다. 해당 보장이 필요하면 `dedicated_host_required`로 차단하고 별도 PC/GPU에서 실행한다.

## 1차 범위 밖

- 암호화된 네트워크 본문 복호화, 미계측 단말의 완전 탐지
- 자동 차단, 자동 사건 종결, 자동 법률 적용·준수 인증
- CipherGuard를 이용한 위치별 마스킹·전문 번역
- 운영용 SSO/SIEM vendor connector의 모든 제품 지원
- 실제 모델 성능·VRAM·CNI 검증이 끝나기 전의 운영 배포
