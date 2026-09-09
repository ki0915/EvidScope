# 수집·감사 계약 v1

## 서명 수집

`POST /api/ingest` (수집 gateway 기본 `http://127.0.0.1:8081`). JSON UTF-8, 최대 16 KiB. 외부 운영 전송은 TLS 필수. Bearer token과 별도 HMAC secret은 source별 발급된 개발 자격이다. source 등록/회전은 현재 vault config 교체·재시작 운영 절차이며 제품에서 업무 AI 권한을 발급하지 않는다.

헤더:

```
Authorization: Bearer <source-token>
Content-Type: application/json
X-Evid-Timestamp: <Unix milliseconds, 13 digits>
X-Evid-Nonce: <fresh UUID>
X-Evid-Signature: <HMAC-SHA256 hex>
```

서명 입력은 UTF-8 `${timestamp}.${nonce}.${exactBody}`. 수신 시각 차이 ±5분, nonce는 10분 보존. 재시도마다 nonce/서명을 갱신하고 이벤트 내용/ID는 유지한다. 출처별 rate quota는 현재 미지원이며 gateway 동시성 100, body 16 KiB, request timeout 10초, 분석 적체 10,000 action backpressure를 둔다. 429는 아직 사용하지 않는다.

```json
{
  "id": "event-1", "kind": "intent", "occurredAt": "2026-09-08T00:00:00.000Z",
  "traceId": "trace-1", "actionId": "action-1",
  "actor": "support-agent", "model": "synthetic-v1", "tool": "customer-api",
  "action": "write", "resource": "case-42", "destination": "internal.example",
  "policyVersion": "auth-v1", "dataCategories": ["synthetic"], "note": "합성 메타데이터"
}
```

필수: id/kind/occurredAt/traceId/actionId. 일반 문자열 256자, note 1,024자. 식별자는 영숫자 `._:@/-`, 최대 120자. optional: parentActionId, actor/model/tool/action/resource/destination/status, dataCategories(16개), policyVersion, validFrom/validUntil, scope, authorityId, reviewer, targetVersion, note, purpose. 알 수 없는 필드는 거부한다. source/tenant/sourceKind/assurance/receivedAt/hash는 서버가 결정하며 제출자가 보내면 거부한다.

`dataRefs`는 최대16개 참조 배열이다. 각 항목은 `{id,kind,version,hash,role,locator?,description?}`. kind=document/dataset/record/retrieval/artifact, role=input/retrieved/output, hash는 SHA-256 hex 또는 not_provided다. 자료 본문·prompt·secret·verification 필드는 받지 않는다. locator는 자동 조회하지 않는다. `/api/actions/:id`는 참조마다 source/eventId/assurance/observedAt/verification을 서버에서 붙이고, 수신 업무 이벤트 중 참조가 있는 건수와 제한된 분모를 표시한다. 전체 모델 지식/자료의 coverage 비율이 아니다.

| 인증 sourceKind | 제출할 수 있는 kind |
|---|---|
| agent | intent, self_report, delegation |
| tool | execution, result |
| authority | grant, revoke, human_approval, automated_review |
| safety | stop_requested, block_registered, stop_confirmed, safety_alert |
| telemetry | heartbeat, gap, notice |

grant/human_approval/automated_review는 당시 policyVersion, validFrom/validUntil, scope 필요. human_approval은 외부 reviewer 참조 필요. scope 허용 키는 actor/tool/action/resource/destination/parentActionId. matched 판정을 위해 actor/tool/action/resource와 실행 정책 버전이 일치해야 하며 권한 발급이 실행보다 늦을 수 없다. revoke는 같은 authority source의 grant id를 authorityId로 참조한다. parent 관계 자체로 권한을 상속하지 않는다.

202 응답은 최소 접수 정보 `{accepted,duplicate,durability:'sqlite_full_commit',analysis:'asynchronous',externalSeal:false}`뿐이다. 원본 ID·hash·검색 결과를 source에 반환하지 않는다. HMAC 실패/시각 오류 401, 자격 유형 위반 403, 형식 400, replay/ID collision 409, body 초과 413, 저장·upstream 장애/적체 503. 접수 성공과 외부 봉인·분석 완료는 다르다. timeout은 재전송해 중복 상태를 확인한다.

`src/client.mjs`의 `Observer.observe(event)`는 메모리 큐에 넣고 즉시 반환한다. capacity 초과/유한 재시도 실패는 dropped로 기록한다. 프로세스 crash 시 이 메모리 큐는 유실될 수 있으며 지속성으로 부르지 않는다. source의 metrics를 조직 수집 건강에 별도 전달해야 한다. SDK는 업무 도구 실행을 감싸거나 차단하지 않는다.

## 인간 API

인간 Bearer token으로 감사 gateway `8082`를 사용한다. tenant query parameter로 tenant를 바꿀 수 없다. 모든 GET API는 같은 tenant 접근 감사에 남는다. 모든 변경은 원장 snapshot을 추가한다. POST는 JSON이며 error 형식은 `{error: string}`이다.

| 경로 | 의미 |
|---|---|
| GET /api/overview | 수집 건강·사건·backlog·한계 |
| GET /api/events?q=&traceId=&kind=&limit=100&offset=0 | 문자열 검색·필터·최대 500건 반환 |
| GET /api/actions/:actionId | 이벤트 및 최신순 평가 이력 |
| GET /api/agents?range=7d&focus=all&sort=attention | 기간별 에이전트 현황; 상세 id, 종료 end, 검색 q, limit/offset 지원. [산정 기준](agent-policy-metrics.md) |
| GET /api/monitoring?range=1h | 수신 시각 기반 운영 시계열; range=10m/1h/24h/7d, 선택적 source |
| GET /api/alerts | 최신 평가의 경보, 예외 억제 상태 |
| GET/POST /api/assets | 자산 등록·소유자·목적·버전·허용 목적지 |
| GET/POST /api/cases | 사건 목록/생성 |
| POST /api/cases/:id | owner, comment, status, reason, task 변경; closed는 reason 필수 |
| GET/POST /api/rules | 룰 버전 목록/초안 |
| POST /api/rules/:id/test | {version}; 최대 최근 1,000건 시험 |
| POST /api/rules/:id/approve | {version}; 시험 후 다른 검토자 승인 |
| GET/POST /api/exceptions | ruleId,actionId,reason,owner,expiresAt(90일 이내) |
| POST /api/exceptions/:id/approve | 작성자/소유자와 다른 검토자 |
| GET /api/export, /api/integrity | 독립 export·해시체인 검사 |
| POST /api/rebuild | admin 전용 원장 기반 검색 사본 재생성 |
| GET /api/metrics | tenant 접수·분석·backlog와 vault RSS |
| GET /api/governance | 요구사항·시스템·평가·보완과제 |
| POST /api/governance/systems | 사실관계 및 별도 한국/EU 분류 입력 |
| POST /api/governance/assessments | 출처 snapshot·통제·증거·인간 평가·기한 |
| GET /api/governance/report?systemId= | 적용성 초안·미충족·검토 상태·과제 |
| POST /api/governance/tasks/:id | status,reason; 조치/재검토 기록 |
| GET /api/retention | 보존 정책·대상·hold·파기계획·한계 |
| POST /api/retention/policy | retentionSeconds,purpose,reason,legalReview; 새 이벤트에만 적용 |
| POST /api/retention/holds | scope(tenant 또는 actionId),reason |
| POST /api/retention/holds/:id/release | reason; 다른 검토자 해제 |
| POST /api/retention/plans | reason; 만료·hold·사건 확인한 최대1,000건 구체 계획 |
| POST /api/retention/plans/:id/approve | reason; 작성자와 다른 검토자 |
| POST /api/retention/plans/:id/execute | admin, 승인 후 상태 재확인; live key/검색 사본 파기 |

내부 worker 계약은 `/internal/claim` 및 `/internal/complete`다. 일반 source/감사자에 허용하지 않는다. claim 최대5작업/10MiB, lease30초, commit 최대1MiB. worker가 분석해 `{leaseId,result}`를 제출하며 임의 tenant/action/타인의 증거 참조는 거부한다. 예전 `/internal/analyze`는410을 반환한다. 분석 한도 초과는 명시적 격리이며 분석완료로 집계하지 않는다.

증거 ref는 `event`: `sourceId/eventId` (동일 tenant에 실제 존재 검증), document/test/attestation: 인간이 제공한 참조·버전·내용 hash(선택)다. 후자 URL은 다운로드하지 않는다. 보고서는 과거 요구/시스템 hash 및 재검토일을 비교하여 stale 평가를 다시 검토 대상으로 표시한다. 전체 법률 자동 적용 엔진이나 외부 문서 검증 엔진이라고 주장하지 않는다.

외부 공급자 계약은 아직 이 중립 스키마로 변환하는 합성 adapter뿐이다. 미공개 API·내부 사고과정·비공개 모니터 점수를 추측하거나 수집하지 않는다.

## 행동 조사함·인간 판단·서명 사건 보고서

아래 경로는 auditor/reviewer/admin에만 허용되며 source는 제출 외 접근할 수 없다.

| API | 계약 |
|---|---|
| GET /api/investigations | q, state=all\|needs_review\|reviewed, limit=1..100, offset. 행동별 관측·참조·분석·인간 검토 상태와 집계. 집계는 검색어 적용 후 상태 필터 적용 전이며 전체 조직 사용률이 아니다. |
| GET /api/cases/:id/review-context | 서명 원장과 사본을 대조한 case/events/references/evaluations/analysis/contextHash/decisions/latestDecision/reviewState |
| POST /api/cases/:id/decisions | contextHash, conclusion=confirmed_issue\|no_issue_found\|inconclusive, reason, scope, limitations, nextReviewAt, evidence[{ref,supports: supports\|contradicts\|context,note}]. 필수 문구 공백 거부, 미래 재검토 시각, 근거 최대30개·중복 금지·같은 행동/tenant 실존 검증. 유보 외에는 최소1개 근거. 알 수 없는 필드·작성자/시각 위조는400, 변경된 문맥은409. |
| GET /api/cases/:id/report | evidscope-case-report-v1. snapshot+signature+publicKeyFingerprint. 이벤트·사건·평가·인간 판단 사본을 서명 원본과 대조한 뒤 발급. |

decision은 서버 작성자/시각, 당시 전체 evidenceManifest(ref/hash/seq), evaluationManifest(id/version), analysisVersion 및 checkpoint를 자동 추가한다. 판단 수정 API는 없다. 검토 상태는 unreviewed/reviewed/inconclusive/stale이며 근거·분석 변경, 정당한 원문 파기, 재검토 기한 도래를 반영한다. 근거 변경 보호는 동시 검토자 예약 잠금이나 정족수 승인과 다르다.

보고서는 canonical({format,snapshot})의 Ed25519 base64 서명이다. fingerprint는 공개키 DER SPKI의 SHA-256 hex다. 별도 배포된 신뢰키를 사용하는 `scripts/verify-case-report.mjs`로 검증하며 전체 체인 포함 증명·출처 진실성·외부 시각 봉인·법적 준수로 확대 해석하지 않는다. Markdown은 같은 snapshot의 비서명 읽기용 표현이다.

사건 문맥의 한도: 이벤트1,000개, 평가100개, 판단200개, 합계8MiB, 원장 단일행2MiB. 보고서10MiB. 한도 초과413은 부분 결과를 성공으로 반환하지 않는다. 조사함은 한도 초과 행동을 상세 제한으로 표시한다. `/api/actions/:id`에도 analysis.version/analyzed/pending을 제공한다. 분석 effect는 mixed_results를 지원하며 서비스 성공과 실패가 함께 있으면 성공으로 축약하지 않는다.

## Kubernetes 준비 상태와 분산 진단

모든 컴포넌트의 GET `/healthz`는 로컬 생존 상태를, GET `/readyz`는 준비 상태를 반환한다. vault는 SQL 접근, ingress/audit는 검증된 TLS로 vault의 health를 확인, worker는 최근30초 내 성공한 처리 루프를 확인한다. 실패/종료 중은503, 준비 상태는200이다. 반환은 component와status뿐이며 자격을 노출하지 않는다. gateway 검사는1.5초 한도·500ms 캐시·동시 요청 합치기를 사용한다.

POD_NAME 환경 값이 있으면 서버가 안전하게 정제한 x-evidscope-instance 헤더를 자체 응답에 넣는다. 이는 비밀이나 서명 증거가 아닌 분산 진단 메타데이터이며 실제 Kubernetes Pod UID/EndpointSlice와 별도로 대조한다. 헬스 경로가 업무 source에 원본 조회·수정 권한을 부여하지 않는다.
