# 사람 승인 대기열 가이드

> 2026-10-07 개선 3라운드(R3-H)에서 추가한 기능입니다. 레지스트리와 정책 결정 수집은 [에이전트 레지스트리](agent-registry.md),
> 증거 계층 전체 구조는 [증거 계층 아키텍처](evidence-layer.md)를 보세요.

## 무엇을 하고 무엇을 하지 않는가

지금까지 EvidScope는 `require_approval` 결정을 **사후에 대조**만 했습니다. 정책 엔진이 승인을 요구했는데 사람 승인 증거(`human_approval`)
없이 실행되었으면 `REQUIRED_APPROVAL_MISSING`을 냈지만, 승인 자체는 밖(Slack, 티켓, 게이트웨이 화면)에서 이뤄졌고 누가 답할 수 있었는지,
그 답이 어느 대상에 대한 것이었는지는 증거로 남지 않았습니다.

이번 라운드는 승인을 vault 안으로 가져옵니다.

1. **요청.** `enforcement` 출처 자격(게이트웨이·정책 엔진)이 실행을 멈추고 승인 요청을 엽니다. 요청은 대상 행동 하나(행위자·도구·자원·목적지)와
   정책 결정 id에 묶이며, 호출 본문은 받지 않습니다.
2. **답.** 검토자·관리자가 작업공간의 **승인 대기열**에서 사유와 함께 승인하거나 거절합니다. 누가 답할 수 있는지는 서명된 레지스트리 정책의
   데이터이고, 요청을 연 순간의 값이 요청에 고정됩니다. 기한 안에 답이 없으면 **만료는 거절**입니다.
3. **확인.** 게이트웨이는 OpenID Connect CIBA Core 1.0 poll 모드와 같은 방식으로 답을 폴링하고, vault 공개키로 **오프라인 검증한
   서명된 답(DSSE)**에만 실행합니다. 그 밖의 모든 결과(거절, 만료, 오류, EvidScope 무응답)는 거절입니다.
4. **증거.** 요청과 답은 모든 버전이 남는 서명 원장 객체(`approval_request`)이고, 내보내기·오프라인 검증·정책 재생에 그대로 들어갑니다.
   평가는 실행 시점 기준으로 "승인 전에 실행", "거절·만료 뒤 실행", "실행 창 밖", "다른 대상", "제외된 사람의 승인"을 찾아냅니다.

하지 않는 일도 분명히 둡니다. EvidScope는 **실행을 직접 막지 않습니다.** 막는 주체는 서명된 답을 검증하는 게이트웨이입니다. 알림(push,
Slack, 메일)도 보내지 않습니다. 사람은 대기열 화면을 보고, 게이트웨이는 폴링합니다. vault는 이 기능 때문에 밖으로 나가는 호출을 하지 않습니다.

승인 요청을 한 번도 쓰지 않은 tenant는 평가·스냅샷 해시·내보내기·검증 결과가 이전과 바이트 단위로 같습니다.

## 흐름

```text
게이트웨이                         EvidScope vault                          검토자(작업공간)
  │ 정책 엔진: require_approval         │                                         │
  │ POST /api/approvals/requests ───▶ 요청 v1 서명(pending), 답변 자격 고정        │
  │ ◀── {auth_req_id, expires_in, interval}                                      │
  │ POST /api/approvals/token ──────▶ authorization_pending (400)                │
  │   (interval초마다)                  │ ◀── GET /api/approvals (대기열) ─────────┤
  │                                     │ ◀── POST /api/approvals/{id}/approve ───┤ 사유 + 본 버전
  │                                     │ 요청 v2 서명(승인 1/2) … v3 서명(approved)
  │ POST /api/approvals/token ──────▶ 200 {decision, answer: DSSE, executionWindow}
  │ vault 공개키로 answer 검증 → 대상·행동·실행 창 확인 → 한 번만 실행 → 실행 이벤트 수집
```

## 전송 형식과 CIBA 계보

게이트웨이 쪽 두 엔드포인트는 CIBA poll 모드의 이름과 의미를 그대로 따릅니다. 다른 점은 아래 표에 적었습니다.

| CIBA Core 1.0 | EvidScope | 차이 |
|---|---|---|
| 백채널 인증 요청(`/bc-authorize`) | `POST /api/approvals/requests` | 클라이언트 인증 대신 `enforcement` 출처 Bearer 토큰 + `/api/ingest`와 같은 HMAC(`x-evid-timestamp`·`x-evid-nonce`·`x-evid-signature`) |
| `login_hint`·`id_token_hint` (사용자 지정) | `target`·`decisionId`·`actionId` | 특정 사용자가 아니라 정책이 정한 검토자 집단이 답합니다 |
| `binding_message` | `binding_message` (필수, 200자) | 검토자 화면에 그대로 보이는 요약. 게이트웨이가 쓴 글이라 텍스트로만 표시합니다 |
| `requested_expiry` | `requested_expiry` (초) | 정책의 `maxLifetimeSeconds`로 잘립니다 |
| 응답 `auth_req_id`·`expires_in`·`interval` | 같음 | `auth_req_id`는 160비트(`apr_` + base64url 27자). 같은 결정 id로 다시 열면 같은 요청을 돌려줍니다(`duplicate: true`) |
| 토큰 요청 `grant_type=urn:openid:params:grant-type:ciba` | `POST /api/approvals/token`, JSON `{grant_type, auth_req_id}` | 폼 인코딩 대신 JSON |
| `authorization_pending`·`slow_down`·`expired_token`·`access_denied` | 같음, 모두 HTTP 400 | `slow_down`은 간격을 5초 늘려(최대 60초) `interval`로 알려 줍니다 |
| 성공 시 ID/액세스 토큰 | 서명된 답 `answer`(DSSE) | 토큰이 아니라 오프라인 검증용 증명. 거절도 서명되어 `access_denied`의 `answer`로 옵니다 |

요청 본문 예:

```json
{"decisionId": "dec-7f3", "actionId": "pay-1", "traceId": "t-1", "enforcementPointId": "gw-eu-1",
 "policyId": "payments.refund", "policyVersion": "2026-10-01",
 "target": {"actor": "pay-agent", "tool": "payment_transfer", "resource": "acct:991", "destination": "bank-api"},
 "binding_message": "환불 120만 원 · 계좌 991", "requested_expiry": 600}
```

- `target`에는 `actor`, `tool`, `action`, `resource`, `destination`만 들어가고 `actor`와 `tool`·`action` 중 하나는 필수입니다.
  `input`·`arguments`·`payload`·`prompt` 같은 호출 본문 필드는 이유를 밝혀 400으로 거부합니다. 대기열은 **대상**을 저장하지 호출을 저장하지 않습니다.
- 응답은 `{auth_req_id, expires_in, interval, status, targetDigest, eligibility: {tier, approvers}, duplicate}`입니다.
  `targetDigest`는 `target`의 정규 JSON SHA-256이며, 게이트웨이가 실행하려는 대상과 같은지 이 값으로 대조합니다.
- 같은 결정 id로 다른 대상·요약을 보내면 409, 한 출처가 한 행동에 여는 요청은 최대 10개입니다. 요청은 지워지지 않으므로 이 한도를
  테넌트 전체로 세면 집행 지점 자격 하나가 다른 게이트웨이의 행동 id에 요청 10개를 먼저 열어 그 행동의 승인을 영구히 막을 수 있었습니다
  (6라운드 재감사 F2). 행동 하나의 분석 입력은 집행 출처 수 × 10개로 묶입니다.
- 한 출처가 답을 기다리는(답하지 않았고 만료되지 않은) 요청은 정책의 `maxPendingPerSource`(기본 100, 1~1000)개까지이며, 넘으면 429입니다.
  같은 요청의 재전송은 상한에서도 그대로 응답합니다(4라운드 재감사 제안 P-2). 유출된 집행 지점 자격 하나가 대기열을 가득 채우지 못하게 합니다.

폴링 응답:

| 상태 | HTTP | 본문 |
|---|---|---|
| 답 대기 | 400 | `{"error": "authorization_pending", "expires_in": 412}` |
| 너무 빠른 폴링 | 400 | `{"error": "slow_down", "interval": 10}` |
| 만료 | 400 | `{"error": "expired_token"}` — 거절로 처리 |
| 거절 | 400 | `{"error": "access_denied", "decision": "refused", "answer": {DSSE}, ...}` |
| 승인 | 200 | `{"auth_req_id", "decision": "approved", "answer": {DSSE}, "executionWindow": {"notBefore", "notAfter"}, "ledger": {"seq", "recordHash"}}` |
| 모르는 id·다른 자격의 요청 | 400 | `{"error": "invalid_grant"}` — 둘을 구분하지 않습니다 |

폴링 간격은 vault 메모리의 표(최대 10,000개, 재시작하면 잊음)로 지킵니다. 이 표는 출처마다 공평하게 나눕니다. 표가 차면 만료된 항목을
먼저 지우고, 그래도 차 있으면 이미 몫(10,000 ÷ 표에 있는 출처 수) 이상을 가진 출처의 새 요청만 `slow_down`(간격 60초)을 받습니다. 몫보다
적게 가진 출처가 오면 가장 많이 가진 출처의 가장 오래된 항목을 비우고, 그 출처는 비워진 항목의 다음 폴링 시각까지 표에 없는 요청도 이르게
폴링한 것으로 봅니다. 그래서 출처 하나가 표를 채워 모두가 `slow_down`을 받는 일이 없고, 밀려난 출처도 간격을 건너뛰지 못합니다
(6라운드 재감사에서 남긴 낮음 항목, 7라운드에 고침).

서명된 답은 `predicateType`이 `…/approval-queue.md#approval-answer-v1`인 in-toto Statement v1을 담은 DSSE 봉투입니다. 주체(subject)는
`approval/<auth_req_id>`와 대상 digest이고, predicate에 tenant, `auth_req_id`, 요청 버전, `decision`, 결정 id, 행동 id, 대상과 digest,
승인자(주체·역할·시각) 또는 거절자, 결정 시각, 실행 창, `singleUse: true`, 그 답이 기록된 원장 `seq`·레코드 해시가 들어갑니다.
Ed25519는 결정적이므로 같은 답을 여러 번 폴링해도 같은 바이트를 받습니다.

## 누가 답할 수 있는가

규칙은 코드가 아니라 레지스트리 정책의 `approvals` 필드(관리자 전용 `POST /api/registry/policy`, 서명된 `agent_registry_policy`)입니다.
넣지 않으면 기본값이 적용되고 화면과 API에 `built_in_default`로 표시됩니다.

```json
{"approvals": {"defaultLifetimeSeconds": 300, "maxLifetimeSeconds": 900, "intervalSeconds": 5, "executionWindowSeconds": 300,
  "unregisteredTier": "high",
  "answer": {"low":    {"approvers": 1, "roles": ["reviewer", "admin"], "exclude": ["registrant", "editor", "owner"]},
             "medium": {"approvers": 1, "roles": ["reviewer", "admin"], "exclude": ["registrant", "editor", "owner"]},
             "high":   {"approvers": 2, "roles": ["reviewer", "admin"], "exclude": ["registrant", "editor", "owner"]}}}}
```

- **위험 등급**은 `target.actor`를 담은 레지스트리 항목의 등급(재정의 포함)입니다. 등록되지 않은 행위자는 `unregisteredTier`(기본 `high`)입니다.
- **승인자 수**는 서로 다른 사람의 수입니다. 같은 사람이 두 번 승인할 수 없고, 거절은 한 사람으로 충분합니다.
- **역할**은 `reviewer`·`admin` 중에서 고릅니다. 출처 자격(게이트웨이 포함)은 답할 수 없습니다.
- **제외**는 그 에이전트의 등록자(`registrant`), 마지막 구성 수정자(`editor`), 책임자(`owner`)입니다. 요청을 연 게이트웨이 자격도 답할 수 없습니다.
  요청 이후 레지스트리가 바뀌어 새 등록자·수정자가 생기면 그 사람도 답할 수 없습니다(더 엄격한 쪽).
- **등급을 재지정한 사람**도 답할 수 없습니다. 위험 등급 재지정은 검토자 한 사람이 할 수 있으므로, 재지정으로 등급이 계산값과 달라진
  상태에서 요청이 열리면 재지정한 사람을 `eligibility.basis.overrideBy`로 고정하고 그 요청의 답변에서 제외합니다. 3라운드 구현에서는
  검토자 한 사람이 `high`(승인자 2명) 에이전트를 `low`(1명)로 재지정한 뒤 그 요청을 혼자 승인할 수 있었습니다(4라운드 재감사 R4-3에서 수정).
  `overrideBy`는 재계산 비교 키(`tier`·`approvers`·`roles`·`exclude`·`excluded`) 밖에 있어 이전에 열린 요청은 그대로 검증됩니다. 값이 있으면
  오프라인 검증기가 그 시점 원장으로 다시 계산한 값과 대조하고, 그 사람이 답한 버전을 거부합니다.

요청을 여는 순간 등급, 승인자 수, 역할, 제외 목록, 근거(항목 id·버전·상태, 정책 버전)가 `eligibility`로 요청에 고정됩니다. 그래서
정책을 나중에 바꿔도 열린 요청의 규칙은 바뀌지 않고, 오프라인 검증기는 원장에서 그 시점의 레지스트리 항목과 정책을 다시 계산해
고정값과 대조합니다.

답할 때는 화면에서 본 요청 `version`을 함께 보냅니다(`{"reason": "...", "version": 2}`). 그 사이 다른 사람이 답해 버전이 바뀌었으면 409입니다.
이미 결정되었거나 만료된 요청에 답하면 409, 역할·제외 규칙에 걸리면 403입니다.

## 기한과 만료

| 값 | 기본 | 의미 |
|---|---|---|
| `defaultLifetimeSeconds` | 300 | `requested_expiry`가 없을 때 요청 유효 시간 |
| `maxLifetimeSeconds` | 900 | 요청 유효 시간 상한. 더 길게 요청해도 잘립니다 |
| `intervalSeconds` | 5 | 최소 폴링 간격. 0.5초까지는 일찍 와도 인정합니다 |
| `executionWindowSeconds` | 300 | 승인 시각부터 실행해도 되는 기간 |
| `maxPendingPerSource` | 100 | 출처 하나가 동시에 열어 둘 수 있는 답 대기 요청 수. 설정할 때만 서명된 정책에 들어갑니다 |

만료는 별도 기록 없이 `expiresAt`과 현재 시각만으로 정해집니다. 대기열은 만료된 요청을 **만료(거절)**로 보여 주고, 폴링은 `expired_token`을,
평가는 만료 뒤 실행을 `EXECUTION_AFTER_APPROVAL_EXPIRED`로 냅니다. 만료 뒤에는 답할 수 없고, 원장에 만료 뒤 기록된 답이 있으면 오프라인 검증이 실패합니다.

## 게이트웨이에서 답 검증하기

게이트웨이는 vault 공개키를 밖에서(배포 설정으로) 받아 두고, 실행 직전에 다음을 확인합니다.

1. DSSE 서명이 vault 공개키로 맞고, 본문이 정규 JSON이며, predicate가 승인 답 형식인지
2. `actionId`(그리고 가능하면 `auth_req_id`, `decisionId`, `tenant`)가 지금 실행하려는 것과 같은지
3. 지금 실행하려는 대상의 digest가 승인된 `targetDigest`와 같은지
4. `decision`이 `approved`이고 지금이 `executionWindow` 안인지
5. 이 `auth_req_id`로 아직 실행한 적이 없는지(**한 번만 실행**은 게이트웨이가 기록합니다)

1~4는 `src/approvals.mjs`의 `verifyApprovalAnswer`가, 요청부터 폴링까지 전체는 `src/approval-client.mjs`의 `awaitApproval`이 합니다.
`awaitApproval`은 연결 실패·타임아웃·예상 밖 응답·검증 실패·기한 초과를 모두 `approved: false`로 돌려줍니다. 명령줄에서는 의존성 없는 검증기로 확인합니다.

```powershell
node evidscope-verify.mjs approval poll-response.json vault-public.pem --action-id pay-1 --target target.json `
  --auth-req-id apr_... --tenant alpha
```

종료 코드 0은 "그 대상의 승인이고 지금 실행 창 안"일 때뿐입니다. `--at`으로 다른 시각 기준 확인도 할 수 있습니다.

## 평가(엔진 v3)

승인 요청이 있는 행동의 분석 스냅샷에는 `approvals` 키(각 요청의 최신 버전 요약)가 생기고, 그 평가는 엔진 `evidscope-evaluate-v3`로 기록됩니다.
요청이 없는 행동은 키도 없고 엔진도 그대로(v1·v2)입니다. v3로 올린 이유는 재생 때문입니다. 이전 검증기는 모르는 스냅샷 키를 만나면
"스냅샷 해시 불일치"로 보고하는데, 이는 위변조처럼 읽힙니다. 엔진 이름을 바꾸면 이전 검증기는 대신 `engine_unavailable`(재생 불가)로 정직하게 보고합니다.

- vault에서 승인되고 실행 창 안에 같은 대상으로 실행된 행동은 `require_approval`을 충족합니다. 자산 정책의 행동별 사람 승인도 같은
  `policyVersion`의 승인 요청이면 충족합니다.
- 결정이 승인 요청으로 이어졌으면 일반 `REQUIRED_APPROVAL_MISSING`은 내지 않고, 아래의 구체적 발견사항이 대신 보고합니다.

| 코드 | 심각도 | 뜻 |
|---|---|---|
| `EXECUTION_BEFORE_APPROVAL` | high | 사람의 답이 나기 전에 대상이 실행됨 |
| `EXECUTION_AFTER_APPROVAL_REFUSED` | high | 거절 이후 실행됨 |
| `EXECUTION_AFTER_APPROVAL_EXPIRED` | high | 만료(거절) 이후 실행됨 |
| `APPROVAL_WINDOW_EXCEEDED` | high | 승인된 실행 창이 끝난 뒤 실행됨 |
| `APPROVAL_TARGET_MISMATCH` | high | 승인된 대상과 다른 대상이 같은 행동에서 실행됨 |
| `APPROVAL_ANSWERER_EXCLUDED` | high | 승인이 기록된 답변 자격(제외 대상·역할·승인자 수)을 지키지 않아 효력이 없음 |
| `APPROVAL_TIME_UNCERTAIN` | medium | 시계 오차 범위가 경계를 걸쳐 순서를 확정할 수 없음 |

판정은 실행 이벤트 시각(시계 오차 범위 포함)과 요청의 그 시점 기록만으로 하므로 같은 원장 위치에서 언제 다시 돌려도 같은 결과입니다.
vault가 기록한 시각(요청·답·만료)은 정확한 것으로 봅니다.

## 내보내기·오프라인 검증·재생

`approval_request`의 모든 버전은 서명 원장 레코드이므로 내보내기에 그대로 들어갑니다. `evidscope-verify bundle`은 승인 요청이 있는
내보내기에 `approvals` 절을 더해 다음을 확인하고, 하나라도 어긋나면 실패합니다.

- 요청 id가 tenant·요청 출처·결정 id에서 유도되었는지, `targetDigest`가 `target`과 맞는지, 모르는 필드가 없는지
- 첫 버전이 답 없는 v1이고 기록 주체가 요청 출처인지, 유효 시간과 실행 창 길이가 그 시점 정책과 맞는지
- `eligibility`가 그 시점 레지스트리 항목·정책으로 다시 계산한 값과 같은지
- 이후 버전마다 고정 필드가 그대로이고, 기록 주체가 추가된 승인자·거절자 본인이며, 제외 대상·요청 출처·허용되지 않은 역할이 아니고,
  만료 전에 기록되었고, 같은 사람이 두 번 승인하지 않았고, 승인자 수와 실행 창이 맞는지, 최종 답 뒤에 바뀌지 않았는지
- (4라운드 재감사 R4-4) 유효 시간이 `requested_expiry`(없으면 `defaultLifetimeSeconds`)를 `maxLifetimeSeconds`로 자른 값과 정확히 같고 폴링 간격이
  그 시점 정책과 같은지, 답한 사람이 답한 시점의 그 에이전트 등록자·구성 수정자가 아닌지(API가 403으로 막는 경우), 답 시각이 요청 시각과
  이전 답들보다 앞서지 않는지. 3라운드 검증기는 이런 이력도 통과시켰습니다. API가 원래 쓰는 이력은 모두 이 조건을 지키므로 이전 내보내기 결과는 같습니다.

`--replay`는 v3 평가를 그 시점 스냅샷(승인 요약 포함)으로 다시 계산합니다. 이번 라운드 이전에 만든 내보내기는 승인 레코드가 없으므로
`approvals` 절 없이 이전과 같은 결과로 검증됩니다(회귀 테스트가 이전 커밋에서 만든 내보내기 파일로 확인합니다).

## 다른 도구와 비교

| | 승인 상태 위치 | 누가 답하나 | 기한 | 답의 증거 |
|---|---|---|---|---|
| LangGraph `interrupt()` | 애플리케이션 체크포인터. `Command(resume=…)`로 재개 | 애플리케이션이 정함 | 없음(무기한 대기) | 체크포인트 상태. 서명·대상 묶음 없음 |
| Microsoft Agent Framework 함수 승인 | 실행 중인 에이전트 프로세스 | 호출한 애플리케이션 | 애플리케이션이 정함 | 없음 |
| Microsoft Agent Governance Toolkit 승인 | AGT 정책 런타임(`ApprovalRequest`·`ApprovalResolution`) | AGT 설정 | AGT 설정 | AGT 기록. EvidScope는 [AGT 어댑터](agent-registry.md)로 외부 권한 증거로 수집만 합니다 |
| HumanLayer(현재 저장소는 보관 상태) | HumanLayer 클라우드 | Slack·메일로 연락받은 사람 | 설정 가능 | 서비스 기록 |
| EvidScope 승인 대기열 | 서명 원장(모든 버전) | 서명된 레지스트리 정책(등급별 인원·역할·제외) | 필수, 만료는 거절 | vault 서명 DSSE 답, 대상 digest·실행 창·원장 위치 포함, 내보내기·재생 가능 |

이 도구들은 "에이전트를 멈추고 사람에게 묻는" 실행 흐름을 잘 다룹니다. EvidScope가 더하는 것은 그 질문과 답이 **나중에 제3자가 확인할 수 있는
증거**가 되는 부분입니다. 답한 사람이 규칙상 답할 수 있었는지, 답이 어느 대상에 대한 것이었는지, 실행이 답보다 앞섰거나 기한·실행 창을
벗어났는지를 vault 없이도 내보내기 파일과 공개키만으로 확인합니다. 반대로 EvidScope는 워크플로 엔진이 아니므로 재개·상태 저장·알림은
기존 도구나 게이트웨이가 맡습니다. LangGraph 노드에서 `interrupt()` 대신(또는 그 안에서) `awaitApproval`을 호출하는 식으로 함께 씁니다.

## API 요약

| 경로 | 권한 | 용도 |
|---|---|---|
| `POST /api/approvals/requests` | `enforcement` 출처 + HMAC | 승인 요청 열기(CIBA 백채널 요청) |
| `POST /api/approvals/token` | 요청을 연 `enforcement` 출처 | 답 폴링(CIBA 토큰 요청, poll 모드) |
| `GET /api/approvals` | 사람 역할 | 대기열: 만료가 가까운 순 답변 대기(최대 500), 최근 결정 100건, 적용 정책 |
| `GET /api/approvals/{id}` | 사람 역할 | 요청 상세: 대상, 레지스트리 항목, 등급, 같은 행동의 다른 요청과 정책 결정, 서명된 버전 이력, 내가 답할 수 있는지 |
| `POST /api/approvals/{id}/approve`·`/refuse` | 정책이 허용한 검토자·관리자 | `{reason, version}`으로 답 |

두 게이트웨이 경로는 수집 게이트웨이(`ingress`)로도 받고 감사 게이트웨이(`audit`)에서는 막습니다. 화면은 작업공간의 **AI 자산·수집 → 승인 대기열**이며,
열려 있는 동안 15초마다 대기 목록을 다시 읽습니다.

## 현재 한계

- **EvidScope가 실행 경로에 들어갑니다.** 승인이 필요한 행동은 vault가 응답해야 진행됩니다. vault가 내려가 있거나 네트워크가 끊기면
  게이트웨이는 승인을 받을 수 없고, `awaitApproval`은 `evidscope_unreachable`로 거절합니다(fail closed). 이미 받은 승인 답은
  공개키만으로 검증되므로 vault가 내려가도 실행 창 안에서는 쓸 수 있습니다. 가용성이 필요한 곳은 vault를 이중화하거나, 승인이 필요 없는
  결정에는 이 경로를 쓰지 않습니다.
- **한 번만 실행은 게이트웨이의 몫입니다.** 답에 `singleUse: true`가 있지만, 같은 답을 실행 창 안에서 두 번 쓰는 것을 vault가 그 자리에서
  막지는 못합니다. 실행 창 안의 두 번째 실행은 평가에서도 정상 실행으로 보이므로, 게이트웨이가 쓴 `auth_req_id`를 기록해 거부해야 합니다.
- 폴링 간격 기록은 메모리에만 있어 재시작하면 잊습니다. 모르는 id에 대한 폴링은 간격 제한 없이 `invalid_grant`로 바로 답합니다(DB 조회 한 번).
- 폴링은 Bearer 토큰만 확인하고 HMAC은 요청 열기에만 씁니다. 토큰이 새면 그 출처의 답을 읽을 수 있지만 답을 바꿀 수는 없습니다.
- 역할은 vault 설정에서 오고 내보내기에는 없으므로, 오프라인 검증은 기록된 역할이 정책에 맞는지만 확인합니다. 서명 키를 가진 사람은
  처음부터 끝까지 앞뒤가 맞는 거짓 이력을 서명할 수 있습니다(투명성 로그·위트니스가 이를 외부에 묶습니다).
- 알림이 없습니다. 검토자는 대기열 화면을 직접 봐야 하며, 15초 갱신은 폴링입니다.
- 실행 이벤트가 `target`의 모든 필드를 담고 있어야 같은 대상으로 판정됩니다. 게이트웨이가 승인 요청과 실행 이벤트에 같은 값을 써야 합니다.
