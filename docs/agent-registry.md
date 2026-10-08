# 에이전트 레지스트리·정책 결정 수집 가이드

> 2026-10-07 개선 3라운드(R3-G)에서 추가한 기능입니다. OTLP 결정 span과 Cedar 어댑터는 4라운드(R4-D)에서 더했습니다. 증거 계층 전체
> 구조는 [증거 계층 아키텍처](evidence-layer.md)를 보세요.

## 무엇을 하고 무엇을 하지 않는가

지금까지 에이전트는 등록된 대상이 아니었습니다. `/api/agents`는 이벤트에서 에이전트를 추려 낼 뿐이고, 자산(행위자+도구 정책)과
거버넌스 시스템은 서로도, 에이전트와도 연결되지 않았습니다. 정책 엔진이 내린 허용·거부 결정을 받는 경로도 없었습니다.

이번 라운드는 두 가지를 더합니다.

1. **에이전트 레지스트리.** 에이전트마다 서명된 등록 객체 하나를 두고 모든 버전을 원장에 남깁니다. 상태 전이는 별도의 서명 기록이며,
   승인이 필요한 전이는 등록자·구성 수정자·요청자가 아닌 검토자가 승인합니다(4-eyes). 전이 조건(게이트)과 위험 등급 규칙은 코드가 아니라
   서명된 정책 데이터입니다.
2. **정책 결정 수집.** 게이트웨이·정책 엔진·가드레일 같은 집행 지점을 `enforcement` 출처로 등록해 `policy_decision`·`guardrail_decision`
   기록을 받고, 같은 행동의 독립 도구 기록과 비교합니다. OPA 결정 로그와 Cedar 결정(Amazon Verified Permissions CloudTrail 기록, Cedar
   응답을 담은 로그)은 어댑터로 변환하고, 게이트웨이가 내보내는 OTLP 결정 span은 OTLP 수신기가 받습니다.

**EvidScope는 여전히 아무것도 차단하지 않습니다.** 정지(suspended)나 폐기(retired) 상태로 바꿔도 에이전트 실행은 멈추지 않습니다. 차단은
AI/MCP 게이트웨이와 OPA·Cedar·AGT 같은 정책 엔진이 하고, EvidScope는 그 결정과 실제 실행 기록을 서명해 보관하고 어긋남을 발견(finding)으로
보고합니다. 추적 화면은 Langfuse·Phoenix에 남깁니다. 정책 엔진·게이트웨이·추적 UI를 새로 만들지 않습니다.

모든 기능은 켜야 동작합니다. 레지스트리 기록과 결정 기록이 없는 tenant는 평가 결과·스냅샷 해시·내보내기·검증이 이전과 같습니다.

## 등록 항목

`POST /api/registry`(검토자·관리자)로 `draft` 또는 `discovered` 상태의 항목을 만듭니다. 모든 사람 역할이 조회할 수 있습니다.

| 필드 | 의미 |
|---|---|
| `id` | 등록 식별자. `candidates`·`policy`·`transitions`는 예약어입니다. |
| `name`, `owner`, `purpose` | 이름, 책임자, 목적 |
| `sources` | 이 에이전트가 쓰는 **인증된 출처 자격**(설정 파일의 source principal id). 없는 자격이면 400입니다. |
| `actors` | 출처가 보고하는 행위자 이름. 자기 보고이므로 출처 자격보다 약한 연결입니다. |
| `assetIds`, `systemId` | 연결할 자산(행위자+도구 정책)과 거버넌스 시스템. 서명된 객체가 있어야 합니다. |
| `models`, `tools` | 모델 목록, 도구 목록. 도구는 `{"name":"payment_transfer","enforcement":"required"}`처럼 정책 결정 필수 여부를 가질 수 있습니다. |
| `dataCategories`, `destinations` | 다루는 데이터 범주, 목적지 |
| `fingerprint` | 버전 지문: `codeCommit`(7~64자리 16진수), `promptDigest`·`configDigest`(SHA-256), `version` |

출처 자격 하나와 행위자 이름 하나는 폐기되지 않은 항목 하나에만 들어갈 수 있습니다(겹치면 409). 같은 활동이 두 항목에 걸리면 시점별
상태 판단이 모호해지기 때문입니다.

`POST /api/registry/:id`는 새 버전을 씁니다. 준 필드만 바뀌고 나머지는 이전 버전 값을 잇습니다. `approved`·`production` 상태에서는
구성(`sources`·`actors`·`models`·`tools`·`dataCategories`·`destinations`·`fingerprint`)을 바꿀 수 없습니다(409). 정지한 뒤 고치고 다시
승인받습니다. 새 버전이 생기면 승인 대기 중인 전이 요청은 `superseded`로 닫힙니다. 폐기된 항목은 고칠 수 없습니다.

## 생애주기

```
discovered → draft → testing → approved → production ⇄ suspended
                     (어느 상태에서든) → retired
```

| 전이 | 승인 |
|---|---|
| `discovered→draft`, `draft→testing`, `→retired`, `production→suspended` | 요청만으로 적용됩니다(게이트 조건이 있으면 충족해야 함). |
| `testing→approved`, `approved→production`, `suspended→production` | 승인 대기(`pending`)로 기록되고, 다른 사람이 승인해야 적용됩니다. |

- 전이 요청 `POST /api/registry/:id/transitions` 본문은 `{"to":"approved","reason":"...","evidence":[{"type":"event","ref":"..."}]}`입니다.
  증거 참조 유형은 `event`·`asset`·`system`·`case`·`governance_document`·`external`이며, 요청 시점에 `event`는 보관 중인 이벤트인지,
  `asset`·`system`·`case`는 서명된 객체인지 확인해 `verification`에 남깁니다. 나머지는 `self_asserted`입니다.
- 승인 `POST /api/registry/transitions/:tid/approve`, 거절 `.../refuse`(둘 다 `reason` 필수). 등록자, 마지막 구성 수정자, 전이 요청자는
  승인할 수 없습니다(403). 요청 이후 항목이 바뀌었으면 승인은 409이며 새로 요청해야 합니다. 승인 때 게이트를 다시 확인합니다.
- 항목 하나에 승인 대기 요청은 하나만 둡니다. 정지(`production→suspended`)는 승인 없이 즉시 적용해 사고 대응을 늦추지 않습니다.
- 상태는 전이 기록으로만 바뀝니다. 각 상태 변경 버전은 `lastTransition`으로 전이 기록을 가리킵니다.

## 게이트

게이트는 위험 등급별·목표 상태별 조건 목록입니다. 요청할 때와 승인할 때 이미 서명된 기록과 대조하고, 응답의 `gate.conditions`가 조건마다
`met`과 근거(`detail`)를, `gate.unmet`이 미충족 조건 id를 알려 줍니다. 상세 조회(`GET /api/registry/:id`)의 `next`도 가능한 전이별 게이트
미리보기를 보여 줍니다.

| 검사(`check`) | 확인 내용 |
|---|---|
| `fields_present` | 지정 필드(`owner`·`purpose`·`systemId`·`assetIds`·`fingerprint`·`models`·`tools`·`dataCategories`·`destinations`)가 비어 있지 않음 |
| `events_in_state` | 항목이 그 상태였던 구간에 받은 이벤트 수(`sourceKinds`로 OTLP 등 제한, `min`) |
| `decisions_received` | 항목의 행위자에 대한 정책 결정 기록 수(선택: `state` 구간, `min`) |
| `approval_rule_for_tools` | `tier` 이상 위험 도구마다, 그 도구와 행위자에 대해 지금 유효한 `approvalRequired:true` 자산이 있음 |
| `assets_linked`, `system_linked` | 연결한 자산·거버넌스 시스템이 서명된 객체로 있음 |
| `fingerprint_recorded` | `codeCommit`·`promptDigest`·`configDigest` 중 하나 이상 |
| `evidence_attached` | 전이 요청에 붙인 증거 참조 수(`min`) |

기본 게이트(서명된 정책이 없을 때, 응답에 `policySource:"built_in_default"`로 표시)는 다음과 같습니다.

| 등급 | → approved | → production |
|---|---|---|
| low | 책임자·목적 | 없음 |
| medium | 책임자·목적, testing 중 텔레메트리(OTLP·agent·tool) 1건, 정책 결정 1건 | 자산 연결 |
| high | 책임자·목적, testing 중 OTLP 1건, 정책 결정 1건, 고위험 도구의 사람 승인 규칙, 거버넌스 시스템 연결 | 자산 연결, 버전 지문, 증거 참조 1건 |

## 위험 등급

설문 없이 등록된 도구·데이터 범주·목적지에 규칙을 적용해 계산합니다. 가장 높은 등급이 항목의 등급이고, 응답의 `reasons`가 어떤 규칙이
걸렸는지 밝힙니다. 기본 규칙은 다음과 같습니다.

| 규칙 | 조건 | 등급 |
|---|---|---|
| `tool-payment`, `tool-destructive` | 도구 이름에 `payment`·`transfer`·`refund` 등, `delete`·`shell`·`exec`·`deploy`·`admin` 등이 들어 있음 | high |
| `tool-outbound`, `tool-write` | 도구 이름에 `email`·`send`·`publish`·`upload` 등, `write`·`update`·`create` 등이 들어 있음 | medium |
| `data-sensitive` | 데이터 범주가 `personal`·`sensitive`·`health`·`biometric`·`financial`·`credential` 등 | high |
| `data-internal` | 데이터 범주가 `confidential`·`internal`·`customer` | medium |
| `destination-external` | `.internal`·`.local`·`.corp`·`.lan`·`localhost`로 끝나지 않는 목적지 | medium |

정확한 값은 `GET /api/registry/policy`의 `riskRules`로 확인합니다. 규칙은 `field`(`tool`·`dataCategory`·`destination`), `op`, `values`,
`tier`로 된 데이터입니다.

검토자는 `POST /api/registry/:id/risk`(`{"tier":"high","reason":"..."}`, 해제는 `"tier":null`)로 등급을 재지정할 수 있습니다. 재지정은 새
버전으로 기록되고(해제하면 해제한 사람과 사유가 그 버전에 남습니다), 등록자나 구성 수정자는 할 수 없습니다(403). 재지정은 당시 구성(도구·데이터 범주·목적지)의 해시에 묶여 있어, 구성이
바뀌면 효력을 잃고 계산값으로 돌아갑니다.

## 레지스트리 정책

`POST /api/registry/policy`(관리자 전용)는 `enforcement`, `gates`, `riskRules`를 서명된 `agent_registry_policy` 객체로 바꿉니다. 주지 않은
필드는 이전 값을 잇고, 모르는 필드·검사·상태는 400입니다.

- `enforcement:"off"`(기본): 등록되지 않은 활동은 발견으로 보고하지 않습니다.
- `enforcement:"unregistered_activity"`: 그 시점 이후 어느 등록 항목에도 들지 않는 에이전트 활동을 `AGENT_UNREGISTERED_ACTIVITY`로 보고합니다.

## 미등록 후보

`GET /api/registry/candidates`는 EvidScope가 이미 보는 미등록 에이전트를 나열합니다. 보관 중인 agent·OTLP·tool 활동의 출처와 행위자,
최신 평가의 `UNREGISTERED_ASSET`·`AI_UNREGISTERED_ASSET` 발견, 활동이 없는 agent 출처 자격이 근거입니다(최대 200개). **자동 등록하지
않습니다.** 후보에서 등록할 때 `discoveredFrom`을 남기면 출처를 추적할 수 있습니다.

## 평가(엔진 v2)

레지스트리 기록이나 결정 기록이 있는 행동은 평가 엔진 `evidscope-evaluate-v2`로 평가합니다. 그런 입력이 없는 행동의 스냅샷은 이전과 바이트
단위로 같고 `evidscope-evaluate-v1`로 기록됩니다. 등록 항목이나 레지스트리 정책을 쓸 때마다 tenant의 모든 행동을 다시 평가합니다(자산과 같은 방식).

등록 상태는 행동 시점 기준입니다. 이벤트의 `occurredAt`에서 시계 오차(`clockUncertaintyMs`) 범위 안의 모든 시점을 보고, 그 범위 안에서
상태가 바뀌었으면 확정하지 않습니다.

| 발견 | 등급 | 조건 |
|---|---|---|
| `AGENT_SUSPENDED_ACTIVITY` | high | 행동 시점에 정지 상태인 항목이 포함하는 출처·행위자의 활동 |
| `AGENT_RETIRED_ACTIVITY` | high | 행동 시점에 폐기 상태인 항목의 활동. 같은 출처·행위자를 포함하는 폐기되지 않은 항목이 있으면(새 id로 다시 등록) 그 항목을 따릅니다. |
| `AGENT_UNREGISTERED_ACTIVITY` | medium | `unregistered_activity`가 켜진 시점에 어느 항목에도 들지 않는 활동(악성 확정 아님) |
| `AGENT_REGISTRY_STATE_UNCERTAIN` | medium | 시계 오차 범위 안에서 상태가 바뀌어 확정할 수 없음 |
| `EXECUTION_AFTER_DENY` | high | 같은 대상에 대한 거부 결정 뒤의 실행 기록. 그 사이 **같은 출처·집행 지점**의 allow·modify가 있으면 제외하며, 다른 집행 지점은 거부를 지울 수 없습니다. |
| `DECISION_ORDER_UNCERTAIN` | medium | 거부와 실행의 순서를 시계 오차 때문에 확정할 수 없음 |
| `ENFORCEMENT_DECISION_MISSING` | high | 행동 시점 등록 항목이 `enforcement:"required"`로 표시한 도구를, 앞선 결정 기록 없이 실행 |
| `REQUIRED_APPROVAL_MISSING` | high | `require_approval` 결정 뒤 실행 시점에 유효한 사람 승인 없이 실행 |
| `REQUIRED_APPROVAL_TIME_UNCERTAIN` | medium | 위 순서나 승인 유효기간을 확정할 수 없음 |
| `REPEATED_DENIES` | medium | 한 행위자에 대한 거부가 10분 안에 3건 이상(다른 행동 포함) |

활동으로 보는 기록은 agent·OTLP 출처의 활동(intent·execution·self_report·result·delegation)과 행위자를 밝힌 tool 기록입니다. 실행은
tool 출처의 `execution` 또는 성공한 `result`입니다. 결정은 행위자가 같고, 결정이 밝힌 `tool`·`action`·`resource`·`destination`이 실행
기록과 모두 같을 때 그 실행의 결정으로 봅니다. 앞의 네 결정 규칙 중 반복 거부를 뺀 셋은 **같은 `actionId`의 기록끼리** 비교하므로, 집행
지점이 대상 행동의 `actionId`를 결정 기록에 실어야 합니다. 반복 거부는 다른 행동의 거부 요약(최대 50건)을 스냅샷 입력으로 함께 서명해
재생할 수 있게 합니다. 창·임계값은 엔진 상수이며 바꾸면 새 엔진이 됩니다.

## 정책 결정 수집

집행 지점마다 출처 자격을 하나씩 둡니다.

```json
{"id": "alpha-gateway", "tenant": "alpha", "role": "source", "kind": "enforcement", "token": "...", "hmacSecret": "..."}
```

`enforcement` 출처는 `policy_decision`·`guardrail_decision`만 보낼 수 있고, 다른 출처가 결정 필드를 보내면 400, 다른 출처가 결정 종류를
보내면 403입니다. 결정 기록의 필드는 기존 필드(`actor`·`tool`·`action`·`resource`·`destination`·`traceId`·`actionId`·`policyVersion`·
`clockUncertaintyMs`·`note`)에 다음을 더한 허용 목록이며, 모르는 필드는 거부합니다.

| 필드 | 값 |
|---|---|
| `decision` (필수) | `allow`·`deny`·`require_approval`·`modify` |
| `engine` (필수), `engineVersion` | 정책 엔진 이름과 버전 |
| `decisionId`, `enforcementPointId` (필수) | 결정 id, 집행 지점 id |
| `policyId`, `bundleDigest` | 정책 id, 정책 묶음 digest |
| `latencyMs` | 0~3600000 정수 |
| `recordedBeforeExecution` | 실행 전에 기록했는지(집행 지점의 자기 보고) |

`actor`와 `tool` 또는 `action`도 필수입니다. 결정 기록은 집행 지점이 그렇게 결정했다는 **인증된 서비스 기록**이며, 그 결정이 실제로 집행됐다는
증거는 아닙니다. 집행 여부는 독립 도구 기록과의 비교(위 발견)로만 드러납니다.

## OPA 결정 로그 어댑터

`src/opa-decision-adapter.mjs`는 [OPA 결정 로그](https://www.openpolicyagent.org/docs/management-decision-logs) 형식(`decision_id`·
`labels`·`bundles`·`path`·`input`·`result`·`timestamp`·`metrics`·`erased`·`masked`·`trace_id`)을 `policy_decision` 기록으로 바꿉니다.

- **남기는 것:** 결정 id, 시각, 결정 경로(정책 id), 묶음 이름·리비전(정책 버전)과 그 digest, OPA 버전 라벨, 지연 시간, 지운·가린 필드 수.
- **남기지 않는 것:** `input`·`result` 본문, 질의(`query`) 본문(digest만), `request_context`·헤더, `nd_builtin_cache`, `requested_by`, 다른 라벨.
- 대상 행동(행위자·도구·action·resource·목적지·`actionId`·`traceId`)은 신뢰하는 수집기 설정의 JSON pointer로만 읽습니다. pointer는 `input`·
  `result`·`trace_id`·`span_id`·`labels`·`path` 아래만 가리킬 수 있고 문자열만 받습니다. `actor`는 필수입니다.
- 결과는 수집기 설정의 `decision.values`로 네 결정 중 하나에 대응시킵니다(기본 `true→allow`, `false→deny`). 대응되지 않거나 필수 값이
  없는 이벤트는 추측하지 않고 `rejected`로 보고합니다.
- 이벤트 id는 수집기와 결정 id에서 만들어져 같은 로그를 다시 보내도 중복으로 처리됩니다. `actionId`를 주지 않으면 `opa:<decision_id>`가
  되어 반복 거부 규칙에만 쓰입니다. 같은 행동의 실행과 비교하려면 `actionId` pointer를 지정하세요.

```json
{"id": "alpha-gateway", "tenant": "alpha", "kind": "enforcement", "enforcementPointId": "opa-sidecar-1", "recordedBeforeExecution": true,
 "target": {"actor": {"pointer": "/input/agent"}, "tool": {"pointer": "/input/tool"}, "actionId": {"pointer": "/input/action_id"}},
 "decision": {"pointer": "/result/decision", "values": {"needs_review": "require_approval"}}}
```

```powershell
node scripts/collect-opa-decisions.mjs --log decisions.json.gz --collector collector.json            # 미리보기(기본)
node scripts/collect-opa-decisions.mjs --log decisions.json.gz --collector collector.json --send --config config.json --base https://ingress.example.com/
```

입력은 OPA가 올리는 JSON 배열(gzip 가능, 8MiB, 1000건 이하)입니다. 전송은 설정 파일에서 수집기와 같은 id·tenant의 `enforcement` 출처 자격을
찾아 HMAC 수집 경로로 보냅니다. 거부된 이벤트가 있으면 종료 코드 1입니다. 어댑터는 OPA 서명·결정 로그의 완전성·실제 집행을 확인하지
않으며, 결과의 `assurance`가 이를 밝힙니다.

### OPA 결정 로그의 서명

OPA 문서([결정 로그](https://www.openpolicyagent.org/docs/management-decision-logs), [설정](https://www.openpolicyagent.org/docs/configuration))에는
결정 로그 자체에 서명이나 무결성 값을 붙이는 방법이 없습니다. 서명은 정책 묶음(bundle) 검증에만 있고, 결정 로그 업로드의 `services[_].credentials`
(bearer·OAuth2·mTLS 등)는 업로드하는 쪽을 서비스에 인증할 뿐 로그 내용을 서명하지 않습니다. 또 OPA는 버퍼 한도·초당 한도·`drop` 규칙에 따라
결정 이벤트를 버릴 수 있습니다. 그래서 어댑터는 서명을 검증하지 않고(`assurance.signatureVerified:false`), 서명 형식을 따로 만들지도 않습니다.
EvidScope가 확인하는 것은 전송한 수집기의 `enforcement` 출처 자격(HMAC)까지입니다.

## Cedar 결정 어댑터

Cedar의 권한 판단 응답은 `decision`(Allow·Deny)과 `diagnostics`(`reason`: 결정을 만든 정책 id 목록, `errors`: 평가 중 오류가 난 정책 id와
오류)로 이루어집니다. Cedar 자체에는 결정 로그 형식이 없으므로 `src/cedar-decision-adapter.mjs`는 문서로 정해진 두 형태를 받습니다.

| `format` | 입력 | 결정·정책 | 시각·결정 id |
|---|---|---|---|
| `avp-cloudtrail` | [Amazon Verified Permissions CloudTrail](https://docs.aws.amazon.com/verifiedpermissions/latest/userguide/monitoring-cloudtrail.html) 데이터 이벤트(`{"Records":[...]}`, `IsAuthorized`·`IsAuthorizedWithToken`·`BatchIsAuthorized`·`BatchIsAuthorizedWithToken`) | `additionalEventData.decision`(배치는 `results[i].decision`), 기록에 있으면 `determiningPolicies`·`errors` | `eventTime`, `requestID`(배치는 `requestID:i`) |
| `cedar-response` | 애플리케이션이 Cedar 응답(`{decision, diagnostics}`, FFI·WASM의 `{type:"success", response}`, Cedar Agent 응답)을 담아 남긴 로그 항목 | `decision`, `diagnostics.reason`, `diagnostics.errors[].policyId` | 수집기 설정 `record.id`·`record.time` pointer |

- **결정:** 대소문자와 상관없이 `allow`·`deny`만 받습니다. `type:"failure"`(판단 자체 실패), CloudTrail `errorCode`가 있는 호출, 그 밖의 값은
  추측하지 않고 `rejected`로 보고합니다.
- **정책:** 결정을 만든 정책이 하나면 그 id가 `policyId`, 여럿이면 정렬한 id 목록의 digest(`cedar-policies:<32자리>`)가 `policyId`이고 id 목록은
  `note`에 남깁니다(길이 한도 안에서). 오류는 개수와 정책 id만 남기고 오류 메시지는 남기지 않습니다. AVP 정책 저장소 id는 `note`에 남깁니다.
- **남기지 않는 것:** 요청 `context`·엔터티, 오류·경고 메시지, CloudTrail의 `userIdentity`·`sourceIPAddress`·`userAgent`·`eventID`·리소스 ARN.
- **대상 행동:** OPA 어댑터와 같이 수집기 설정의 JSON pointer로만 읽습니다. `avp-cloudtrail`에서는 결정 하나의 요청(`principal`·`action`·
  `resource`·`context`) 아래만 가리킬 수 있습니다. `actor`는 필수이고, `actionId`를 주지 않으면 `cedar:<결정 id>`가 됩니다.
- AVP가 아닌 이벤트, 다른 API 호출, 수집기 설정 `policyStoreId`와 다른 정책 저장소의 이벤트는 `skipped`에 이름별 개수로만 셉니다.
  CloudTrail이 같은 기록을 두 번 전달하면 `skipped.duplicate`로 세고, 같은 결정 id에 내용이 다르면 거부합니다.
- 이벤트 id는 수집기 id와 결정 id에서 만들어 같은 로그를 다시 보내도 중복으로 처리됩니다. `engine`은 `amazon-verified-permissions` 또는 `cedar`입니다.

```json
{"id": "alpha-gateway", "tenant": "alpha", "kind": "enforcement", "enforcementPointId": "photo-app", "format": "avp-cloudtrail",
 "policyStoreId": "PSEXAMPLEabcdefg111111",
 "target": {"actor": {"pointer": "/principal/entityId"}, "action": {"pointer": "/action/actionId"},
            "actionId": {"pointer": "/context/contextMap/action_id/string"}}}
```

```powershell
node scripts/collect-cedar-decisions.mjs --log cloudtrail.json.gz --collector collector.json            # 미리보기(기본)
node scripts/collect-cedar-decisions.mjs --log cloudtrail.json.gz --collector collector.json --send --config config.json --base https://ingress.example.com/
```

전송·한도·종료 코드는 OPA 수집 스크립트와 같습니다(8MiB, 결정 1000건). AVP의 `decision`은 AVP가 그렇게 판단했다는 기록이지, 호출한
애플리케이션이 그 판단을 집행했다는 기록이 아닙니다. CloudTrail 데이터 이벤트는 기본으로 꺼져 있고 늦게 전달될 수 있으므로 늦은 증거
(`LATE_EVIDENCE`)와 함께 보세요.

## OTLP 결정 span

게이트웨이·사이드카가 결정을 OpenTelemetry span으로 내보내면 기존 OTLP 수신기(`POST /v1/traces`)가 받습니다. OTel 시맨틱 컨벤션에는 권한
결정 결과 속성이 아직 없고(보안 규칙 `security_rule.*`만 개발 단계로 있음), [kube-agentic-networking 제안 0033](https://kube-agentic-networking.sigs.k8s.io/proposals/0033-Observability/)이
검사 span에 `event.action`(allow·deny)과 `event.outcome`(검사 자체의 성공·실패)을 두자고 제안합니다. EvidScope는 이 제안을 따릅니다.
agentgateway는 현재 정책 호출 child span(`agentgateway.outbound.kind: Policy`)과 `reason`만 내고 allow·deny 속성은 없으므로, Collector의
transform 처리기로 0033 속성을 붙여야 합니다.

| span 속성 | 결정 기록 필드 |
|---|---|
| `event.action` (`allow`·`deny`만) | `decision`. 이 속성이 있는 span만 결정 span입니다. 다른 값은 `unsupported_decision`으로 거부합니다. |
| `gen_ai.agent.name`·`agent.name`·`gen_ai.agent.id`·`agent.id`(0033 baggage) | `actor`(필수) |
| `gen_ai.tool.name`·`tool.name` | `tool`. 없으면 `mcp.method.name`이 `action`이 됩니다(둘 다 없으면 `decision_target_missing`). |
| `security_rule.ruleset.name`, `security_rule.version` | `policyId`(식별자 형식이 아니면 digest), `policyVersion` |
| `event.outcome` (`success`·`failure`·`unknown`) | `status` |
| span 끝 시각(없거나 시작보다 이르면 시작 시각), 길이 | `occurredAt`, `latencyMs` |
| trace id, span id | `actionId: otel-trace:<trace>`, `decisionId: otel:<trace>:<span>`, 이벤트 id `otel-decision:<trace>:<span>` |

- `security_rule.name`이 있는 0033 규칙 span(`mcp.authorization.rule` 등)은 부모 검사 span의 결정을 설명할 뿐이라 저장하지 않습니다
  (`decision_rule_span`). 둘 다 저장하면 결정 하나가 두 번 세어집니다.
- 0033 예시의 검사 span에는 행위자·도구가 없고 부모 요청 span에 있습니다. 게이트웨이나 Collector가 검사 span에 `gen_ai.agent.id`와
  `gen_ai.tool.name`을 함께 실어야 저장됩니다.
- `error.message`, span 이름·이벤트·링크·상태 메시지, `guardrail.*`·`audit.*` 같은 다른 속성은 디코딩하지 않습니다.
- 도구 출처가 같은 행동의 실행과 비교되게 하려면 실행 기록의 `actionId`를 `otel-trace:<W3C trace id>`로 보내야 합니다.

**어느 자격이 결정을 저장하는가.** 결정은 `enforcement` 출처만 저장합니다. OTLP 수신기는 bearer 토큰만 받으므로, OTLP로 결정을 보내는 집행
지점은 자기 `enforcement` 자격에 `otlpDecisions`를 켜야 합니다(OPA 상태 보고 경로처럼 bearer 토큰으로 인증하며, HMAC 비밀은 `/api/ingest`용으로 유지).

```json
{"id": "alpha-gateway", "tenant": "alpha", "role": "source", "kind": "enforcement", "token": "...", "hmacSecret": "...",
 "otlpDecisions": {"enforcementPointId": "mcp-gw-1", "engine": "envoy-ext-authz", "clockUncertaintyMs": 1000}}
```

- vault는 결정 기록에 이 설정의 `enforcementPointId`·`engine`(기본 `otel`)·`clockUncertaintyMs`(기본 `unknown`)와 매핑 버전
  (`note`의 `otel-decision-map-1`)을 더합니다. span이 이 값들을 정할 수 없습니다. 설정이 틀리면 서버가 시작하지 않습니다.
- `otlp` 출처는 결정을 저장할 수 없습니다. 결정 span은 `decision_needs_enforcement_source`로 거부되고, GenAI span의 매핑·저장·
  거부 개수는 이전과 같습니다. `otlpDecisions`가 없는 `enforcement` 자격은 OTLP 경로에서 403입니다.
- `otlpDecisions`를 켠 자격이 보낸 GenAI span은 저장하지 않습니다(`not_decision_span`). 한 span이 GenAI span이면서 결정 span이면
  자격에 맞는 쪽 하나만 저장하고 거부로 세지 않습니다.
- `recordedBeforeExecution`은 쓰지 않습니다. span은 끝난 뒤 묶음으로 내보내지므로 결정이 실행 전에 기록됐는지 span으로는 알 수 없습니다.
- `clockUncertaintyMs`를 정하지 않으면 시계 오차를 모르는 것으로 보아 거부와 실행의 순서를 확정하지 않습니다. 이때 거부 뒤 실행은
  `EXECUTION_AFTER_DENY`가 아니라 `DECISION_ORDER_UNCERTAIN`으로 보고됩니다.
- 같은 span을 다시 받으면 중복으로 처리됩니다. 자격 설정(`engine` 등)을 바꾼 뒤 같은 span을 다시 보내면 내용 충돌(`id_conflict`)입니다.

## 출처별 매핑과 증명 범위

| 출처 | 결정 근거 | 증명하는 것 | 증명하지 않는 것 |
|---|---|---|---|
| 직접 수집(`/api/ingest`, HMAC) | 집행 지점이 보낸 결정 기록 | 그 `enforcement` 자격이 이 내용을 보냈다는 것(요청 서명·nonce) | 실제 집행, 기록 시각의 정확성, 빠짐없음 |
| OPA 결정 로그 어댑터 | `decision_id`·`result`·`path`·`bundles` | 수집기 자격이 이 결정 로그 내용을 전달했다는 것, 묶음 리비전 digest | OPA가 서명하지 않으므로 로그가 OPA에서 바뀌지 않았다는 것, 버려진 결정이 없다는 것, 집행 |
| Cedar 어댑터(AVP CloudTrail) | `additionalEventData.decision`, 요청 | 수집기 자격이 이 CloudTrail 기록을 전달했다는 것 | CloudTrail 다이제스트 검증(하지 않음), 애플리케이션의 집행, 데이터 이벤트 기록이 켜져 있었다는 것 |
| Cedar 어댑터(Cedar 응답 로그) | `decision`·`diagnostics` | 수집기 자격이 이 로그 항목을 전달했다는 것 | 로그 항목이 실제 Cedar 호출에서 나왔다는 것, 집행 |
| OTLP 결정 span | `event.action` 등 허용 목록 속성 | `otlpDecisions`를 켠 `enforcement` 자격(bearer)이 이 span을 보냈다는 것 | 요청 서명(OTLP는 bearer만), 실행 전 기록 여부, 내보내지 않은 span, 집행 |

모든 경로에서 결정 기록은 같은 필드 허용 목록과 검증(`validateEvent`)을 거치고, 같은 결정 규칙(`EXECUTION_AFTER_DENY` 등)이 같은 방식으로
적용됩니다. 집행 여부는 어느 경로에서든 독립 도구 기록과의 비교로만 드러납니다. 이런 출처가 없는 tenant는 평가·스냅샷 해시·내보내기·검증이
이전과 같습니다.

## 내보내기·오프라인 검증·재생

레지스트리 기록(`agent_registry`·`agent_transition`·`agent_registry_policy`)은 다른 서명 객체처럼 내보내기에 들어갑니다. 검증기는 레지스트리
기록이 있는 묶음에서 생애주기를 다시 확인해 `registry` 항목으로 보고하고, 문제가 있으면 실패합니다.

```powershell
node scripts/verify.mjs export.json trust-anchor.pem --replay
node scripts/evidscope-verify.mjs bundle export.json trust-anchor.pem --replay
```

`registry`는 버전이 차례대로인지, 상태가 앞서 기록된 적용·승인 전이로만 바뀌었는지, 승인자가 등록자·구성 수정자·요청자와 다른지, 낡은
요청을 승인하지 않았는지, approved·production에서 구성이 그대로인지, 기록 서명 주체가 본문의 주체와 같은지를 확인합니다. `--replay`는
v1·v2 평가를 모두 원장 접두사에서 다시 계산합니다. 레지스트리 기록이 없는 예전 내보내기에는 `registry` 항목이 생기지 않고 결과도 이전과
같습니다. 반대로 이번 라운드 이전의 검증기로 v2 평가를 재생하면 `engine_unavailable`로 보고합니다.

## API 요약

| 경로 | 역할 | 설명 |
|---|---|---|
| `GET /api/registry` | 사람 역할 | 목록, 실효 위험 등급, 승인 대기 전이, 정책 요약 |
| `GET /api/registry/:id` | 사람 역할 | 항목, 버전 이력, 전이 기록, 가능한 전이와 게이트 미리보기, 생애주기 검증 |
| `GET /api/registry/candidates` | 사람 역할 | 미등록 후보 |
| `GET /api/registry/policy` | 사람 역할 | 적용 중인 정책(서명본 또는 기본값) |
| `POST /api/registry` | 검토자·관리자 | 등록(`draft`·`discovered`) |
| `POST /api/registry/:id` | 검토자·관리자 | 새 버전 |
| `POST /api/registry/:id/risk` | 검토자·관리자 | 위험 등급 재지정·해제 |
| `POST /api/registry/:id/transitions` | 검토자·관리자 | 전이 요청 |
| `POST /api/registry/transitions/:tid/approve`, `/refuse` | 검토자·관리자 | 승인·거절 |
| `POST /api/registry/policy` | 관리자 | 적용 방식·게이트·위험 규칙 |

화면은 감사 워크스페이스의 **AI 자산·수집 → 에이전트 레지스트리** 탭(`public/registry.js`)입니다. 목록과 미등록 후보, 상세(버전·전이 이력,
게이트 충족 여부), 등록 초안, 전이 요청과 승인·거절을 제공합니다. 역할·4-eyes·게이트는 서버가 판단하고 화면은 그 응답을 보여 줍니다.

## 현재 한계

- **차단하지 않습니다.** 정지·폐기는 기록과 발견일 뿐이며, 실제 차단은 게이트웨이와 정책 엔진의 설정이 해야 합니다.
- **서명 키를 가진 공격자**는 앞뒤가 맞는 거짓 생애주기를 새로 서명할 수 있습니다. 오프라인 검증은 vault API가 쓰는 규칙을 다시 확인할 뿐이며,
  되돌리기·갈라치기는 [투명성 로그](transparency-log.md)가 맡습니다.
- 행동 시각(`occurredAt`)과 행위자 이름은 출처의 자기 보고입니다. 출처가 시각을 앞당기면 정지 이전 활동처럼 보일 수 있으므로, 등록 항목에
  인증된 `sources`를 넣고 늦게 받은 증거(`LATE_EVIDENCE`)를 함께 봐야 합니다.
- 결정 기록이 실제로 집행됐는지, 결정 로그가 빠짐없는지는 확인하지 않습니다. OPA는 결정 로그 서명 방법을 제공하지 않아 서명 검증이 없고,
  AVP CloudTrail 다이제스트 파일 검증도 하지 않습니다.
- OTLP 결정 span은 0033 제안(제안 단계)의 `event.action` 값 `allow`·`deny`만 받습니다. `require_approval`·`modify`나 가드레일과 정책 결정의
  구분(`guardrail_decision`)은 span 속성으로 정해진 것이 없어 모두 `policy_decision`으로 기록합니다.
- 반복 거부의 창·임계값은 엔진 상수입니다. 등록 항목·정책을 쓸 때마다 tenant 전체를 다시 평가하므로 행동이 많은 tenant에서는 분석 대기열이 늘어납니다.
  평가 스냅샷에는 모든 등록 항목·정책 버전의 요약이 들어가므로, 버전이 아주 많아지면 스냅샷 한도를 넘어 평가가 `quarantined_resource_limit`로 기록됩니다.
- 운영(production) 중에도 `owner`·`purpose`·`assetIds`·`systemId`는 고칠 수 있습니다(새 버전으로 기록). 동결되는 것은 구성 필드뿐입니다.
- 레지스트리 정책은 관리자 한 사람이 바꿉니다(4-eyes 없음). 위험 등급 재지정을 한 검토자도 다른 사람이 요청한 전이는 승인할 수 있습니다.
- 에이전트 목록(`/api/agents`)의 준수 상태는 새 발견 코드를 아직 따로 분류하지 않고 "개별 검토 필요(unconfirmed)"로 둡니다.
