# 킬 스위치: 정지 명령·집행 지점 배포·전파 증거 가이드

> 2026-10-07 개선 3라운드(R3-K)에서 추가한 기능입니다. 등록 항목·생애주기·정책 결정 수집은 [에이전트 레지스트리](agent-registry.md),
> 증거 계층 전체 구조는 [증거 계층 아키텍처](evidence-layer.md)를 보세요.

## 무엇을 하고 무엇을 하지 않는가

레지스트리에서 에이전트를 정지(suspended)해도 지금까지는 기록과 발견만 바뀌었습니다. 집행 지점(게이트웨이·정책 엔진)에 정지를 알리는
경로가 없었고, 집행 지점이 정지를 언제 받아들였는지(또는 받아들이지 않았는지) 보여 주는 기록도 없었습니다.

이번 라운드는 세 가지를 더합니다.

1. **정지 명령.** 검토자·관리자 한 사람이 사유와 증거 참조를 붙여 에이전트 전체나 지정 도구를 정지합니다. 정지 명령은 모든 버전이 원장에
   남는 서명 객체(`agent_stop_order`)이며, 해제는 4-eyes입니다.
2. **pull 배포.** 집행 지점이 자기 출처 자격으로 OPA 묶음(Bundle Service API)과 DSSE 서명 거부 목록을 가져갑니다. **vault는 밖으로 아무것도
   호출하지 않습니다.**
3. **전파 증거.** OPA 상태 보고(Status API)에서 허용 목록의 메타데이터만 받아 활성화마다 `bundle_activation` 기록을 남기고, 정지 명령별로
   어느 집행 지점이 언제 활성화했는지(지연 시간)와 전파 실패·정지 불이행을 발견으로 보고합니다.

**EvidScope는 여전히 아무것도 차단하지 않습니다.** 차단은 OPA·게이트웨이가 합니다. EvidScope는 무엇을 정지하라고 했는지, 집행 지점이 언제
받아들였다고 보고했는지, 그 뒤에도 실행 기록이 있는지를 서명해 남깁니다. 정책 엔진이나 게이트웨이를 새로 만들지 않습니다.

모든 기능은 쓸 때만 동작합니다. 정지 명령과 상태 보고가 없는 tenant는 평가 결과·스냅샷 해시·내보내기·검증이 이전과 같습니다.

## 정지 단계와 EvidScope의 역할

GRC 대시보드 설계(2026-10-07)의 정지 순서를 그대로 따릅니다. 앞 단계일수록 빠르고 범위가 좁으며, 뒤 단계는 앞 단계가 집행되지 않을 때를
대비합니다.

| 순서 | 단계 | EvidScope가 하는 일 | 남는 증거 |
|---|---|---|---|
| 1 | 정책 묶음 거부 | OPA가 pull하는 묶음에 상태·정지 명령을 싣습니다(아래 Rego 예시가 거부). | 묶음 리비전, OPA 상태 보고의 활성화 기록 |
| 2 | 게이트웨이 거부 목록 | OPA를 쓰지 않는 게이트웨이가 pull하는 DSSE 서명 JSON 거부 목록을 만듭니다. | 같은 리비전. 게이트웨이가 `bundle_activation`을 직접 보내면 활성화 기록 |
| 3 | IdP 비활성화 + CAEP/SSF | **호출하지 않습니다.** 운영자가 IdP에서 에이전트 자격을 끄고 CAEP `session-revoked`·`credential-change` 이벤트를 보냅니다. | 정지 명령의 사유·증거 참조(`external` 유형으로 IdP 티켓·이벤트 id) |
| 4 | 컨테이너 중지 | **호출하지 않습니다.** 운영자나 오케스트레이터가 중지합니다. | 정지 명령의 증거 참조, 이후 실행 기록과의 비교(발견) |

3·4단계를 EvidScope가 직접 호출하지 않는 이유는 vault에 IdP·클러스터 자격을 두지 않기 위해서입니다(vault 호스트를 장악한 공격자가
IdP와 클러스터까지 조작하지 못하게). 정지 명령이 그 단계를 수행하라는 기록이 되고, 수행 증거는 증거 참조로 연결합니다.

## 정지 명령

`POST /api/registry/:id/stop`(검토자·관리자). 승인 없이 바로 적용합니다. 정지가 늦어지면 안 되기 때문입니다.

```json
{"scope": "agent", "reason": "프롬프트 주입 사고", "evidence": [{"type": "external", "ref": "INC-7"}], "enforcementPoints": ["alpha-gateway"]}
```

| 필드 | 의미 |
|---|---|
| `scope` | `agent`(전체, 기본값) 또는 `tools`(지정 도구만) |
| `tools` | `scope:"tools"`일 때 정지할 도구 이름(최대 50개, 등록되지 않은 도구도 가능) |
| `reason` (필수), `evidence` | 사유와 증거 참조. 증거 참조 규칙은 레지스트리 전이와 같습니다. |
| `enforcementPoints` | 이 명령을 담당할 집행 지점(`enforcement` 출처 자격) 추가 지정 |

등록 상태별 동작은 다음과 같습니다.

| 상태 | 전체 정지(`agent`) | 도구 정지(`tools`) |
|---|---|---|
| `production` | 같은 커밋에서 `production→suspended` 전이를 적용합니다. 전이 기록은 `stopOrderId`로, 명령은 `suspension.transitionId`로 서로를 가리킵니다. | 상태를 바꾸지 않습니다. |
| `suspended` | 상태는 그대로이고, 승인 대기 중인 복귀 요청은 `superseded`로 닫힙니다. | 상태를 바꾸지 않습니다. |
| `discovered`·`draft`·`testing`·`approved` | 상태는 그대로입니다. 명령이 살아 있는 동안 `approved`·`production`으로의 승격 요청과 승인은 409이며, 승인 대기 중인 승격 요청은 닫힙니다. 시험(`testing`) 전이는 막지 않습니다. | 상태를 바꾸지 않습니다. |
| `retired` | 409. 폐기 상태는 묶음에서 이미 거부되며 더 바꿀 수 없습니다. | 409 |

같은 에이전트에 새 명령을 내리면, 새 명령이 덮는(전체 정지는 모두, 도구 정지는 도구가 모두 포함되는) 이전 활성 명령은 `superseded`로
바뀝니다. 해제 한 번이 정지 한 번을 끝내도록 하기 위해서입니다.

## 해제(4-eyes)

- **정지(suspended) 상태 에이전트의 전체 정지**는 기존 `suspended→production` 전이로만 해제합니다. 요청자와 다른 검토자(등록자·구성 수정자도
  아닌)가 복귀를 승인하면 같은 커밋에서 그 에이전트의 활성 전체 정지 명령이 `lifted`(`lift.via:"transition"`)가 됩니다.
- **그 밖의 명령**(도구 정지, 정지 상태가 아닌 에이전트의 전체 정지)은 `POST /api/registry/stops/:oid/lift`로 해제를 요청하고, 요청자가 아닌
  검토자가 `.../lift/approve`로 승인합니다(`.../lift/refuse`는 거절). 해제를 요청한 사람은 승인할 수 없습니다(403).
- 해제·대체된 명령은 더 바꿀 수 없습니다.

## 배포 1: OPA 묶음

집행 지점마다 `enforcement` 출처 자격을 하나씩 두고([에이전트 레지스트리](agent-registry.md)의 정책 결정 수집과 같은 자격), 그 bearer
토큰으로 가져갑니다. 수집 게이트웨이(`MODE=ingress`)와 vault가 같은 경로를 제공하며, 감사 게이트웨이는 403입니다.

```
GET /api/enforcement/opa/bundles/evidscope
Authorization: Bearer <enforcement 출처 토큰>
If-None-Match: "<이전 ETag>"
```

- [OPA Bundle Service API](https://www.openpolicyagent.org/docs/management-bundles)를 따릅니다. 응답은 `Content-Type: application/gzip`의 tar.gz이며,
  `/.manifest`(`revision`, `roots:["evidscope"]`, `metadata`)와 `/data.json`(`{"evidscope": ...}`)이 들어 있습니다. 정책(`.rego`)은 넣지 않습니다.
- **리비전**은 `<seq>-<hash 앞 16자리>`입니다. 등록 항목·레지스트리 정책·정지 명령 중 가장 최근 기록의 원장 순번과 해시이므로 기록이
  늘 때마다 커지고, 증거에서 리비전만 보고도 어느 원장 상태인지 확인할 수 있습니다. 같은 리비전은 항상 같은 내용입니다.
- `ETag`는 리비전(서명할 때는 서명 키 id를 덧붙임)이고, `If-None-Match`가 같으면 304를 돌려줍니다.
- 묶음에는 그 tenant의 **등록 항목 상태·출처 자격·행위자·도구(정책 결정 필수 여부)와 활성 정지 명령**만 들어갑니다. 이름·책임자·목적·사유·증거
  참조·이벤트 내용은 넣지 않으며, 다른 tenant의 자격으로는 그 tenant의 묶음만 받습니다.
- 등록 id와 행위자 이름은 자유 문자열이라 `__proto__`·`constructor`·`toString`처럼 JavaScript 객체의 기본 속성과 같은 이름도 그대로
  싣습니다. 3라운드 구현은 이런 이름의 등록 항목·행위자를 묶음과 거부 목록에서 빠뜨려, 정지한 에이전트가 허용될 수 있었습니다(4라운드 재감사 R4-1에서 수정).

```json
{"evidscope": {"format": "evidscope-enforcement-bundle-v1", "tenant": "alpha", "revision": "57-3f1c...",
  "agents": {"mail-agent": {"state": "suspended", "stopped": true, "stopped_tools": [], "stop_orders": ["<oid>"],
    "sources": ["alpha-agent"], "actors": ["mail-agent"], "tools": {"mailer": {"enforcement": "required"}}}},
  "actors": {"mail-agent": "mail-agent"}, "sources": {"alpha-agent": "mail-agent"},
  "stop_orders": {"<oid>": {"agent": "mail-agent", "scope": "agent", "tools": [], "issued_at": "..."}}}}
```

### 묶음 서명

OPA 소스(`v1/keys`, `v1/bundle/verify.go`)를 확인한 결과 OPA가 검증하는 `.signatures.json` JWT 알고리즘은 `RS256/384/512`, `PS256/384/512`,
`ES256/384/512`, `HS256/384/512`이며 **Ed25519(EdDSA)는 없습니다.** 그래서 vault 서명 키(Ed25519)로는 묶음을 서명할 수 없습니다.
HS256은 집행 지점이 같은 비밀을 가져야 하므로 쓰지 않습니다(수집 자격과 다른 비밀이라도 집행 지점 쪽에 서명 능력을 주게 됩니다).

새 의존성 없이 Node `crypto`로 만들 수 있는 **RS256·ES256**을 선택 기능으로 제공합니다. `OPA_BUNDLE_SIGNING_KEY_FILE`에 vault 키와 다른
RSA(2048비트 이상) 또는 P-256 개인 키(PKCS#8 PEM)를 주면 `/.signatures.json`을 넣습니다. `OPA_BUNDLE_SIGNING_KEY_ID`(기본 `evidscope`)가
JWT `kid`와 `keyid`가 됩니다. 파일 해시는 OPA 규칙(구조화 파일은 키를 바이트 순으로 정렬한 정규형의 SHA-256)을 따르고, 두 파일을 그 정규형
그대로 써서 바이트 해시와 같게 했습니다. `scope` 클레임은 넣지 않으므로 OPA 쪽 `signing.scope`는 비워 둡니다.

서명 키를 주지 않으면 서명하지 않으며, 이때 묶음의 무결성은 TLS(수집 게이트웨이의 TLS 필수)와 상태 보고에 남는 리비전에 기댑니다. 받은
리비전이 원장에 없는 값이면 활성화 기록이 남지 않으므로, 중간에서 바꾼 묶음을 활성화한 집행 지점은 전파 보기에서 "미활성화"로 드러납니다.

## 배포 2: 게이트웨이 거부 목록

OPA를 쓰지 않는 게이트웨이는 같은 자격으로 `GET /api/enforcement/deny-list`를 가져갑니다(같은 ETag·304). 응답은 vault 서명 키로 서명한
[DSSE](https://github.com/secure-systems-lab/dsse) 봉투(`payloadType: application/vnd.evidscope.deny-list+json`)이며, 게이트웨이는 vault 공개 키
(`trust-anchor.pem`)로 검증합니다. `src/dsse.mjs`를 그대로 쓸 수 있습니다.

```js
import {openEnvelope, ed25519Verifier} from './dsse.mjs';
const {body} = openEnvelope(envelope, [ed25519Verifier(vaultPublicKeyPem)], {payloadTypes: ['application/vnd.evidscope.deny-list+json']});
const list = JSON.parse(body); // {format, tenant, revision, entries:[{agent, state, deny:'all'|'tools', tools, sources, actors, stop_orders}]}
```

목록에는 거부할 에이전트만 들어갑니다. 정지·폐기 상태이거나 전체 정지 명령이 있으면 `deny:"all"`, 도구 정지만 있으면 `deny:"tools"`입니다.
`discovered`·`draft`·`testing`·`approved` 상태는 시험 환경에서 정상 실행될 수 있어 목록에 넣지 않습니다(OPA 묶음에는 모든 상태가 있습니다).
게이트웨이는 `tenant`가 자기 tenant인지, `revision`의 순번이 가진 것보다 작지 않은지 확인해야 합니다. 활성화를 알리려면 HMAC 수집 경로
(`/api/ingest`)로 `bundle_activation` 기록(아래 필드)을 보냅니다.

## OPA 연결

예시 파일은 `deploy/opa/opa-config.example.yaml`(설정)과 `deploy/opa/evidscope-kill-switch.rego`(정책)입니다.

```yaml
services:
  evidscope:
    url: https://ingress.example.com/api/enforcement/opa
    credentials:
      bearer:
        token_path: /var/run/secrets/evidscope/token   # 이 집행 지점의 enforcement 출처 토큰
bundles:
  evidscope:
    service: evidscope
    resource: bundles/evidscope
    polling: {min_delay_seconds: 5, max_delay_seconds: 15}
status:
  service: evidscope        # POST <url>/status 로 활성화를 보고
```

Rego 예시는 `package killswitch`이며, 호출의 출처 자격(없으면 행위자 이름)으로 등록 항목을 찾아 `production`이 아니거나 전체 정지 명령이
있거나 도구가 `stopped_tools`에 있으면 거부합니다. 출처·행위자로 찾은 등록 id가 묶음의 `agents`에 없으면(`agent_not_in_bundle`) 역시 거부해,
조회가 어긋날 때 기본값으로 허용하지 않습니다. 묶음 루트 `evidscope`는 EvidScope 묶음이 소유하므로 정책을 그 아래 패키지에 두지 마세요.
**이 Rego는 예시이며 EvidScope 시험에서 OPA로 파싱하지 않았습니다**(저장소에 OPA 실행 파일이 없고 새로 설치하지 않았습니다). 운영에 쓰기 전에
`opa check`와 `opa test`로 확인하세요.

## 전파 증거: 상태 보고 수집

`POST /api/enforcement/opa/status`(파티션 `.../status/<name>`도 허용, 64KiB 이하)는 [OPA Status API](https://www.openpolicyagent.org/docs/management-status)
보고를 받습니다. **허용 목록만 남깁니다.**

| 남기는 것 | 버리는 것 |
|---|---|
| `labels.id`(인스턴스 id → `enforcementPointId`), `labels.version`(→ `engineVersion`), 묶음별 `name`·`active_revision`·`last_successful_activation` | 다른 라벨, `errors`·`code`·`message`·`http_code`, `metrics`, `plugins`, `decision_logs`, `discovery`, 다른 모든 필드 |

- `active_revision`이 이 tenant 원장이 만든 리비전인 묶음만 기록합니다. EvidScope 형식이 아니면 `foreign_bundle`, 형식은 맞지만 원장에 없으면
  `unknown_revision`으로 세고 아무것도 저장하지 않습니다(다른 tenant의 리비전도 여기에 걸립니다). 응답의 `ignored`가 이유별 개수입니다.
- 활성화마다 `enforcement` 출처의 `bundle_activation` 기록 하나를 남깁니다. 기록 id는 인스턴스·묶음 이름·리비전·활성화 시각에서 만들어져
  같은 보고를 다시 보내도 중복으로 처리됩니다.

| `bundle_activation` 필드 | 값 |
|---|---|
| `occurredAt` | `last_successful_activation`(집행 지점 시계) |
| `enforcementPointId`, `engine`, `engineVersion` | OPA 인스턴스 id, `opa`, OPA 버전 |
| `bundleName`, `bundleRevision` | 묶음 이름, EvidScope 리비전(`<seq>-<hash16>`) |

`bundle_activation`에는 결정·대상 필드(`decision`·`actor`·`tool` 등)를 쓸 수 없고, `enforcement` 출처만 보낼 수 있습니다. 상태 보고는 OPA가
HMAC 서명을 할 수 없어 bearer 토큰만으로 인증합니다. 토큰을 가진 쪽은 활성화를 거짓 보고할 수 있으므로, 활성화 기록은 집행 지점의 **인증된
자기 보고**입니다. 담당 여부는 보고 본문의 `labels.id`가 아니라 보고를 보낸 인증된 출처 id로 판단하므로, 한 집행 지점의 토큰으로 다른
집행 지점의 활성화를 꾸밀 수는 없습니다.

## 집행 지점과 에이전트의 연결

정지 명령을 낼 때 담당 집행 지점을 정해 명령에 서명해 고정합니다(`enforcementPoints:[{id, basis}]`). 근거는 셋입니다.

| `basis` | 의미 |
|---|---|
| `listed` | 정지 요청의 `enforcementPoints`에 지정 |
| `policy` | 레지스트리 정책 `stopPropagation.enforcementPoints`(모든 에이전트를 담당하는 중앙 게이트웨이 등) |
| `decisions_seen` | 명령 이전에 이 에이전트의 행위자에 대한 정책 결정 기록을 보낸 집행 지점 |

담당은 발령 이후 늘어나지 않습니다. 담당이 바뀌었다면 새 명령을 내리세요(이전 명령은 대체됩니다). 담당이 하나도 없으면 전파 보기에
`no_enforcement_point`로 나오고 발견도 그렇게 설명합니다.

전파 기한은 서명된 레지스트리 정책 `stopPropagation.windowSeconds`(10~86400초, 기본 300초)이며 발령 시점의 값이 명령에 고정됩니다.

```json
POST /api/registry/policy  {"stopPropagation": {"windowSeconds": 60, "enforcementPoints": ["alpha-gateway"]}}
```

## 전파 보기와 발견

`GET /api/registry/stops`(목록), `GET /api/registry/stops/:oid`(버전 이력·생애주기 검증 포함), 등록 항목 상세의 `stopOrders`가 명령마다 집행
지점별 상태를 보여 줍니다. 화면은 **에이전트 레지스트리** 탭 상세의 "정지 명령·전파"이며, 정지 버튼(사유 필수)과 해제 요청·승인도 여기에
있습니다.

- 집행 지점이 명령을 담은 리비전(명령 기록 이후, 해제·대체 기록 이전의 리비전)을 처음 활성화한 시각과 지연 시간(`latencyMs`), OPA 인스턴스
- 상태: `activated_in_window`(기한 내), `activated_late`(기한 후), `pending`(기한 전·미활성화), `overdue`(기한 초과·미활성화),
  `ended_before_activation`, 담당이 없으면 `no_enforcement_point`. 담당이 아닌 집행 지점의 활성화도 함께 보입니다.
- 명령 단위 요약(`propagation`)은 담당 집행 지점 중 가장 나쁜 상태입니다(`overdue` → `activated_late` → `pending` → `ended_before_activation`
  → `activated_in_window`). 담당 지점 하나만 기한을 넘겨도 요약은 `overdue`입니다.
- 활성화 시각은 보고된 시각을 쓰되, 그 리비전이 서명된 시각보다 앞서면 서명 시각으로 올리고 vault가 보고를 받은 시각보다 늦으면 받은
  시각으로 내립니다.

정지 명령이 있는 tenant의 행동은 평가 엔진 `evidscope-evaluate-v4`로 평가합니다. 스냅샷에 `stopOrders` 키(명령과, 명령·담당 집행 지점별 첫
활성화)가 들어가고, 정지 명령이 없는 tenant의 스냅샷은 이전(v1~v3)과 바이트 단위로 같습니다. 승인 큐(v3) 입력과 함께 있으면 v4가 둘 다 평가합니다. 판단은 행동 시점 기준이며 이벤트의 시계 오차를
포함합니다.

| 발견 | 등급 | 조건 |
|---|---|---|
| `STOP_ORDER_NOT_HELD` | high | 담당 집행 지점이 명령을 활성화한 **뒤** 정지된 에이전트(전체 또는 정지된 도구)의 도구 실행 기록이 있음. 정지가 집행되지 않았거나 우회 경로가 있음 |
| `STOP_PROPAGATION_MISSING` | high | 명령 발령 후 전파 기한이 지난 시점에 에이전트 활동이 있는데, 기한 안에 활성화를 보고한 담당 집행 지점이 없음 |
| `STOP_PROPAGATION_TIME_UNCERTAIN` | medium | 활성화 시각이 실행의 시계 오차 범위 안에 있어 순서를 확정할 수 없음 |

기존 `EXECUTION_AFTER_STOP_REQUEST`(safety 출처의 중단 요청 뒤 실행)와 `AGENT_SUSPENDED_ACTIVITY`(정지 상태의 활동)는 그대로이며 함께 나올 수
있습니다. 발견의 증거는 그 행동의 이벤트이고, 활성화 기록은 메시지와 스냅샷 입력으로만 들어갑니다.

## 내보내기·오프라인 검증·재생

정지 명령은 다른 서명 객체처럼 내보내기에 들어가고, `bundle_activation`은 이벤트로 들어갑니다. 검증기는 정지 명령이 있는 묶음에서 `stopOrders`
항목을 보고하고 문제가 있으면 실패합니다.

```powershell
node scripts/verify.mjs export.json trust-anchor.pem --replay
node scripts/evidscope-verify.mjs bundle export.json trust-anchor.pem --replay
```

`stopOrders`는 명령마다 버전이 차례대로인지, 발령 주체가 `issuedBy`인지, 발령 당시 등록 버전·상태를 가리키는지, 운영 중 전체 정지에 그 명령을
가리키는 `production→suspended` 전이가 있는지, 내용이 바뀌지 않았는지, 해제가 요청자와 다른 승인자의 승인이나 그 에이전트의 승인된 복귀 전이로만
이뤄졌는지, 정지 상태 에이전트가 해제 없이 복귀하지 않았는지, 명령이 있는 동안 승격되지 않았는지, 대체가 더 넓은 이후 명령으로만 이뤄졌는지를
확인합니다. `propagation`은 내보내기에 공개된 활성화 기록으로 계산한 집행 지점별 지연이며, 마지막 기록 시각을 "지금"으로 봅니다. `--replay`는
v4 평가도 다시 계산합니다. 정지 명령이 없는 예전 내보내기(레지스트리가 있든 없든)에는 `stopOrders` 항목이 생기지 않고 결과가 이전과 같습니다.
v4를 모르는 이전 검증기는 v4 평가를 `engine_unavailable`로 보고합니다.

## API 요약

| 경로 | 자격 | 설명 |
|---|---|---|
| `POST /api/registry/:id/stop` | 검토자·관리자 | 정지 명령 발령(운영 중 전체 정지는 정지 전이 포함) |
| `GET /api/registry/stops`, `GET /api/registry/stops/:oid` | 사람 역할 | 명령·전파 보기, 버전 이력과 검증 |
| `POST /api/registry/stops/:oid/lift`, `/lift/approve`, `/lift/refuse` | 검토자·관리자 | 해제 요청·승인(요청자 외)·거절 |
| `POST /api/registry/policy` (`stopPropagation`) | 관리자 | 전파 기한, 기본 담당 집행 지점 |
| `GET /api/enforcement/opa/bundles/<name>` | enforcement 출처 | OPA 묶음(ETag·304) |
| `GET /api/enforcement/deny-list` | enforcement 출처 | DSSE 서명 거부 목록(ETag·304) |
| `POST /api/enforcement/opa/status[/<part>]` | enforcement 출처 | OPA 상태 보고 → `bundle_activation` 기록 |

## 집행되지 않는 것·현재 한계

- **차단하지 않습니다.** 묶음을 받고도 집행 지점이 적용하지 않거나, 집행 지점을 거치지 않는 경로(직접 API 호출, 다른 게이트웨이)가 있으면
  실행은 계속됩니다. 그것은 이후 실행 기록과의 비교(`STOP_ORDER_NOT_HELD`, `AGENT_SUSPENDED_ACTIVITY`)로만 드러납니다.
- **IdP 비활성화·CAEP/SSF 전송·컨테이너 중지는 EvidScope가 하지 않습니다.** 정지 명령과 그 증거 참조가 기록일 뿐입니다.
- 활성화 기록은 집행 지점의 bearer 토큰으로 인증한 자기 보고입니다. 활성화 시각은 집행 지점 시계이며 리비전 서명 시각과
  보고 수신 시각 사이로만 묶입니다. 그 범위 안의 시각은 집행 지점이 꾸밀 수 있습니다. OPA 오류(`errors`·`code`)는 저장하지 않으므로 "받았지만 활성화 실패"는 "미활성화"로 보입니다.
- 전파 실패 발견(`STOP_PROPAGATION_MISSING`)은 기한 이후 에이전트 **활동이 있을 때** 그 행동의 평가에 나옵니다. 활동이 없으면 서명된 발견은
  생기지 않고 전파 보기의 `overdue`(조회 시점 계산)와 검증기의 `propagation`으로만 보입니다. 평가는 행동마다 이뤄지고 증거는 그 행동의
  이벤트여야 하기 때문입니다.
- 행동을 평가한 뒤에 도착한 상태 보고는 그 행동을 다시 평가하게 만들지 않습니다. 그 행동의 다음 이벤트나 레지스트리·정지 명령 변경 때 다시
  평가됩니다. 늦게 받은 보고는 전파 보기에는 바로 반영됩니다.
- 담당 집행 지점 중 하나라도 기한 안에 활성화했으면 `STOP_PROPAGATION_MISSING`은 생기지 않습니다. 일부 지점만 활성화한 부분 전파는
  전파 보기(지점별 상태와 요약 `overdue`)에서 확인하세요.
- 담당 집행 지점은 발령 때 고정됩니다. 해제가 집행 지점에 전파됐는지는 아직 따로 보여 주지 않습니다(리비전으로는 확인 가능).
- 묶음 서명 키는 vault와 같은 호스트에 둡니다. vault 호스트를 장악한 공격자는 묶음을 서명할 수 있습니다(거부 목록의 vault 키도 같습니다).
- 서명 키를 가진 공격자는 앞뒤가 맞는 거짓 정지·해제 이력을 새로 서명할 수 있습니다. 되돌리기·갈라치기는 [투명성 로그](transparency-log.md)가
  맡습니다.
