# Langfuse·Phoenix 연동: 이미 보는 trace 위에 EvidScope 판정 올리기

> 2026-10-08 개선 5라운드에서 추가한 기능입니다. 증거 계층 전체 설계는 [증거 계층 아키텍처](evidence-layer.md)를 보세요.

## 왜 trace 화면을 따로 만들지 않는가

Langfuse, Arize Phoenix, Logfire는 trace를 펼쳐 보고, 프롬프트와 지연 시간을 비교하고, 평가를 붙이는 화면이 이미 훨씬 좋습니다.
EvidScope가 같은 화면을 다시 만들면 팀은 두 곳을 오가야 하고, 그 화면은 언제나 뒤처집니다.

EvidScope가 줄 수 있는 것은 다른 데 있습니다. **운영자를 믿지 않아도 제3자가 다시 확인할 수 있는 증거**입니다. 서명된 원장,
위트니스가 공동서명한 체크포인트, 오프라인 검증기, 재생 가능한 평가가 그것입니다. 이 차별점은 사람들이 실제로 보는 곳에 나타나야
쓸모가 있습니다. 그래서 EvidScope는 판정만 만들고, 그 판정을 팀이 이미 쓰는 trace 위에 **점수(Langfuse score)와 주석(Phoenix
annotation)** 으로 올립니다. 검토자는 그 trace에서 링크 하나로 EvidScope의 증거로 돌아올 수 있습니다.

```
에이전트 ──OTel──▶ Langfuse / Phoenix  (trace, 프롬프트, 지연 시간 …)
     │                     ▲
     └─OTel·이벤트──▶ EvidScope ── 내보내기 ──▶ push-verdicts (운영자 쪽, 오프라인 검증 후)
                                                   │
                       evidscope.verified / findings / witness / recorded
```

vault는 외부로 아무것도 보내지 않습니다. 전송은 운영자가 실행하는 `scripts/push-verdicts.mjs`가 합니다.

## Langfuse와 Phoenix에 보이는 것

판정 하나는 **EvidScope 행동(action) 하나와 그 행동의 이벤트가 가리키는 OTel trace 하나**의 쌍입니다. OTLP로 들어온 span은
trace id와 span id를 그대로 가지므로 같은 trace·span에 붙습니다. SDK 이벤트는 W3C 형식(소문자 16진수 32자)의 `traceId`가 있을 때만
연결됩니다. OTel trace id가 없는 행동은 보내지 않습니다.

| 이름 | 붙는 곳 | Langfuse | Phoenix | 값 |
|---|---|---|---|---|
| `evidscope.verified` | trace | CATEGORICAL 점수 | trace 주석, label·score(1/0) | `verified`, `unverified`, `tampered` |
| `evidscope.findings` | trace | NUMERIC 점수(열린 발견 수) | trace 주석, label `open`/`none`/`unavailable`, score=개수 | 검증된 경우에만 개수 |
| `evidscope.witness` | trace | CATEGORICAL 점수 | trace 주석 label | 아래 위트니스 수준 |
| `evidscope.recorded` | span(observation) | CATEGORICAL 점수, `observationId`=span id | span 주석 | 판정과 그 span의 원장 위치 |

모든 점수와 주석에는 같은 메타데이터 `evidscope`(형식 `evidscope-verdict-v1`)가 붙습니다.

- `verdict`, `reasons`(이유 코드), `witness`, `analysis`(`current`/`pending`/`not_evaluated`/`incomplete`), `replay`
- `ledger`: 최신 서명 평가의 원장 순번·레코드 해시·평가 버전, span 주석은 그 span 이벤트의 순번·해시
- `checkpoint`: 내보내기 체크포인트의 `count`·`head`
- `findings`: 열린 발견 수, 중요도별 수, 억제된 수, 상위 코드 5개(중요도 순), `STOP_`·`APPROVAL_` 코드
- `approvals`: 이 행동의 승인 요청 상태별 수(대기·승인·거절, [승인 대기열](approval-queue.md))
- `link`: EvidScope 행동 화면 딥링크(`--link-base`를 준 경우)
- `receipt`: 내보내기 파일 SHA-256, 신뢰 앵커 키 SHA-256, 기록 영수증 위치(`/api/receipts/record?seq=N`, [영수증](receipts.md))

Langfuse의 `comment`와 Phoenix의 `explanation`에는 사람이 읽는 한 줄 요약과 딥링크가 들어갑니다. 예:

```
EvidScope verified · signed evaluation at ledger #12 of 40 (head c39efda311c464fc) · witness: signing_key_holder
· open findings 4 [AUTHORITY_MISSING, UNREGISTERED_ASSET, APPROVAL_REQUIREMENT_UNKNOWN] · evidence: https://audit.example/#action=pay-run-1
```

### 판정 값

| 판정 | 뜻 |
|---|---|
| `verified` | 운영자가 고정한 신뢰 앵커로 체크포인트 서명·해시 체인·공개된 이벤트 본문이 맞고, 요청한 투명성 조건과 서명된 등록부·승인·정지 이력 검사가 통과했으며, 이 행동의 최신 서명 평가가 재생 결과와 다르지 않습니다. |
| `tampered` | 서명은 맞는데 기록이 그 서명과 맞지 않습니다(`ledger_altered`), 고정한 체크포인트와 다릅니다(`rollback_detected`), 또는 서명된 평가를 앞선 기록으로 다시 계산하면 결과가 다릅니다(`replay_mismatch`). |
| `unverified` | 확인하지 못했습니다. 서명이 이 키로 확인되지 않거나(`checkpoint_signature_invalid`: 다른 키 또는 위조), 체크포인트가 없거나(`checkpoint_missing`), 요구한 위트니스·투명성 증거가 없거나(`transparency_not_verified`), 서명된 이력이 어긋나거나(`*_history_invalid`), 아직 평가가 없거나(`not_evaluated`), 평가가 자원 한도에서 멈췄습니다(`analysis_incomplete`). |

검증되지 않은 내보내기에서 읽은 내용은 무엇도 `verified`로 보내지 않습니다. 그런 행동에는 발견 수를 보내지 않고, 예전에 보낸 Langfuse
`evidscope.findings` 점수는 지웁니다(Phoenix는 같은 주석을 `unavailable`로 덮어씁니다). 검증되지 않은 내보내기의 trace id는 믿을 수
없지만, 그 결과는 부정 판정뿐이므로 거짓 안심을 만들지는 않습니다.

### 위트니스 수준

`evidscope.witness`는 이 판정이 **되돌리기(rollback)를 누구에 대해 배제했는지**를 그대로 옮깁니다([투명성 로그](transparency-log.md)).

| 값 | 뜻 |
|---|---|
| `vault_host` | 고정한 heads 서명기 키와 origin base 아래 신선한 위트니스 정족수. vault 호스트 전체를 장악한 공격자도 되돌릴 수 없습니다. |
| `signing_key_holder` | 고정한 origin base의 tenant 로그에 신선한 위트니스 정족수. 서명 키를 가진 공격자도 되돌릴 수 없습니다. |
| `database_tamper` | 위트니스 공동서명은 있지만 서명 키 보유자까지는 묶지 못합니다. |
| `pinned_checkpoint` | 운영자가 따로 보관한 체크포인트(`--checkpoint`, `--min-checkpoint`)와 맞습니다. |
| `none` | 되돌리기를 배제하지 못했습니다. 예전 내보내기도 같은 모양으로 검증됩니다. |

## 설정

### 1. 무엇이 필요한가

- EvidScope 신뢰 앵커 공개키(`trust-anchor.pem`): 내보내기나 API가 아니라 운영자가 따로 보관한 파일이어야 합니다.
- 내보내기를 읽을 방법: 내보내기 파일, 또는 감사 게이트웨이 주소와 감사자(auditor) 토큰 `EVIDSCOPE_TOKEN`.
- Langfuse: 프로젝트 설정의 공개키·비밀키 `LANGFUSE_PUBLIC_KEY`, `LANGFUSE_SECRET_KEY`와 기본 주소(예: `https://cloud.langfuse.com`,
  `https://us.cloud.langfuse.com`, 자체 호스팅 주소).
- Phoenix: 기본 주소(예: `https://phoenix.example`, Phoenix Cloud는 `https://app.phoenix.arize.com/s/<space>`)와 인증을 켠 경우 API 키
  `PHOENIX_API_KEY`. 키가 없으면 인증 없이 보내고 결과에 `authenticated:false`를 표시합니다.

### 2. 미리보기(기본)

```bash
export EVIDSCOPE_TOKEN=...   # auditor
node scripts/push-verdicts.mjs --evidscope https://audit.example/ --key trust-anchor.pem --tenant alpha \
  --link-base https://audit.example/ --langfuse https://cloud.langfuse.com --phoenix https://phoenix.example
```

`--send`가 없으면 Langfuse·Phoenix에 연결하지 않습니다. 출력에는 내보내기 판정, 행동별 판정, **나갈 요청 본문 전체**가 들어 있으니
보내기 전에 무엇이 나가는지 확인하세요. 내보내기를 파일로 받았다면 `--evidscope` 대신 `--export EXPORT.json`을 씁니다.

`--tenant`는 필수입니다(`--checkpoint`를 주면 그 체크포인트의 tenant가 고정값이 되고, 둘 다 주면 같아야 합니다). vault 하나의 키가 모든
tenant의 체크포인트에 서명하므로, 검증된 내보내기라도 다른 tenant 것일 수 있습니다. vault 호스트나 경로를 쥔 공격자가 다른 tenant 내보내기로
바꿔치기하면 그 tenant의 출처가 같은 trace id로 만든 "정상" 판정이 이 프로젝트에 올라갑니다. 내보내기의 tenant가 고정값과 다르면
(서명이 맞든 아니든) 판정을 하나도 만들지 않고 `mode: refused`, 이유 `tenant_mismatch`, 종료 코드 1로 끝납니다. 부정 판정도 보내지 않습니다.

[`scripts/verify.mjs`](receipts.md)와 같은 검증 옵션을 그대로 받습니다. `--checkpoint`(외부 체크포인트), `--witness`, `--quorum`,
`--origin-base`, `--max-staleness`, `--require-transparency`, `--require-tenant-witness`, `--heads-key`, `--require-heads-signer`,
`--min-checkpoint`. 평가 재생은 기본으로 켜져 있고 `--no-replay`로 끕니다.

### 3. 보내기

```bash
export LANGFUSE_PUBLIC_KEY=pk-lf-... LANGFUSE_SECRET_KEY=sk-lf-... PHOENIX_API_KEY=...
node scripts/push-verdicts.mjs --evidscope https://audit.example/ --key trust-anchor.pem --tenant alpha --link-base https://audit.example/ \
  --langfuse https://cloud.langfuse.com --phoenix https://phoenix.example --send
```

종료 코드는 0(내보내기 검증, 요청한 전송 모두 성공), 1(내보내기 미검증 또는 전송 오류), 2(사용법 오류)입니다. 주기적으로(예: 15분마다)
실행하면 늦게 도착한 증거로 생긴 새 발견이 같은 점수·주석을 갱신합니다.

- **Langfuse**: `POST /api/public/ingestion`의 `score-create` 이벤트로 보냅니다(Basic 인증, 공개키:비밀키). 이벤트 봉투 id는 보낼 때마다 새로 만들고, 응답 207의 이벤트별 오류를
  확인합니다. 검증되지 않은 행동의 발견 점수는 `DELETE /api/public/scores/{id}`로 지웁니다(404는 이미 없음으로 봅니다).
- **Phoenix**: `POST /v1/trace_annotations?sync=true`, `POST /v1/span_annotations?sync=true`(Bearer 인증). `annotator_kind`는 `CODE`입니다.
  Phoenix에 없는 trace·span은 404가 되며, 그 묶음은 하나씩 다시 보내 없는 항목만 `notFound`로 셉니다(오류가 아닙니다).

### 4. 다시 실행해도 겹치지 않는 이유

- Langfuse는 점수 `id`, `name`, 타임스탬프의 날짜가 모두 같을 때만 기존 점수를 바꿉니다. 점수 id는 tenant·행동·trace·이름(·span)에서
  만든 고정 UUID이고, 타임스탬프는 **그 trace의 이 행동 첫 이벤트를 vault가 받은 시각**(원장 `recordedAt`)이라 바뀌지 않습니다.
  `POST /api/public/scores`는 서버가 현재 시각을 넣으므로 날짜가 바뀐 재실행에서 중복이 생깁니다. 그래서 Langfuse가 점수용으로 계속
  받는다고 밝힌 ingestion의 `score-create` 이벤트를 씁니다(2026-11-16 Cloud v3 종료 뒤에도 `score-create`만은 받습니다).
- Phoenix는 (이름, trace 또는 span, `identifier`)가 같으면 덮어씁니다. `identifier`는 tenant·행동에서 만든 고정 값입니다.

### 5. 서로 오가는 링크

- **도구 → EvidScope**: `--link-base https://audit.example/`을 주면 comment·explanation과 메타데이터에
  `https://audit.example/#action=<행동 ID>`가 들어갑니다. 감사 화면은 로그인 뒤 이 행동의 조사 화면을 엽니다. 행동 ID가 식별자 규칙에
  맞지 않으면 열지 않습니다.
- **EvidScope → 도구**: vault 환경 변수 `TRACE_LINKS_FILE`에 URL 템플릿 JSON 배열을 두면 행동 조사 화면과 Trace ID로 검색한 이벤트
  화면에 같은 trace로 가는 링크가 나타납니다.

```json
[
  {"name": "Langfuse", "url": "https://cloud.langfuse.com/project/<프로젝트 ID>/traces/{traceId}"},
  {"name": "Phoenix", "url": "https://phoenix.example/projects/<프로젝트 ID>/traces/{traceId}"}
]
```

  템플릿은 최대 4개, https만, `{traceId}`는 호스트 뒤(경로·쿼리)에만 올 수 있고, 잘못되면 vault가 시작하지 않습니다. 실제 주소 모양은
  도구 버전마다 다를 수 있으니 그 도구에서 trace 하나를 열어 주소를 복사하고 trace id 자리를 `{traceId}`로 바꾸세요. vault는 링크를
  만들기만 하고 그 주소에 접속하지 않습니다. 링크는 새 탭에서 referrer 없이 열립니다. `config.json`과 따로 둔 이유는 복구 뒤
  `config.json` 변경에는 서명된 재바인딩이 필요하기 때문입니다([vault 복구](vault-recovery.md)).

## 무엇이 나가고 무엇이 나가지 않는가

나가는 것은 판정, 이유 코드, 발견 **코드**(메시지 아님), 중요도별 개수, 승인 요청 상태별 개수, 원장 순번·해시, 체크포인트 크기·head,
위트니스 수준, tenant와 행동 ID, OTel trace·span id, 딥링크, 내보내기·키 다이제스트입니다. 메타데이터는 이 허용 목록으로만 만듭니다.

나가지 않는 것은 이벤트 본문 전부(행위자, 도구, 리소스, 목적지, 메모, 목적, 모델, 데이터 참조, AI 관측 내용)와 발견 메시지입니다.
발견 메시지는 리소스 이름 같은 원본 값을 담을 수 있어 보내지 않습니다. 시험은 이런 필드에 넣은 표지 문자열(canary)이 Langfuse·Phoenix로
가는 요청 어디에도 없음을 확인합니다. 행동 ID와 tenant는 vault의 식별자 규칙에 맞는 값만 보냅니다.

## 판정이 증명하는 것과 증명하지 않는 것

증명하는 것:

- 이 판정을 만든 사람이 아니라 **운영자가 고정한 키**로 서명된 원장에, 이 trace를 가리키는 행동의 이벤트와 그 행동의 평가가 이 순번에
  들어 있습니다. 같은 내보내기와 키로 누구나 `scripts/verify.mjs EXPORT.json KEY.pem --replay`를 다시 실행해 같은 결과를 얻습니다.
- 평가의 발견은 앞선 서명 기록만으로 다시 계산한 결과와 같습니다(재생을 끄지 않은 경우).
- `witness`가 `none`이 아니면 그 수준에 맞는 상대에 대해 되돌리기가 배제됐습니다.

증명하지 않는 것:

- trace의 내용이 사실이라는 것. 출처가 보고한 값을 인증된 출처가 보냈다는 것까지만 묶입니다([증거 계층](evidence-layer.md)).
- Langfuse·Phoenix에 보이는 trace가 EvidScope가 받은 것과 같다는 것. 두 도구의 데이터는 EvidScope 밖에 있고, 같은 trace id를 쓴다는
  것만 연결 근거입니다.
- 점수·주석 자체의 진위. 도구 관리자나 같은 API 키를 가진 누구나 `evidscope.verified=verified` 점수를 직접 쓸 수 있습니다. 점수는
  안내판이고, 판단은 딥링크와 메타데이터의 내보내기 다이제스트·원장 순번으로 **EvidScope 증거를 다시 검증해서** 내려야 합니다.
- `witness: none`인 `verified`는 예전 내보내기일 수 있습니다. 공격자가 예전에 정상이던 내보내기를 다시 보내게 만들면 더 늦게 생긴
  발견이 가려질 수 있으니, 운영에서는 위트니스나 고정 체크포인트를 함께 쓰세요.
- 서명 키를 가진 사람은 일관된 거짓 이력을 서명할 수 있습니다. 이는 오프라인 검증기 전체의 한계와 같습니다.

## 네트워크와 자격 증명

- 모든 대상은 https만 받습니다. 시험용으로 루프백 주소(`127.0.0.1`, `[::1]`, `localhost`)만 http를 허용합니다. URL에 사용자 정보·쿼리·
  fragment가 있으면 거부합니다. 경로 접두사(자체 호스팅 하위 경로)는 유지합니다.
- 리다이렉트는 따라가지 않고 오류로 처리합니다(`redirect: manual` 후 3xx 거부). 자격 증명이 다른 호스트로 가지 않습니다.
- 응답은 1 MiB(내보내기는 512 MiB)까지만 읽고, 요청마다 15초 제한, 네트워크 오류·429·5xx만 최대 3번 시도합니다. `Retry-After`는
  5초까지만 따릅니다. 4xx는 다시 보내지 않습니다. 같은 id를 쓰므로 재시도는 중복을 만들지 않습니다.
- 자격 증명은 환경 변수에서만 읽고 출력·오류 메시지에 넣지 않습니다. 출력 전에 환경 변수 값이 섞였는지 한 번 더 지웁니다. `--send` 없이
  실행하면 Langfuse·Phoenix 자격 증명은 읽지도 않습니다.
- 신뢰 앵커는 `--key` 파일로만 받습니다. API 응답이나 내보내기에 든 키는 쓰지 않습니다.

## 확인한 외부 문서(2026-10-08)

- Langfuse 공개 API OpenAPI(서버 4.54.0): `langfuse/langfuse` 저장소 `web/public/generated/api/openapi.yml`
  (`https://cloud.langfuse.com/generated/api/openapi.yml`과 같은 파일). `POST /api/public/scores`, `POST /api/public/ingestion`의
  `score-create`, `ScoreBody`, `ScoreDataType`(NUMERIC, BOOLEAN, CATEGORICAL, CORRECTION, TEXT), `DELETE /api/public/scores/{scoreId}`, Basic 인증.
- Langfuse 문서(`langfuse/langfuse-docs`): `docs/evaluation/evaluation-methods/scores-via-sdk`(멱등 키와 id·name·날짜 규칙),
  `faq/all/tracing-data-updates#updating-scores`, `docs/evaluation/scores/data-model`(`source`: API·EVAL·ANNOTATION),
  `docs/api-and-data-platform/features/public-api`, `integrations/native/opentelemetry/migration-to-v4`(OTel trace id·span id가 trace·observation).
  `POST /api/public/scores`가 타임스탬프를 현재 시각으로 넣는 것은 `web/src/features/public-api/server/scores-api-service.ts`에서 확인했습니다.
- Phoenix REST API OpenAPI(20.19.0): `Arize-ai/phoenix` 저장소 `schemas/openapi.json`의 `/v1/trace_annotations`, `/v1/span_annotations`
  (`annotator_kind` LLM·CODE·HUMAN, `result.label/score/explanation`, `identifier`, `metadata`, `sync`). (이름, 대상, identifier) 덮어쓰기와
  `sync=true`의 404는 `src/phoenix/server/api/routers/v1/spans.py`·`traces.py`, Bearer 인증은 `src/phoenix/server/bearer_auth.py`에서 확인했습니다.

시험은 실제 서비스가 아니라 위 요청 모양을 검사하는 로컬 모의 서버를 씁니다(`test/push-verdicts.test.mjs`).

## 현재 한계

- 판정 단위는 행동입니다. 한 trace에 행동이 여럿이면(예: OTLP의 trace 행동과 도구 실행 span 행동) 같은 trace에 판정 점수가 여럿
  붙고, 각 메타데이터의 `actionId`로 구분합니다. span 점수는 trace당 100개까지입니다.
- 검증되지 않은 내보내기에서 원장 `recordedAt`이 바뀌어 있으면 Langfuse 타임스탬프 날짜가 달라져 `tampered` 점수가 예전 `verified`
  점수를 바꾸지 못하고 옆에 하나 더 생길 수 있습니다. Phoenix는 identifier로 덮어쓰므로 이 문제가 없습니다.
- Langfuse Cloud의 공개 API는 쓰기 반영이 몇 분 늦을 수 있습니다. Phoenix에 아직 없는 trace는 다음 실행에서 붙습니다.
- Logfire는 아직 대상이 아닙니다. 같은 판정 매핑에 대상만 추가하면 됩니다.
- 마지막으로 보낸 체크포인트를 기억하지 않으므로, 더 오래된 내보내기를 막는 것은 위트니스·고정 체크포인트의 몫입니다.
