# OpenTelemetry로 EvidScope에 GenAI 증거 보내기

EvidScope는 별도 수집기를 요구하지 않습니다. 이미 쓰고 있는 OpenTelemetry SDK나 Collector가 GenAI span을
**OTLP/HTTP**로 수집 게이트웨이(ingress)의 `POST /v1/traces`에 보내면 됩니다. 수신 측은 허용 목록에 있는 메타데이터만
읽어 최소화된 증거 이벤트로 바꾸고, 프롬프트·응답·도구 인자 같은 본문은 저장하지 않습니다.

```
앱(OTel SDK) ──OTLP──▶ 에지 Collector(이 디렉터리 설정) ──OTLP/HTTP gzip + Bearer──▶ EvidScope ingress /v1/traces ──▶ vault
```

## 1. 자격 준비

- OTLP 출처는 tenant마다 `kind: "otlp"` 원칙(principal)을 씁니다. Bearer 토큰만 쓰며 HMAC 비밀값을 두지 않습니다.
  로컬에서는 `node scripts/init.mjs`가 `alpha-otlp`, `beta-otlp`를 만듭니다. 운영 `config.json`에는 다음처럼 추가합니다.
  ```json
  {"id": "acme-otlp", "tenant": "acme", "role": "source", "kind": "otlp", "token": "<32자 이상 임의값>"}
  ```
- 이 토큰은 `/v1/traces`에서만 쓸 수 있습니다. 기존 HMAC 수집 경로(`/api/ingest`)나 조회 API에서는 거부됩니다.
- 토큰은 환경 변수나 비밀 저장소로만 전달하고 설정 파일에 직접 쓰지 마세요.

## 2. 권장 구성: 에지 Collector

`evidscope-collector.yaml`은 Collector **core 배포판**(0.140 이상) 구성 요소만 씁니다.

- `filter/genai-only`: `gen_ai.operation.name` 또는 `openinference.span.kind`가 없는 span을 보내지 않습니다.
- `filter/genai-content-events`, `attributes/drop-genai-content`: 본문이 담기는 span event와 속성(`gen_ai.input.messages`,
  `gen_ai.output.messages`, `gen_ai.tool.call.arguments`, OpenLLMetry `gen_ai.prompt.N.*`, OpenInference `input.value` 등)을
  **고객 네트워크 안에서** 지웁니다. EvidScope도 수신 시 허용 목록으로 다시 거르지만, 본문이 망 밖으로 나가지 않게 하는 것이 목적입니다.
- `batch`: 요청당 최대 1,024 span. EvidScope 한도(8,192 span, 압축 4 MiB / 해제 8 MiB)보다 충분히 작아야 합니다.
  413은 재시도되지 않아 그대로 버려집니다.
- `otlphttp/evidscope`: protobuf + gzip, `Authorization: Bearer ${env:EVIDSCOPE_OTLP_TOKEN}`, 재시도·대기열 사용.

```sh
export EVIDSCOPE_OTLP_ENDPOINT=https://evidscope-ingress.example.com:8080/v1/traces
export EVIDSCOPE_OTLP_TOKEN=...            # tenant의 otlp 토큰
export EVIDSCOPE_CA_FILE=/etc/evidscope/ca.pem   # 사설 CA일 때
otelcol validate --config evidscope-collector.yaml
otelcol --config evidscope-collector.yaml
```

앱은 이 Collector(`127.0.0.1:4317` gRPC 또는 `127.0.0.1:4318` HTTP, `OTELCOL_OTLP_*_ENDPOINT`로 변경)로 보냅니다.
Kubernetes에서는 Collector Pod에 `evidscope.io/client: collector` 라벨을 붙여야 ingress NetworkPolicy를 통과합니다.

### 이미 Collector가 있다면

기존 파이프라인 옆에 EvidScope 전용 파이프라인을 추가하세요. 위 파일의 `processors`와 `exporters.otlphttp/evidscope`를 복사하고
`service.pipelines`에 `traces/evidscope`를 넣으면 됩니다. 기존 APM 파이프라인은 그대로 둡니다.

## 3. SDK에서 직접 보내기 (Collector 없이)

OTLP/HTTP만 지원합니다(gRPC는 Collector로 변환하세요). 표준 환경 변수로 설정합니다.

```sh
OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=https://evidscope-ingress.example.com:8080/v1/traces
OTEL_EXPORTER_OTLP_TRACES_PROTOCOL=http/protobuf        # 또는 http/json
OTEL_EXPORTER_OTLP_TRACES_COMPRESSION=gzip
OTEL_EXPORTER_OTLP_TRACES_HEADERS="Authorization=Bearer%20<토큰>"
```

GenAI 계측 라이브러리의 본문 수집은 꺼 두세요(`OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT` 미설정,
OpenLLMetry는 `TRACELOOP_TRACE_CONTENT=false`). 직접 전송 시에는 본문이 EvidScope ingress 메모리까지는 도달합니다(저장은 안 함).

저장된 OTLP 내보내기 파일은 `node scripts/replay-otlp.mjs <url>/v1/traces FILE...`로 다시 보낼 수 있습니다
(토큰은 `EVIDSCOPE_OTLP_TOKEN` 환경 변수). 예전 `collect-ai-observations.mjs otlp` 모드는 폐기되었습니다.

## 4. 응답과 재시도

| 응답 | 의미 | 송신 측 동작 |
|---|---|---|
| 200, 본문 없음/`{}` | 전부 저장 또는 이미 저장됨(같은 span 재전송은 중복으로 처리) | 완료 |
| 200 + `partialSuccess` | 일부 span 미저장. 사유: `not_genai`, `unsupported_operation`, `invalid_span_context`, `invalid_time`, `future_time`, `id_conflict`(같은 span ID에 다른 내용), `invalid_event` | 재시도 안 함. Collector 경고 로그 확인 |
| 400 / 401 / 403 / 413 / 415 | 해석 불가, 토큰 오류, otlp 자격 아님, 크기 초과, 형식·압축 미지원 | **재시도 없이 폐기**. 경보로 감시하세요 |
| 503 + `Retry-After` | 해당 tenant의 분석 적체, 저장소·vault 일시 장애 | Collector/SDK가 지정 시간 후 재시도 |

응답 본문은 요청과 같은 Content-Type(`application/x-protobuf` 또는 `application/json`)의 `ExportTraceServiceResponse` 또는
`google.rpc.Status`입니다. 분석 적체 한도는 tenant별이므로 한 tenant가 밀려도 다른 tenant의 수집은 막히지 않습니다.

서버 측 조정 값(ingress/vault 환경 변수): `OTLP_MAX_BODY_BYTES`(4 MiB), `OTLP_MAX_DECODED_BYTES`(8 MiB), `OTLP_MAX_SPANS`(8192),
`OTLP_MAX_INFLIGHT`(8), `OTLP_FORWARD_TIMEOUT_MS`(15000), `ANALYSIS_BACKLOG_LIMIT_PER_TENANT`(10000, vault).
수신기는 본문을 읽기 전에 vault에 Bearer 토큰을 확인하고(토큰 해시별 결과를 허용 30초·거부 5초 캐시), 해석 비용은 `OTLP_MAX_SPANS`에서
정한 구조 한도로 묶습니다: ResourceSpans+ScopeSpans ≤ 4×, 속성(KeyValue)+배열 값 ≤ 64×(JSON은 객체·배열 ≤ 64×, 값 ≤ 128×,
최소 64/4,096). 넘으면 413입니다. 분석 적체 한도는 묶음이 새로 추가할 행동 수까지 더해 판단하며, 적체가 0이면 한도보다 큰 묶음도 받습니다.

## 5. 무엇이 어떻게 기록되나 (매핑 `otel-genai-map-1`)

| span | EvidScope 기록 | 주요 값 |
|---|---|---|
| `chat`, `text_completion`, `generate_content`, `embeddings` (OpenInference `LLM`, `EMBEDDING`) | `notice` + AI 관측(`aiObservation`), 같은 trace는 하나의 행동 `otel-trace:<trace>` | provider, model(응답 모델 우선), 토큰 수, 목적지 host/port |
| `execute_tool` (OpenInference `TOOL`) | `self_report`, 행동 `otel:<trace>:<span>` | 도구 이름, 성공/실패 |
| `invoke_agent`, `create_agent` (OpenInference `AGENT`) | `self_report` | 에이전트 ID/이름, 모델. 토큰은 하위 호출의 합계이므로 **세지 않음** |
| 기타 GenAI 작업(retrieval, memory, workflow 등) | provider나 model이 있으면 `notice`(토큰 미집계), 없으면 미저장 | |

- 이벤트 ID는 `otel:<traceId>:<spanId>`라서 재전송·중복 전송이 안전합니다. JSON과 protobuf, SDK와 Collector 어느 경로로 와도 같은 기록이 됩니다.
- 상태: span status `ERROR` 또는 `error.type`이 있으면 실패, `UNSET`/`OK`는 성공(OTel 규약상 성공 시 UNSET).
- `gen_ai.provider.name`과 폐기 예정 `gen_ai.system`, `gen_ai.usage.prompt_tokens/completion_tokens`도 읽습니다.
- 행위자(actor)는 `gen_ai.agent.name` → `gen_ai.agent.id` → `service:<service.name>` 순입니다. 모두 **자기 신고**입니다.
- AI 가시성 화면의 자산은 `otel-service:<service.name>`으로 표시되고 처음에는 미등록 후보입니다. 같은 ID로 자산을 등록하면
  등록 자산으로 대조합니다(그 tenant의 OTLP 출처가 보고한 서비스 이름을 받아들인다는 뜻입니다).
- 에이전트 화면은 OTLP `self_report`를 보고된 행위자별로 묶고, 같은 trace의 모델 호출을 그 에이전트의 모델로 보여 줍니다.
  모니터링의 `telemetryFailures`는 OTLP span이 스스로 보고한 오류 수입니다.

## 6. 보증 수준과 한계

- OTLP 기록의 `assurance`는 `authenticated_telemetry_report`입니다. 인증된 출처가 보낸 **에이전트 자체 텔레메트리**이며
  독립된 도구 실행 증거가 아닙니다. 따라서 OTLP만으로는 에이전트 화면의 "준수"가 되지 않고 미확인으로 남습니다.
- Bearer 토큰은 TLS 종단·ingress에서 보입니다. 토큰을 가진 쪽은 같은 tenant 출처로 기록을 만들 수 있으니 주기적으로 교체하세요.
- 샘플링·Collector 재시작(core 배포판 대기열은 메모리)으로 빠진 span은 EvidScope가 알 수 없습니다. 증거 등급 전달이 필요하면
  contrib 배포판의 `file_storage` 확장으로 영속 대기열을 쓰세요.
- 매핑 버전이 바뀐 뒤 이전 span을 다시 보내면 `id_conflict`로 거부될 수 있습니다(기존 기록은 덮어쓰지 않음).
- `self_report`에는 부모 span 관계가 아직 저장되지 않으며, 5분보다 긴 span은 시작 시각 기준으로 늦은 증거(`LATE_EVIDENCE`)로 표시될 수 있습니다.
