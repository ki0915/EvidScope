# 개선 라운드 기록

각 라운드는 **부족한 점 재감사 → 바퀴의 재발명 여부 확인 → 차별점 구현** 순서로 진행하고, 끝날 때 다음 라운드 후보를 남깁니다.
방향과 근거는 [증거 계층 아키텍처](evidence-layer.md)를 보세요.

## 1라운드 (2026-10-06)

출발점은 같은 날의 적대적 감사입니다. 감사는 이 제품을 "SIEM이 아니라 서명된 AI 에이전트 행위 증거 원장의 동작하는 로컬 파일럿"으로
판정했고, 유일한 차별점인 변조 증거가 관리자·호스트 공격자에게는 의미가 없다고(S1·S2) 지적했습니다. 아래 S·F 번호는 감사와 재검토 보고서의 번호입니다.

### 방향

- 이름과 설명을 "AI 에이전트 행위 증거 계층"으로 바꾸고 SIEM 표현을 내렸습니다.
- 수집·저장·검색·상관분석은 만들지 않고 표준에 붙입니다(OpenTelemetry, OCSF, C2SP, 기존 위트니스).
- 직접 만드는 것은 증거 원장, 외부 위트니스와 묶인 투명성 로그, 오프라인 검증기·정책 재생, 한국 규제 증거 묶음으로 좁혔습니다.

### 감사 결함 처리

| 감사 항목 | 처리 | 확인 |
|---|---|---|
| S1 키 없이 tenant 삭제·과거 사본 롤백 미탐지 | RFC 6962 tenant 로그 + C2SP 체크포인트 + heads 로그를 독립 위트니스가 공동서명. enforce 모드는 rollback·fork·tenant 삭제 시 시작 거부·격리. `notChecked`를 정직하게 표시 | `test/transparency-server.test.mjs`, `test/litewitness-interop.test.mjs` |
| S2 서명 키에서 데이터 키 유도 | HKDF 용도별 데이터 키를 별도 비밀로 분리, 키 ID를 AAD에 묶음, 분리된 vault의 예전 방식 백업 거부 | `test/data-key-separation.test.mjs`, `test/data-key-cli.test.mjs` |
| S2 서명 키 보유자의 tenant 단위 되돌리기(재검토 F1) | heads 행마다 tenant 크기가 줄지 않는지 vault가 확인하고 줄어드는 행은 위트니스에 내지 않음. 선택 기능 `witnessTenantLogs`로 tenant 로그를 각자의 origin으로 위트니스에 제출해 위트니스가 직접 되돌리기를 거부, 검증 결과에 `rollbackCheckedAgainst`(`database_tamper`·`signing_key_holder`)와 `--require-tenant-witness` 추가. heads 이력 재생 모니터(`transparency.mjs monitor`). 남은 범위: 신선도 창, 복구 epoch, 미등록 tenant, 키 보유자의 tenant 삭제(모니터로만 탐지) | `test/transparency-anchors.test.mjs`, `test/transparency-tenant-witness.test.mjs`, `test/litewitness-interop.test.mjs` |
| S4 파기 후 SQLite 잔여 페이지 | `secure_delete` + WAL truncate | `test/erasure-remnants.test.mjs` |
| S5 조회마다 원장 증가·전체 재검증·쓰기 락 | 검증 상태 증분 캐시, 열람 기록을 원장 밖 봉인 로그로 이동, GET은 읽기 전용 스냅샷, 커버링 인덱스 | `test/verified-state-reads.test.mjs`, `test/access-log.test.mjs`, `test/read-transactions.test.mjs` |
| S7 전역 분석 적체로 tenant 간 수집 차단 | tenant별 적체 계산, OTLP 배치는 남길 적체로 판단 | `test/otlp-ingest.test.mjs`, `test/otlp-http.test.mjs` |
| S6, S8~S12 | 진행 중(worker tenant 바인딩, 로그인 폭주, 4-eyes, 자기주장 증거 표시, 인증 전 본문 버퍼링, 복구 후 설정 재바인딩) | |
| S3 이벤트 키를 같은 DB에 평문 보관 | 목적이 파기임을 문서에 명시. KEK 감싸기는 2라운드 후보 | [데이터 키 분리](data-key-separation.md) |
| 품질: CI·린터 없음, 비공개 산출물 의존 테스트 | GitHub Actions 워크플로, 의존성 없는 소스 검사(`npm run check`, 새 파일 160자·긴 줄 증가 금지), 시험 fixture 정리, 비공개 산출물 시험은 이유와 함께 skip | `.github/workflows/`, `scripts/check-source.mjs` |

### 바퀴의 재발명 점검

| 영역 | 이전 | 1라운드 결정 |
|---|---|---|
| 수집 | stdin 파이프, 자체 형식 | OTLP/HTTP `/v1/traces` 수신. 실제 OTel Collector 0.140·OTel JS SDK와 상호운용 시험 통과. 본문 제거·버퍼링은 Collector에 맡김 |
| Merkle·체크포인트 | 자체 해시 체인만 | RFC 6962와 C2SP signed-note·tlog-checkpoint. C2SP 시험 벡터로 검증 |
| 외부 앵커 | 없음 | 위트니스 서버는 만들지 않고 litewitness·OmniWitness(C2SP tlog-witness) 사용. 실제 litewitness와 rollback 거부·fork 422 시험 |
| SIEM 연동 | 없음 | OCSF Detection Finding(2004) 1.3.0·1.9.0 직렬화만 구현. 상관분석·UEBA는 만들지 않음 |
| 정책 | 자체 규칙 | 새 정책 언어를 만들지 않고 OPA·Cedar·AGT 결정을 증거로 받음. 결정적 `evaluate()`만 유지 |

직접 구현한 것 중 재발명 논란이 있는 것은 두 가지입니다. OTLP protobuf 디코더와 C2SP 라이브러리는 vault의 무의존성 원칙
(공급망 표면 최소화) 때문에 직접 썼고, 각각 실제 Collector·SDK·litewitness와 바이트 단위 상호운용 시험으로 보정했습니다.
의존성 정책이 바뀌면 `@opentelemetry/otlp-transformer`와 `golang.org/x/mod/sumdb/note` 계열 구현으로 교체할 수 있습니다.

### 차별점 진행

| 차별점 | 1라운드 결과 |
|---|---|
| D1 위트니스 공동서명·되돌리기 거부 로그 | 구현. 운영 가이드 [투명성 로그](transparency-log.md) |
| D2 권한에 묶인 증거 사슬과 오프라인 정책 재생 | 구현. `verify.mjs --replay`, `replay-findings.mjs` |
| D3 조문 단위 한국 규제 증거 묶음 | 기존 기능 유지. 법률 검토는 미완료 |
| D4 검증 가능한 최소화·파기 | S4 수정, 데이터 키 분리 |
| D5 위트니스 체크포인트에 연결된 OCSF | 구현. `GET /api/export/ocsf`, `scripts/export-ocsf.mjs` |

### 적대적 재검토

구현 후 별도 검토자가 공격자 입장에서 PoC를 만들어 확인했습니다. 찾은 문제와 처리입니다.

| # | 문제 | 처리 |
|---|---|---|
| F1 | 서명 키 보유자가 heads 잎 안에서 tenant 하나만 되돌려도 위트니스가 공동서명 | `witnessTenantLogs`(선택)로 tenant 로그도 위트니스에 제출: 위트니스가 tenant 되돌리기를 거부하고, enforce 시작 검사는 위트니스가 더 큰 tenant 로그를 가지면 거부. 검증 결과는 보증 수준을 `rollbackCheckedAgainst`로 표시(heads만이면 `database_tamper`). PoC는 신선한 tenant 공동서명이 없어 `--require-tenant-witness`에서 실패. 키 보유자의 tenant 삭제는 heads 모니터로만 탐지 |
| F2 | monitor 모드가 rollback 뒤에도 pin을 덮어써 흔적을 지움 | pin은 일관성이 확인된 방향으로만 이동, 위반 뒤에는 고정 |
| F3 | pin 파일이 없으면 첫 기동처럼 통과 | 새 vault는 크기 0 pin을 먼저 기록, 기존 로그는 `pin-bootstrap`으로 명시적으로 고정 |
| F4 | 사례 보고서 이벤트에 순번·해시가 없으면 포함 증명 없이 통과 | 순번·해시 필수, 서명된 tenant 트리에 포함된 것만 허용 |
| F5 | 위트니스 응답을 끝까지 버퍼링 | 64 KiB까지만 읽고 나머지 스트림 취소 |
| F6 | 시작 시 위트니스 조회와 DB 확인 사이 경쟁 조건 | 조회한 heads 루트를 기록해 같은 DB인지 확인, startupProbe 정족수 요구 |
| F7 | 실행 중 tlog 상태가 사라지면 갈라진 이력을 다시 봉인 | 재구성은 시작 시에만, 실행 중에는 추가를 거부 |
| F8 | heads 행이 tenant 수만큼 커짐 | 바뀐 tenant 항목만 저장 |
| OTLP | 인증 전 디코딩으로 메모리 증폭(2,470 ms → 80 ms, 384 MB 힙 OOM 해소), vault 경로 우회, 백업 다운그레이드 | 인증 먼저, 구조 예산, 배치 적체 게이트, 분리 유지 검사 |

### 측정

| 항목 | 감사 시점(로컬 사본) | 1라운드 후 |
|---|---|---|
| 전체 시험 | 1,023개 중 1,013 통과·9 실패·1 skip | 1,155개 중 1,149 통과·0 실패·6 skip(비공개 산출물 의존, 이유 표시) |

조회 지연(18,337행, 같은 컨테이너, ms):

| API | 이전 | 이후 |
|---|---|---|
| governance | 1,046.9 | 2.5 |
| events | 1,058.5 | 1.9 |
| overview | 628.5 | 24.3 |
| cases | 218.9 | 1.0 |
| investigations | 3,821.6 | 61.8 |
| alerts | 334.0 | 24.3 |
| review-context | 917.7 | 3.1 |
| integrity(전체 재검증) | 1,803.8 | 3,219.5 |

GET 95회가 만들던 원장 레코드는 95건에서 6건(봉인 배치)으로 줄었습니다. 대신 전체 재검증(`/api/integrity`)과 시작 시간(657 → 1,687 ms)은
투명성 상태와 열람 로그 검증이 더해져 늘었습니다.

수집 벤치마크(`scripts/benchmark.mjs`, 감사와 같은 컨테이너, 원본 스냅샷과 개선본을 번갈아 3회씩, 투명성 로그 꺼짐):

| 항목 | 원본(3회 범위) | 개선본(3회 범위) |
|---|---|---|
| burst 처리량(동시 20) | 261~294 EPS | 269~318 EPS |
| burst p95 | 114~192 ms | 88~154 ms |
| sustained(20 EPS 고정) p95 | 59~77 ms | 11~12 ms |
| 조사함 조회 p95 | 143~148 ms | 26~37 ms |
| 단일 사례 보고서 p95 | 186~266 ms | 6~7 ms |

처리량은 쓰기 프로세스가 하나라 그대로입니다. 개선본 2회차의 normal 구간 p95 295 ms 한 번은 다른 회차에서 재현되지 않았습니다.
투명성 로그를 켠 상태의 처리량 측정은 2라운드에서 합니다.

### 남은 한계

- 서명 키와 데이터 키를 같은 vault 프로세스가 읽습니다. HSM·KMS 또는 서명 전용 프로세스 분리는 아직입니다.
- 실제 고객 환경 연동, 운영 부하 측정, 법률 검토를 거친 매핑은 없습니다.
- 사례 보고서에 복구 epoch 정보가 없고, 열람 로그의 아직 봉인되지 않은 끝부분은 vault 재시작 전까지 서명되지 않습니다.
- 파기(retention)와 보조(assistance) 경로는 아직 전체 스캔입니다. 전체 재검증과 시작 시간이 늘었습니다.
- enforce로 운영하던 배포는 업그레이드 시 pin 부트스트랩과 startupProbe를 확인해야 하며, 바뀐 heads 행은 예전 빌드가 읽지 못합니다.
- Kubernetes 매니페스트에 pin 전용 볼륨이 없습니다.

## 2라운드 후보

1. 서명 키 격리: 데이터 볼륨을 마운트하지 않는 서명 전용 프로세스, 이후 KMS·PKCS#11 연동(S2 잔여).
2. 이벤트 키 감싸기(KEK)와 `payloadHash` HMAC 커밋먼트(S3).
3. SCITT·in-toto DSSE 호환 영수증 내보내기와 무의존성 검증기 CLI 분리 공개(감사 권고, 결정 4).
4. heads 모니터를 운영 경로로: `scripts/transparency.mjs monitor`(모든 heads 잎을 재생해 tenant별 단조 증가·삭제를 확인, 1라운드 F1에서 추가)를 정기 작업으로 돌리고 `status --probe`와 묶어 위트니스가 공동서명한 heads 로그와 대조. 키 보유자의 tenant 삭제를 시작 검사에서 잡는 방법도 검토.
5. 시작·전체 재검증 비용 줄이기(검증 상태 스냅샷), 파기·보조 경로 인덱스화.
6. 데모가 OTLP 경로로 AI 가시성 화면을 채우도록(감사 3.2: 데모 후에도 관측 0).
7. Kubernetes 매니페스트에 pin 볼륨·위트니스 설정, enforce 업그레이드 절차 자동 점검.
8. D3: 법률 검토용 조문 매핑 패키지, ISMS-P·AI 기본법 하위 고시 정렬.
