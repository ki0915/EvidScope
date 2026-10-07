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
| S6 worker 자격 하나로 모든 tenant 복호화 사본 수신·임의 결과 서명 | worker를 config `tenants` 목록(없으면 자기 `tenant`)에 묶어 claim·적체·commit 제한. vault가 같은 snapshot으로 `evaluate()`를 다시 계산해 다른 결과는 422로 거부. `suppressedBy`는 승인된 예외만 | `test/worker-tenant-binding.test.mjs` |
| S8 활성 복구 후 토큰 회전·principal 추가 시 기동 거부 | `vault-backup.mjs rebind`로 vault 키 서명 재바인딩 연쇄와 외부 pin 기록. 기동 시 검증하고 원장에 `recovery_config_rebinding` 기록 | `test/recovery-config-rebinding.test.mjs` |
| S9 익명 `/auth/login` 폭주로 OIDC 로그인 5분 잠김 | 로그인 흐름(state·nonce·PKCE verifier·만료)을 vault 메모리 대신 AES-256-GCM으로 봉인한 5분 쿠키에 보관. callback은 state 대조·1회 사용 | `test/oidc-login-flood.test.mjs` |
| S10 auditor의 사건 종결·예외 확정 | 사건을 열거나 다시 연 사람은 종결 불가(4-eyes). 예외는 다른 reviewer·admin이 대기 중 요청을 한 번 승인해야 효력. README 역할 표 정정 | `test/four-eyes.test.mjs` |
| S11 자기주장 증거만으로 평가 완료, 1인 작성·법률 검토·종결 | 보고서에 `evidenceAssurance`(`self_asserted` 등) 표시. 법률 검토는 작성자가 아닌 reviewer·admin이 평가 해시에 남긴 확인으로만 `reviewed`. 작성자는 과제 종결 불가 | `test/governance-separation.test.mjs` |
| S12 인증 전 본문 버퍼링, 토큰 비교 전 재생, URIError 503, 롤백 시 문서 고아 | 큰 본문 경로는 본문 수신 전 인증(gateway는 vault `/internal/preauthorize`). run 토큰을 상수 시간 비교 후 재생. 잘못된 퍼센트 인코딩은 400. 롤백된 문서 파일 삭제 | `test/request-hardening.test.mjs` |
| S3 이벤트 키를 같은 DB에 평문 보관 | 목적이 파기임을 문서에 명시. KEK 감싸기는 2라운드 후보 | [데이터 키 분리](data-key-separation.md) |
| 품질: CI·린터 없음, 비공개 산출물 의존 테스트 | GitHub Actions 워크플로, 의존성 없는 소스 검사(`npm run check`, 새 파일 160자·긴 줄 증가 금지), 시험 fixture 정리, 비공개 산출물 시험은 이유와 함께 skip | `.github/workflows/`, `scripts/check-source.mjs` |

#### S6·S8~S12에서 운영자가 알아야 할 변경

- **worker 바인딩:** `scripts/init.mjs`가 만드는 `analysis-worker`는 `tenants:["alpha","beta"]`를 가진다. 기존 로컬 설정의 `tenant:"internal"` worker는 목록이 없어도 `synthetic-local`에서 모든 tenant를 계속 처리한다. `enterprise` 프로필은 목록 없는 `internal` worker로 기동하지 않는다. vault가 결과를 다시 계산하므로 분석 CPU가 행동당 약 두 배이고, vault와 worker는 같은 분석 엔진 버전이어야 한다. 불일치 결과는 lease를 `rejected`로 닫고(서명 원장 밖) 같은 행동을 다시 배정한다.
- **4-eyes:** auditor는 사건을 계속 만들 수 있지만 자신이 열거나 다시 연 사건은 종결하지 못한다. 거버넌스 평가의 `legalReview:"reviewed"` 입력은 작성자의 주장으로만 표시되며, `POST /api/governance/assessments/:id/legal-review`로 다른 reviewer·admin이 확인해야 한다. 기존 평가도 확인 전까지 `legalStatus:"pending"`이다. 법률 검토자는 과제를 종결할 수 있고 평가 작성자는 종결할 수 없다(2인 규칙. 세 사람을 모두 분리하려면 종결 검사에 법률 검토자 조건 한 줄을 추가한다).
- **로그인 흐름:** 흐름 쿠키는 vault 프로세스마다 새로 만드는 키로 봉인한다. 로그인 도중 vault가 재시작되면 그 흐름은 실패하고 다시 로그인해야 한다(이전의 메모리 표와 같다). 429 한도는 없어졌다.
- **요청 처리:** 문서·공급사 묶음·OTLP JSON·worker 결과·보조 결과 본문은 인증·역할 확인 뒤에만 읽는다. 잘못된 퍼센트 인코딩은 400이다.
- **복구 후 설정 변경:** [복구 안내](vault-recovery.md)의 config rebinding 절차를 따른다. `scripts/upgrade-local.mjs`는 복구된 vault의 설정을 직접 고치지 않고 이 절차를 안내한다.

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
| 전체 시험 | 1,023개 중 1,013 통과·9 실패·1 skip | 1,189개 중 1,183 통과·0 실패·6 skip(비공개 산출물 의존, 이유 표시) |

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

수집 벤치마크(`scripts/benchmark.mjs`, 감사와 같은 컨테이너, 원본 스냅샷과 최종본을 번갈아 3회씩, 투명성 로그 꺼짐):

| 항목 | 원본(3회 범위) | 최종본(3회 범위) |
|---|---|---|
| burst 처리량(동시 20) | 276~298 EPS | 270~286 EPS |
| burst p95 | 137~151 ms | 119~145 ms |
| sustained(20 EPS 고정) p95 | 57~69 ms | 11~12 ms |
| 조사함 조회 p95 | 150~170 ms | 25~28 ms |
| 단일 사례 보고서 p95 | 154~171 ms | 6.7~7.5 ms |

최종본은 S6 수정으로 vault가 worker의 분석 결과를 다시 계산하는데도 1,000건 모두 분석되었고 적체는 0이었습니다.
처리량은 쓰기 프로세스가 하나라 그대로입니다. 투명성 로그를 켠 상태의 처리량 측정은 2라운드에서 합니다.

### 남은 한계

- 서명 키와 데이터 키를 같은 vault 프로세스가 읽습니다. HSM·KMS 또는 서명 전용 프로세스 분리는 아직입니다.
- 실제 고객 환경 연동, 운영 부하 측정, 법률 검토를 거친 매핑은 없습니다.
- 사례 보고서에 복구 epoch 정보가 없고, 열람 로그의 아직 봉인되지 않은 끝부분은 vault 재시작 전까지 서명되지 않습니다.
- 파기(retention)와 보조(assistance) 경로는 아직 전체 스캔입니다. 전체 재검증과 시작 시간이 늘었습니다.
- enforce로 운영하던 배포는 업그레이드 시 pin 부트스트랩과 startupProbe를 확인해야 하며, 바뀐 heads 행은 예전 빌드가 읽지 못합니다.
- Kubernetes 매니페스트에 pin 전용 볼륨이 없습니다.

## 2라운드 (2026-10-07)

아래 2라운드 후보 10번의 적대적 재감사가 1라운드 수정에서 확인 결함 4건과 가능성 있는 결함 1건을 찾았습니다.
재감사 PoC는 판정을 뒤집어 회귀 시험으로 남겼습니다. 수정 전 코드에서는 실패하고 수정 후 통과합니다.

### 재감사 결함 처리

| 재감사 항목 | 처리 | 확인 |
|---|---|---|
| S6(중간) 같은 ID의 worker 항목이 tenant 범위를 공유. alpha 전용 자격이 beta 복호화 사본을 받고 beta 평가에 서명 | 설정 적재·config rebinding·`scripts/upgrade-local.mjs`에서 principal ID 중복 거부. 분석 범위와 lease를 인증한 자격(토큰 SHA-256 지문)에 묶고 `analysis_leases.credential`에 기록, claim한 자격만 `/internal/complete` 가능 | `test/worker-duplicate-id.test.mjs` |
| S9(낮음~중간) 익명 login/callback 한 쌍마다 IdP token 요청. 사용한 state 기록이 1만 개를 넘으면 오래된 것부터 버려 재전송 callback이 token endpoint에 도달 | IdP 요청 전에 프로세스 전체 token bucket(`tokenExchangesPerMinute` 기본 60, burst 20)과 동시 교환 4개 제한, 초과 시 `/?auth=failed`. 사용 기록은 흐름 만료까지 유지(용량 burst + 5 × 분당 값), 만료 항목만 삭제, 가득 차면 fail closed | `test/oidc-callback-replay.test.mjs` |
| S11(낮음) 작성자가 `legalReview:"reviewed"`라고 쓰면 법률 검토 과제가 생기지 않아 작업 목록에서 사라짐 | 충분 평가를 포함한 모든 평가가 과제를 열고, 작성자가 아닌 확인 전에는 종결 불가. 기존 자기 확인 평가는 다음 기동 때 `legal-review-task-migration-v1`이 과제를 한 번 보충 | `test/legal-review-claim-task.test.mjs` |
| S11(낮음) 작성자가 직접 올린 합성 공급사 묶음이 `supplier_signed_bundle`·`source_bound`로 표시 | 라벨을 `vault_retained_supplier_bundle`로 바꾸고, 합성이 아니며 평가 작성자가 아닌 사람이 출처를 확인한 묶음만 source-bound. 나머지는 `self_asserted` | `test/supplier-bundle-assurance.test.mjs` |
| 가능성(낮음) 한 worker 자격이 lease를 무제한 보유, 끝난 lease 행이 계속 쌓임 | 자격당 살아 있는 lease 64개 상한. 만료·거부된 lease 행은 claim 후 24시간이 지나면 다음 claim 때 삭제(완료 행은 보존) | `test/worker-duplicate-id.test.mjs` |

#### 운영자가 알아야 할 변경

- **자격 설정:** principal ID는 역할과 관계없이 고유해야 합니다. 중복이 있으면 vault는 DB를 열기 전에 기동을 거부하고, config rebinding과 `scripts/upgrade-local.mjs`도 거부합니다. 배포마다 worker ID를 따로 주세요.
- **worker lease:** lease는 claim한 토큰에 묶입니다. 업그레이드 때 진행 중이던 lease와 토큰 회전 전에 받은 lease는 다시 claim해야 합니다. 같은 토큰을 쓰는 replica를 합쳐 살아 있는 lease는 64개까지이며, 상한에서는 빈 작업 목록을 받습니다.
- **법률 검토 과제:** 작성자가 `reviewed`로 입력해도 과제가 열립니다. 업그레이드 후 첫 기동에서 기존 자기 확인 평가에 "법률 적용성 검토(작성자 자기 확인만 있음)" 과제가 생길 수 있습니다.
- **증거 보증 라벨:** 보고서·API의 `supplier_signed_bundle`은 `vault_retained_supplier_bundle`이 되었고, 작성자 본인이 올리거나 확인한 묶음은 `self_asserted`로 내려갑니다. 이 라벨을 읽는 도구를 확인하세요.
- **로그인:** IdP token 교환은 기본 분당 60회·동시 4개로 제한됩니다. 폭주 중에는 실제 사용자 로그인도 `/?auth=failed`가 될 수 있으므로 프록시에서 IP별 제한을 함께 두세요. 1라운드에서 없앤 429 한도와 달리 `/auth/login`은 제한하지 않습니다.

### 바퀴의 재발명 점검

| 영역 | 2라운드 결정 |
|---|---|
| 영수증 형식 | 자체 형식을 만들지 않고 [DSSE v1](https://github.com/secure-systems-lab/dsse)·[in-toto Statement v1](https://github.com/in-toto/attestation)과 C2SP `tlog-proof`·`tlog-policy`를 씀. Go 독립 구현(torchwood `VerifyProof`, `golang.org/x/mod/sumdb/note`)과 교차 검증 |
| 서명 키 보관 | 키 저장소는 만들지 않음. 파일 외에 ssh-agent 프로토콜(하드웨어 키·OS 키 저장소)과 외부 명령(클라우드 KMS CLI)에 맡기고, 직접 만든 것은 heads 잎의 규칙을 검사하는 얇은 서명기뿐 |
| 이벤트 키 | 표준 봉투 암호화(KEK가 DEK를 감쌈, AES-256-GCM의 AAD로 tenant·키 ID·순번을 묶음). KMS는 인터페이스만 두고 SDK 의존성은 더하지 않음 |
| 숨김 커밋먼트 | 이벤트마다 32바이트 salt를 둔 HMAC-SHA256. 새 암호 구성을 만들지 않음 |
| ISMS-P | 인증기준 원문(고시 [별표 7])과 KISA 세부점검항목을 근거로 그대로 쓰고 자체 통제 체계를 만들지 않음 |
| 실시간 통제(설계만) | 실행 추적 화면, 호출 가로채기, 허용 판단은 Langfuse·Phoenix, AI·MCP 게이트웨이, OPA·Cedar·AGT에 맡기는 구조로 설계 |

직접 구현한 것 중 재발명 논란이 있는 것은 DSSE와 `tlog-policy` 파서입니다. vault의 무의존성 원칙 때문에 직접 썼고, DSSE 명세 시험 벡터와
Go 독립 검증기로 보정했습니다. RFC 9942 COSE 영수증은 CBOR·COSE 코드가 새로 필요하고 상호운용 도구가 없어 만들지 않았습니다.

### 차별점 진행

| 차별점 | 2라운드 결과 |
|---|---|
| D1 되돌리기·삭제 거부 로그 | heads 로그 서명 키를 vault 밖의 [heads 서명기](signer.md)로 옮겼습니다. 서명기는 루트를 스스로 계산하고 tenant 로그가 빠지거나 줄거나 같은 크기에서 바뀌거나 일관성 증명 없이 자라는 잎에는 서명하지 않습니다. 서명기 키를 `--heads-key`로 고정한 검증자는 새 수준 `rollbackCheckedAgainst:"vault_host"`를 받습니다(3라운드부터 `--origin-base` 고정도 필요) |
| D2 권한에 묶인 증거 사슬 | 내보내기·사건 보고서를 `?attest=intoto`로 받으면 같은 바이트를 subject로 하는 DSSE 증명이 함께 나오고, `GET /api/receipts/record?seq=N`이 레코드 하나의 `c2sp.org/tlog-proof@v1`을 냅니다. 의존성 없는 `evidscope-verify` 묶음을 따로 배포할 수 있습니다([표준 영수증](receipts.md)) |
| D3 한국 규제 증거 묶음 | 국내 접속으로 고시를 다시 확인했습니다(아래). ISMS-P 인증기준 101개 항목과 [항목 단위 참고 정렬](isms-p-alignment.md)을 만들어 27개 항목에는 증거가 닿는 확인사항 위치와 사람이 할 일을, 74개에는 제외 사유를 적었습니다. `scripts/isms-p-report.mjs`는 내보내기를 먼저 검증한 뒤 항목별 증거 건수·기간을 뽑습니다. 증거가 있다는 것이 기준 충족 판정은 아닙니다 |
| D4 검증 가능한 최소화·파기 | 원장에 salt를 넣은 커밋먼트만 서명하고 이벤트 키를 키 epoch 비밀로 감쌌습니다. epoch를 파기하면 모든 DB 사본과 vault 백업에서 그 기간을 읽을 수 없습니다([이벤트 키 감싸기](event-key-wrapping.md), 감사 S3) |
| D5 OCSF 발견사항 | OTLP 모델 호출의 목적지(없으면 모델 이름)를 `resources`에 담았습니다 |

#### 공격 재현 결과

- **서명 키 보유자의 tenant 되돌리기(재검토 F1):** 시작 커밋 cf45e19에서는 vault 키를 가진 공격자가 tenant를 7건에서 5건으로 되돌린 heads 잎을 만들면
  실제 litewitness가 공동서명하고(200), 5건짜리 내보내기가 `rollbackChecked:true`로 검증됐습니다. 서명기를 쓰면 위트니스는 403, 서명기는 422 rollback으로
  거부하고, 서명기 키를 고정한 새 내보내기는 `vault_host`로 검증됩니다. 서명기 없이 운영하면 같은 공격은 여전히 성공합니다(문서에 적음).
- **파기한 이벤트 추측 확인(S3):** 9177cee에서는 지운 이벤트 `status-11`을 원장의 `payloadHash`와 수집 영수증의 원문 해시로 확인할 수 있었습니다.
  v2 레코드에서는 확인되지 않습니다(`test/event-commitments.test.mjs`).
- **영수증 변조:** subject 1바이트, payload 비트, 서명 키, 레코드, 정책, 로그 키, 체크포인트 변조를 우리 검증기, 따로 묶은 `evidscope-verify`, Go 검증기가
  모두 거부합니다.

#### 고시와 ISMS-P 원문 확인

- 2026-10-07 국내 접속으로 국가법령정보센터 Open API의 행정규칙을 다시 조회했습니다. 과학기술정보통신부 소관 2026-01-01~10-06 발령분 182건(본부 67건,
  그중 고시 49건)에서 인공지능기본법 하위 고시는 제2026-50호(「인공지능제품ㆍ서비스 확인 절차 운영에 관한 고시」, 2026-07-21) 하나였고, 매핑이 기다리는
  여섯 고시의 최종본은 없었습니다. 관보는 대조하지 않았으므로 상태는 미확인 그대로입니다([법령 출처](legal-sources.md)).
- ISMS-P 인증기준은 「정보보호 및 개인정보보호 관리체계 인증 등에 관한 고시」(2024-07-24 일부개정·시행) [별표 7]을 원문으로 받았고, KISA 인증기준
  안내서(2023.11.23)와 세부점검항목(2023.10.31, 확인사항 328개)을 함께 받아 SHA-256을 기록했습니다. 2024-07-24 개정 이유에 [별표 7]이 없어
  인증기준 자체는 바뀌지 않은 것으로 보입니다.

### 측정

- 전체 시험(Linux 컨테이너, litewitness·OTel Collector·OTel JS·Go 시험 포함): 시작 1,189건 → 2라운드 끝 1,275건(통과 1,269건). 실패 0, 건너뜀 6은 시작과 같은 항목입니다.
- 이벤트 키 감싸기 비용(1,000건, `scripts/benchmark.mjs`와 프로세스 안 측정, 범위는 반복 실행의 최소~최대):

| 측정 | 시작(9177cee) | DB 모드 | 키스토어 모드 |
|---|---|---|---|
| 수집, 이벤트당 ms | 3.0–3.4 | 3.1–3.5 | 3.45–3.47 |
| 1,000건 내보내기, ms | 99–130 | 140–166 | 199–250 |
| 1,000건 전체 복호화, ms | 85–120 | 123–134 | 202–218 |
| `/api/integrity`, ms | 372–383 | 548–600 | 699–840 |
| 순간 처리량, 이벤트/초 | 233 | 231 | 215 |
| 조사 질의 p95, ms | 28.4 | 28.0 | 32.1 |

읽기 비용의 대부분은 이벤트마다 하는 HMAC 커밋먼트, 감싸기 키 HKDF, GCM 풀기(각각 약 20~25µs)입니다. epoch별 키 캐시로 줄일 수 있습니다.

### 운영자가 알아야 할 변경(2라운드 기능)

- **검증기:** 2라운드 이후의 내보내기는 2라운드 검증기가 필요합니다. 1라운드 검증기는 v2 커밋먼트와 서명기가 서명한 앵커를 거부합니다.
- **이벤트 키스토어:** `npm run upgrade:local`과 새 로컬 설치는 `.local/event-keystore/`를 만들고 기존 키를 옮깁니다. 이 폴더가 없으면 어떤 이벤트도 읽을 수
  없으므로 vault 백업과 따로, 자주 백업하고 epoch를 파기한 뒤에는 오래된 키스토어 백업도 지워야 합니다. Kubernetes 매니페스트는 아직 DB 모드입니다.
- **중복 판정:** 수집 영수증 지문이 `fp2:`로 바뀌었습니다. 같은 본문의 재전송은 계속 중복으로 처리되지만, epoch를 파기한 뒤의 재전송은 409를 받습니다.
- **heads 서명기:** 설정에 `signer`를 넣을 때만 켜집니다. 기존 vault 키 heads 로그는 위트니스가 24시간 안에 공동서명한 체크포인트에서 handover하고,
  첫 서명기 체크포인트가 공동서명되면 위트니스에서 vault 키를 지워야(`witness.mjs del-key`) 보호가 완성됩니다. 로컬은
  `npm run upgrade:local -- --heads-signer`, Kubernetes는 `deploy/heads-signer-overlay.mjs`(sidecar 또는 별도 Deployment)입니다.

### 남은 한계

- EvidScope는 여전히 사후 관측 설계라 어떤 호출도 실시간으로 막지 못합니다. 결정 로그 수신·격리 명령·승인 대기열은 3라운드 후보입니다.
- 서명기: 장악된 vault가 앵커를 멈추는 공격은 막지 못하며(`vault_host`는 앵커된 이력만 보장), 보호는 handover 시점부터입니다. Windows 이름 있는 파이프,
  AWS·GCP KMS 명령 예시, Kubernetes overlay의 실제 기동은 시험하지 못했습니다.
- 영수증: 레코드 영수증 하나마다 tenant 트리를 다시 계산합니다(O(n)). 내보내기의 `issuedAt`은 vault 시계이고, `quorum none` 영수증은 vault 키만 증명합니다.
- 키: 업그레이드 전 v1 레코드는 salt 없는 해시를 유지합니다. 운영 중인 `evidence.db`와 디스크 사본에는 평문 검색 사본이 남습니다(vault 백업만 제외).
  tenant 삭제를 근거로 한 epoch 파기, 키스토어 백업 명령은 없습니다.
- 규제: 고시 최종본의 관보 대조와 법률 검토는 하지 않았습니다. ISMS-P 정렬은 사람 검토 전 초안이며 인증 판정이 아닙니다.
- 문서 정정: 이전 문서가 금융위원회 금융분야 AI 가이드라인과 금융감독원 AI RMF를 조문 단위로 매핑했다고 적었지만 `data/requirements.json`에는
  해당 항목이 없었습니다. 2라운드에서 문서를 데이터에 맞췄습니다.
- 모든 시험은 Linux 컨테이너에서만 돌렸습니다.

### 2라운드 후보 처리 결과

| 후보 | 결과 |
|---|---|
| 1. 서명 키 격리 | heads 서명기로 완료. KMS·하드웨어 키는 ssh-agent·명령 백엔드로 연결(KMS 예시는 미시험). 레코드·tenant 체크포인트는 여전히 vault 키로 서명 |
| 2. 이벤트 키 KEK와 HMAC 커밋먼트 | 완료 |
| 3. DSSE 영수증과 검증기 분리 | 완료. SCITT·COSE 영수증은 미구현 |
| 4. heads 모니터 운영 경로 | 서명기가 서명 시점에 tenant 삭제·축소를 거부하는 것으로 일부 대체. 정기 모니터는 미구현 |
| 5. 시작·전체 재검증 비용 | 미구현. 키스토어 모드에서 `/api/integrity`가 약 2배 느려져 더 중요해짐 |
| 6. 데모 OTLP | 완료. 데모가 OTLP GenAI span을 보내 AI 가시성 화면이 채워짐 |
| 7. Kubernetes 매니페스트 | heads 서명기 overlay만 완료. pin·키스토어 볼륨, enforce 업그레이드 점검은 미구현 |
| 8. 고시·ISMS-P | 국내 접속 재확인과 ISMS-P 항목 단위 정렬 완료. 법률 검토와 관보 대조는 미완료 |
| 9. Windows 시험 | 미실시. PC에 Node.js v24.15.0이 있음을 확인 |
| 10. 적대적 재감사 | 완료(위 표) |

## 3라운드 (2026-10-07, 진행 중)

출발점은 아래 3라운드 후보입니다. 후보 14번의 적대적 재감사를 먼저 하고, 같은 날 설계한 "에이전트 통합 관리·GRC 감사 대시보드"의
구현 순서(후보 1~6)를 따릅니다. 이번 라운드에서 끝낸 것은 재감사 수정, 레지스트리와 수명 주기(후보 1), 정책 결정 수집(후보 2),
위험 등급 규칙(후보 5의 절반)이며, 격리 명령·배포(후보 3)와 사람 승인 대기열(후보 4)은 구현 중입니다.

### 재감사 결함 처리

재감사는 2라운드에서 추가한 heads 서명기, 이벤트 키스토어, 영수증·검증기, ISMS-P 보고서를 공격자 입장에서 다시 살폈습니다.
결함마다 수정 전 코드(9a15b5f)에서 실패하는 재현 시험을 회귀 시험으로 남겼습니다.

| 재감사 항목 | 처리 | 확인 |
|---|---|---|
| F2(높음) DB 쓰기 권한만 있는 공격자가 `event_keystore_usage.moved_at`을 지우고 epoch 행을 심으면, 다음 기동 때 그 행이 키스토어로 들어가 살아 있는 epoch가 파기되고 이후 epoch 비밀이 공격자가 아는 값이 됨 | 키스토어 폴더의 `moved.json`으로 첫 이전을 기록하고, 이전이 끝난 키스토어에는 DB의 epoch 행을 다시 들이지 않음 | `test/event-keystore-planted-epochs.test.mjs` |
| F1(중간) 복구 epoch 승인에서 vault가 만든 `claims.json`이 서명한 크기와 같거나 큰 다른 이력을 주장하면 손실 목록에 나오지 않고 서명됨 | 서명기가 같은 크기 이상의 다른 이력을 fork로 거부하고, 손실은 크기 제한 없이 모두 표시 | `test/signer-epoch-claims.test.mjs` |
| F3(중간) `tlog-proof --policy --key`가 정책의 첫 로그 줄만 고정 키와 비교해, 같은 origin에 다른 키를 한 줄 더 적은 가짜 영수증이 통과 | origin의 모든 정책 로그 키가 고정 키여야 통과 | `test/tlog-policy-pinned-key.test.mjs` |
| A(중간) 은퇴한 heads origin을 위트니스가 계속 공동서명해 epoch 이전 내보내기가 `vault_host`로 보임 | 검증 계약 변경: `--origin-base`를 고정하고 그 base의 heads 체크포인트일 때만 `vault_host`. `--require-heads-signer`에는 `--origin-base`가 필요(없으면 `evidscope-verify` 종료 코드 2) | `test/heads-signer-retired-origin.test.mjs` |
| 낮음: 인증 전 TLS 상대 하나가 서명기 연결 64개를 모두 붙잡아 vault 요청이 실패 | TLS 핸드셰이크 5초 제한, 주소당 연결 8개(`maxConnectionsPerAddress`, 초과는 `counters.refusedConnections`) | `test/signer-tls-slots.test.mjs` |
| 개선: 다른 origin이 active인데 `authorize-genesis` 실행 | 승인은 만들되 active origin과 `authorize-epoch`·`revoke --id`를 알리는 경고 | `test/signer-genesis-warning.test.mjs` |

결함이 아니라고 판단한 것: 사건 보고서 검증기가 v2 커밋먼트를 대조하지 않는 점(스냅샷이 vault 키로 서명됨), ISMS-P 보고서 Markdown의
"되돌리기 확인"에 수준이 빠진 점(JSON의 transparency 블록에 있음). `tlog-policy` 파서, DSSE PAE와 subject 검사, ISMS-P Markdown·HTML
이스케이프, 키스토어 AAD 바꿔치기, v2→v1 강등, 검증기 묶음의 파일 범위는 다시 확인했고 결함이 없었습니다.

### 바퀴의 재발명 점검

| 영역 | 3라운드 결정 |
|---|---|
| 정책 판단 | 정책 엔진을 만들지 않음. 게이트웨이·OPA·Cedar·AGT가 내린 결정을 `enforcement` 출처의 기록으로 받고, OPA는 문서화된 결정 로그 형식을 어댑터로 변환(`input`·`result` 본문은 버리고 허용 목록 메타데이터만) |
| 추적 화면 | 만들지 않음. 실행 추적은 Langfuse·Phoenix에 두고 레지스트리 화면은 기존 감사 워크스페이스의 탭 하나 |
| 수명 주기 | 단계는 대시보드 설계 문서의 수명 주기를 그대로 썼습니다. 새로 만든 것은 전이를 서명 기록으로 남기는 부분과 4-eyes·게이트 검사뿐이며, 저장·4-eyes는 기존 자산·규칙의 방식을 재사용 |
| 위험 등급 | 설문 대신 등록된 도구·데이터 범주·목적지에 대한 규칙(서명된 정책 데이터)으로 계산하고, 검토자 재지정도 기록 |
| 에이전트 목록 | 자동 등록하지 않음. 이미 보이는 미등록 출처·행위자(`/api/agents`, `UNREGISTERED_ASSET`)를 후보로만 나열. 기존 카탈로그(Backstage, A2A Agent Card)에서 가져오기는 아직 없음 |

### 차별점 진행

| 차별점 | 3라운드 결과 |
|---|---|
| D1 되돌리기·삭제 거부 로그 | 재감사로 서명기·키스토어·영수증의 결함 4건을 고치고 `vault_host` 판정 조건을 좁혔습니다(위 표) |
| D2 권한에 묶인 증거 사슬 | [에이전트 레지스트리](agent-registry.md): 에이전트마다 서명된 등록 객체와 모든 버전, 별도 서명 기록인 상태 전이(discovered→draft→testing→approved→production⇄suspended, 어디서든 retired), 승인 전이의 4-eyes, 위험 등급별 게이트를 정책 데이터로 둡니다. 평가 엔진 v2가 행동 시점의 등록 상태로 정지·폐기·미등록 에이전트의 활동을 보고하고, 오프라인 검증기가 생애주기를 다시 확인합니다 |
| D2 결정과 실행의 대조 | 집행 지점의 `policy_decision`·`guardrail_decision`을 받아 거부 후 실행, 결정 필수 도구의 결정 누락, 승인 요구 후 무승인 실행, 반복 거부를 같은 `actionId`의 독립 도구 기록과 비교합니다. 결정 기록은 "그렇게 결정했다"는 인증된 기록일 뿐 집행 증거가 아니라는 점을 문서에 적었습니다 |

레지스트리·결정 기록이 없는 tenant는 평가 스냅샷과 해시가 이전과 바이트 단위로 같고, 2라운드 검증기는 새 내보내기의 사슬을 검증하면서
v2 평가만 `engine_unavailable`로 보고합니다. 2라운드 내보내기(`test/fixtures/pre-registry-export-9a15b5f.json`)는 이전과 똑같이 검증·재생됩니다.

### 측정

- 전체 시험(Linux 컨테이너, litewitness·OTel Collector·OTel JS·Go 시험 포함): 2라운드 끝 1,275건 → 재감사 병합 후 1,284건 → 레지스트리 병합 후
  1,307건(통과 1,301건). 실패 0, 건너뜀 6은 시작과 같은 항목입니다.
- 재감사 병합 직후 한 번 실패한 `transparency-signer` 시험은 두 번의 검증 사이에 벽시계가 1초 넘어가면 `ageSeconds`가 달라지는 시험 자체의 문제였습니다
  (수정 전 코드에서도 20회 중 3회 실패). 같은 시각으로 두 번 검증하게 고쳤습니다.

### 운영자가 알아야 할 변경(3라운드)

- **검증기:** `vault_host`를 받으려면 `--heads-key`와 함께 `--origin-base`를 고정해야 합니다. `--require-heads-signer`만 주면 사용법 오류입니다.
  복구 epoch 뒤에는 새 base로 다시 고정하고, 위트니스에서 예전 origin 키를 지우세요([heads 서명기](signer.md) 복구 epoch 6·7단계).
- **heads 서명기:** TLS 리스너는 핸드셰이크 5초, 주소당 연결 8개로 제한됩니다. 한 NAT 주소 뒤의 vault 여러 개는 이 한도를 나눠 씁니다.
- **이벤트 키스토어:** 첫 이전 뒤 키스토어 폴더에 `moved.json`이 생깁니다. 키스토어 백업에 함께 넣으세요. 이전 전 DB 사본을 이전된 키스토어 옆에
  복원하면 epoch 행이 다시 들어오지 않고 무결성 점검에 표시됩니다.
- **레지스트리·결정 수집:** 켜야 동작합니다. 집행 지점마다 `kind:"enforcement"` 출처 자격을 두고, OPA는 `scripts/collect-opa-decisions.mjs`로 보냅니다
  (기본은 미리보기). 레지스트리 정책(적용 방식·게이트·위험 규칙)은 관리자만 바꿉니다. 레지스트리가 든 내보내기는 3라운드 검증기가 생애주기까지 확인하며,
  생애주기가 맞지 않으면 종료 코드 1입니다.

### 남은 한계

- EvidScope는 여전히 아무것도 차단하지 않습니다. 정지·폐기는 기록과 발견이며, 집행 지점에 알리는 배포와 전파 증거는 구현 중입니다.
- 서명 키 보유자는 앞뒤가 맞는 거짓 생애주기를 새로 서명할 수 있습니다(되돌리기·갈라치기는 투명성 로그가 맡음). 행동 시각과 행위자 이름은 자기 보고라
  정지 이전으로 시각을 앞당길 수 있으므로 인증된 `sources`와 `LATE_EVIDENCE`를 함께 봐야 합니다.
- 레지스트리·정책을 쓸 때마다 tenant 전체를 다시 평가하고, 평가 스냅샷에 모든 등록 버전이 들어가 이력이 아주 길면 스냅샷 한도에 걸립니다.
- 레지스트리 정책 변경은 관리자 한 사람이 하고, 반복 거부의 창·임계값은 엔진 상수입니다. 운영 중에도 `owner`·`purpose`·`assetIds`·`systemId`는 고칠 수 있습니다.
- 재감사 F2는 수정 전에 이미 이전한 키스토어에서, 다음 기동 전에 DB 쓰기 권한자가 `moved_at`을 지우면 한 번 더 들어올 수 있습니다(그 기동부터 `moved.json`이 생김).
  복구 epoch 뒤 예전 base를 계속 고정한 검증자는 문서 절차로만 보호됩니다. 주소당 연결 제한은 여러 주소를 가진 공격자를 막지 못합니다.
- 새 발견 코드는 에이전트 목록(`/api/agents`)에서 따로 분류하지 않고, OPA 서명 결정 로그 검증과 OTLP span의 결정 매핑은 없습니다.
- 모든 시험은 Linux 컨테이너에서만 돌렸습니다.

### 3라운드 후보 처리 결과(중간)

| 후보 | 결과 |
|---|---|
| 1. 레지스트리 통합과 수명 주기 | 완료. 자산·거버넌스 시스템은 등록 항목에서 id로 연결 |
| 2. 결정 로그 수신 | 완료(OPA 어댑터). Cedar·AI 게이트웨이 어댑터와 OTLP 결정 매핑은 미구현 |
| 3. 격리·킬스위치 통제 API | 구현 중 |
| 4. 사람 승인 대기열 | 구현 중 |
| 5. 공통 통제 목록과 위험 등급 규칙 | 위험 등급 규칙만 완료. 요구사항·ISMS-P 공통 통제 ID는 미구현 |
| 6~13 | 미착수 |
| 14. 적대적 재감사 | 완료(위 표) |

## 2라운드 후보

1. 서명 키 격리: 데이터 볼륨을 마운트하지 않는 서명 전용 프로세스, 이후 KMS·PKCS#11 연동(S2 잔여).
2. 이벤트 키 감싸기(KEK)와 `payloadHash` HMAC 커밋먼트(S3).
3. SCITT·in-toto DSSE 호환 영수증 내보내기와 무의존성 검증기 CLI 분리 공개(감사 권고, 결정 4).
4. heads 모니터를 운영 경로로: `scripts/transparency.mjs monitor`(모든 heads 잎을 재생해 tenant별 단조 증가·삭제를 확인, 1라운드 F1에서 추가)를 정기 작업으로 돌리고 `status --probe`와 묶어 위트니스가 공동서명한 heads 로그와 대조. 키 보유자의 tenant 삭제를 시작 검사에서 잡는 방법도 검토.
5. 시작·전체 재검증 비용 줄이기(검증 상태 스냅샷), 파기·보조 경로 인덱스화.
6. 데모가 OTLP 경로로 AI 가시성 화면을 채우도록(감사 3.2: 데모 후에도 관측 0).
7. Kubernetes 매니페스트에 pin 볼륨·위트니스 설정, enforce 업그레이드 절차 자동 점검.
8. D3: 법률 검토용 조문 매핑 패키지, ISMS-P·AI 기본법 하위 고시 정렬.
9. PC(Windows)에서 전체 시험 통과 확인과 CI의 Windows 실행. 1라운드 시험은 Linux 컨테이너에서만 돌렸습니다.
10. 2라운드 시작 전 적대적 재감사: 1라운드에서 새로 만든 tenant 위트니스, 설정 재바인딩, 로그인 쿠키, worker 바인딩을 공격자 입장에서 다시 점검합니다.

## 3라운드 후보

앞의 여섯은 2026-10-07 "에이전트 통합 관리·GRC 감사 대시보드" 설계(메뉴·감사 증적 스키마·실시간 통제 구조)의 구현 순서이며, 앞 번호가 뒤 번호의 전제입니다.

1. 레지스트리 통합과 수명 주기: 자산·AI 시스템·에이전트 집계를 하나의 서명 객체로 묶고, 발견→초안→시험→승인→운영↔중지→폐기 전환에 "작성자가 아닌 승인자" 규칙과 정책 팩 증거 조건을 겁니다.
2. 결정 로그 수신: 정책 결정(허용·거부·승인 필요·변형, 엔진·정책 버전·번들 해시) 이벤트 종류와 OPA·Cedar·AI 게이트웨이 어댑터. 거부된 행동은 실행 전에 기록합니다. OTel에 결정 속성이 없으므로 `event.action`·`event.outcome`을 빌립니다.
3. 격리·킬스위치 통제 API: 레지스트리 상태를 정책 번들·게이트웨이 거부 목록으로 내보내고 자격 폐기를 호출한 뒤, 집행 지점의 `stop_confirmed`로 사건을 닫습니다.
4. 사람 승인 대기열: 집행 지점의 "승인 필요" 판정을 EvidScope에서 처리하고 결과를 돌려줍니다. EvidScope가 실행 경로에 들어가는 유일한 곳이므로 시간 초과는 거부로 둡니다.
5. 공통 통제 목록과 위험 등급 규칙: 요구사항 31개와 ISMS-P 항목을 통제 ID로 묶고, 위험 등급을 설문이 아니라 등록된 도구 권한·데이터 범주·목적지에서 계산합니다.
6. 실시간 피드와 역할별 화면: 30초~15분 주기 조회를 서버 푸시로 바꾸고, 운영자·검토자·감사인의 기본 화면을 나눕니다.
7. heads 모니터 정기 실행과 tile 기반 증명(C2SP tlog-tiles): 레코드 영수증의 O(n) 비용을 없앱니다.
8. 키 운영: Kubernetes 키스토어 볼륨, tenant 종료 시 epoch 파기, 키스토어 백업 명령, epoch별 키 캐시.
9. RFC 9942 COSE 영수증(SCITT 호환).
10. 시작·전체 재검증 비용 줄이기(검증 상태 스냅샷).
11. 고시 최종본의 관보 대조와 국내 AI 제품·서비스 확인제(고시 제2026-50호) 대응 검토, 금융분야 AI 가이드라인을 실제 매핑 데이터로 넣을지 결정.
12. PC(Windows)에서 전체 시험과 CI의 Windows 실행.
13. 검증기 묶음의 라이선스와 공개 위치(소유자 결정).
14. 3라운드 시작 전 적대적 재감사: heads 서명기, 이벤트 키스토어, 영수증 경로를 공격자 입장에서 다시 점검합니다.
