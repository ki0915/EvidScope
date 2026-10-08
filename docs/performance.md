# 수집 처리량: 측정과 그룹 커밋

> 2026-10-08 개선 5라운드에서 추가한 문서입니다. 수집 경로의 시간이 어디에 쓰이는지 먼저 재고, 그 결과에 따라 고친 내용과 남은 한계를 적습니다.

## 왜 손댔는가

ee068f7에서 `node scripts/benchmark.mjs`로 잰 급증(burst) 처리량은 초당 약 250건이었습니다(동시 출처 20개, 이벤트 1 KiB, p95 약 100 ms).
관측 도구는 초당 수천 span을 받습니다. 원장은 열 저장소(columnar store)와 같은 속도를 낼 수 없지만, 250 EPS에서 멈추는 원장은 도입을 막습니다.
목표는 같은 벤치마크에서 2,000 EPS 쪽으로 가되, **보증을 하나도 내주지 않는 것**이었습니다.

## 방법과 환경

- 환경: 4 vCPU 컨테이너(Linux 6.18), Node 24.21.0, `node:sqlite` WAL + `synchronous=FULL`, vault·ingress·audit 프로세스 각 1개, 분석 worker 2개.
  다른 에이전트가 같은 기계에서 테스트를 돌릴 때가 있어, 비교는 기준(ee068f7)과 변경본을 번갈아 실행하고 기계가 조용할 때의 값을 적었습니다.
  같은 조건에서도 실행마다 ±10% 정도 흔들립니다.
- 벤치마크(`scripts/benchmark.mjs`, 이번에 확장):
  - `normal` 20 EPS × 10초, `burst` 200건 동시성 20, `sustained` 20 EPS × 30초(기존)
  - `burst50`: HMAC 서명 이벤트 2,000건, 동시성 50(신규)
  - `otlp`: GenAI chat span 2,000개를 OTLP/JSON으로, 요청당 500개, 동시성 2, ingress `/v1/traces` 경유(신규)
  - `BENCHMARK_PHASES=burst50,otlp`로 일부만, `BENCHMARK_REPORT_DIR`로 보고서를 `reports/` 밖에 남길 수 있습니다.
- 프로파일: 내장 `node --cpu-prof`만 사용했습니다(`NODE_OPTIONS=--cpu-prof`로 vault·ingress·클라이언트 각각의 프로파일). 같은 2,000건
  급증과 같은 양의 OTLP 묶음을 따로 재고, 자체 함수(self)·포함(inclusive) 시간을 함수별로 합산했습니다.

## 시간이 어디에 쓰였나 (ee068f7, 급증 2,000건, vault 프로세스)

vault는 단일 스레드로 거의 100% 바빴고(idle 7%), ingress는 25%만 썼습니다. 병목은 vault였습니다. 이벤트 하나당 CPU 시간입니다.
일부 항목은 겹칩니다(체크포인트 검증은 투영 검사와 append 안에서 각각 한 번씩 일어납니다).

| 항목 | ee068f7 (µs/건) | 변경 후 (µs/건) | 비고 |
|---|---:|---:|---|
| BEGIN IMMEDIATE·COMMIT·fsync(`synchronous=FULL`) | 610 | 100 | 트랜잭션당 1회 → 묶음당 1회 |
| 저장된 v1 체크포인트 Ed25519 검증 | 360 | 25 | 트랜잭션당 2회(투영 검사, append 머리 확인) |
| 새 v1 체크포인트 Ed25519 서명 | 170 | 16 | 트랜잭션당 tenant마다 1회 |
| 투영 증분 검사(직전 이벤트 복호·대조) | 790 | 245 | 체크포인트 검증 포함. 이벤트당 복호는 그대로 남김 |
| 원장 append(암호화·커밋먼트·해시·삽입) | 750 | 240 | 암호화 190 → 90 |
| 접수 지문 HMAC(에포크 키 HKDF 포함) | 165 | 55 | 파생 키 캐시 |
| 분석 적체 COUNT(행동 전체 스캔) | 165 | 6 | 부분 인덱스, 묶음당 1회 |
| 검색 사본·영수증·행동 투영 쓰기 | 80 | 60 | 문 재사용 |
| canonical 직렬화(여러 곳 합계) | 185 | 120 | 중복 계산 제거, 배열 없는 구현 |
| HTTP·요청 HMAC·JSON·검증(route) | 140 | 150 | 거의 그대로 |
| GC | 150 | 60 | |

OTLP 묶음(요청 하나가 이미 한 트랜잭션)에서도 이벤트당 약 1.2 ms가 들었습니다. 즉 커밋·서명만이 아니라 이벤트당 작업도 컸습니다.
원인은 SQLite 문을 쓸 때마다 새로 준비(prepare, 건당 약 5 µs, `projectionMutation` 한 번에 두 번), Node 24에서 Buffer 키로 HMAC·AES를 만들 때의
느린 경로(호출당 약 15 µs), 영수증 태그마다 에포크 비밀의 HKDF, 원장 레코드 canonical 문자열의 이중 계산, 이벤트마다 `sqlite_schema` 조회였습니다.

## 바꾼 것

### 1. 그룹 커밋 (`src/ingest-batch.mjs`)

가까이 도착한 `/api/ingest` 이벤트가 **트랜잭션 하나**를 함께 씁니다.

- 묶음 하나에 BEGIN IMMEDIATE·fsync 1회, tenant마다 투영 검사 1회와 v1 체크포인트 서명 1회, tlog note 1개.
- 이벤트마다 **자기 원장 행**(`event`, `event_receipt`), **자기 해시 체인 위치**, **자기 영수증**은 그대로입니다. 묶음 마지막 머리에 서명하는
  v1 체크포인트가 해시 체인을 통해 묶음 안 모든 행을 덮습니다. 그래서 **새 레코드 형식이 필요 없고**, 체크포인트 형식·내보내기·오프라인 검증기
  (`evidscope-verify`)·위트니스·heads 서명기는 바뀌지 않습니다. 이전 내보내기도 그대로 검증됩니다.
- 이벤트마다 savepoint 안에서 처리합니다. 재사용 nonce, 내용 충돌, 분석 적체는 **그 이벤트만** 되돌리고 거절합니다.
- 응답은 그 이벤트가 든 COMMIT이 끝난 뒤에만 보냅니다. **202는 여전히 내구 저장을 뜻합니다.** 커밋하지 못한 묶음은 아무것도 남기지 않고
  묶음 안 모든 요청이 오류를 받습니다.
- SQLite가 오류(SQLITE_FULL, SQLITE_IOERR 등)로 트랜잭션을 스스로 되돌린 뒤에는 `Store.transaction`이 더 쓰지 않고 거절합니다.
  묶음이 이벤트별 오류를 잡고 다음 이벤트로 넘어가므로, 이 확인이 없으면 다음 이벤트가 autocommit으로 체크포인트 없이 커밋될 수 있었습니다.
- `Store.transaction`은 동기 그대로이고, 묶기는 그 앞의 수집 경로에서 합니다.
- 분석 적체 한도는 묶음 시작에 tenant별로 한 번 세고 이벤트마다 갱신하므로, 이벤트 하나하나가 보는 값은 이벤트별 트랜잭션 때와 같습니다.

| 환경 변수 | 기본값 | 범위 | 뜻 |
|---|---|---|---|
| `INGEST_BATCH_MAX_WAIT_MS` | 0 | 0-1000 | 첫 이벤트가 다른 이벤트를 기다리는 최대 시간. 0이면 현재 이벤트 루프 차례 끝에 커밋합니다. 직전 커밋이 도는 동안 도착한 이벤트가 다음 묶음이 되고, 혼자 온 이벤트는 기다리지 않습니다. |
| `INGEST_BATCH_MAX_EVENTS` | 256 | 1-4096 | 이만큼 모이면 즉시 커밋합니다. 1이면 이벤트마다 트랜잭션(이전 동작)입니다. |

대기 시간은 **가장 오래 기다린 이벤트** 기준이라 뒤이어 오는 이벤트가 늘리지 못합니다. 잘못된 값이면 vault가 시작하지 않습니다.
측정에서 대기 0이 2·5 ms보다 처리량과 지연 모두 나았습니다(급증 2,000건 동시성 50: 0 ms 966 EPS, 2 ms 877, 5 ms 828). 평균 묶음 크기는 약 19건이었습니다.

### 2. 이벤트당 작업

- `Store.cachedStatement`·`Store.projectionStatement`: 자주 쓰는 SQL의 준비된 문을 재사용합니다. SQLite authorizer는 실행이 아니라 **준비할 때** 돌므로,
  인가 결과가 시점에 따라 달라질 수 없는 문만 캐시합니다. 읽기와 보호되지 않은 테이블 쓰기, 그리고 보호된 테이블 쓰기는 `projectionMutation` 안에서만
  실행되도록 강제합니다(밖에서 부르면 예외). 그래서 projection 변경 시계가 보는 쓰기는 이전과 같습니다.
- HMAC·AES 키를 KeyObject로 넘깁니다. 출력은 같습니다.
- 에포크 파생 키(접수 지문 키, 키 감싸기 키)를 tenant·에포크·용도별로 캐시합니다. 비밀은 **매번 조회**하고, 조회한 비밀의 SHA-256이 같을 때만
  캐시를 씁니다. 파기되거나 바뀐 에포크는 캐시에서 나오지 않고, 파기하면 그 에포크의 파생 키를 버립니다.
- canonical을 중간 배열 없이 만들고(출력 동일, 이전 구현과 대조하는 테스트), append에서 레코드 canonical 문자열을 한 번만 만듭니다.
- 인덱스 `actions_pending(tenant) WHERE analyzed<version`, `nonces_expires(expires)`: 적체 COUNT와 만료 nonce 삭제가 전체 스캔이 아니게 됩니다.
  행동·nonce가 수십만 개로 늘어도 묶음당 비용이 커지지 않습니다.
- 키스토어 확인(`event_keystore_usage`)은 쓰기 트랜잭션당 한 번만 합니다(BEGIN IMMEDIATE가 다른 writer를 막고 있습니다).

## 결과 (전후 비교)

같은 기계에서 ee068f7과 변경본을 번갈아 세 번씩 실행했습니다(동시 출처 3개, 이벤트 약 1 KiB).

| 단계 | ee068f7 | 변경 후 | 배수 |
|---|---|---|---|
| `burst50` 2,000건·동시성 50 | 262-270 EPS, p95 209-219 ms, p99 약 1,000 ms | 755-840 EPS, p95 72-79 ms, p99 108-195 ms | 약 3.1× |
| `otlp` span 2,000개·요청당 500 | 759-789 EPS, 요청 p95 1.3-1.4 s | 1,566-1,764 EPS, 요청 p95 0.6-1.0 s | 약 2.2× |
| `burst` 200건·동시성 20 | 242-250 EPS, p95 180-240 ms | 360-618 EPS, p95 55-133 ms | 1.5-2.5× (짧아 예열 영향 큼) |
| `normal` 20 EPS p95 | 11.8-15.1 ms | 9.9-11.1 ms | |
| `sustained` 20 EPS p95 | 25-38 ms | 24-38 ms | 앞 단계 4,400건의 분석이 도는 중. 혼자 온 이벤트는 기다리지 않음 |
| 키스토어 모드 `/api/integrity` 1,000건 | 890-1,055 ms | 518-582 ms | 약 1.9× |
| 키스토어 모드 `/api/export` 1,000건 | 282-363 ms | 188-229 ms | 약 1.5× |

전 단계에서 접수·원본·검색 사본·분석 수가 일치했고 내보내기 검증이 통과했습니다. 그룹 커밋만 켠 상태(이벤트당 작업 개선 전)는 급증 2,000건에서
약 560 EPS, 그룹 커밋을 끄고(`INGEST_BATCH_MAX_EVENTS=1`) 이벤트당 개선만 둔 상태는 약 350 EPS였습니다.

**목표 2,000 EPS에는 이르지 못했습니다.** 서명 이벤트 급증은 약 800 EPS, OTLP 묶음은 약 1,700 EPS입니다.

## 남은 천장

변경 후 vault는 이벤트당 약 0.9 ms의 CPU를 씁니다(묶음 안 0.75 ms, HTTP 0.15 ms). vault를 직접 두드려도 동시성 50에서 약 960 EPS,
동시성 100에서 약 1,200 EPS였습니다. 남은 비용은 줄일 수 없는 일이 대부분입니다.

- 투영 증분 검사(약 0.25 ms): 다음 묶음이 쓰기 전에 직전 묶음의 이벤트를 원장 암호문에서 **다시 복호**해 검색 사본·키·영수증·행동 투영과 대조합니다.
  쓰기 전에 검증한다는 보증이라 그대로 두었습니다.
- 이벤트 암호화(AES-GCM, 무작위 키·솔트·IV, HMAC 커밋먼트)와 두 원장 행의 SHA-256, 그리고 SQLite 삽입 6개와 각 삽입의 변경 시계 트리거.
- vault는 단일 스레드입니다. 동시성 50의 닫힌 루프 클라이언트에서는 커밋하는 동안 다음 요청이 들어오지 않아 vault가 약 20% 쉬었습니다.
- ingress는 요청당 약 0.7 ms(undici `fetch`)를 써서 단독으로 약 1,400 EPS가 한계입니다. ingress는 상태가 없으므로 여러 개로 늘리면 됩니다.

## 다음 단계

1. **직전 묶음 쓰기 기록으로 복호 생략**: 이 프로세스가 직전 묶음에 쓴 행은 해시가 같고 저장된 키 바이트가 같으면 다시 복호하지 않고 대조합니다.
   보증은 같지만 검증 경로를 바꾸므로 따로 검토가 필요해 이번에 넣지 않았습니다. 기대 효과는 이벤트당 약 0.1 ms입니다.
2. **암호화를 worker thread로**: 순번(seq)에 묶이지 않는 작업(키·솔트·IV 생성, 평문 canonical, 지문 원문 해시)을 트랜잭션 밖 스레드에서 미리 합니다.
3. **투영을 별도 저장소로**: 검색 사본·행동 투영을 다른 SQLite 파일(또는 비동기 투영기)로 옮겨 원장 트랜잭션을 원장·영수증·키만으로 줄입니다.
4. **타일 기반 증명**: tlog를 C2SP tlog-tiles로 내보내 체크포인트·증명 제공을 정적 파일로 넘기고, 위트니스·감사자 읽기를 vault에서 덜어냅니다.
5. ingress의 `fetch`를 keep-alive `http.request`로 바꾸거나 ingress를 여러 개 둡니다.

## 시험

- `test/ingest-group-commit.test.mjs`: 동시성에서 묶음 처리와 제출 순서, 재시도 중복·충돌, 유실·중복 없음; 묶음 안 거절과 묶음 전체 실패;
  묶음을 쓰는 도중 SIGKILL(프로세스 안, 그리고 부하 중인 실제 vault 프로세스) 뒤 202 무손실·반쯤 커밋된 묶음 없음; 묶음 내보내기와 ee068f7 내보내기
  (`test/fixtures/pre-group-commit-export-ee068f7.json`)를 `verifyBundle`과 `evidscope-verify`로 검증, 묶음 안 변조(암호문, 순서, 삭제, 잘라내기,
  공개 사본, 영수증) 거부; SQLite가 트랜잭션을 먼저 끝낸 경우; 대기 한도.
- `test/ingest-hot-paths.test.mjs`: canonical 동일성, 문 캐시와 projection 쓰기 강제, 인덱스 계획, 파생 키 캐시가 바뀐·파기된 비밀을 쓰지 않음, KeyObject 출력 동일.

## 2단계: 다시 재고 고친 것 (6라운드)

> 2026-10-08 개선 6라운드에서 추가한 절입니다. 기준은 8b3af6c(5라운드 종료)입니다.

### 다시 잰 결과 (8b3af6c)

방법은 5라운드와 같습니다(`--cpu-prof`로 vault·ingress·클라이언트 각각의 프로파일). 이번에는 프로파일러 부담 없이 프로세스별 CPU 시간도
`/proc/<pid>/stat`으로 쟀습니다(급증 4,000건, 동시성 50, 분석 worker 없음, 세 번의 중앙값).

| 프로세스 | 8b3af6c (ms/건) | 6라운드 후 (ms/건) |
|---|---:|---:|
| vault | 0.93 | 0.74 |
| ingress | 0.74 | 0.32 |
| 부하 생성 클라이언트(`src/client.mjs`, fetch) | 0.65 | 0.59 |
| vault 핵심(HTTP 없이 같은 프로세스에서 `service.handle`) | 0.66 | 0.55 |

8b3af6c의 vault 프로파일에서 큰 항목은 다음과 같았습니다(급증 2,000건, 건당).

- 묶음 시작의 투영 증분 검사 약 0.25 ms: 직전 묶음이 쓴 원장 행을 다시 읽어 해시를 계산하고(0.06), 이벤트를 다시 복호하고(0.07),
  투영 행과 대조(0.07)했습니다. 이 프로세스가 바로 전에 쓴 행입니다.
- 원장 append 약 0.24 ms(암호화 0.1, SHA-256, canonical, 삽입 6개와 각 삽입의 변경 시계 트리거).
- HTTP(파싱·응답) 약 0.14 ms, ingress의 undici `fetch` 약 0.4 ms.
- COMMIT은 50건 묶음에 약 3.5 ms(건당 70-80 µs)였고 대부분 CPU였습니다(WAL 쓰기). WAL 자동 체크포인트를 끄거나 키워도 거의 같았습니다.

### 바꾼 것

1. **검증 상태를 자기 쓰기 위로 이어가기** (`Store._advanceVerifiedStates`). 쓰기 트랜잭션이 현재(current) 검증 상태에서 시작했다면,
   COMMIT 직전에, 아직 쓰기 잠금을 쥔 채로, 자기가 append한 행을 그 상태에 적용합니다. 재생(replay)과 투영 대조(delta check)는 SQL에서 읽은
   접미부(suffix)일 때와 **같은 코드**입니다. 생략하는 것은 이 트랜잭션이 만든 값을 다시 만드는 일뿐입니다: 삽입한 레코드 문자열과 해시를
   다시 읽어 계산하기, 그리고 봉인한 평문과 키 바이트를 다시 복호해 얻기. 다음 트랜잭션은 직전 묶음을 다시 읽지도 복호하지도 않습니다.
   - 다른 연결의 커밋은 `data_version`을, 이 연결이 `projectionMutation` 밖에서 한 쓰기는 변경 시계(mutation serial)를 바꾸고, 어느 쪽이든
     다음 검사가 전체(cold) 재검증이 되는 것은 이전과 같습니다. SQLite를 거치지 않은 파일 편집은 이전에도 최대 나이(`verifiedStateMaxAgeMs`)
     뒤의 cold 검증에서 찾았고, 직전 묶음의 행은 같은 연결의 페이지 캐시에서 읽혔으므로 이전의 재검사도 그런 편집을 보장해 찾지는 못했습니다.
   - 외부 트랜잭션, 결함(fault)이 있는 상태, 이 트랜잭션이 쓰지 않은 행, 16 MiB를 넘는 행은 이어가지 않고 다음 검사에 맡깁니다. 적용 중 오류는
     상태를 버리고, 롤백은 이어간 상태를 캐시에서 지웁니다.
   - 같이 고친 것: 롤백 뒤 관찰한 변경 시계를 트랜잭션 시작 때 값으로 되돌립니다. 이전에는 savepoint에서 되돌린 이벤트의 쓰기가 "projectionMutation
     밖 쓰기"로 보여 다음 검사가 tenant 원장 전체를 cold로 다시 읽었습니다. 시작 때 관찰하지 못한 변경은 여전히 불일치로 잡힙니다.
2. **게이트웨이 → vault를 node:http keep-alive로** (`src/upstream-http.mjs`). ingress·audit 게이트웨이의 `fetch`를 전역 keep-alive agent 위의
   `http(s).request`로 바꿨습니다. 리다이렉트를 따르지 않고 그대로 돌려주며, TLS는 Node 기본 신뢰 저장소로 검증하고(`NODE_EXTRA_CA_CERTS`
   포함), `NODE_USE_ENV_PROXY`는 전역 agent를 통해 그대로 적용되고, 기한은 응답 본문까지 덮습니다. ingress 0.74 → 0.41 ms/건.
3. **ingress → vault 봉투 전달** (`src/ingest-forward.mjs`). ingress는 같은 이벤트 루프 차례에 도착한 `/api/ingest` 요청을 bearer 토큰별로
   `POST /internal/ingest-forward` 하나(최대 64건, 1 MiB)에 담습니다. vault는 봉투의 bearer를 출처(source)로 사전 인증하고(S12a), 항목마다
   동시성 한도를 세고, 각 항목을 그 항목의 시각·nonce·HMAC 서명·원본 본문 그대로 `/api/ingest` 경로로 처리합니다. 그래서 출처마다 혼자 보냈을
   때와 같은 상태 코드와 본문을 받고, 202는 여전히 그 이벤트가 든 COMMIT 뒤에만 나갑니다. 줄어드는 것은 이벤트마다의 HTTP 왕복입니다.
   - vault가 이 경로를 모르는 이전 버전이면(응답에 `x-evidscope-ingest-forward`가 없고 403·404·413) ingress는 그 묶음을 한 건씩 보내고 1분 동안
     봉투를 쓰지 않습니다. `INGRESS_FORWARD_MAX_EVENTS`(기본 64, 1-64)를 1로 두면 예전처럼 한 건씩 보냅니다. 외부 API는 바뀌지 않습니다.
   - 쿠키 세션만으로 `/api/ingest`를 부르는 잘못된 요청은 이제 vault에서 403 대신 401을 받을 수 있습니다(봉투는 서명 헤더 셋과 bearer만 나릅니다).
4. **이벤트당 작은 정리**: 키·솔트·IV를 CSPRNG 한 번에 뽑기, 요청 서명 HMAC 키(KeyObject) 재사용, 보존 정책 계산 한 번, 에포크 비밀 조회 한 번,
   이벤트 하나를 projectionMutation 범위 하나로, 접수·중복 카운터를 묶음마다 한 번(유지된 savepoint의 이벤트만). 출력은 같습니다.

**worker_threads는 넣지 않았습니다.** 이벤트 암호화의 AAD와 레코드 해시는 순번(seq)과 직전 해시에 묶여 있어 트랜잭션 안에서만 계산할 수 있습니다.
미리 할 수 있는 일(키 생성, 페이로드 커밋먼트 HMAC, 평문 canonical)은 건당 약 40 µs로 vault CPU의 7%쯤이고, 묶어 보내면 스레드 전달 비용은 작지만
(50건 묶음에 건당 약 2 µs) 키 재료가 스레드를 오가게 되고 동기 트랜잭션 앞에 비동기 단계가 하나 더 생깁니다. 이 기계(4 vCPU)에서는 vault 외에
ingress·클라이언트·분석 worker가 이미 코어를 나눠 쓰므로 얻을 몫이 더 작습니다.

### 결과

같은 기계에서 8b3af6c와 6라운드 끝을 번갈아 세 번씩 `node scripts/benchmark.mjs`를 돌렸습니다(분석 worker 2개 포함, 다른 테스트 묶음이 돌지
않을 때). 값은 세 번의 범위와 중앙값입니다. 모든 실행에서 접수·저장·검색 사본·분석 수가 같았고 내보내기 검증이 통과했습니다.

| 단계 | 8b3af6c | 6라운드 후 | 배수(중앙값) |
|---|---|---|---|
| `burst50` 2,000건·동시성 50 | 753-790 EPS(중앙 760), p95 84-85 ms, p99 193-211 ms | 976-1,061 EPS(중앙 1,031), p95 67-78 ms, p99 92-154 ms | 1.36× |
| `otlp` span 2,000개·요청당 500 | 1,131-1,596 EPS(중앙 1,524), 요청 p95 0.6-1.0 s | 1,794-1,905 EPS(중앙 1,868), 요청 p95 0.6-1.1 s | 1.23× |
| `burst` 200건·동시성 20 | 588-635 EPS, p95 48-64 ms | 566-721 EPS, p95 54-63 ms | 짧아 예열 영향 큼 |
| `normal` 20 EPS p95 | 10.1-14.7 ms | 8.4-12.5 ms | |
| `sustained` 20 EPS p95 | 17.8-29.1 ms | 15.0-31.4 ms | |

분석 worker 없이 잰 급증 4,000건(위 CPU 표와 같은 실행)은 949-995 → 1,167-1,321 EPS, OTLP 4,000 span은 1,540-1,617 → 1,653-1,884 EPS였습니다.

**목표(`burst50` 2,000 EPS, OTLP 3,000 EPS)에는 이르지 못했습니다.**

- vault는 여전히 이벤트당 약 0.74 ms(급증) / 0.55 ms(OTLP)의 CPU를 쓰는 단일 스레드입니다. 2,000 EPS에는 0.5 ms, 3,000 EPS에는 0.33 ms가 필요합니다.
  남은 비용은 SQLite 쓰기(삽입 약 10개와 변경 시계 트리거 6개, COMMIT의 WAL 쓰기, 합쳐 약 0.2 ms), 이벤트 암호화와 레코드 해시(약 0.1 ms),
  쓰기 전 검증의 투영 대조(약 0.07 ms)이고, 모두 보증의 일부입니다.
- 이 벤치마크는 부하 생성기(fetch 클라이언트, 이벤트당 약 0.6 ms)와 ingress, vault, 분석 worker 2개, audit가 4 vCPU 하나를 나눠 씁니다.
  2,000 EPS면 클라이언트만 코어 하나를 넘게 씁니다. 같은 기계에서 vault 핵심만(HTTP 없이) 돌리면 약 1,800 EPS입니다.
- 동시성 50의 닫힌 루프에서는 진행 중인 요청 대부분이 한 묶음에 들어가, 그 묶음을 쓰는 동안 다음 요청이 오지 않아 vault가 15-20% 쉽니다.
  묶음 크기 상한을 16·25로 낮춰도 나아지지 않았습니다(16: 1,100 EPS, 25: 1,225 EPS, 256: 1,200 EPS).

### 다음 단계

1. **투영을 원장 트랜잭션 밖으로**: 검색 사본·행동 투영(삽입 3개와 트리거, 투영 대조)을 별도 저장소나 비동기 투영기로 옮기면 쓰기 트랜잭션이
   원장·영수증·키만 남습니다. 투영 검증 경로를 다시 설계해야 하므로 별도 검토가 필요합니다.
2. **vault 여러 개(tenant 분할)**: 원장은 tenant마다 독립이므로 tenant를 나눠 vault 프로세스를 늘리면 코어 수만큼 늘어납니다.
3. 순번에 묶이지 않는 암호 작업을 worker로 미리 하기(위 검토 참고, 기대 효과 약 7%).
4. SDK `submit`(fetch)도 node:http keep-alive로: 출처 쪽 CPU가 줄고, 같은 기계 벤치마크의 부하 생성기 몫도 줄어듭니다.

### 시험 (6라운드)

- `test/ingest-stage2.test.mjs`: 다음 묶음이 직전 묶음을 복호·재독하지 않고 이어간 상태가 cold 재생과 같음(재시도 중복, 재사용 nonce 포함);
  다른 SQLite 연결이 바로 전에 쓴 투영 행이나 원장 행(일관된 해시로, 추가 전용 트리거를 지우고)을 바꾸면 다음 쓰기 전에 거절;
  vault 연결이 projectionMutation 밖에서 바꾼 경우도 거절; COMMIT 시점에 실패한 묶음은 이어간 상태를 남기지 않음; 쓰고 나서 거절된 항목은
  혼자 되돌아가고 다음 묶음은 cold가 아님; 카운터; 8b3af6c 내보내기(`test/fixtures/pre-stage2-export-8b3af6c.json`)를 두 검증기로 검증하고
  새 내보내기의 레코드 모양이 같음; 게이트웨이 upstream의 리다이렉트·기한·크기 한도·keep-alive.
- `test/ingest-forward.test.mjs`: 봉투 항목이 각자의 서명 헤더와 봉투 bearer로 처리되고 오류가 항목에 머묾; ingress 묶기(토큰별, 전체 거절,
  이전 vault로의 대체, 연결 끊김); 실제 프로세스에서 ingress 경유와 vault 직접의 응답이 같음; 부하 중 vault SIGKILL 뒤 ingress가 준 202 무손실.
- 기존 `test/tls.test.mjs`가 게이트웨이 → vault TLS 인증서·호스트 검증을 새 upstream으로 그대로 확인합니다.

## 3단계: 측정을 나누고 vault의 건당 비용 줄이기 (7라운드)

> 2026-10-08 개선 7라운드에서 추가한 절입니다. 기준은 d7413a0(6라운드 종료)입니다.

### 측정을 바꾼 것

2단계까지의 숫자는 부하 생성기(fetch 클라이언트, 건당 약 0.6 ms), ingress, vault, 분석 worker 2개, audit가 4 vCPU를 나눠 쓴
**종단 처리량**이었습니다. vault가 얼마나 받을 수 있는지와 같은 기계의 클라이언트가 얼마나 보낼 수 있는지가 섞여 있었습니다.
`scripts/benchmark.mjs`에 다음을 더했습니다(기본값은 이전과 같아 예전 숫자와 비교됩니다).

- `BENCHMARK_CLIENT=fetch|http`: `fetch`(기본, 이전 단계와 같은 방식)와 node:http keep-alive 풀(`http`). SDK `submit`에 `agent`
  선택지를 더했습니다(`src/client.mjs`, `src/upstream-http.mjs`를 씀: 응답 1 MiB 한도, 리다이렉트 거절, 기한). 클라이언트 CPU가
  건당 0.62 ms에서 0.40 ms로 줄어듭니다.
- `BENCHMARK_PIN=1`: `taskset -a`로 vault를 CPU 0, ingress를 1, 부하 클라이언트를 2, 나머지(audit, worker)를 3에 고정합니다.
  `vault:0,ingress:1,client:2-3,other:3`처럼 직접 줄 수도 있습니다. taskset이 없거나 CPU가 4개 미만이면 고정하지 않고 보고서에 `null`로 남깁니다.
- 모든 부하 단계 결과에 `cpuMsPerEvent`: `/proc/<pid>/stat`의 utime+stime 차이를 그 단계의 이벤트 수로 나눈 값입니다(프로파일러 부담 없음).
  `vault`, `vaultMainThread`(JavaScript 스레드. SQLite·암호·HTTP가 모두 여기서 돌아 처리량을 묶는 값), `ingress`, `audit`, `workers`, `client`.
  보고서 `environment`에 클라이언트 방식과 실제 고정 배치가 남습니다.

숫자를 읽는 법:

- **EPS**(`observedEPS`): 클라이언트가 보낸 뒤 202를 받기까지의 종단 처리량입니다. 그 기계와 배치(클라이언트 방식, 고정 여부)에 묶입니다.
- **vault 주 스레드 ms/건**: vault가 이벤트 하나에 쓰는 CPU입니다. `1000 / 이 값`이 다른 프로세스와 CPU를 다투지 않을 때 vault 하나의 CPU 상한입니다.
  다만 COMMIT의 fsync(synchronous=FULL) 동안 주 스레드는 CPU를 쓰지 않고 기다리므로(50건 묶음에 약 3 ms, 건당 약 60 µs) 실제 상한은 그보다 낮습니다.
- `normal`·`sustained`(20 EPS)의 ms/건은 고정 배경 비용(분석 폴링, 타이머, 접근 기록 봉인)을 적은 이벤트 수로 나눈 값이라 용량 지표가 아닙니다.

### 시간이 어디에 쓰였나 (d7413a0)

`--cpu-prof`(vault·ingress·클라이언트 각각)와 HTTP 없이 같은 프로세스에서 `service.handle`만 돌리는 측정으로 찾은 것입니다.

- **분석이 행동마다 체크포인트 서명을 다섯 번 검증**했습니다. 분석 worker의 claim·commit마다 `_verifiedActionState`·`verifiedRows`·원장 머리 적재가
  저장된 v1 체크포인트를 Ed25519로 다시 검증했고(건당 약 130 µs), 이벤트 1,000건의 분석에 5,128번이었습니다. 분석 1건에 vault CPU 약 4.5 ms.
- 평가(evaluations) 증분 대조가 `OFFSET`으로 그 tenant의 이전 행을 모두 훑었고(`evaluations(tenant)` 인덱스도 없음), 분석 스냅샷은 행동 하나의
  이벤트를 찾으려고 tenant의 보존 이벤트를 모두 걸렀습니다. 둘 다 원장이 길어질수록 분석 1건이 비싸집니다.
- 수집 묶음은 이벤트마다 SAVEPOINT를 두었고, 이벤트당 약 40 µs(서브 저널 페이지 복사)였습니다. 거절은 거의 없는데 모든 이벤트가 냈습니다.
- 남은 수집 비용(건당, 묶음 50): 이어간 검증 상태 갱신(`_advanceVerifiedStates`) 약 110 µs, 암호화 약 80 µs, canonical 약 70 µs,
  COMMIT 약 90 µs(CPU 36 µs, 나머지 fsync 대기), 지문 봉인 약 30 µs, 투영 쓰기 약 26 µs. 변경 시계 트리거는 하나에 약 1 µs라 그대로 두었습니다.
- 분석 worker는 200 ms마다 5건씩 claim하므로 worker 2개는 초당 약 50 행동이 상한입니다. 급증 동안 분석은 뒤처지지만 수집을 막지는 않습니다
  (적체 한도에 걸리기 전까지). 이번에는 바꾸지 않았습니다.

### 바꾼 것

1. **체크포인트 서명 검증을 글자 그대로의 텍스트당 한 번** (`Store._verifiedCheckpoint`, `_verifyStoredCheckpoint`, 8fef815).
   Ed25519 검증은 체크포인트 텍스트와 공개키만의 결정적 함수입니다. 그래서 tenant마다 마지막으로 검증한(또는 이 저장소가 자기 키로 서명해 COMMIT한)
   텍스트를 기억하고, 저장된 행이 **정확히 그 텍스트**일 때만 다시 검증하지 않습니다. 다른 텍스트(다른 연결이나 SQLite 밖에서 바꾼 행, 되돌린 옛
   체크포인트)는 전부 다시 검증하고, 머리(count·head) 대조와 투영 대조는 그대로입니다. 기억은 COMMIT이 성공한 뒤에만 남습니다.
2. **평가 증분 대조를 id 커서로** (`evaluations(tenant)` 인덱스, `_verifyActionDelta`, 8fef815). 마지막으로 검증한 행의 id 뒤만 읽습니다.
   평가 행은 추가만 되고(AUTOINCREMENT), 다른 변경은 다른 연결(data_version)이나 projectionMutation 밖 쓰기(변경 시계)로 오므로 어느 쪽이든
   이전처럼 cold 재검증이 됩니다. 커서가 맞지 않으면 예전 `OFFSET` 경로로 갑니다.
3. **행동별 이벤트 색인** (`state.eventsByAction`, 8fef815). 검증된 상태에 `eventsBySequence`와 함께 행동 id → 순번 집합을 두고, 보존 처분으로
   이벤트가 빠질 때 같이 뺍니다. 분석 스냅샷은 tenant 전체를 거르지 않고 이 색인에서 읽습니다.
4. **수집 묶음의 이벤트별 SAVEPOINT 없애기** (`src/ingest-batch.mjs` `isolation:'optimistic'`, f8044c6). 수집 처리 순서를 바꿔 모든 거절
   (nonce 재사용, 같은 출처 이벤트 ID의 내용 충돌·비교 불가, 분석 적체)이 첫 쓰기 **전에** 나도록 했습니다. 이벤트는 savepoint 없이 돌고,
   예외가 나면 SQLite `total_changes()`로 그 사이 바뀐 행이 없었는지 봅니다. 없으면 그 이벤트만 거절하고 묶음은 계속 갑니다(이전에 savepoint를
   되돌린 결과와 같음). 쓰기 뒤에 예외가 났거나 SQLite가 트랜잭션을 스스로 끝냈다면 묶음 전체를 되돌리고 이벤트마다 savepoint를 두는 예전 방식으로
   다시 돌립니다(`isolatedRetries` 지표). 그래서 결과는 항상 예전 방식과 같습니다. 묶음의 테넌트 보존 정책과 적체 한도도 한 번만 읽습니다.

원장·영수증·체크포인트·내보내기 형식은 바뀌지 않았습니다. d7413a0이 만든 내보내기(`test/fixtures/pre-stage3-export-d7413a0.json`)를
`verifyBundle`과 `evidscope-verify`가 그대로 검증하고, 새 내보내기의 레코드 모양이 같습니다. synchronous=FULL과 "202 = 영속"은 그대로입니다.

### tenant 분할(시제품, 기본 꺼짐)

tenant 하나의 원장은 한 프로세스가 차례로 쓰는 해시 체인 하나이므로, vault 하나가 그 tenant의 처리량을 묶습니다. 여러 tenant의 **합계**는
tenant를 나눠 가진 vault 여러 개로 늘릴 수 있습니다(`src/vault-tenants.mjs`, c79bcd6).

- `VAULT_TENANTS=alpha,beta`: 이 vault가 맡는 tenant. 그 tenant의 자격 증명만 받고(다른 tenant의 것은 여기서 모르는 토큰, 401), worker의 tenant
  목록은 맡은 부분만 남깁니다. `Store.append`는 맡지 않은 tenant에 쓰기를 421로 거절하고, 맡지 않은 tenant의 원장 이력을 가진 데이터베이스로는
  시작하지 않습니다. 분할 데이터베이스를 `VAULT_TENANTS` 없이 열어도 시작하지 않습니다. 레거시 worker의 `internal` tenant는 분할 vault에서 원장을 갖지 않습니다.
- `VAULT_TENANT_REGISTRY_DIR`(배포의 모든 vault가 공유): tenant마다 `<sha256(tenant)>.owner` 파일 하나를 배타적으로(O_EXCL, 0600) 만들어 그 tenant를
  가진 데이터베이스(데이터베이스마다 처음 만든 무작위 vault id)를 적습니다. 다른 데이터베이스가 같은 tenant를 맡으려 하면 시작하지 않고, 읽을 수 없는
  항목도 거절합니다. `VAULT_TENANTS` 없이 registry만 주면 자격 증명의 모든 tenant를 같은 방식으로 주장합니다.
- 게이트웨이(ingress·audit)의 `VAULT_ROUTES_FILE`: `{"vaults":{"<tenant>":"<vault URL>"},"credentials":{"<route key>":"<tenant>"}}`.
  route key는 `sha256("evidscope/vault-route/v1\n" + bearer 토큰)`이라 파일에 자격 증명이 없습니다. 목록에 없는 자격 증명은 `VAULT_URL`로 갑니다.
  vault URL은 https이거나 loopback http여야 합니다. 일반 API, 수집 봉투, OTLP, enforcement 전달이 모두 이 경로를 따릅니다.
- 경로 파일이 틀려도 다른 tenant의 vault는 그 자격 증명을 모르므로 401로 거절하고 아무것도 쓰지 않습니다(시험으로 확인).
- 한계: OIDC 세션은 아직 지원하지 않습니다(분할에서 켜면 시작하지 않음). registry는 운영 실수를 막는 장치이지 변조 방지가 아닙니다. 데이터베이스
  파일을 통째로 복사하면 vault id도 복사되므로 복사본은 막지 못합니다. 감사 화면과 내보내기는 tenant의 vault에서 하나씩 봅니다.

### 결과

같은 기계(4 vCPU, Node 24.21.0)에서 기준(d7413a0에 측정 커밋 45cddfc만 더한 것)과 변경본을 번갈아 세 번씩 돌렸고, 다른 시험이 함께 돈 실행은
그 짝과 함께 버리고 다시 쟀습니다. 값은 세 번의 범위와 중앙값입니다. 모든 실행에서 접수·저장·검색 사본·분석 수가 같았고 내보내기 검증이 통과했습니다.
"vault ms/건"은 vault 주 스레드 CPU(괄호 안은 프로세스 전체)입니다.

| 단계와 측정 방식 | d7413a0 | 7라운드 후 | 배수(중앙값) |
|---|---|---|---|
| `burst50`, fetch(이전 단계와 같은 방식) | 757-890 EPS(중앙 889), p95 81 ms, vault 0.95(1.07) ms/건 | 1,030-1,087 EPS(중앙 1,075), p95 71 ms, vault 0.75(0.83) ms/건 | 1.21× |
| `burst50`, node:http | 758-889 EPS(중앙 789), p95 78 ms, vault 1.05(1.17) ms/건 | 968-1,143 EPS(중앙 995), p95 69 ms, vault 0.81(0.88) ms/건 | 1.26× |
| `burst50`, node:http + CPU 고정 | 741-895 EPS(중앙 836), p95 85 ms, vault 0.97(1.03) ms/건 | 909-1,105 EPS(중앙 971), p95 71 ms, vault 0.82(0.88) ms/건 | 1.16× |
| `otlp`, fetch | 1,580-1,703 EPS(중앙 1,583), vault 0.53(0.61) ms/건 | 1,554-1,769 EPS(중앙 1,607), vault 0.55(0.62) ms/건 | 차이 없음 |
| `otlp`, node:http | 1,548-1,810 EPS(중앙 1,728), vault 0.52(0.60) ms/건 | 1,439-1,615 EPS(중앙 1,597), vault 0.55(0.63) ms/건 | 잡음 범위 |
| `otlp`, node:http + CPU 고정 | 1,372-1,434 EPS(중앙 1,389), vault 0.56(0.62) ms/건 | 1,279-1,491 EPS(중앙 1,466), vault 0.51(0.58) ms/건 | 잡음 범위 |
| `sustained` 중 vault CPU(앞 단계 4,400건의 분석이 도는 동안), fetch | 22.4 ms/건 | 15.5 ms/건 | −31% |

node:http 행의 "후"는 tenant 분할 커밋까지 넣은 HEAD로 쟀습니다(분할을 켜지 않으면 append마다 null 검사 하나와 게이트웨이의 경로 함수 하나가 더해질 뿐입니다).
바꾼 것마다 따로 잰 값(같은 방식으로 번갈아 세 번, 중앙값):

| 바꾼 것 | 측정 | 전 | 후 | 차이 |
|---|---|---:|---:|---:|
| 1-3 (8fef815) | 분석 1건당 vault CPU(1,500건 수집 뒤 worker 2개가 비울 때까지) | 4.23 ms | 2.81 ms | −34% |
| 4 (f8044c6) | HTTP 없는 vault 핵심, 4,000건·묶음 50, 건당 경과 시간 | 0.622 ms | 0.498 ms | −20% |
| 4 (f8044c6) | 같은 측정의 건당 CPU | 608 µs | 482 µs | −21% |
| 4 (f8044c6) | 분석 1건당 vault CPU | 2.81 ms | 2.73 ms | 잡음 범위 |

`otlp`는 이미 요청 하나를 트랜잭션 하나로 savepoint 없이 쓰고 있었고(`src/otlp-ingest.mjs`), 분석은 단계가 끝난 뒤에 돌아 이번 변경이 거의 닿지 않습니다.

CPU 고정은 기대와 달리 처리량을 올리지 않았습니다. vault의 모든 스레드(주 스레드, GC, libuv)를 CPU 하나에 묶으면 주 스레드가 그 CPU를 다른 스레드와
나눠 쓰기 때문입니다. 고정 모드의 EPS는 "CPU 하나만 쓰는 vault"의 값으로 읽고, vault의 몫과 부하 생성기의 몫을 가르는 데는 프로세스별 ms/건을 씁니다.
node:http 클라이언트는 클라이언트 CPU를 0.62에서 0.40 ms/건으로 줄였지만 EPS는 오르지 않았습니다. 같은 기계에서 클라이언트가 vault의 CPU를 빼앗는
몫은 생각보다 작았고, 남은 한계는 vault 자신입니다.

**tenant 분할**(HEAD, node:http 클라이언트, tenant 2개 각각 동시성 50으로 2,000건씩, vault마다 분석 worker 1개, 고정 없음, 번갈아 세 번):

| 구성 | 합계 EPS | p95 | vault CPU(건당, 각 vault가 자기 이벤트에) |
|---|---|---|---|
| vault 1개가 두 tenant 모두 | 1,377-1,400(중앙 1,383) | 91-101 ms | 0.69 ms |
| vault 2개, tenant 하나씩, ingress 하나가 경로 지정 | 2,036-2,179(중앙 2,160) | 67-72 ms | 0.76 ms |

합계는 1.56배입니다. 같은 4 vCPU에 vault 2개·ingress·클라이언트·worker 2개가 함께 돌아 2배가 되지 않았고, 코어가 더 있는 기계나 vault를 다른
기계에 두면 vault 수에 비례해 늘어날 것으로 봅니다. tenant 하나의 처리량은 늘지 않습니다.

### 목표

**목표(`burst50` 2,000 EPS, OTLP 3,000 EPS)에는 이르지 못했습니다.** `burst50`은 1,075 EPS(1.21×), OTLP는 약 1,600 EPS로 그대로입니다.

- `burst50`은 tenant 하나의 체인 하나라서 분할로 늘릴 수 없습니다. vault 주 스레드가 건당 0.75 ms를 쓰므로 CPU만으로도 약 1,330 EPS가 상한이고,
  COMMIT의 fsync 대기(건당 약 60 µs)와 닫힌 루프의 빈 시간이 더해집니다. 2,000 EPS에는 건당 0.5 ms 미만이 필요합니다.
- HTTP 없는 vault 핵심만은 이제 약 2,000 EPS(4,000건, 묶음 50: 1,837-2,054)입니다. 남은 차이는 HTTP 파싱·응답, 요청마다의 HMAC 검증,
  ingress 봉투, 그리고 같은 4 vCPU를 나눠 쓰는 ingress·클라이언트·worker입니다.
- OTLP 3,000 EPS에는 건당 0.33 ms가 필요한데 vault가 0.55 ms를 씁니다. 대부분 이벤트마다의 암호화·canonical·해시·삽입(위의 남은 수집 비용)으로,
  보증의 일부입니다.
- 여러 tenant의 합계로는 vault 2개에서 2,160 EPS로 2,000을 넘었습니다. 이것은 목표의 단일 tenant 측정과는 다른 숫자입니다.

### 다음 단계

1. 이어간 검증 상태 갱신(`_advanceVerifiedStates`, 건당 약 110 µs)이 이제 가장 큰 단일 항목입니다. 자기 쓰기에서 이미 만든 값(복호한 이벤트, 투영 행)을
   다시 만들지 않고 넘기면 줄어듭니다. 쓰기 전 검증 경로라 별도 검토가 필요합니다.
2. 분석 worker의 claim 간격과 크기(200 ms, 5건)를 적체에 따라 늘리기. 지금은 worker 2개가 초당 약 50 행동이 상한입니다.
3. tenant 분할을 운영 기능으로: OIDC 세션의 tenant 경로 지정, registry를 데이터베이스 복사본까지 막는 잠금(예: 호스트 잠금 파일), 감사 화면의 여러 vault 모음.
4. 순번에 묶이지 않는 암호 작업을 worker thread로(2단계 다음 단계 3).

### 시험 (7라운드)

- `test/ingest-stage3.test.mjs`: SDK `submit`의 keep-alive agent(fetch와 같은 요청, 연결 하나, 리다이렉트 거절, 기한); 벤치마크의 프로세스별 CPU와
  고정 배치 검사; 체크포인트를 한 번 검증한 텍스트는 다시 검증하지 않고(공개키 읽기 수로 확인), 위조하거나 되돌린 체크포인트는 거절; 평가 증분 대조가
  OFFSET 없이 읽고 어긋난 행을 여전히 찾음; 행동별 색인이 전체 훑기와 같고 보존 처분을 따라감; optimistic 격리에서 쓰기 전 거절은 savepoint 없이,
  쓰기 뒤 거절은 묶음 전체를 savepoint 방식으로 다시 돌려 결과가 같음; 수집 거절(nonce 재사용, 내용 충돌, 적체)이 행도 nonce도 남기지 않고
  SAVEPOINT가 0개; d7413a0 내보내기(`test/fixtures/pre-stage3-export-d7413a0.json`)를 두 검증기로 검증하고 새 내보내기의 레코드 모양이 같음.
  이 가운데 다섯(검증 기억, 평가 커서, 행동 색인, optimistic 격리, savepoint 수)은 d7413a0에서 실패합니다.
- `test/vault-shards.test.mjs`: `VAULT_TENANTS`·경로 파일 검사; 프로세스 안 분할 vault 둘이 각자 tenant만 받고 쓰며(다른 tenant 자격 증명 401,
  `append` 421), 공유 worker 자격 증명이 각 분할에서 자기 tenant를 분석; registry가 준 tenant를 다른 데이터베이스가(분할로도, 분할 없이도) 맡지 못함,
  재시작한 같은 데이터베이스는 다시 맡고 이력이 있는 tenant를 버리지 못함, 분할 데이터베이스를 `VAULT_TENANTS` 없이 열지 못함, 읽을 수 없는 registry
  항목 거절; 실제 프로세스 vault 둘과 ingress 하나에서 tenant별로 경로가 갈리고 두 내보내기가 검증되며, 잘못된 경로 파일로 보낸 자격 증명은 거절되고
  아무것도 쓰이지 않음.
