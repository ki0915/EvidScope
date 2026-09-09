# EvidScope 개발 가이드

작성일 2026-09-09 · 대상 버전 0.1 파일럿. 소스의 현재 동작을 기준으로 하며 운영 배포 승인을 대체하지 않는다.

## 1. 시작하기

Node.js 24.15.x 환경을 기준으로 개발했다. `package.json`은 24.15 이상 25 미만을 요구한다. 외부 npm 런타임 의존성은 없다. 일반 실행·단위 시험에는 Docker나 유료 AI 계정이 필요 없다.

저장소를 내려받은 뒤 프로젝트 루트에서:

```powershell
node --version
npm run init
npm start
```

별도 터미널에서 `npm run demo`를 실행하고 `http://127.0.0.1:8082`를 연다. `.local/config.json`의 해당 인간 역할 토큰으로 로그인한다. 토큰을 채팅·이슈·스크린샷·커밋에 넣지 않는다. 초기화는 설정이 이미 있으면 재사용한다. 설정만 남고 키가 사라진 경우 새 키로 덮어쓰기 전에 백업과 기존 증거의 검증 경로를 확인한다.

| 프로세스 | 기본 포트 | 사용 주체 |
|---|---:|---|
| vault | 8080 | gateway·worker |
| ingress | 8081 | source 제출 |
| audit | 8082 | 인간 브라우저·API |
| worker health | 8083 | 운영 상태 점검 |

`Ctrl+C`로 로컬 실행기와 자식 프로세스를 종료한다. UI 시험용 `scripts/ui-fixture.mjs --reuse`는 별도 `.test-runs/ui`와 9080–9083을 사용한다. 이 fixture는 공개된 합성 시험 토큰을 설정하므로 loopback 합성 자료 시험에만 사용한다. 일반 실행 설정과 혼용하지 않는다.

## 2. 디렉터리와 수정 위치

| 위치 | 내용 / 변경 시 확인할 사항 |
|---|---|
| `src/server.mjs` | 서비스 모드, gateway, TLS, 정적 파일 허용목록, readiness |
| `src/service.mjs` | 인증·역할·API 연결; source와 인간·worker 경계 유지 |
| `src/model.mjs` | 이벤트 허용 필드, 정규화, 권한 대조, 룰 조건 |
| `src/store.mjs` | 스키마, 트랜잭션, 원장, 조회 사본, 재구축 |
| `src/analysis.mjs`, `src/worker.mjs` | claim/lease/완료 정합성 |
| `src/crypto.mjs`, `src/encryption.mjs` | commitment·서명·암호화·독립 검증 |
| `src/audit-workbench.mjs` | 조사함, 인간 판단, 사건 보고서 |
| `src/retention.mjs` | 보존 정책·hold·별도 승인·파기 |
| `src/agent-inventory.mjs`, `src/monitoring.mjs` | 에이전트 분모·기간·추이·운영 집계 |
| `src/client.mjs` | 비동기 Observer, 유한 큐·재시도·drop |
| `public/` | 프레임워크 없는 한국어 DOM UI·CSS·그래프 |
| `data/` | 합성 업무 자료와 출처가 연결된 규정 catalog |
| `deploy/` | Kubernetes 리소스 및 재생성 스크립트 |
| `scripts/`, `test/` | 실행·합성 실험·독립 검증·회귀 시험 |
| `reports/` | 과거 조건별 실측; 최신 소스 검증과 구분 |

## 3. 설정과 비밀

주요 환경변수는 `MODE`, `HOST`, `PORT`, `DATA_DIR`, `CONFIG_FILE`, `SIGNING_KEY_FILE`, `VAULT_URL`, `WORKER_TOKEN`, `TLS_CERT_FILE`, `TLS_KEY_FILE`, `NODE_EXTRA_CA_CERTS`다. 정확한 사용은 `src/server.mjs`와 [운영 문서](operations.md)를 따른다.

기본 바인딩은 loopback이며 비 loopback 리스너는 TLS 설정 없이는 시작하지 않는다. 역할별 자격과 tenant는 vault 설정에서 결정된다. 프런트엔드 토큰은 메모리에만 유지한다. DB·서명키·실제 인증 설정·TLS 개인키·모델 파일은 Git에 올리지 않는다.

## 4. API 개발

전체 이벤트 계약과 오류 코드는 [수집·감사 계약](contract.md)에 있다. source는 ingress의 `POST /api/ingest`, 사람은 audit의 `/api/*`, worker는 vault의 `/internal/claim`과 `/internal/complete`를 사용한다.

| 기능 | 주요 API | 구현상 주의 |
|---|---|---|
| 이벤트 검색 | `GET /api/events` | tenant는 인증에서 결정 |
| 행동 근거 | `GET /api/actions/:id` | 요청·실행·결과·권한·참조 출처를 구분 |
| 에이전트 | `GET /api/agents` | range/focus/sort/q/id/end/limit/offset |
| 실시간 운영 집계 | `GET /api/monitoring` | 10m/1h/24h/7d, 수신 시각 집계 |
| 인간 조사 | `/api/investigations`, `/api/cases/*` | 새로운 증거·기한 만료에 따른 재검토 |
| 규정 검토 | `/api/governance/*` | 기술 상태·충분성·법률 검토 분리 |
| 독립 증거 | `GET /api/export`, `/api/integrity` | export 안의 임의 키를 신뢰하지 않음 |

새 이벤트 필드를 추가할 때는 허용 필드·길이·종류·출처 권한을 함께 정의한다. 기존 fingerprint·서명·중복 판단과의 호환성을 검토한다. 새 탐지 코드는 에이전트 준수율 분류에도 반영한다. 분류되지 않은 코드를 자동 충족으로 처리하지 않는다.

## 5. UI 개발 원칙

- 비신뢰 문자열은 DOM textContent로 렌더링한다. 로그·참조 URL을 코드나 원격 요청으로 실행하지 않는다.
- 로딩·빈 상태·실패·권한 거부·부분 결과를 구분한다. 취소된 조회나 이전 로그인 세션의 응답이 현재 화면을 덮어쓰지 않게 epoch 검사를 유지한다.
- 화면 이탈 시 타이머를 정리하고 인증 실패 후 자동 재시도를 멈춘다.
- 준수율과 평가 범위를 함께 보여준다. 미확인·대기·예외와 0분모를 통과로 바꾸지 않는다.
- 새 정적 파일은 `src/server.mjs`의 허용목록에도 등록한다. 현재 UI는 별도 번들 빌드가 없다.

## 6. 검증 명령과 판정

```powershell
# 전체 회귀: 실제 로컬 HTTP/TLS/SQLite 경계 포함
npm test

# 에이전트 운영 기능의 집중 검증
node --test test/agent-inventory.test.mjs test/agent-operations.test.mjs test/agent-explorer-ui.test.mjs test/monitor-ui.test.mjs

# 정적 배포 검사와 UI 문법을 포함한 결과 보고서 생성
npm run validate

# 부하 실험: 합성 자료를 사용하며 실행 조건별 보고서를 남김
npm run bench
```

전체 검증은 임시 디렉터리, 프로세스, loopback 포트, TLS 도구를 사용할 수 있어야 한다. Windows에서는 이전에 listen EFAULT가 관측됐다. 실행 실패는 원자료로 남기고 Linux 성공 결과로 덮어쓰지 않는다. `validate`는 시각별 보고서와 `validation-latest.json`을 쓰므로 이전 시각별 결과를 보존한다.

에이전트 기간·집계·UI 변경에는 시간 경계, 기간 밖 근거, 0분모, 미분류 경보, 다중 귀속, 다른 tenant 접근, 100개 초과 행동, 그래프 합계, 필터 조합을 검증한다. 암호·보존·권한·동시성 변경에는 해당 통합 시험을 함께 수행한다.

이미 UI fixture가 실행 중인 환경에서 `node scripts/verify-agent-operations.mjs`로 실제 9082 API를 검증할 수 있다. fixture가 없으면 이 스크립트만 실행해도 서비스를 시작하지는 않는다.

## 7. 실제 로컬 AI 시험

일반 서비스는 모델 없이 동작한다. 선택적 시험에서는 기존 Ollama와 Qwen3 0.6B, 고정된 합성 자료 조회 도구를 사용했다. 모델의 실제 tool call이 없으면 성공으로 가공하지 않고 실패로 기록한다. 모델 출력 전체를 운영 원장에 저장하지 않는다.

준비와 기존 결과는 [로컬 AI 파일럿](local-ai-pilot.md)을 확인한다. UI fixture와 로컬 모델 endpoint가 준비된 뒤:

```powershell
node scripts/local-ai-test.mjs
node scripts/verify-local-ai-test.mjs
```

첫 명령은 AI·도구 관측을 제출한다. 두 번째는 별도 인간 감사자 단계에서 서명 원장과 대조한다. 실행기 분리와 실제 업무 품질은 후속 검증이다. 외부 API 요금은 도입하지 않았지만 로컬 자원 비용은 발생한다.

## 8. Kubernetes 개발과 배포

```powershell
node deploy/render-manifests.mjs
node scripts/k8s-static.mjs
docker build -t evidscope:local .
```

위 명령은 manifest 생성·오프라인 검사·로컬 이미지 빌드다. 실제 배포는 [운영 문서](operations.md)의 명시적 클러스터 context, Secret 준비, server dry-run, 배포, 준비 상태 검사를 따른다. 기존 클러스터를 기본 context 추정만으로 변경하지 않는다. vault replica 수를 늘리는 방식으로 SQLite HA를 만들지 않는다.

배포 이미지는 운영 승격 전에 검증한 digest와 공급망 검토를 연결해야 한다. 수집·감사·worker 부하와 vault 저장소 병목을 따로 측정한다. [로드밸런싱 문서](kubernetes-load-balancing.md)의 실험 조건과 실패 건수를 함께 확인한다.

## 9. 변경 검토와 인수 기준

1. 문제·사용자 동작·변경 범위를 기록하고 필요한 합격 기준을 시험 전에 정한다.
2. 원장·사본·판정·인간 의견의 경계를 유지한다. 데이터 포맷 변경 시 기존 export 검증 호환성을 설명한다.
3. 권한·tenant·비신뢰 입력·자원 한도 관련 회귀를 실행한다.
4. 사람이 실제 UI에서 검색 → 근거 비교 → 검토·보고서로 이동할 수 있는지 확인한다.
5. 명령·exit code·환경·조건·실패·미검증 범위를 `reports/`에 기록한다. 과거 성공을 최신 전체 회귀로 표시하지 않는다.
6. 문서·API 계약·개선 계획을 최종 구현에 맞춰 수정한다. 런타임 비밀과 데이터는 업로드 대상에서 제외한다.

현재 프로젝트는 `UNLICENSED`이며 별도 오픈소스 사용 허가를 부여한 상태가 아니다. 공개 배포·라이선스 변경은 소유자의 별도 결정이 필요하다.
