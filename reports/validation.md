# 검증 현황 — 진행 중

작성일 2026-09-08. 전체 목표는 **미완료**다. Kubernetes 실배포·Service 분산·HPA·Pod 복구는 실행했으며 실패와 한계를 아래 기록했다. source·운영 계정 연동, KMS/WORM, 저장소 HA, 법률 검토 완료를 주장하지 않는다.

## 현재 검증 결과

**실제 Kubernetes:** [전용 클러스터 결과](kubernetes-runtime-20260908.md). 준비 뒤 수집/감사 각60/60·각2Pod, HPA2→3 및 새 Pod18건 처리, 이후2로 축소 관측. 수집 Pod 종료 중297/300성공·3실패, 교체 뒤60/60성공. vault Pod 재생성 후 성공접수515건과 기존 signed checkpoint 연속성 보존. 120초 감사 부하는5203시도·8timeout, p95 778.57ms로 무오류 기준 실패. CNI 허용6·거부21회와 규칙을 관측했으나 개별 packet-hit 귀속은 미입증이다.

**최신 Windows 회귀:** [08:01 UTC 원자료](validation-2026-09-08T08-01-38-754Z.json)56 PASS/10 FAIL. `listen EFAULT`로 여러 시험 서버가 시작하지 못했고 TLS 하위 시험 일부는 미실행이다. 실패 보고서를 보존한다. 별도 Linux 컨테이너 결과는 `linux-validation`에 보관하며 Windows 실패를 덮어쓰지 않는다.

**최신 Linux 회귀:** [08:06 UTC 원자료](linux-validation/validation-2026-09-08T08-06-28-225Z.json) **70 PASS/0 FAIL/0 SKIP**,35.82초, exit0. Kubernetes 정적23리소스·2분산Job과 UI 구문도 통과했다. 컨테이너Node24.20.0·Windows24.15.0 버전 차이를 포함한 [환경 기록](linux-validation/environment.json)을 확인한다. Windows 실패 원인을 OS만으로 확정하지 않는다.

### 실배포 이전 검사 이력

**Kubernetes 로드밸런싱 보강 후:** `node scripts/validate.mjs` **exit0 · 67 PASS / 0 FAIL / 0 SKIP**, [07:34 UTC 원자료](validation-2026-09-08T07-34-53-979Z.json). 회귀 시험33.18초, core23리소스와 분산 시험Job2개의 정적 검사, UI 구문 검사 통과. 실제 로컬 HTTP에서 서로 다른 backend2개 처리·새 TCP 연결·자격 분리·실패/timeout 보존을 확인했다. vault 종료/복구에 따른 gateway readiness503/200, 생존 검사 유지, 동시 준비 검사 합치기, 처리 Pod 헤더 위조 방지도 시험했다. Kubernetes 상태 수집기7개 시험은 **합성 API 응답**이며 Pod UID/IP·서비스·Ready·노드와 EndpointSlice 대조, 중복/종료/오류 제외를 검증한다. 실제 Kubernetes 분산·CNI·HPA·장애복구 시험으로 계산하지 않는다.

선행 실행 [07:32 UTC 원자료](validation-2026-09-08T07-32-37-273Z.json)는65 PASS/1 FAIL이다. 보존 시험의 ingress 시작에서 Windows `listen EFAULT`가 재발했고, 이미 시작한 시험 vault가 남아 실행기 종료를 지연했다. 해당 실행의 부모 PID 관계를 확인해 남은 시험 자식 서버만 종료했다. 초기화 실패 시 생성한 자식을 정리하도록 harness를 수정했으며 원래 실패를 재시도로 감추지 않는다. OS socket 오류 원인은 여전히 미확정이다.

**당시 배포 상태:** 이67개 검사 시점에는 Docker 복구 승인 대기였다. 이후 승인된 임시 소켓 보관·재시작으로 Docker를 복구했고, 별도 실험 클러스터를 사용했다. 기존 `k3d-dlp` context는 사용하지 않았다. 외부 LoadBalancer와 vault 저장소 HA는 미구현이다. [배포 범위와 실제 통과 기준](../docs/kubernetes-load-balancing.md)을 따른다.

### 행동 조사·감사 고도화의 선행 결과

`node scripts/validate.mjs`: **exit 0 · 50 PASS / 0 FAIL / 0 SKIP**, [2026-09-08 07:13 UTC 원자료](validation-2026-09-08T07-13-01-908Z.json). 22.55초의 실제 HTTP·TLS·SQLite·복구·보존·분산 worker·행동 조사/판단/보고서 시험과 Kubernetes JSON 보안 검사23리소스, UI 구문 검사가 통과했다. 새 mixed_results를 model에 추가한 뒤 분석 commit의 허용 상태에도 반영해야 했던 회귀 실패(48/50)는 `validation-2026-09-08T07-06-01-820Z.json`에 보존했다. 수정 후 전체 검증을 다시 실행했다.

**실무 감사 흐름:** 같은 행동·tenant 원본만 선택, 공백 사유·작성자 위조 거부, 늦은 증거와 분석 변경의409, 재검토 기한 만료, 정당한 파기 이후 과거 판단 보존, 이벤트/사건/평가/판단 조회 사본 각각의 변조 시 보고서 발급 거부, 다른 공개키·내용 변경·외부 체크포인트 불일치 실패를 확인했다. 독립 CLI의 성공/변조 exit code도 시험했다. 서비스 성공·실패 혼재를 성공으로 축약하지 않는다.

**실제 브라우저(9082):** 행동 검색으로 demo-ba8bc13a-action을 선택하고 자기보고/서비스 결과와 product-guide v1/v2 참조를 대조했다. 근거3개를 체크해 합성 판단 유보·범위·한계·재검토일을 저장했고 alpha-auditor 작성자와 이력을 확인했다. 실제 다운로드된 JSON을 CLI로 검증하고 Markdown 내 전체 snapshot과 같은지 대조했다. 브라우저 자동화의 download 이벤트는 timeout이었지만 실제 Downloads 폴더에 두 파일이 저장되었으며 파일 직접 검증으로 성공을 확인했다. 후속 합성 도구 성공 결과를 추가하자 사건이 재검토로 바뀌고 행동 상세는 성공·실패 혼재를 표시했다. SSO·실제 사람의 업무 평가 시험은 아니다.

- [브라우저에서 받은 읽기용 보고서](case-review-example.md), [서명 JSON](case-review-example.json), [독립 검증 결과](case-review-example-verification.json)
- 예제는 새 후속 증거 추가 **이전** 07:14:52 UTC 스냅샷이며, 이후 화면은 재검토 상태다. 예제 공개키는 `case-review-example-public-key.pem`에 따로 저장했다. 운영 신뢰 경로를 입증하는 예제가 아니다.

**조사함을 동시 조회한 부하:** [07:02 UTC 원자료](benchmark-2026-09-08T07-02-18-863Z.json), **exit0 / pass=true**. 동일 로컬 Windows/Node24.15.0 환경에서 source3·worker2·사용자룰1, 조사함500ms간격 조회, 총1,000건 생성=접수=보존=검색=분석, 중복/오류0·최종backlog0. peakbacklog210, vault peakRSS256,249,856bytes.

| 항목 | 실제 측정 |
|---|---|
| 정상20EPS×10초 접수 p50/p95/p99 | 4.46 / 16.32 / 21.85ms |
| 급증200건·동시성20 접수 p50/p95/p99 | 68.01 / 128.71 / 134.50ms |
| 지속20EPS×30초 접수 p50/p95/p99 | 58.63 / 187.44 / 254.35ms |
| 조사함116회 조회 p95 | 315.53ms · 최종행동1,000개 일치 |
| 전체원장 대조 포함 단일사건 보고서5회 p95 | 137.29ms · 서명 모두 검증 |

사전 기준인 조사함p95<1,000ms·보고서p95<2,000ms를 통과했다. 단일 로컬 감사자 규모이며 큰 데이터셋, 동시 감사자, 외부 storage/network, HPA 성능으로 일반화하지 않는다. UI409와 저장 후 다른 화면으로 이동하는 경합 보호는 코드리뷰 및 HTTP 시험으로 확인했으며 브라우저 지연 주입 시험은 미실행이다.

## 선행 검증과 측정 이력

`node scripts/validate.mjs`: **exit0**, `reports/validation-2026-09-08T06-38-49-331Z.json`. 실제 HTTP·TLS·SQLite·복구·보존·참고자료·권한 시점·분산 worker 시험 **44 PASS / 0 FAIL / 0 SKIP**. 추가 읽기 전용 Kubernetes JSON 보안 검사(23리소스)와 UI JavaScript 구문 검사도 exit0이다. 정적 검사 결과는 배포·CNI·HPA 실행을 증명하지 않는다.

`node scripts/benchmark.mjs`: **exit0**, `reports/benchmark-2026-09-08T06-35-20-741Z.json`. 새 이벤트 암호화·분산 worker·streaming 무결성 검증을 포함한다. Intel i7-12700F, 논리 CPU20, RAM34,212,798,464 bytes, Windows x64, Node24.15.0, local SQLite FULL WAL, worker2, source3, 사용자 룰1, 감사 조회500ms 간격. 이벤트1,052~1,070bytes. 총 생성/시도/접수/원본/검색/분석 각각 **1,000**, 중복0·오류0·최종 backlog0, peak backlog188, peak vault RSS275,226,624bytes. 독립 export 서명/무결성 통과.

| 부하 | 건수 | 실제 EPS | 접수 p50 / p95 / p99 (ms) |
|---|---:|---:|---|
| 정상20EPS×10초 | 200 | 20.08 | 4.93 / 17.39 / 27.20 |
| 급증, 동시성20 | 200 | 291.82 | 65.50 / 91.32 / 91.96 |
| 지속20EPS×30초 | 600 | 20.03 | 46.65 / 148.10 / 193.74 |

사전 p95<1,000ms·성공접수의 최종 수량 일치 기준을 유지했다. 지속 부하의 지연·메모리가 이전 구조보다 증가했고 vault의 암호/서명 및 원장 순회 비용이 남는다. 저비용 로컬 사용 사례 측정이며 대규모·HA·정전·CNI·HPA·공급자 실연동 결과가 아니다.

## 이전 원자료와 UI 범위

`reports/benchmark-2026-09-08T06-09-31-707Z.json`은 암호화 이벤트/분산 계산 변경 **이전**의 원자료다. 생성·접수·저장·검색·분석 각 1,000, 중복/오류 0, 최종 backlog 0, 전체 기준 pass=true. 정상20EPS×10초 p95 7.20ms, 동시성20 급증200건 p95 56.43ms, 지속20EPS×30초 p95 7.33ms. peak vault RSS 122,675,200 bytes. 이 결과를 새 변경의 성능 검증으로 대체 사용하지 않는다.

실제 HTTP 통합13개 + 권한 의미4개 =17 tests exit0 확인에서 시작했고 TLS·분산 worker·보존·참고자료·무결성 검사를 확장했다. 모든 최종 검사는 위 timestamp 원자료에 저장했다.

브라우저 선행 확인: 인증 실패, 로그인/로그아웃, 10개 이벤트·21개 경보·1개 사건, 문자열/종류 검색·빈 상태, 원본 scope/정책 참조, 사건 의견 저장, auditor 룰 시험403, 2개 거버넌스 시스템·증거 부족 보고, JSON export, 무결성 검증. 공격 문자열 `<script>`는 텍스트로 표시됐고 콘솔 오류0. 이후 보존 탭과 행동·참고자료 비교 UI를 추가했지만 현재 CUA는 `apps:[], browsers:[]`, `No browser is available`을 반환했다. open_in_codex는 queued 상태. **최종 UI의 브라우저 조작·스크린샷·파기 dialog 시험은 미실행**이며 backend API/구문 통과와 구분한다.

## 실패와 수정 기록

- 초기 배포 smoke harness exit1: `fork`가 `--input-type`를 상속한 시험 실행기 문제. `execArgv:[]` 수정 후 smoke exit0. 애플리케이션 장애와 분리했다.
- TLS fixture 첫 실행: OpenSSL 기본 config의 CA `basicConstraints` 중복. 자체 테스트 config와 CA 검증으로 수정 후8 tests exit0.
- Windows socket 단발 `listen/connect EFAULT(-4074)`: TLS 중간 실행 exit1 및 암호화 변경 후 HTTP suite exit1(8pass/5fail)을 관측. 후자는 multiwriter 연결 실패 이후 restart·저장장애·demo 시험까지 연쇄 실패했다. 자동 재시도로 숨기지 않았다. 원인 확정 전 OS socket 환경 문제로 분류하며, 동일 코드의 후속 실제 integration22 tests exit0도 함께 기록한다.
- 코드 리뷰로 사후 발급 권한의 과거 적용, 정책/parent 범위 누락, 다른 대상의 중단 확인, 예외 만료 후 재평가 누락, 시스템 변경 후 과거 평가의 유지, 보완과제 ID 불일치 수정. 각각 의미/HTTP 회귀시험으로 확인.
- 증거 변경 후 원장 다시 서명하는 위험을 막기 위해 append 전에 기존 서명 checkpoint와 현재 head 일치를 검사. 손상된 원장을 다시 봉인하지 않는다. 실패를 원장에 쓸 수 없는 경우 외부 사건 기록 필요 상태를 반환한다.
- `reports/validation-2026-09-08T06-33-40-314Z.json`: 회귀43 PASS였으나 PowerShell 실행 정책이 `.ps1` 실행을 거부해 aggregate exit1. 실행 정책을 변경하지 않고 별도 읽기 전용 `scripts/k8s-static.mjs`로 JSON을 검증했다. 배포용 PowerShell 실행은 이 검사로 우회하거나 수행하지 않는다.
- 보존 추가시험에서 환경 `listen EFAULT` 재발로4중1시험이 시작하지 못한 exit1을 관측했다. 그 뒤 최종 full suite44 PASS. 독립 순수 HTTP bind/close30회는 오류0이었고 netsh 예약 포트 목록 확인만 수행했다. 간헐적 Windows socket 오류의 원인은 확정하지 않았으며 네트워크 시스템 설정을 변경하지 않았다.

## 현재 차단 증거와 재개 조건

`docker version`: client29.6.1 존재, `docker_engine` named pipe 없음. 사용자 `.docker/config.json` 읽기 Access denied. `kubectl config current-context` 및 `kubectl get nodes`: 사용자 `.kube/config` 읽기 Access denied. `wsl --list --quiet`: `Wsl/EnumerateDistros/Service/E_ACCESSDENIED`. 사용자 설정이나 다른 계정으로 우회하지 않았다.

정식 require_escalated 권한 검토를 거친 읽기 전용 확인은 허용됐다. 실제 Docker context는 `desktop-linux`, 기존 kube context는 `k3d-dlp`이며 둘을 EvidScope 전용이라고 간주하지 않았다. 설치된 Docker Desktop4.80.0을 Hidden 시작한 PID5040은 약10초 후 종료됐다. 2026-09-08T06:41:22Z 시작 로그는 `initializing Inference manager`의 `...Docker/run/dockerInference` 접근/경로 오류를 기록했다. `docker desktop status`도 실행 중 아님을 반환했고 WSL Ubuntu/docker-desktop은 Stopped였다. factory reset·기존 context 변경·socket 삭제를 수행하지 않았다. 공용 Docker 환경 복구 범위는 사용자에게 확인 요청했다.

재개 조건: 정상 시작한 허가된 Docker/Kubernetes 환경과 명시적 시험용 context, 필요한 CNI·metrics-server·PVC·이미지·TLS secret. 공유/유료 cluster 변경은 별도 권한 확인 대상이다. `deploy/kubernetes.json` 및 부하/관측/복구 스크립트는 준비했지만 offline 체크는 실배포 근거가 아니다. 현재 클러스터의 런타임 실패 원인과 UI 연결 부재를 코드 오류 또는 제품 검증 완료와 혼동하지 않는다.
