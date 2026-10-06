# 증거 무결성 처리량과 저자원 정식 학습 결과

## 달성한 변화

EvidScope의 반복 조회와 수집 경로가 매 요청마다 테넌트 전체 서명 원장을 재생하던 병목을 제거했다. 수집·분석·감사 결과의 무결성 범위는 유지하면서, 확인된 checkpoint 이후의 서명 suffix와 projection delta만 검증한다. 로컬 합성 20 EPS 부하에서 이전 최신 결과는 sustained 600건 중 84건만 접수되고 나머지는 503이었으나, 수정 후 600/600을 접수하고 분석 backlog를 0으로 비웠다. p95는 약 6초에서 240.51ms로 낮아졌다.

이 결과는 외부 대출·신용평가 AI의 공급사 증빙, 승인, AI 서비스 기록, 업무 결과를 대조하는 제품 경로를 실용적인 응답 시간으로 만드는 작업이다. 범용 승인 엔진이나 SIEM을 새로 구현하는 범위가 아니라, 이미 받은 기록의 서명 계보·버전·충돌·누락을 감사자가 재검토할 수 있게 하는 데 집중한다.

## 구현 범위

- transaction 안의 여러 append를 하나의 최종 checkpoint로 묶고, 실패한 savepoint나 외부에서 시작된 transaction의 중간 상태를 cache에 게시하지 않는다.
- tenant별로 인증된 action/event receipt/event key/object/evaluation projection과 원장 head를 보관한다. 다음 읽기는 현재 checkpoint 서명과 head, 새 suffix, 각 projection delta를 검증한다.
- SQLite `data_version`, `schema_version`, runtime mutation clock으로 프로세스 외 변경과 직접 SQL 변경을 탐지한다. 보호 projection을 바꾸는 알 수 없는 trigger, checkpoint 후퇴·교체, 행 감소는 fail-closed다.
- 사건·인간 판단·평가도 서명 원장과 대조한다. 최신 사람 판단은 재삽입으로 바뀔 수 있는 SQL `rowid`가 아니라 signed ledger `seq`로 선택한다.
- 조사함은 선택된 페이지의 상세만 복호화·분석한다. 평가 101개 초과는 성공으로 축약하지 않고 제한 상태로 표시하며, 한 행동의 사건 1,001개 초과가 무관한 검색 결과까지 차단하지 않게 범위 오류를 선택 항목에 적용한다.
- `/api/integrity`, 전체 export와 backup 검증은 cache에 의존하지 않고 전체 체인과 projection을 끝까지 검사한다.

## 성능 증거

최종 코드의 기준 파일은 `reports/benchmark-2026-10-05T06-29-04-501Z.json`이다. 이전 2026-10-04 측정과 동일한 1,000건 합성 시나리오를 재실행했다.

| 구간 | 요청/접수 | 관측 처리량 | p95 |
|---|---:|---:|---:|
| normal | 200/200 | 20.08 EPS | 15.07ms |
| burst | 200/200 | 158.34 EPS | 156.15ms |
| sustained | 600/600 | 19.86 EPS | 206.81ms |

총 1,000건을 저장·검색 projection·분석했고 최종 backlog는 0이다. peak backlog는 181, vault RSS는 145,510,400 bytes였다. 1,000개 행동을 대상으로 한 조사함 검색 p95는 362.52ms, 단일 사건 서명 보고서 p95는 239.46ms였다. `benchmark-latest.json`도 이 최종 실행을 가리킨다.

## 무결성 검증

- Windows 전체 회귀는 568개 중 559개 통과했다. 실제 제품 기대값 회귀 1개는 수정 후 evaluation 무결성 10/10을 통과했다. 나머지 8개 실패는 Windows의 `listen EFAULT`로 load-balancing 5개, retention 2개, TLS 1개였다.
- 같은 제품 경로를 제한 Linux 컨테이너에서 다시 실행해 관련 무결성·금융·조사·worker·보존 112/112, load-balancing 5/5, openssl을 포함한 TLS 8/8을 통과했다.
- 최신 signed-seq 회귀를 포함한 독립 검토는 50/50을 통과했다. 검토자가 추가로 찾은 무관한 행동의 사건 한도 전파 문제를 수정했고 workbench 7/7을 통과했다.
- 앞선 최종 cache 집중 회귀는 94/94를 통과했다.

평가 연결 코드까지 포함한 최종 소스의 Windows 전체 회귀는 **592/592 통과**했다. [전체 테스트 로그](enterprise-final-host-tests-after-diagnostic-20261005.log). 진단 Python 검증도 **23/23 통과**했다. [Python 테스트 로그](public-qa-stage2-diagnostic-python-tests-20261005.log). 최종 로컬 제품 이미지 `evidscope:enterprise-20261005-r14`는 Linux amd64, ID `sha256:92dfc6675e63deb2df85e1e0e3389793a0aaef6567f7b7ea935f597b0f56d0df`다. 네트워크 차단, read-only root, UID 1000:1000, CPU 2, RAM 1GiB, capability 전체 drop, no-new-privileges 조건에서 무결성·금융·조사함·worker 집중 **131/131 통과**했다. [제한 컨테이너 로그](enterprise-container-tests-r14-20261005-retry.log). 첫 제한 실행은 테스트용 `.test-runs` 쓰기 경로가 없어 20건이 실패했고, 해당 경로에만 비영속 tmpfs를 제공한 동일 이미지의 재실행에서 모두 통과했다. 오프라인 빌드의 `npm ci`는 로컬 npm 패키지 캐시 부족으로 실패했으며, 고정 `package-lock.json`으로 네트워크 빌드해 위 이미지를 생성했다.

## Docker와 학습 실행

Docker Desktop 재부팅 오류는 접근 불가능한 reparse socket 두 개에서 재현됐다. Docker 프로세스만 정지한 뒤 기존 socket 디렉터리를 보존 이름으로 이동하고 빈 디렉터리를 만들어 엔진을 복구했다. DLP 컨테이너는 원래 상태로 복구했으며 AhnLab이 포트 58670을 점유한 기존 `k3d-dlp-serverlb`는 시작하지 않았다.

2026-10-05 `public-qa-stage2-lowmem-20261005-r4`에서 공개 인간 작성 KLUE QA 320개 학습·64개 검증으로, 동일 Foundation-Sec-8B-Reasoning 베이스의 검증된 20단계 체크포인트를 재개해 **21∼40단계의 실제 optimizer 갱신 20회**를 완료했다. 누락·건너뛴 갱신은 0이며 Job 종료 코드 0, Pod 회수 확인, 전용 PVC에서 회수한 후보·checkpoint-30·checkpoint-40의 파일 SHA-256 검증이 통과했다. 30·40단계 체크포인트의 학습 중 원본 PVC 해시와 회수본 해시도 일치했고, 최종 체크포인트와 후보 어댑터 해시가 동일했다. [학습 산출물 검증](public-qa-stage2-artifact-verification-20261005.json), [원본·회수 비교](../.local/training/public-qa-run/public-qa-stage2-lowmem-20261005-r4/pvc-export-comparison.json).

같은 베이스에서 adapter를 끈 검증 loss는 1.28445, adapter를 적용한 검증 loss는 0.11026이었다. 이는 64개 공개 QA 정답 형식에 대한 손실 진단이며 실제 답변·인용 정확도나 금융·법률 판단 개선의 증거가 아니다. CUDA 최고 할당 7,125,966,848 bytes(약 6.64GiB), 호스트 관측 GPU 최고 사용 8,300MiB·온도 73°C였다. 컨트롤러 317개 표본의 최소 물리 메모리 여유는 7.379GiB, 최소 커밋 여유는 9.192GiB, 컨테이너 OOM kill은 0건이다. 학습 후 전용 노드를 정지해 GPU를 회수하고, 임시 정지한 DLP 컨테이너 5개를 원래 ID로 복구했다. [복구 기록](../.local/training/public-qa-run/dlp-after-stage2-r4-20261005.json).

## 실제 한국어 응답 비교

별도 KLUE QA 64개(답 있음 32, 없음 32)의 동일 문맥·프롬프트·NF4 베이스·128토큰 한도에서 adapter OFF와 새 40단계 후보를 순차 실행했다. `public-qa-diag-stage2-20261005-r1`은 **128개 실제 호출**, Job exit 0, Pod 회수, 개별 응답 128개, 응답/영수증의 PVC 원본·회수본 해시 대조와 [실행 검증](public-qa-stage2-diagnostic-verification-20261005.json)이 통과했다. [고정 규칙 채점](public-qa-stage2-diagnostic-score-20261005.json)은 다음과 같다.

| 지표 | 베이스 | 20단계 후보(기존 실행) | 40단계 후보 |
|---|---:|---:|---:|
| JSON 형식 충족 | 0/64 | 64/64 | 64/64 |
| 원문 정답 일치 | 0/64 | 12/64 | 16/64 |
| 근거 인용 충족 | 0/64 | 22/64 | 32/64 |
| 판단 보류 여부 일치 | 0/64 | 33/64 | 34/64 |
| 모든 조건 충족 | 0/64 | 8/64 | 16/64 |

같은 평가 데이터 해시에서 20단계 대비 새로 통과한 문항은 9개이고 실패로 바뀐 문항은 1개다. 답이 없는 32개 중 올바르게 보류한 것은 4개뿐이다. 베이스는 64개 모두 출력 한도에 도달했고, 새 후보의 응답 형식 개선이 금융 감사나 한국법 판단 품질을 뜻하지 않는다. 채점기는 모델 실행을 단독 인증하지 않으므로 실행 검증 보고서와 함께 해석한다. 사람의 한국어 의미·안전 검토와 실제 금융 데이터 평가 전에는 품질 인정·운영 배포를 계속 금지한다. 이 평가에서는 DLP를 멈추지 않았고 종료 후 GPU 노드만 정지했다. [최종 복구 상태](../.local/training/public-qa-run/public-qa-diag-stage2-20261005-r1/post-evaluation-recovery.json).

## 해석 한계

성능 수치는 i7-12700F, RAM 32GiB, 로컬 SQLite WAL, 단일 writer, 합성 이벤트의 Windows 측정이다. HA, 원격 스토리지, Kubernetes HPA, 장애 복구, 디스크 전원 손실, 실제 금융 고객 데이터나 상용 공급사 API를 입증하지 않는다. 서명은 EvidScope가 받은 기록과 발급한 문맥의 무결성을 다루며 외부 기록의 진실성, 한국 AI 기본법 준수, 법률 결론이나 인증을 보증하지 않는다.

학습 데이터는 공개 인간 작성 KLUE QA의 원문 주석을 사용한다. 이는 한국어 추출·인용 형식 학습에 대한 출처 근거이며, 금융 도메인 판단·법률 적용·실제 고객 품질 승격을 뜻하지 않는다. 기존 540개 합성 금융 데이터는 사람 검토가 완료되지 않았으므로 정식 학습에서 제외한다.
