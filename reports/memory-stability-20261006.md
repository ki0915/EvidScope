# 메모리 안정화와 검증 작업 충돌 방지 — 2026-10-06

페이지 파일의 실제 할당·지속 설정은 30GiB다. 이전 메모리 조정 이후 실제 추가 가중치 학습 20 optimizer step을 완료했고, 후보 이력은 80 step이다. 현재 별도의 동일 베이스·어댑터 순차 비교 평가가 실행 중이다. 이 보고서는 평가 완료나 품질 인정 보고서가 아니다.

## 실제 측정

2026-10-06 15:26 KST Windows 측정에서 물리 RAM 여유 4.119GiB, 예약 여유 7.370GiB, 예약 한도 61.863GiB, C 드라이브 여유 10.467GiB를 확인했다. 페이지 파일을 더 키우는 대신 적용된 설정과 작업 중 실제 여유를 확인했다. 프로세스별 private/working set은 관측치이며 게스트·컨테이너 수치와 합산하지 않았다.

15:27 KST까지 진행 중인 평가의 실제 관측 203회에서는 최소 물리 여유 3.617GiB, 최소 예약 여유 6.450GiB, 컨테이너 최대 점유 약 2GiB, GPU 전체 최대 점유 8416MiB, OOM/oom_kill 0을 기록했다. 생성 호출은 당시 94/256이다. 장래 자원 상태나 평가 성공을 보장하지 않는다.

기존 NF4·batch 1·CPU 2·RAM hard limit 12GiB·memory.high 2GiB 회수 기준과 GPU 프로세스 할당 비율 0.65를 유지한다. memory.high는 2GiB 강제 상한이 아니며 GPU 비율은 PC 전체 GPU의 격리가 아니다. 활성 평가의 고정 런타임을 변경하지 않았다.

## 재발 방지 변경과 검사

- `npm test`는 `scripts/test-serial.mjs`에서 활성 공개 QA 작업 lease를 확인한 후 모든 배포된 `.test.mjs`를 순차 실행한다. 기존 concurrency 1과 전체 파일 범위를 유지한다.
- 10회 출시 검증은 시작 전·매 라운드 전에 같은 lease를 확인한다. 활성·손상·오래된 lease를 자동 삭제하거나 무시하지 않는다. 새 guard와 runner도 출시 소스 해시 감시 범위에 추가했다.
- 실제 GPU 작업 실행 중 `npm test`와 출시 명령 모두 exit 1로 테스트 시작 전에 차단됐다. 출시 검증 출력 디렉터리도 생성되지 않았다.
- 소규모 실제 자식 프로세스 검사까지 포함한 6/6 검증을 통과했다. 전체 파일 실행, 실패 exit 전달, 잘못된 인자 거부와 lease 보존을 확인했다.
- 첫 fixture 검사 4/6 실패도 보존했다. 상위 `node:test`의 `NODE_TEST_CONTEXT`가 새 테스트 실행을 억제하는 것을 확인해 자식 테스트 환경에서 그 마커를 제거했고, 명시 TAP로 실제 실행과 실패를 검증했다.

이 변경은 실행 순서 검사이며 OS 수준의 원자적 잠금이 아니다. 직접 `node --test`나 별도 `test:*` 명령은 이 경로를 우회할 수 있고, lease 검사 직후 다른 작업이 시작되는 경쟁도 완전히 제거하지 않았다. 전체 회귀와 새 10회 출시 증명은 GPU 종료·정리 확인 뒤 실행한다. 사용자 앱은 종료하지 않았으며 WSL 전체 재시작도 하지 않았다.

증적: [구조화된 측정](memory-stability-20261006.json), [Windows 원본 관측](memory-live-host-20261006.json), [최종 6개 검사](memory-execution-boundary-final-fixed-tests-20261006.log), [원래 실패 기록](memory-execution-boundary-final-tests-20261006.log), [실제 npm 차단](memory-npm-active-job-block-proof-20261006.log), [실제 출시 검사 차단](memory-active-job-block-proof-20261006.log), [이전 추가 학습 검증](public-qa-grounding-continuation-verification-20261006.json).
