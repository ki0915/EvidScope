# Public QA 종료 상태 재조회 독립 검토

2026-10-06. 소스·기존 테스트는 편집하지 않았다. 검토 파일 `scripts/run-public-qa-job.mjs` SHA-256: `3a38527c88b26f79bca19d56aa24bd457bf60df1ca9150909dd6b2c188482628`.

검토한 변경 범위에서 새로운 P1/P2 오완료·신원 치환·기존 반환 형태 호환성 결함은 발견하지 못했다. 이는 아래 경계의 코드 검토와 mock 조회 실행 결과이며 실제 r3 컨테이너 종료·학습 산출물 검증을 대신하지 않는다.

- 58행: 관측한 containerID의 정확한 `task <CID> not found`와 exec 생성 실패 문구가 함께 있을 때만 추가 상태 재조회를 허용한다. 다른 CID·CID 접미사·exec 문구 없는 오류는 추가 대기하지 않는다.
- 61–65행: 매 재조회마다 Pod UID·이름, namespace·Job UID·이미지·자원·보안 범위, 컨테이너 이름·CID·restartCount·restartPolicy를 다시 확인한다. diagnostic 모드는 기존 mount 검사도 실행한다.
- 66–73행: 실제 정수 exitCode가 있고 running/waiting 상태가 없을 때만 종료를 반환한다. 원래 CID와 다른 종료 CID도 거부한다. 종료 상태가 없으면 최대 4회 조회·250/500/1000ms의 추가 대기 이후 원래 오류를 유지한다. 조회 오류도 원래 측정 오류를 유지한다. 대기값은 추가 pause의 상한이며 API 조회 지연까지 1.75초라고 주장하지 않는다.
- 150행: 반환된 exitCode가 0일 때만 process_completed이고 1/137 등은 process_failed다. 85·181행의 trainingRunCompleted는 여전히 false이며 산출물 검증을 요구한다. successful sample 반환 형태는 유지되고 terminalRecheck에는 statusReads만 추가된다.

독립 집중 재실행: `node --test --test-concurrency=1 test/public-qa-controller-terminal.test.mjs test/public-qa-grounding-controller.test.mjs` → **24/24**, fail/cancelled/skipped/todo 0, exit 0, 194.1783ms. 로그 `reports/public-qa-terminal-independent-review-20261006.log`.

추가 report-only probe `reports/public-qa-terminal-independent-cases-20261006.mjs` → **12개 시나리오 통과**, exit 0. 지연 종료 0/1/137의 원래 코드 유지, 관련 없는 세 오류의 추가 대기 거부, 지연 중 이미지·CPU·RAM·GPU·기본 볼륨 쓰기·종료 CID 변경 거부를 확인했다. 결과 `reports/public-qa-terminal-independent-cases-20261006.json`, 로그 같은 이름 `.log`.

실제 r3 controller의 원래 error receipt를 성공으로 고치거나 새로 만들지 않았다. 실제 exit0, raw CRI, 엄격한 새 verifier 검사는 별도 담당 범위다. 검사 프로세스는 모두 종료했다.
