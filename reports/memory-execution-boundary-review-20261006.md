# 메모리 실행 경계 독립 검토 — 2026-10-06

페이지 파일 확대는 실제로 적용됐으며, 현재의 병목은 남은 Windows 예약 메모리 여유와 실행 작업의 중첩이다. GPU 평가 중에 출시 반복 검증과 전체 회귀를 새로 시작하지 않는 것이 가장 좁은 개선이다. 이 검토는 읽기 전용으로 수행했으며, 실행 중인 작업·GPU·Docker·WSL·가드·모델 설정을 변경하지 않았다. 새 파일은 이 보고서 하나뿐이다.

## 현재 실측과 완료 범위

2026-10-06 **15:25:28 KST**, 독립 Windows CIM 조회 결과다. 첫 sandbox 조회는 CIM 접근 불가였고, 그 실패에서 계산된 0 값은 전부 폐기했다. 이후 읽기 전용 권한으로 실제 호스트를 조회했다.

| 항목 | 실제 관측 |
|---|---:|
| 물리 RAM 여유 | 4.120GiB |
| 예약 메모리 한도 / 사용 / 여유 | 61.863 / 55.254 / 6.609GiB |
| 예약 메모리 사용률 | 89% — 해당 정수 카운터 |
| 페이지 파일 설정 initial / maximum / 실제 allocated | 30720 / 30720 / 30720MiB |
| 페이지 파일 현재 사용 / 과거 최고 사용 | 1161 / 1338MiB |
| C드라이브 여유 | 10.468GiB |
| Pages Input/sec | 756 — 순간 관측, 장기 평균 아님 |

페이지 파일은 물리 RAM 추가 설치가 아니다. 현재 C드라이브 여유는 기존 10GiB 보존 목표보다 약 0.468GiB 많으므로, 추가 증설은 첫 조치로 적절하지 않다. 할당량 30GiB와 현재 사용량 약 1.13GiB도 서로 다른 값이다.

읽은 과거 원본은 [최초 부분 실패](../.local/training/pagefile-resize-20261006-r1/result.json)와 [후속 영속 설정 성공](../.local/training/pagefile-resize-20261006-r1/persistent-result.json)이다. 최초 영수증의 `failed_or_partial`과 `liveExpansionVerified:false`를 수정하거나 성공으로 덮어쓰지 않았다. 후속 영수증의 30GiB 설정·할당과 이번 독립 실측이 현재 상태를 확인한다.

[추가 학습 실행 검증](public-qa-grounding-continuation-verification-20261006.json)은 새로운 optimizer 20회·누적 이력 80회를 확인했다. 원본 controller의 종료 관측 경합 `state:error`는 보존했고, 같은 컨테이너의 exit0와 sealed adapter를 별도로 검증한 결과다. 품질 인정과 승격은 여전히 허용하지 않는다.

현재 `public-qa-fresh-20261006-r2`는 완료된 학습 후보의 순차 생성 평가다. 읽은 controller의 저장 상태는 `created`이며, 166회 자원 관측과 실제 생성 진행 로그가 존재한다. 이것을 `process_completed`나 평가 검증 통과로 바꾸어 해석하지 않았다. 읽은 최신 생성 로그에는 baseline **83/128회**까지의 호출이 있으며, 전체 목표는 baseline128 + candidate128이다. 완료·최종 품질 결과는 이 보고서의 범위 밖이다.

## 실제 메모리 영역 대조

15:25:21 KST controller 관측은 Windows 물리 여유4.536GiB·예약 여유7.717GiB, 게스트 available12.489GiB, 컨테이너 current1.9995GiB/hard limit12GiB/OOM0, GPU 전체 사용8182/12288MiB·72°C였다. 실제 적용된 `memory.high`는 2GiB다. 이는 회수·압력 기준이며, 컨테이너 hard limit이나 전체 Windows 사용량 2GiB 제한이 아니다.

| 실행 | 마지막 시작 예약 여유 | 실행 중 최소 예약 여유 | 관측 결과 |
|---|---:|---:|---|
| continuation r1 | 14.379GiB | 4.814GiB | 사용률92.218%에서 `windows_memory_pressure` 중단, 종료 확인 |
| continuation r3 | 15.868GiB | 6.055GiB | 추가20회 실제 학습 완료, OOM0, 종료 경합 별도 검증 |
| fresh r2, 15:25:21 저장 스냅샷 | 17.307GiB | 6.876GiB | 평가 진행 중, 관측 가드 모두 allowed |

별도 15:25:28 호스트 조회의 예약 여유6.609GiB는 위 저장 스냅샷 뒤의 측정이다. 서로 다른 시각의 값이며, 저장 스냅샷의 최소값을 잘못 갱신한 것이 아니다. fresh 시작 마지막 값 대비 전체 Windows 예약 여유 감소는 약 **10.698GiB**다. 이는 전체 PC 변화량이며 모델 단독 점유로 귀속할 수 없다.

호스트 프로세스 관측에서 `vmmemWSL` private10.861GiB/working set4.201GiB와 별도 `vmmem` private4.008GiB/working set1.217GiB가 컸다. 이 결과만으로 특정 VM을 식별하거나 전체 예약 메모리 변화의 원인을 확정하지 않았다. Windows 물리 여유·예약 여유, WSL available, 컨테이너 current, GPU 사용량은 측정 대상이 겹치거나 다른 영역이므로 **합산하지 않았다**. Windows WDDM 프로세스 목록 개수도 실제 학습 프로세스 수로 사용하지 않았다.

현재 카운터의 예약 한도61.863GiB에서 사용률92% 경계는 여유 약4.949GiB다. 여유6.609GiB에서 이 경계까지의 추가 사용 가능 폭은 약 **1.660GiB**에 불과하다. 따라서 계속 조건의 `commitFree>=3GiB`만 보고 3.609GiB가 모두 안전 여유라고 판단하면 안 된다. 사용률 조건이 먼저 중단시킬 수 있다.

## 실행 경계와 코드 검토

검토 중 primary agent가 구현한 현재 코드와 확보한 [실제 차단 로그](memory-npm-active-job-block-proof-20261006.log)를 읽었다. 무거운 테스트를 새로 실행하지 않았다.

- [공유 guard](../scripts/execution-memory-boundary.mjs:6)는 `.local/training/manual-public-qa-active.json`의 존재를 `lstat`로 확인한다. 정상·불완전·잘못된 내용·오래된 lease 모두 차단하며, 다른 조회 오류도 성공으로 해석하지 않는다. 테스트가 lease를 지우지 않는다.
- [전체 회귀 runner](../scripts/test-serial.mjs:9)는 guard 통과 후 실제 `.test.mjs` 목록을 명시해 `--test-concurrency=1`로 자식 테스트를 실행한다. 현재 `npm test`의 차단 로그에는 guard 오류만 있고 테스트 runner 실행 결과가 없다. primary agent가 확인한 exit1과 일치한다.
- [출시 검증](../scripts/release-verify.mjs:163)은 출력 디렉터리 생성 전에 guard를 검사하고, 각 반복 회차 시작 전에도 재검사한다. 원래 테스트 직렬 실행·시간 제한·종료 확인·소스 해시 검사도 유지한다. runner 파일은 현재 `watchedFiles`에 추가되어 있다.
- [패키징](../scripts/package-release.mjs:27)은 기존 10회 영수증·소스 해시·회차 로그를 검증하고 신규 디렉터리에 복사한다. 모델 가중치·실험 자료를 복제해 GPU를 실행하는 경로는 아니다. 현재 runner를 새로 복사한 패키지의 `npm test`에는 같은 guard가 적용된다. 이전에 만든 패키지까지 이 변경이 적용됐다고 확인한 것은 아니다.

이 경계는 **원자적 상호 배제나 GPU 유휴 증명은 아니다**. CPU 검사 시작 직후 또는 같은 반복 회차 도중 GPU 작업이 새로 시작하면, 다음 lease 검사 전까지 겹칠 수 있다. 직접 `node --test`와 다른 `test:*` npm 스크립트도 현재 공유 guard를 우회할 수 있다. 별도 설치 디렉터리의 guard는 그 디렉터리의 `.local`을 검사하므로 원본 workspace의 활성 lease를 전역으로 감지한다고 주장하지 않는다.

처음 검토한 runner는 추가 CLI 인수를 무시해 작은 검사 요청이 전체 검사로 확대될 가능성이 있었다. primary agent가 `process.argv.length!==2`를 명시적으로 거부하도록 수정했고, 변경된 코드와 [최종 소규모 검사6/6](memory-execution-boundary-final-fixed-tests-20261006.log)를 독립적으로 읽어 해당 finding이 해결됐음을 확인했다. 같은 검사에서 실제 임시 프로젝트의 테스트2개 실행, 실제 실패 exit1 전달, 잘못된 인수 입력 시 sentinel 테스트 미시작을 확인했다. 이 검토자가 해당 검사를 다시 실행한 것은 아니다.

최초 fixture 검사4/6 실패는 상위 `node:test`의 `NODE_TEST_CONTEXT`가 새 테스트 자식에 상속되어 실행이 억제된 문제였다. 원본 실패 로그를 보존하고, 현재 runner는 환경을 복사한 뒤 **자식 환경에서만** 이 marker 하나를 제거하며 명시적 TAP reporter를 사용한다. 상위 프로세스 환경을 변경하거나 테스트를 건너뛰어 통과 처리하지 않는다. 읽기 검토에서 추가 중대한 회귀는 발견하지 않았다. 이6개 작은 fixture 통과를 제품 전체 회귀나 실제 GPU 평가 완료로 확대하지 않는다.

## 다음 실행의 구체 조건

1. 현재 GPU 평가가 종료되고 같은 Job/Pod의 종료·GPU 회수·영수증/파일 해시를 확인한 뒤 전체 회귀와 출시10회를 실행한다. 활성 lease가 남으면 검사는 계속 차단한다. 시간 경과만으로 lease를 삭제하지 않는다.
2. CPU 전체 회귀와 출시 검증을 한 번에 하나씩 실행하고, 그동안 새로운 GPU 실행을 시작하지 않는다. 현재 가장 작은 해결책은 이 실행 순서를 지키고 새 guard를 표준 진입점에 사용하는 것이다. 전역 mutex가 이미 구현됐다고 주장하지 않는다.
3. 다음 GPU 시작은 기존 정책을 그대로 통과해야 한다: 최신3개 관측·전체 안정 구간20초 이상·각 관측5초 이상 간격, Windows 물리 여유4GiB 이상·예약 여유14GiB 이상·사용률85% 이하, 게스트 available10GiB 이상·PSI full avg10<1, GPU 여유9216MiB 이상·온도75°C 이하, CPU50% 이하·AC 전원. PC 동시 사용 허용은 유지하되 다른 자원 조건은 완화하지 않는다.
4. 현재 예약 여유6.609GiB에서는 **새 GPU 실행을 시작할 수 없다**. 기존14GiB는 최소 조건이며, r1의 실제 실패와 fresh의 약10.7GiB 전체 예약 변화량을 고려하면 다음 동일 규모 실행의 운영 목표는 **시작 여유17GiB 정도**가 더 안정적이다. 이는 정책 값을 변경한 것이 아니라 재시도 시점의 여유 목표다.
5. 다음 실행에서도 NF4·BF16·batch1·CPU2·RAM hard12GiB·memory.high2GiB를 유지한다. 미확인 제안으로 hard limit이나 GPU fraction을 더 줄이면 로딩/forward 실패를 만들 수 있으므로 현 실행의 hash 고정 설정을 수정하지 않는다. 추후 더 작은 생성 budget을 시험한다면 별도 신규 실험·토큰 admission·동일 baseline/candidate 조건·자원 측정부터 수행해야 한다. 절감량을 현재 증명한 것은 아니다.

현재 실행이 사용하는 동결 파일·증거·제한을 변경하지 않았고, 다른 사용자 프로그램도 종료하지 않았다. 페이지 파일 추가 증설보다 **GPU 실행 종료 확인 → CPU 검사 직렬 실행 → 안정 여유 확인 → 필요한 신규 GPU 실행** 순서가 우선이다.

## 읽은 근거의 무결성·제한

- fresh controller, 15:25:21까지 포함된 읽기 스냅샷 SHA-256: `1a6a554ad8300f2181cfeada66741cb5efe7b0b9d3c39b14e745ec773e0cf833`. 실행 중인 파일이므로 이후 저장으로 hash가 바뀔 수 있다.
- continuation r1 controller: `255d6ade76ba83c4610d1e0fff5fec3779d7af99a4968d46c58534c7e9cc5a26`.
- continuation r3 원본 controller: `bbb6504733765876abf85ff557f9726b762cbe565422672ee07ce4880c54409d`.
- pagefile 최초 부분 실패 / 후속 영속 성공: `6e0d63608024cd9bc23ead9d7bc52bcf470aad2b7623f138075807cd5eddba64` / `92143921007cb166136a28830237ec8dac33ad93868e3a404339cbacb8a55cc9`.
- 현재 npm 차단 로그: `2f0b3ac85d2b89e40023eff8faac0b08b3bd65800334082c05d9106bc3b3505d`.

과거 memory registry의 학습 미실행 상태는 현재 source80 실행 증거를 대신하지 않는다. 현재 사실은 위 실제 controller·후속 검증 보고서·독립 호스트 측정으로 확인했다. 테스트 동시 실행의 개별 메모리 기여도나 특정 VM의 원인을 분리 측정하지 않았으므로 그것을 확정하지 않았다. 이 보고서는 메모리 실행 경계 검토이며 금융 고객 운영, 법률 준수 인증, 새 모델 품질 승격의 증거가 아니다.
