# v0.1.2 반복 검증 9회차 실패 조사

2026-10-06. 원본 `reports/release-012-20261006/round-09.log`와 실패 SQLite 원장은 변경하지 않았다. 1~8회 통과 뒤 9회차 119개 중 117개 통과·2개 실패는 보존하며, 이를 10회 완료로 계산하지 않는다.

## 제33조: 합성 fixture의 시각 역전

읽기 전용 조사 `release-012-kr33-retained-timing-20261006.mjs/.json`은 실패 fixture `.test-runs/run-La6liJ`의 평가 `1584189e-c872-4e07-aebc-1edfa8c70361`을 현재 규칙으로 재평가했다. 필수 사전 검토는 지원 상태이며 선택적 확인 요청에만 `high_impact_confirmation:observation_after_fixed_receipt`가 존재했다.

| 원장에 고정된 값 | 실제 값 |
| --- | --- |
| 출처/이벤트 | `alpha-authority/ce7548d2-9d65-491f-b7e7-ff1d1ca896d9` |
| 발생 시각 | `2026-10-06T06:11:27.568Z` |
| 불변 수신 시각 | `2026-10-06T06:11:27.565Z` |
| 선언된 시계 불확실성 | `0ms` |
| 요청 시각 | `2026-10-06T06:11:26.502Z` |

발생 시각이 수신 시각보다 **3ms 늦다**. 동일 밀리초의 보수적 경계 문제가 아니다. 각각 실행되는 프로세스의 `Date.now()`가 오차 0으로 정렬된다는 테스트 가정에 문제가 있다. `src/kr-governance-evidence.mjs:134–155`의 보수적 순서 검증은 수정하지 않았다.

`test/kr-governance-33-http.test.mjs:22–39`에서 합성 완료 관측을 전송 1초 이전, 요청을 2초 이전으로 구성했다. 실제 기존 이벤트나 평가 시각을 바꾸지 않으며 과거 signed report도 변경하지 않는다. 정상 요청 접수 검증 실패 시 fixture 경로와 전체 typed technicalEvidence를 assertion에 출력한다. 문서 누락, 비권위 출처, 필수 사전 검토 누락, 근거 없는 종결 거부, 과거 보고서·테넌트·재시작 검증은 유지한다.

## 권한 검사: 전송 원인 미확정

실패 fixture `.test-runs/run-IFj0Od`를 읽기 전용으로 조사했다. reviewer/admin 성공 변경이 남아 있고 마지막 signed record는 seq18 `audit_access`, `alpha-auditor`, `/api/export`, `2026-10-06T06:11:23.929Z`이다. 자세한 원본 레코드는 `release-012-authorization-last-access-20261006.json`에 보존했다.

기존 TAP는 `TypeError: fetch failed`만 포함하며 원인 code, stack, 요청 단계가 없다. `/api/export`가 기록된 사실은 최종 signed-state 수집 이후 영역을 좁히지만, 해당 응답 전송 실패인지 재시작 이후 요청인지 구별하지 못한다. 재시작 중 기존 pooled loopback 연결 재사용은 확인된 원인이 아니다. 같은 로그의 `listen EADDRINUSE ::1:25687`는 별도 startup-conflict 테스트의 예상 출력이므로 이 실패의 원인으로 사용하지 않았다.

`test/governance-authorization.test.mjs:9–19,25–49`에 진단만 추가했다. 향후 fetch/restart 실패에는 정확한 fixture 절대경로, 단계, path/base/role/tenant/method, 원래 error/cause/code/stack, 세 서버의 PID·종료 상태·로그를 fixture의 `governance-authorization-failure.json`과 실패 메시지에 기록한다. 본문·인증 헤더·토큰은 기록하지 않는다. 실패를 재시도하거나 성공으로 대체하지 않고 원래 error 객체를 다시 던진다. 30개 권한 거부와 signed 상태 불변, reviewer/admin 성공, 근거 없는 종결 409, 재시작·테넌트·무결성 검사를 유지했다. 이번 통과 실행은 실패 진단 분기를 실제로 발생시키지는 않았다.

## 제한된 재검증

실제 독립 HTTP 서버, `EVIDSCOPE_TEST_HOST=::1`, `--test-concurrency=1`로 두 대상만 실행했다. `reports/release-012-targeted-timing-diagnostics-20261006.log`: **2/2 통과, 실패·취소·제외 0, 종료 0, 3064.4988ms**. teardown을 포함해 프로세스 종료가 완료되어 계속 실행 중인 테스트 핸들은 없다. GPU 평가와 병행 중이므로 전체 회귀나 10회 검증은 이 작업에서 실행하지 않았다. 원래 전송 실패의 원인은 여전히 미확정이며 최종 10회 완료는 별도 실제 실행 결과를 필요로 한다.

동결 SHA256:

- KR33 HTTP test: `7263fe9661b7a18c5a21d494eb69c91e80cbbcbd5c3d951f123867d7863e169a`
- Authorization test: `dfde9082ef29d75415c8dc1cd38b976bfa14a43bb5583e8e2ecb9c2e4e002cf8`
- 변경하지 않은 KR governance source: `41da1d7116e462deb35fe96b59d978a3b31bd855ed3b50c7e079d4678defbb13`

생산 코드, GPU/runtime 설정, release archive는 변경하지 않았다.
