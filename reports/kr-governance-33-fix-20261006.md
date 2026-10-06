# 제33조 필수 사전 검토와 선택적 확인 요청 상태 분리

2026-10-06. 변경 범위는 `src/kr-governance-evidence.mjs`, `test/kr-governance-evidence.test.mjs`, 새 `test/kr-governance-33-http.test.mjs` 및 이 조사 증거다. 서비스 경로·인증·학습·작업 관리자·검증기·릴리스 아카이브는 수정하지 않았다.

## 문제와 법률 출처

수정 전에는 유효한 제공 전 검토에 `confirmationRequested=true`가 있으면 선택적 요청의 접수 증거까지 KR-33 필수 완료 조건에 추가했다. 그 결과 필수 검토가 완료되어도 요청 누락·첨부 오류·접수 실패가 전체 검토 지원 상태를 낮췄다.

[법 제33조제1항](https://www.law.go.kr/LSW/lsSideInfoP.do?docCls=jo&joBrNo=00&joNo=0033&lsiSeq=282791&urlMode=lsScJoRltInfoR)은 사전 검토 의무와 필요한 경우의 확인 요청을 구별한다. 직접 확인한 조문 표시는 법률 제21311호, 2026-01-20 일부개정, 해당 조문 2026-01-22 시행이다. 전체 표제의 2026-07-21 시행과 구별한다. 추가 법률 대조 범위·불확실성은 `reports/kr-governance-current-law-review-20261006.md`를 유지한다.

기존 실제 평가 함수 재현은 `.test-runs/law-review-c647f20af1bb49b48675c4fa117965e0/evidence.json`에 남겼다. 동일한 완료 사전 검토에서 요청 입력 false일 때 지원, true일 때 부족이 되는 원본 결과다. 정부 접수·문서 전송 실증을 뜻하지 않는다.

## 변경

- `src/kr-governance-evidence.mjs:230`: 선택적 요청의 형식·인증 출처·시각·문서·모델·요구사항 바인딩 오류를 선택적 workflow의 사유로 분리한다.
- 같은 파일 `245`: KR-33에만 `optionalWorkflows`를 추가한다. `not_requested`, `request_state_unknown`, `request_receipt_missing`, `request_evidence_insufficient`, `request_receipt_supported`를 구별하고 누락·사유·연결 증거를 보관한다.
- 같은 파일 `256`: 필수 검토의 누락·모순·실패는 여전히 지원을 차단한다. 선택적 요청의 유효한 접수 보고는 `supportsRequestReceipt`로 따로 표시한다. 정부 회신·고영향 해당성 결정·법적 준수 완료를 표시하지 않는다.

기존 API 경로와 입력 스키마 및 `supportsHumanAssessment/status/missingChecks`를 유지한다. 새 조회 결과의 KR-33 객체에만 속성을 추가하며 다른 조항 응답 형태는 그대로다. 데이터 마이그레이션이나 역사 보고서 재서명은 없다. 전체 assessment의 문서·이벤트 stale 경계는 기존대로 유지한다.

## 검증 결과

| 검사 | 결과 | 증거 |
|---|---|---|
| 패치 전 새 회귀 | 61개 중 56 통과, 5 실패 | `reports/kr-governance-33-before-20261006.log` |
| 패치 후 최초 sandbox 실행 | 60/61; HTTP 하나 EACCES | `reports/kr-governance-33-focused-20261006.log` |
| 실제 로컬 HTTP 허용 환경에서 집중 검사 | 61/61, exit 0, 1943.4051ms | `reports/kr-governance-33-focused-network-20261006.log` |
| 관련 8파일 순차 회귀 | 103/103, exit 0, 9209.3966ms | `reports/kr-governance-33-affected-20261006.log` |
| 패치 전 fixture 역사 조회 | 과거 서명 보고서 4개 및 signed 기록 8개 불변, exit 0 | `reports/kr-governance-33-history-recheck-20261006.json` 및 `.mjs/.log` |

첫 패치 전 실행의 HTTP 실패는 sandbox `connect EACCES ::1`였으며 제품 결함의 HTTP 재현으로 계산하지 않는다. 나머지 4개는 새 의미 검사의 실패로 보존했다. 패치 후에도 같은 sandbox 제한을 별도로 보존하고 로컬 네트워크가 허용된 실행에서 실제 HTTP를 검증했다. 성공 결과는 테스트 제외·Windows 오류 무시·재시도 엔진 추가로 만들지 않았다.

관련 회귀 명령:

```powershell
$env:EVIDSCOPE_TEST_HOST='::1'
node --test --test-concurrency=1 test/kr-governance-33-http.test.mjs test/kr-governance-evidence.test.mjs test/kr-governance-http.test.mjs test/kr-governance-integration.test.mjs test/governance-policy.test.mjs test/governance-authorization.test.mjs test/finance-evaluation-binding.test.mjs test/evaluation-integrity.test.mjs
```

단위 회귀 `test/kr-governance-evidence.test.mjs:148–194`는 선택적 요청 누락, 미접수, 첨부 부족, 실패, 미래 시각, 미확인 시계, 잘못된 출처·모델·시스템·법령·문서, 형식 오류, 변조된 snapshot, 좋은 기록으로 실패를 덮는 시도를 검사한다. 필수 검토 누락·실패·지연·모순·stale은 계속 차단한다.

실제 HTTP 회귀 `test/kr-governance-33-http.test.mjs:8`은 별도 ingress/vault/audit 프로세스로 등록→파일 보관→HMAC 기록 수집→사람 평가→현재 보고→서명 보고→재시작을 실행한다. 접수 누락은 필수 증거 보완 task를 만들지 않지만 잘못된 요청 출처는 workflow 부족으로 남는다. 접수만 있고 사전 검토가 없으면 부족이며 task 종결은 409다. 보고서 서명·해시, 현재 결과 반복, 다른 tenant의 404, 문서 복구와 integrity를 확인한다.

역사 재검증은 기존 `.test-runs/run-7uPpS6`의 패치 전 보고서 4개를 새 서버에서 조회했다. 과거 KR-33에는 새 optionalWorkflows가 없는 원래 응답 형태가 그대로이며, 기존 공급사·보고서 signed 기록 8개도 body·hash가 그대로다. 합성 fixture의 기술 검증이며 실제 기관이나 법적 충분성 인증은 아니다.

## 확인한 파일 식별자

- source SHA-256: `e4da8f5c9dd01f9ec1f6db82c10fdd4a6fe71ecefc39d5a4f79f9031e2b285e6`
- 단위 테스트 SHA-256: `4d8f6bbbd71981ed4f5db738c6b347431143353050d6e6971875a990f291ff82`
- HTTP 테스트 SHA-256: `67630a95ed11903e0ce583d0b63c669412a1844cbf32689d586e2bfc7fc2ac01`

공급사 간주의 신규 typed 경로, 정부 확인 회신 스키마, 전체 제품 회귀·새 배포 패키징은 이번 수정 범위 밖이다. 실행한 검사와 재검증 프로세스는 모두 종료했다.
