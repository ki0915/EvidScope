# 금융 공급사 미확인 참조의 기술적 일치 오판정 수정

2026-10-06. 합성 입력을 독립 ingress·vault·audit 프로세스에 제출하여 재현·수정 검증했다. 실제 금융기관 연동이나 법적 준수 인증을 입증하지 않는다.

## 확인한 결함

`src/finance-evidence.mjs`의 `known()`이 소문자 `unknown`만 미확인으로 처리했다. 시스템과 공급사 묶음의 공급사·목적·모델·버전에 동일한 `UNKNOWN` 또는 `not_recorded`를 넣으면 `technical_match_human_review_required`, 문제 목록 없음으로 표시됐다. 인증된 tool 결과 기록에도 모델 미확인 경고가 없었으며 신규 서명 보고서에 그 상태가 저장됐다. 소문자 `unknown` 대조군은 6개 미확인 문제와 재검토 상태로 남았다. 법률 자동 판정으로 승격된 것은 아니다.

원본 실제 재현: `.test-runs/supplier-known-e44fb3a69f2e43c7985c27cce80beec2/evidence.json`. 새 회귀는 수정 전에 1/2 통과, `UNKNOWN` 상태 비교에서 실패했다. `reports/finance-known-reference-before-20261006.log`에 원본 실패를 보존했다.

## 수정과 검증

공통 `knownGovernanceReference()`를 재사용하여 대소문자·공백·NFKC·기록되지 않은 표식을 동일하게 판별한다. 저장된 문자열은 정규화하거나 다시 서명하지 않는다. 확인 가능한 실제 참조끼리의 비교는 기존 대소문자 구별을 유지한다.

새 실제 HTTP 회귀는 미확인 표식 9개, 공급사 근거만으로 충분 판단을 시도하면 400, 실제 tool 기록의 모델 경고와 평가 진행 상태, 서명 보고서·다른 테넌트 404·재시작 보존, 정상 참조 일치와 대소문자 불일치, 과거 signed record 보존을 확인한다.

금융 HTTP·금융 증거·원자적 snapshot·평가 결합/무결성·한국 거버넌스 관련 10개 파일: **123/123**, fail/cancelled/skipped/todo 0, 실제 프로세스 종료 코드 0, 22644.9319ms. 로그 `reports/finance-known-reference-affected-20261006.log`. 기존 v0.1.1 아카이브는 수정하지 않았다.

## 기존 보고서 불변의 실제 확인

패치 전에 생성한 별도 합성 fixture를 수정 후 HTTP 서버로 다시 열었다. 과거 보고서 4개와 공급사·보고서 signed record 8개는 내용 및 해시가 그대로였다. 이전 보고서의 기술적 일치 상태 3개도 과거 snapshot으로 보존됐다. 현재 조회는 같은 값을 재검토로 판정하고 실제 미확인 모델 기록에 경고를 표시한다. 이전 보고서 자체를 현재 판단으로 덮어쓰지 않는다.

실제 확인 기록: `.test-runs/supplier-history-f7659098958e4b3993a07ab8ded33dd6/evidence.json`. 이 검증은 합성 원본과 조회·서명·암호화 문서 연결의 기술적 증거이며 측정값·문서 내용의 진실성이나 법률 충분성의 자동 보증이 아니다.
