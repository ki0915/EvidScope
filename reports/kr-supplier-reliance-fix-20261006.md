# 한국 금융 공급사 조치 검토의 typed 지원 공백 수정

2026-10-06. 변경 소유권: `src/kr-governance-evidence.mjs`, 새 `test/kr-supplier-reliance.test.mjs`, 기존 `test/kr-governance-evidence.test.mjs`의 정의 범위 검사 및 `docs/kr-supplier-reliance.md`. service/server/finance/runtime/학습/릴리스는 편집하지 않았다. UI 보완은 root가 별도로 담당했다.

## 재현한 공백과 공식 출처

현재 흐름은 공급사 묶음의 실제 파일·모델·목적·조치 범위를 확인했지만, 검토한 공급사 실제 조치를 자체 운영 측정 대신 연결하는 typed 경로가 없었다. 공급사 묶음만으로 충분하다고 하지 않는 경계는 유지해야 하나, 명시적 근거 검토를 기록해도 자체 시험만 요구하는 지원 공백이 있었다. 패치 전 전용 검사에서 해당 경로는 실제 HTTP 400, 평가 함수는 지원 부족이었다.

직접 확인한 [시행령 제27조제3항](https://www.law.go.kr/LSW/lsSideInfoP.do?docCls=jo&joBrNo=00&joNo=0027&lsiSeq=288781&urlMode=lsScJoRltInfoR)은 공급사가 실제 이행한 제1~3호, 제공받은 시스템, 중대한 기능 변경이 없는 조건에서 전부 또는 일부의 이행 간주를 정한다. 대통령령 제36580호, 2026-08-20 시행 원문을 읽었다. [법 제34조](https://www.law.go.kr/LSW/lsSideInfoP.do?docCls=jo&joBrNo=00&joNo=0034&lsiSeq=282791&urlMode=lsScJoRltInfoR)의 해당 조문은 법률 제21311호, 2026-01-22 시행 표시다. 제33조·사람 감독·문서 보관까지 대체한다고 확대하지 않았다. 법률 판단과 최종 세부 고시의 확인 한계는 기존 법률 조사 보고서에 남는다.

## 좁은 구현과 실제 계약 확인

- core 51행: KR-34-RISK/EXPLAIN/PROTECT에만 세 supplier_*_reliance 정의를 기존 자체 측정의 대안으로 추가한다. 기존 자체 시험 경로와 18개 요구사항은 유지한다.
- core 208–219행: 권한 출처의 검토자·수행 시각, 실제 묶음 참조·manifest hash, 현재 시스템·모델·정책·요구사항, 실제 이용사업자 및 사업자 사실, 공급받은 목적·버전, 중대한 변경 없음에 결합한다. 단순 acknowledgement나 부분 범위는 부족으로 남는다.
- core 244·259행: manifest 바인딩을 검증하고 묶음 ref/hash·검토자를 matchedChecks에 보존한다. 선택한 실패 측정은 다른 성공 기록으로 지울 수 없다. 법적 결론은 계속 사람 상태다.

최초 draft는 finance.evidence가 반환한 풍부한 verification을 assessment에도 저장한다고 가정해 실패했다. 실제 service는 검증된 문자열 `supplier_bundle_verified_at_assessment`와 contentHash만 보관한다. 이를 고치기 위해 service 스키마를 확대하지 않고, **기존 sufficient supplier intake guard 및 현재 stale 검사**를 재사용한다. 이 대안의 documentHash는 개별 파일 해시를 새로 주장하지 않고 공급사 묶음 manifest hash와 반드시 같다. 상세 사용 계약은 새 전용 문서에 기록했다.

## 실행 증거

| 실행 | 결과 | 로그 |
|---|---|---|
| 패치 전 candidate 전용 검사 | 2/4, 지원 경로와 실제 HTTP 실패 | kr-supplier-reliance-before-20261006.log |
| 최초 draft | 63/64, 실제 assessment 계약 차이 실패 | kr-supplier-reliance-focused-20261006.log |
| 실제 manifest 계약에 맞춘 집중 검사 | 64/64, exit 0, 1553.4815ms | kr-supplier-reliance-focused-r2-20261006.log |
| 확장한 9파일 영향 검사 | 112/113; 기존 finance-http fetch ECONNRESET 1회 | kr-supplier-reliance-affected-20261006.log |
| 실패한 기존 금융 HTTP 독립 재검증 | 1/1, exit 0, 1225.5266ms | kr-supplier-reliance-finance-recheck-20261006.log |
| 동일 9파일 순차 재검증 | **113/113**, exit 0, 16640.3341ms | kr-supplier-reliance-affected-r2-20261006.log |

로그는 모두 reports 아래다. 첫 ECONNRESET의 원인은 확정하지 않았으며 실패를 삭제·정상 결과로 바꾸지 않았다. 새 retry 엔진이나 테스트 제외 없이 다시 실행했다. 겹치는 실행 카운트는 합산하지 않는다.

```powershell
$env:EVIDSCOPE_TEST_HOST='::1'
node --test --test-concurrency=1 test/kr-supplier-reliance.test.mjs test/kr-governance-evidence.test.mjs test/kr-governance-integration.test.mjs test/kr-governance-33-http.test.mjs test/finance-evidence.test.mjs test/finance-known-reference.test.mjs test/finance-http.test.mjs test/governance-policy.test.mjs test/governance-authorization.test.mjs
```

실제 독립 ingress/vault/audit HTTP 검사에서 세 조치의 지원 경로, 묶음만으로 부족, 부분 범위 부족, legalStatus pending의 종결 409, 검토자·권한 출처·현재 버전 바인딩, 다른 tenant 거부, 재시작, 문서 envelope 손상과 복구, 묶음 변경 후 과거 검토 재사용 거부를 검증했다. 파일 손상 시 현재 상태는 재검토이며 충분 assessment 신규 기록은 400이다. 이 과정에서도 기존 서명 보고서의 본문·서명은 그대로다. 복구 후 integrity는 valid다.

단위 검사에서는 단순 ACK, 검토 누락, 미확인 검토자·시계, 미래 수행, 실패·변조, 다른 묶음·manifest·모델·정책·법령, 원래 공급 목적·버전 불일치, 미확인 변경 여부, 다른 역할을 차단했다. 제33조 사전 검토·감독·문서 대체와 좋은 기록으로 실패를 숨기는 시도도 차단한다.

## 한계와 동결

공급사 실제 조치의 자연어 내용·전체 범위·검토자의 적격성은 이 검증으로 독립 증명하지 않는다. 인증된 권한 출처의 보고와 사람 평가를 현재 증거에 연결한다. 일부 조치의 잔여 의무를 자동 조합하지 않으며 해당 조치 전체의 검토가 기록된 경로만 기술적으로 지원한다. 합성 자료·로컬 보관 제한, 실제 기관 연동 미검증, 자동 법적 인증 없음은 유지한다.

코드 동결 해시:

- src/kr-governance-evidence.mjs: `41da1d7116e462deb35fe96b59d978a3b31bd855ed3b50c7e079d4678defbb13`
- test/kr-supplier-reliance.test.mjs: `4ec55569815d5d2d7b06db80892b5392d7fbd2ee3fb1d9fb0de21e7ee96c8470`
- test/kr-governance-evidence.test.mjs: `a978b8fac5f75180170e82c2c8ba19efc9a6c0460bb103937a191f1929fb8c97`

실행 프로세스는 모두 종료했다. 이 보고서 시점에서 추가 코드 변경 예정은 없다. 전체 제품 회귀·별도 독립 검토·다음 패키징은 root 범위다.
