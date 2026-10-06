# 한국 AI 기본법 현행 조문과 구현 대조

확인일: 2026-10-06. 읽기 전용 조사이며 생산 코드·기존 평가·출시 아카이브를 변경하지 않았다. 이 보고서는 법률상 준수 인증이나 실제 기관 연동 검증이 아니다.

## 직접 읽은 공식 출처와 버전

| 출처 | 이번 직접 읽은 범위 | 표시 버전 |
|---|---|---|
| [현행 법률 표제](https://www.law.go.kr/LSW/lsInfoP.do?lsiSeq=282791) | 표제·공포번호·시행일 | 법률 제21311호, 2026-01-20 일부개정, 전체 현행 표제 2026-07-21 시행 |
| [법 제31조](https://www.law.go.kr/LSW/lsSideInfoP.do?docCls=jo&joBrNo=00&joNo=0031&lsiSeq=282791&urlMode=lsScJoRltInfoR) | 제1~4항 | 위 법률의 해당 조문 표시는 2026-01-22 시행 |
| [법 제33조](https://www.law.go.kr/LSW/lsSideInfoP.do?docCls=jo&joBrNo=00&joNo=0033&lsiSeq=282791&urlMode=lsScJoRltInfoR) | 제1~4항 | 위 법률의 해당 조문 표시는 2026-01-22 시행 |
| [법 제34조](https://www.law.go.kr/LSW/lsSideInfoP.do?docCls=jo&joBrNo=00&joNo=0034&lsiSeq=282791&urlMode=lsScJoRltInfoR) | 제1항 각 호 및 제2~3항 | 위 법률의 해당 조문 표시는 2026-01-22 시행 |
| [시행령 제27조](https://www.law.go.kr/LSW/lsSideInfoP.do?docCls=jo&joBrNo=00&joNo=0027&lsiSeq=288781&urlMode=lsScJoRltInfoR) | 제1~5항 | 대통령령 제36580호, 2026-08-18 타법개정, 2026-08-20 시행 |
| [시행령 제23조](https://www.law.go.kr/LSW/lsSideInfoP.do?docCls=jo&joBrNo=00&joNo=0023&lsiSeq=288781&urlMode=lsScJoRltInfoR) | 제1~4항 | 같은 시행령 |

국가법령정보센터 원문을 웹으로 직접 확인했다. 전체 법률 표제의 시행일과 개별 조문의 시행일을 구별한다. 사용자 승인 계획은 제품 요구사항이며 법률 전문을 대신하는 출처가 아니다. 기존 `docs/legal-sources.md`의 상세 조사 결과는 구현 범위를 이해하는 데 재사용했으나, 그 문서에 있는 모든 다른 조문·가이드·별표를 이번 조사에서 다시 읽지는 않았다.

## 재현한 차이: 선택적 확인 요청과 필수 사전 검토를 같은 완료 조건으로 묶음

[법 제33조제1항](https://www.law.go.kr/LSW/lsSideInfoP.do?docCls=jo&joBrNo=00&joNo=0033&lsiSeq=282791&urlMode=lsScJoRltInfoR)은 제공 전 고영향 해당 여부 검토를 요구하고, 필요한 경우 장관에게 확인을 요청할 수 있도록 한다. 법문상 사전 검토와 확인 요청은 동일한 필수 절차가 아니다.

`data/requirements.json`의 KR-33 및 `docs/legal-sources.md:18`은 이를 구별한다. `src/kr-governance-evidence.mjs:39`도 확인 요청 정의를 선택적으로 등록한다. 그러나 같은 파일 **235행**에서 유효한 사전 검토에 `confirmationRequested=true`가 있으면 `high_impact_confirmation`을 필수 그룹에 추가한다. 173행은 그 기록에 `requestAccepted=true`도 요구한다. 따라서 사전 검토가 완료되어도 선택적 요청의 접수 증거가 없으면 전체 KR-33 기술적 증거 지원 상태가 낮아진다.

실행한 독립 재현: `.test-runs/law-review-c647f20af1bb49b48675c4fa117965e0/repro.mjs` 및 같은 경로 `evidence.json`. 실행 방법: 저장소 루트에서 `node .test-runs/law-review-c647f20af1bb49b48675c4fa117965e0/repro.mjs`.

| 동일한 완료 사전 검토의 입력 차이 | supportsHumanAssessment | 결과 | 누락 |
|---|---|---|---|
| confirmationRequested=false | true | authenticated_reported_measurement_supported | 없음 |
| confirmationRequested=true | false | typed_evidence_insufficient | high_impact_confirmation |

두 경우 모두 사전 검토는 `matchedChecks`에 남았다. 이는 **구조적으로 검증된 스냅샷을 입력한 평가 함수의 실제 실행**이다. HTTP 전송, 실제 문서 저장·복구, 정부 접수 사실을 검증한 결과가 아니다. 기존 `test/kr-governance-evidence.test.mjs:149–151`도 같은 조건을 의도적으로 테스트한다.

영향: 확인 요청을 선택한 사업자의 완료 사전 검토가 선택적 요청의 미접수 때문에 필수 법정 조치 증거 부족처럼 함께 보일 수 있다. 코드가 자동 법 위반을 선언하는 것은 아니며, 조직이 추가 완료 기준을 두는 것 자체를 위법이라고 판단하지 않는다. 다만 법정 사전 검토 지원과 제품의 요청 추적 완료 기준을 분리해 표시할 필요가 있다.

좁은 개선 제안: 사전 검토에 대한 기술적 지원 상태는 필수 검토 증거로 계산하고, 선택적 확인 요청은 별도 `미접수/접수/회신/재확인` 업무 상태로 추적한다. 기존의 연결된 모순·실패 측정값 검사와 사람의 최종 판단은 유지한다. 별도 승인 없이 이번 조사에서 수정하지 않았다.

## 추가 지원 한계: 공급사 간주를 위한 대체 증거 경로

[시행령 제27조제3항](https://www.law.go.kr/LSW/lsSideInfoP.do?docCls=jo&joBrNo=00&joNo=0027&lsiSeq=288781&urlMode=lsScJoRltInfoR)은 공급 사업자의 실제 조치, 제공받은 시스템, 이용사업자 역할 및 중대한 기능 변경이 없다는 조건 아래 제34조제1항제1~3호의 전부 또는 일부를 이행한 것으로 본다. 사람 감독·문서 보관으로 그 범위를 확대하지 않는다.

현재 `src/finance-evidence.mjs:11,41–52`는 제1~3호만 인정 후보로 제한하고 모델·목적·역할·변경 여부의 기술적 대조를 수행한다. 반면 한국법 측정 평가의 문서 허용 목록은 `src/kr-governance-evidence.mjs:207`의 검증된 `governance-document:*`에 한정된다. `test/kr-governance-evidence.test.mjs:55–59,87–99`는 공급사 간주 검사 종류를 포함하지 않고 공급사 묶음 자체가 측정 증거를 대체하지 못함을 명시적으로 검증한다.

따라서 공급사 메타데이터 일치만으로 간주가 성립했다고 자동 선언하지 않는 경계는 적절하다. 다만 공급사 실제 이행 자료를 사람이 검토하고 조건을 확정한 경우의 **별도 간주 근거를 typed 평가 지원으로 연결하는 경로**는 현재 확인한 구현에 없다. 이는 법문 오기보다 제품 지원 범위의 공백이다. 공급사 묶음을 무조건 일반 측정 증거로 허용하는 패치는 제안하지 않는다.

## 확인한 일치 사항

- 제31조의 고영향 또는 생성형 사전 고지, 생성형 결과 표시, 사실적인 합성물 고지를 `src/governance-policy.mjs:40–51`에서 별도 후보로 처리한다. 시행령 제23조의 명백성·내부 업무 등 예외를 자동 확정하지 않고 사람 검토에 남긴다. 근거: [법 제31조](https://www.law.go.kr/LSW/lsSideInfoP.do?docCls=jo&joBrNo=00&joNo=0031&lsiSeq=282791&urlMode=lsScJoRltInfoR), [시행령 제23조](https://www.law.go.kr/LSW/lsSideInfoP.do?docCls=jo&joBrNo=00&joNo=0023&lsiSeq=288781&urlMode=lsScJoRltInfoR).
- 제34조의 사람 감독과 개별 실행 사전 승인을 구별한다. `src/model.mjs:89–91`은 당시 정책의 approvalRequired가 true일 때 누락을 판정하고 미확인 정책은 별도 상태에 둔다. `src/kr-governance-evidence.mjs:240–242`의 사람 감독 증거는 별도다. [법 제34조](https://www.law.go.kr/LSW/lsSideInfoP.do?docCls=jo&joBrNo=00&joNo=0034&lsiSeq=282791&urlMode=lsScJoRltInfoR).
- 5년 대상은 조치 근거 문서이며 모든 원본 이벤트의 동일 보존기간으로 치환하지 않는다. `src/governance-documents.mjs:14,61,107`은 수신 시점부터 5년의 보관 메타데이터를 저장·검사하고 실제 복구 시 바이트·해시를 검사한다. 이는 경과한 5년의 보존 실적이 아니다. [시행령 제27조제2항](https://www.law.go.kr/LSW/lsSideInfoP.do?docCls=jo&joBrNo=00&joNo=0027&lsiSeq=288781&urlMode=lsScJoRltInfoR).
- 시행령 제27조의 게시 제1항, 보관 제2항, 공급사 간주 제3항, 자료 요청·협력 노력 제4항, 타법 인정 제5항을 `docs/legal-sources.md:32–36`에서 구별한다. 사람 감독·문서 보관을 공급사 조치의 자동 승계 대상으로 두지 않는다.

## 남은 불확실성

이번 직접 확인은 위 조문에 한정된다. 제34조제1항제6호의 현행 위원회 결정, 세부 고시의 최종 현행본, 시행령 별표1 개별 타법 이행 요건, 실제 금융기관의 역할·고영향 해당성은 새로 확인하지 않았다. 기존 문서의 해당 미확인 표시를 해소했다고 보고하지 않는다. 자연어 문서의 실질적 충분성·예외·중대한 변경·법적 간주 판단은 사람 검토가 필요하다. 기술적 증거 지원, 법률 적용 판단, 실제 운영 준수는 계속 별개의 상태다.
