# 한국법 금융 증거 검토: 중복과 추가 검증 범위

2026-09-22. 공개 설명, 고정 commit 코드 열람, EvidScope 합성 실행을 구별한다. 상용 경쟁 도구를 동일 입력으로 실행하거나 감사자의 검토 시간을 측정하지 않았으므로 우위 수치는 없다.

| 대상 | 확인 근거 | 재사용·연동 경계 | 미확인 |
|---|---|---|---|
| xsoft comply | [제품](https://xsoftcomply.com/), [공식 SDK 배포 설명](https://pypi.org/project/xsoft-comply/) | 한국법 진단·실행 기록·정책 차단·사람 검토·서명 자체를 차별점으로 주장하지 않음 | 별도 승인·은행 업무 결과의 교차검증, 실제 성능 |
| KOMPLI | [제품](https://kompli.kr/), [공급망 책임 설명](https://kompli.kr/blog/ai-developer-service-provider-responsibility) | 문서관리·승인·공급사 조치 설명을 재작성하는 범용 DMS를 만들지 않음 | 설명된 공급사 조치의 실제 증빙 승계 워크플로와 운영 결과 연동 |
| Regula | [고정 결정 모델](https://github.com/kuzivaai/getregula/blob/fbed8f3baf81f0c5f0860ebaf56a2845b632b547/references/decision_model.v1.json) | 한국 후보 분류의 비교 기준. 규제 JSON을 복사하지 않음 | 현재 법령·고시 전체의 정확성 및 금융 규제 전체 지원. 코드 실행은 미실시 |
| Microsoft AGT | [고정 승인 coordinator](https://github.com/microsoft/agent-governance-toolkit/blob/662d77b496635bfcc798d9c54b3b75e590ab6cff/agent-governance-python/agent-mesh/src/agentmesh/governance/approval_protocol/coordinator.py#L311) | 별도 승인 발급/집행 엔진 대신 기존 승인 결과의 수집 어댑터 | 실제 AGT 배포와 연결, 은행의 독립 업무 결과 대조 범위 전체 |

Regula engine은 Apache-2.0/EUPL 선택이며 규칙·규제 데이터에는 DRL 관련 조건이 있으므로 전체를 Apache 코드로 취급하지 않는다. AGT root는 MIT이나 이번 어댑터는 원 구현을 복제하지 않고 확인한 입력 구조를 변환한다.

## 동일 금융 사례로 확인할 것

| 사례 | EvidScope 구현·합성 결과 | 추가 연결 작업 |
|---|---|---|
| 공급사 v1 증빙으로 실제 v2 검토 | 모델 버전 불일치와 재검토 | 공급사 문서 bundle, 현재 배포 모델 identity |
| 권한 철회 이후 실제 실행 | 당시 권한 불일치 | 권한 grant/revoke와 실행의 문맥·시각 |
| 차단 기록과 처리 성공 | 같은 시도·모델·대상의 충돌 | 안전 통제 및 업무 결과를 별도 출처로 수집 |
| 건별 승인 없는 정상 자동 처리 | 당시 정책 false일 때 승인 누락 없음 | 조직 정책의 버전·유효기간·승인 필요 여부 |
| 실행 전 승인, 늦은 수신 | 수신 지연 표시; 사후 승인으로 오인하지 않음 | 발생/수신 시각 및 시계 오차 범위 |
| 실행 없음·문서 변조 | 증거 부족·복구 불가 | 수집 범위와 로컬 보관 복구 확인 |

각 실행 결과·프로세스 수·프로그램 조회 시간은 [합성 파일럿 보고서](finance-pilot-latest.json)에 있다. `humanReviewSeconds:null`은 미측정이다. 경쟁사에서 공개하지 않은 기능은 미지원으로 단정하지 않는다. 동일 사례를 기존 도구만으로 더 간단히 해결할 수 있다면 자체 기능을 확장하지 않고 해당 도구 연동을 우선한다.

## 법령 근거

- [법 제31조](https://www.law.go.kr/LSW/lsSideInfoP.do?docCls=jo&joBrNo=00&joNo=0031&lsiSeq=282791&urlMode=lsScJoRltInfoR): 사전 고지, 생성형 결과 표시, 사실적인 합성물 표시의 조건 구별.
- [법 제34조](https://www.law.go.kr/LSW/lsSideInfoP.do?docCls=jo&joBrNo=00&joNo=0034&lsiSeq=282791&urlMode=lsScJoRltInfoR): 인간 감독을 모든 행동의 사전 승인으로 치환하지 않음.
- [시행령 제27조](https://www.law.go.kr/LSW/lsSideInfoP.do?docCls=jo&joBrNo=00&joNo=0027&lsiSeq=288781&urlMode=lsScJoRltInfoR): 근거 문서 보관, 제1~3호 조치 활용 조건, 자료 요청, 다른 법령의 조치 인정 구별.
