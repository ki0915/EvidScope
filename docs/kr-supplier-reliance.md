# 공급사 조치 검토 근거 연결

현재 합성 금융 실증에서는 공급사 묶음의 기술적 일치만으로 한국 AI 기본법 조치의 충분성을 인정하지 않는다. 제34조제1항제1~3호에 한해, 검토자가 공급사의 실제 조치 자료와 전체 인정 범위를 검토한 기록을 해당 묶음·현재 시스템·법령 버전에 연결하는 typed 대안을 제공한다. 법률 적용성·간주·충분성의 결론은 사람 판단이다.

2026-10-06 직접 확인한 [시행령 제27조제3항](https://www.law.go.kr/LSW/lsSideInfoP.do?docCls=jo&joBrNo=00&joNo=0027&lsiSeq=288781&urlMode=lsScJoRltInfoR)은 공급사 실제 이행, 제공받은 시스템 및 중대한 기능 변경이 없다는 조건 아래 제1~3호의 전부 또는 일부를 이행한 것으로 본다. 확인 버전은 대통령령 제36580호, 2026-08-20 시행이다. 사람 감독·문서 보관은 이 간주 범위가 아니다. [법 제34조](https://www.law.go.kr/LSW/lsSideInfoP.do?docCls=jo&joBrNo=00&joNo=0034&lsiSeq=282791&urlMode=lsScJoRltInfoR)의 해당 조문 표시는 법률 제21311호, 2026-01-22 시행이다.

## 사용할 수 있는 대안

| requirementId | 기존 자체 운영 증거 | 공급사 검토 대안 |
|---|---|---|
| KR-34-RISK | high_impact_risk_management | supplier_risk_reliance |
| KR-34-EXPLAIN | explanation_plan | supplier_explanation_reliance |
| KR-34-PROTECT | user_protection | supplier_protection_reliance |

일반 `governance_check` 수집 API와 기존 공급사 묶음·assessment API를 사용한다. 별도 승인 엔진이나 공급사 문서관리 엔진을 추가하지 않는다.

수집 이벤트는 인증된 `authority` 출처여야 하며 `systemId/modelId/modelVersion/policyVersion` 및 `reviewer`가 실제 참조로 기록되어야 한다. governanceCheck의 기존 schemaVersion 1, requirementId, checkType, result, systemHash, requirementHash 필드에 현재 정확한 값을 사용한다.

이 대안에서 **documentHash는 개별 파일 해시가 아니라 공급사 묶음의 contentHash**, 즉 문서 해시 목록과 대상·조치 범위를 포함한 manifest의 해시다. measurements는 아래 필드를 모두 요구한다.

| 필드 | 값·의미 |
|---|---|
| supplierBundleRef | 실제 등록된 `supplier-bundle:<id>` |
| supplierBundleHash | 위 묶음의 현재 contentHash; documentHash와 같아야 함 |
| reviewer | 이벤트 reviewer와 같은 실제 검토자 참조 |
| reviewedAt | 이미 수행한 검토의 ISO 시각 |
| reviewedAtUncertaintyMs | 0~300000ms 또는 unknown; unknown은 완료 시각의 지원 근거로 인정하지 않음 |
| supplierPerformedMeasureReviewed | 공급사의 실제 이행 자료를 검토했는지 |
| fullMeasureScopeReviewed | 해당 조치 전체의 인정 범위가 검토되었는지 |
| noSubstantialModificationReviewed | 본래 목적·용도·중대한 변경 조건을 검토했는지 |

마지막 세 값은 true일 때만 이 대안의 전체 조치 지원 후보가 된다. 체크박스만으로 자료 내용의 진실성을 독립 검증하지 않는다. 실제 자료·범위·검토자의 적격성은 사람 판단이다. 일부 조치만 검토한 경우 전체 충분으로 승격하지 않는다. 현재 버전은 부분 조치를 합성해 전체 의무 지원으로 계산하지 않는다.

assessment에는 해당 공급사 묶음 문서 참조와 이 authority 이벤트 원본 참조를 함께 연결한다. 기존 서비스가 sufficient supplier assessment를 받을 때 대상 조치, 모델·목적, 공급받은 버전·목적, 이용사업자 역할, 변경 조건 및 문서 복구를 확인한다. 그 검증된 sufficient 스냅샷과 현재 stale 검사를 재사용한다. evaluateKrGovernanceEvidence를 직접 호출하면 원장을 새로 인증하는 것이 아니므로 임의 입력을 외부 인증 증거로 취급하지 않는다.

## 재검토와 한계

묶음 변경은 contentHash를 바꾼다. 과거 hash의 검토를 새로운 묶음에 재연결해도 지원하지 않는다. 목적·모델·정책·요구사항 변경은 기존 해시·버전 대조를 통해 재검토하며, 개별 파일 손상은 기존 공급사 문서 복구·stale 경로에서 차단한다. 과거 서명 보고서는 그대로 보존한다. 다른 tenant의 묶음·이벤트·보고서 접근은 기존 경계에서 거부한다.

공급사 대안은 제33조 사전 검토, 제34조 사람 감독, 문서 작성·보관 또는 정부 확인 요청을 대체하지 않는다. 기술 근거가 있어도 legalStatus pending인 작업은 종결할 수 없다. 자동 법적 간주 판정·준수 인증·실제 기관 연동을 제공하지 않으며, 기존 합성 자료 제한과 사람 검토를 유지한다.
