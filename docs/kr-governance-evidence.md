# 한국 AI 기본법 이행 근거 연결 계약

한국의 조건부 의무·노력의무·공공 도입·국외 사업자·실제 명령 대응을 18개 요구사항으로 관리한다. 20개 조치 시험 유형을 인증된 출처 기록, 보관한 원본 문서, 현재 시스템과 결합한다. 파일과 수집 기록의 기술적 관계를 검사하며 법률 적용·충분성·인증은 사람의 판단으로 남긴다. 공식 법령의 확인 범위와 미확인 세부 고시는 [법령 출처](legal-sources.md)를 따른다.

## 등록과 사람 검토

시스템은 schema 4이며 빠진 사실은 `unknown`이다. 국내 영향, 실제 AI사업자 역할, 고영향 활용 영역과 중대한 영향, 국방 전용 여부, 실제 또는 예정 제공 시각, 국내 주소·영업소, 직전 매출과 이용자 수 등을 기록한다. 금융 분야만으로 고영향 또는 이용사업자라고 결정하지 않는다. 외부 AI 대출심사 서비스를 그대로 사용하는 은행은 AI이용자일 수 있고, AI 모델 또는 제품·서비스를 개발·제공하는 역할과 구별한다. [NIA 공식 안내](https://www.nia.or.kr/site/nia_kor/ex/bbs/View.do?bcIdx=28987&cbIdx=99835&parentSeq=28987)

사람의 `sufficient` 평가를 저장해도 기술 근거가 부족하면 보완 과제가 열린다. `not_applicable`은 현재 시스템에 연결된 복구 가능한 근거 문서와 사람의 사유·법률 검토를 요구한다. 문서 해시를 확인했다는 사실이 그 비적용 판단을 법적으로 입증하지 않는다. 법령·시스템·모델·정책·문서 변경, 검토 만료와 미확인 적용성은 종결 시 다시 대조한다.

## 원본 문서

검토자 또는 관리자가 `POST /api/governance/documents`로 `id`, `systemId`, `name`, `mediaType`, `sha256`, `contentBase64`를 보낸다. 실제 문서 바이트는 한 파일 최대 4MiB, HTTP JSON은 6MiB 한도다. 동일 ID의 개정은 버전을 추가한다. 서버가 해시·복구·테넌트·시스템·버전을 검증하고 AES-GCM으로 보관한다. `GET /api/governance/documents/{id}/export`는 원본 바이트를 반환한다. 실제 복구와 해시 일치 없이 성공을 표시하지 않는다.

문서는 `governance-document:<id>`로 평가에 연결한다. 외부 URL·사용자 입력 해시·공급사 문서가 있다는 사실만으로 해당 조치를 충분 처리하지 않는다. 시행령 제27조의 조치 근거 문서 5년 보관 정책과 전체 이벤트 보존 정책은 별개다. 지금의 저장·복구 시험은 실제 5년 보존 실적이 아니다.

## 인증된 조치 시험 기록

기존 `submit()` 클라이언트 또는 HMAC 수집 API를 사용한다. AI 에이전트 출처는 `governance_check`를 발급할 수 없다. 정부 제출·확인·대리인 신고·명령 대응 접수 유형은 `authority` 출처만 받는다. 이러한 출처 권한은 해당 기관의 직접 인증이나 보고한 접수 사실의 독립 검증을 뜻하지 않는다.

`node scripts/kr-governance-contract.mjs`는 현재 법령 목록의 해시, 유형별 허용 필드와 검증 코드의 해시를 JSON으로 출력한다. `src/kr-governance-evidence.mjs`가 엄격한 필드·형식·조건 검사 원본이다. 아래 예시는 수집 구조이며 해시는 실제 등록된 정규화 시스템·현재 요구사항·접수 문서에서 계산해야 한다.

```js
const event = {
  id: crypto.randomUUID(), kind: 'governance_check',
  occurredAt: measuredObservationTime, clockUncertaintyMs: measuredClockBound,
  traceId, actionId, systemId: system.id,
  modelId: system.modelId, modelVersion: system.modelVersion,
  policyVersion: system.policyVersion,
  governanceCheck: {
    schemaVersion: 1, requirementId: 'KR-31-1',
    checkType: 'notice_pre_delivery', result: 'pass',
    systemHash: digest(system), requirementHash: digest(requirement),
    documentHash: retainedDocument.sha256,
    measurements: {
      noticeAt, providedAt: system.providedAt,
      noticeAtUncertaintyMs, providedAtUncertaintyMs,
      noticeDelivered: true, deliveryMethod: 'screen',
      methodBasisRecorded: false, targetUsersCovered: true,
    },
  },
};
await submit(ingressUrl, trustedTelemetryPrincipal, event);
```

완료 보고 시점은 관측 시점과 서버 고정 `receivedAt`보다 이미 발생했음을 선언된 오차 범위 안에서 확인한다. 미래 접수·완료, 시계 오차 미확인, 겹치는 시간 구간은 지원 근거로 인정하지 않는다. `0`은 실제 시계 검사로 정당화되는 경우만 사용한다. 사전 이행 유형의 `providedAt`은 등록된 시스템 시각과 일치해야 하며 미확인은 재검토로 남는다. 미래 예정 제공 시각은 사전 준비 범위의 근거일 뿐 실제 서비스 제공의 성공을 입증하지 않는다. 과거 스냅샷의 누락 시각을 현재 시각으로 채우지 않는다.

평가에는 문서와 정확한 `source/eventId`를 함께 연결한다. 서버가 원본 이벤트의 최소 스냅샷을 고정하므로 호출자가 제출한 스냅샷이나 해시는 이를 대체하지 못한다. 같은 평가에 연결된 실패·판단 보류 기록은 새 `pass`를 추가해도 사라지지 않는다. 출처가 허위 측정을 보고했는지, 평가에서 중요한 실패를 누락했는지는 사람이 원본 범위와 함께 검토해야 한다.

## 조치별 범위

| 범위 | 기술 검사 |
|---|---|
| 제31조 | 사전 전달과 시점, 생성형 출력별 표시, 기계 판독 표시 선택 시 생성 안내, 사실적 합성물의 고지·접근성 |
| 제32조 | 수명주기 위험관리, 사고 대응 체계·훈련, 이행 결과와 외부 접수 기록 |
| 제33조 | 제공 전 해당 여부 검토, 요청한 경우의 선택적 확인 자료·접수 |
| 제34조 | 위험관리·설명·보호 운영 근거, 감독 계획과 별도 사람 수행 기록, 게시 4항목과 제외 근거·5년 보관 정책·접근·복구 시험 |
| 제35조 | 영향평가 내용 7항목·취약계층·필요 시 개선 계획 또는 미완료 노력 기록, 공공 우선 고려 |
| 제30조 | 사전 검·인증 노력과 완료 구별, 공공 우선 고려 |
| 제36조 | 조건별 적용 후보, 서면 국내대리인 지정·업무 범위·신고 접수 |
| 제40조 | 실제 명령 수령·요청 조치·기한·이행과 대응 접수 |

시험 항목은 모든 이용자·모든 출력이나 자연어 문서 내용의 충분성을 자동 검사하지 않는다. 외부 기관 확인 결과·재확인 절차·고시별 세부 제출 서식, 공급사 및 타법 조치의 법적 인정은 별도 사람 검토이며 자동 법률 판정으로 구현하지 않는다. 공급사 인정 범위 제34조제1항제1~3호를 감독·보관까지 확대하지 않는다. 두 금융권 타법 인정 항목도 해당 설명·보호 조치 범위에서만 검토한다.

## 고정 보고서와 검증

`POST /api/governance/finance/report`로 당시 요구사항·시스템·문서·원본 기록·검증 결과·사람 판단을 동결하고 서명한다. 별도로 확보한 vault 공개키로 서명과 원장 체크포인트를 확인한다. 서명은 기록이 바뀌지 않았다는 검증이며 그 내용의 진실성을 보증하지 않는다.

과제 종결은 현재 시스템·법령 목록·문서·평가 만료 여부와 법률 검토 상태를 다시 검사한다. 제40조 과제는 원래 평가의 명령 식별자도 서명된 과제에 고정한다. 명령 A의 실패를 같은 시스템의 명령 B 대응으로 종결할 수 없으며, 식별자가 없던 기존 과제는 서명된 최초 평가에서 연결 대상을 복구한다. 명령의 실제 발급 여부와 대응의 충분성은 기관 원본과 담당자의 검토를 필요로 한다.

실제 로컬 HTTP·파일 경계·이력·테넌트·변조·복구 검사는 `test/kr-governance-http.test.mjs`, `test/kr-governance-integration.test.mjs`, 기존 거버넌스·금융·복구 테스트에 있다. `scripts/portfolio-governance-demo.mjs`는 정상·모델/목적 변경·공급사/감독 문서 개정·감독 기록 누락의 6개 합성 사례를 반복하고 서명 보고서를 보존한다. 실제 금융사 운영이나 경쟁 제품 동일 입력 실증은 아직 이 검사 범위가 아니다.
