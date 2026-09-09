# 실무 감사 흐름: 관측 → 근거 선택 → 사람 판단 → 재검토 → 보고

**2026-09-08 확인.** [제품 참고 조사](product-reference.md)를 보완하는 실무 수용 기준이다. 아래 제품 기능은 공식 공개 문서 확인이며 계정·설치·실연동 시험 결과가 아니다. EvidScope 구현을 승인하거나 준수를 판정하는 문서가 아니다.

## 완제품에서 확인한 사용성 → 적용할 기준

| 공개 문서에서 확인한 기능 | EvidScope에 적용할 기준 |
|---|---|
| LangSmith는 run 또는 전체 thread를 검토 대상으로 명시한다. thread 연결 메타데이터가 없으면 run만 열린다. [검토 범위](https://docs.langchain.com/langsmith/annotation-queues#assign-runs-and-threads-to-a-single-run-queue) | 조사함에서 선택한 행동, 포함 이벤트, 시간 범위·누락을 보인다. 한 행동의 판단을 모든 AI 행동의 결론으로 확대하지 않는다. |
| Langfuse는 trace·observation·session을 큐에 넣고 사람이 의견과 항목별 점수를 남긴다. [사람 검토 큐](https://langfuse.com/docs/evaluation/evaluation-methods/annotation-queues) | 원본 근거를 선택한 다음 판단·사유를 기록한다. 자동 발견 사항은 검토의 입력이며 인간 판단과 별도다. |
| LangSmith는 담당자별 진행 상태와 일정 시간의 검토 예약을 제공한다. run에는 reviewer notes가 있고 thread에는 없다. [협업 설정](https://docs.langchain.com/langsmith/annotation-queues#collaborator-settings) | 누가 검토 중이고 누가 완료했는지 구별한다. 동시 작성 충돌을 숨기지 않는다. 제품에 없는 기능을 우리 화면 이름만으로 구현됐다고 하지 않는다. |
| Langfuse Enterprise 감사 로그는 queue item 완료·점수 변경, 사용자/API key, 변경 전후 및 당시 역할을 기록한다. [감사 이력](https://langfuse.com/docs/administration/audit-logs) | 사람 판단의 작성자·시각·선택한 근거·판단 당시 버전을 보존한다. 새 판단으로 과거 기록을 덮어쓰지 않는다. |
| Copilot 감사는 대화 ID, 메시지 ID와 사용 파일·문서 참조를 구별한다. [감사 schema](https://learn.microsoft.com/en-us/office/office-365-management-api/copilot-schema) | 자료 ID·버전·제출 출처를 행동에 연결한다. 참조 등록과 내용 확인, 실제 사용 입증은 다른 상태로 표시한다. |
| Purview DSPM for AI **classic** 문서는 서비스별 감사·권한·수집 정책 전제를 명시한다. [수집 전제](https://learn.microsoft.com/en-us/purview/dspm-for-ai-considerations) | 미연결·늦은 수신·미수집 필드를 조사 화면에서 확인하게 한다. 기록이 없다는 이유로 정상·미사용을 판정하지 않는다. |

## 실무 수용 시나리오 6개 — 구현 후 HTTP·UI·검증기로 확인할 조건

| 합성 사례 | 감사자가 할 수 있어야 하는 일 / 통과 조건 |
|---|---|
| **자기보고 성공 / 서비스 결과 실패** | 같은 행동·대상의 두 원본을 나란히 확인하고 출처를 구별하여 모순 판단의 근거로 선택한다. 서로 다른 대상의 결과는 모순으로 묶지 않는다. |
| **참고자료 버전 충돌** | 동일 자료의 source별 버전·hash·사용 역할을 비교하고 충돌 근거를 남긴다. 의도적인 버전 변경 가능성도 사람이 검토하며 자동 위법 판정을 내리지 않는다. |
| **근거 부족** | 결과나 참고자료가 없는 행동을 부족 상태로 보존하고 필요한 자료·담당자·보완 조치를 기록한다. 빈 근거로 정상/준수 판정을 자동 생성하지 않는다. |
| **새 증거로 재검토** | 판단 후 늦게 도착한 결과를 추가하면 판단 당시 근거와 현재 근거의 차이를 표시하고 재검토한다. 과거 판단·시각·근거는 남으며 조용히 최신 결론으로 바뀌지 않는다. |
| **담당자 판단 추적** | 다른 감사자가 사건을 열어 누가 언제 어떤 원본·평가 버전을 보고 어떤 사유로 판단했는지 따라간다. 임의 입력한 담당자 이름과 인증된 작성자 ID를 구별한다. |
| **외부 보고서 검증** | 사건 보고서의 범위·선택 근거·사람 판단·서명 정보를 외부 검증기로 대조한다. 내용/근거 변경은 실패해야 한다. 서명 성공은 내용의 진실성·판단의 적절성·법적 준수를 보장하지 않으며 최신성에는 별도 checkpoint가 필요하다. |

## 현재 확인한 기반과 운영 공백

조사 시점의 `src/service.mjs`, `src/model.mjs`, `src/store.mjs` 및 [API 계약](contract.md)을 확인했다. 개발 중인 조사함·판단 snapshot·사건 보고서의 완료 여부는 이 문서로 확정하지 않는다.

- **있는 기반:** tenant와 source 자격 구분, auditor/reviewer/admin 역할 검사, 사건 작성·변경 이력, 행동/자료 참조 조회, 과거 자동 평가 보존, 원장·서명 export. 이는 파일 기반 개발 자격으로 동작하는 범위다.
- **SSO/RBAC 공백:** 고정 bearer token과 역할 검사는 확인했다. 운영 IdP SSO/MFA·입퇴사 회수·세분화된 사건별 접근 정책은 미연동이다. 개발 역할 이름만으로 조직의 신원·직무분리를 입증하지 않는다.
- **다중 검토자 공백:** DB 트랜잭션·worker lease와 사람이 편집 중인 사건의 예약 잠금은 다르다. 조사 시점에 검토자 예약/만료·정족수·오래된 화면의 판단 제출 충돌 보호는 확인하지 못했다. 추가 구현 시 두 브라우저의 충돌·만료·재시도 시험이 필요하다.
- **연결 범위 공백:** 합성 source와 중립 `dataRefs` 계약은 있다. Langfuse/LangSmith/Purview 실제 connector·조직별 필드 coverage는 미연동이다. 전체 참고자료·내부 사고과정·미제공 원문을 추정하지 않는다.

기존 제품의 annotation·export 기능을 독립 증적 검증과 동일시하지 않는다. 원문은 기본 미수집이고, 자료를 자동 실행·조회하지 않으며, 최종 판단은 인증된 사람이 남긴다. 위 6개 시나리오는 **시험 요구사항**이며 실행 결과가 기록되기 전에는 통과로 표시하지 않는다.

**구현 후 확인(같은 날):** 행동 조사함, 원본 선택 판단과 당시 증거 manifest, 근거 변경409, 기한/파기 재검토, 서명 사건보고서가 구현되었다. 위 시나리오의 HTTP 검증은 `test/workbench.test.mjs`와 `test/visibility.test.mjs`, 브라우저와 다운로드 검증 결과는 [실측 보고](../reports/validation.md)에 기록했다. 근거 변경 충돌 보호는 추가됐지만 검토 예약 잠금·정족수·운영 SSO·실제 connector 공백은 여전히 남는다.
