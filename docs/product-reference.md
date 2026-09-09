# 완제품 참고 조사: 사람이 판단할 수 있는 AI 행동·참고자료 가시성

확인일: **2026-09-08 (Asia/Seoul)**. 공식 제품 문서·공식 저장소의 공개 자료를 확인했다. 제품 설치, 유료 가입, 실제 공급자 계정 연결, 성능 비교는 실행하지 않았다. 아래의 “확인”은 문서에서 확인한 기능이며 EvidScope의 실연동이나 검증 결과가 아니다. 문서는 계속 갱신되므로 도입 때 배포 버전과 라이선스를 다시 고정해야 한다.

**우선할 제품 경험은 한 행동을 열었을 때 요청, 도구 실행, 참고한 자료, 결과, 당시 권한, 누가 남긴 기록인지, 무엇이 아직 확인되지 않았는지를 사람이 함께 볼 수 있게 하는 것이다.** 자동 점수는 이 판단을 대신하지 않는다. 이름이나 화면을 모방하는 것보다 기존 제품이 이미 해결한 trace 탐색·검토 작업을 참고하고, EvidScope의 독립 증거·권한 대조에 개발을 집중한다.

## 1. 행동과 참고자료 가시성 비교

| 제품 | 문서에서 확인한 행동·참고자료 모델 | 사람의 검토와 평가 | EvidScope에 적용할 화면·데이터 패턴 |
|---|---|---|---|
| **Langfuse** | session → trace → nested observation. `agent`, `tool`, `retriever`, `generation` 등의 observation 유형을 구분한다. 입력·출력 및 메타데이터를 붙일 수 있지만 instrumentation이 보내지 않은 자료의 계보를 자동 입증한다는 의미는 아니다. [데이터 모델](https://langfuse.com/docs/observability/data-model), [관측 유형](https://langfuse.com/docs/observability/features/observation-types) | 사람이 trace·observation·session을 annotation queue에서 검토하고 의견·점수를 남긴다. 자동 평가도 제공하므로 평가 출처를 구별해야 한다. [사람 검토 큐](https://langfuse.com/docs/evaluation/evaluation-methods/annotation-queues) | 상위 작업과 개별 행동을 나누고, 행동 안에서 자료 검색·도구 실행·결과를 구분한다. 참고자료는 긴 JSON 안에 숨기지 않고 유형·ID·버전·출처를 읽을 수 있는 표로 제공한다. |
| **LangSmith** | project → trace → run, 여러 trace를 thread로 묶는다. run은 LLM·retrieval·기타 단계의 작업 단위이고 입력·출력·metadata·feedback을 붙인다. [관측 개념](https://docs.langchain.com/langsmith/observability-concepts) | run 또는 thread를 사람 검토 큐에 넣고 담당 검토자·메모·완료 상태를 관리한다. 여러 검토자의 완료 조건 및 검토 예약 기능이 문서화되어 있다. [검토 큐](https://docs.langchain.com/langsmith/annotation-queues) | 사건 목록 → 선택한 행동의 근거 → 사람 검토 기록을 한 흐름으로 연결한다. “자동 분석 완료”와 “담당자가 판단 완료”를 서로 다른 상태로 표시한다. |
| **Arize Phoenix** | OpenTelemetry/OTLP 및 OpenInference 기반 trace로 model call·retrieval·tool use·custom logic을 표시한다. trace/span 비교, 입력·출력 품질 평가, dataset/experiment 기능을 제공한다. [제품 문서](https://arize.com/docs/phoenix) | UI·REST API·client를 통한 annotation을 지원한다. 인간·코드·LLM 평가를 구별하는 모델을 제공한다. [주석](https://arize.com/docs/phoenix/tracing/how-to-tracing/feedback-and-annotations), [평가 출처](https://arizeai-433a7140.mintlify.app/docs/phoenix/tracing/how-to-tracing/feedback-and-annotations/llm-evaluations) | 자료 참조 한 건에 대한 사람 의견을 행동 전체의 자동 탐지 결과와 분리한다. retrieval 결과가 없으면 “검색 안 함”으로 추론하지 않고 수집 여부를 보여준다. |
| **IBM watsonx.governance** | AI use case에 관련 모델·prompt template과 버전을 연결하고 lifecycle별 factsheet에 생성 정보·사용 데이터 등 추적된 사실을 모은다. 이것은 개별 실행의 모든 retrieval/tool span을 자동 포착한다는 보장이 아니다. [거버넌스 구성](https://www.ibm.com/docs/en/watsonx/saas?topic=governing-ai) | use case Overview/Lifecycle/Access와 factsheet·보고서로 담당자와 검토 흐름을 연결한다. 평가·모니터 기능도 있으나 인간의 책임 판단과 별개다. [use case 관리, 2.3.x](https://www.ibm.com/docs/en/watsonx/w-and-w/2.3.x?topic=cases-setting-up-ai-use-case) | 시스템별 목적·소유자·버전·근거문서를 운영 이벤트와 연결한다. “문서 참조만 등록”과 “관측 이벤트를 실제로 연결”을 구분하여 근거 충분성을 검토하게 한다. |
| **Microsoft Purview (DSPM for AI / Copilot 감사)** | Copilot 감사 schema는 `ThreadId`, `Messages` ID, `Contexts`, `AccessedResources`, `AISystemPlugin`을 구분한다. `AccessedResources`는 Copilot이 사용한 M365 파일·문서 참조이며 모든 제3자 AI의 tool trace나 전체 학습 데이터 계보를 뜻하지 않는다. [공식 Copilot schema](https://learn.microsoft.com/en-us/office/office-365-management-api/copilot-schema) | 지원하는 AI 상호작용·자료 보안 사건을 Activity explorer 및 감사·eDiscovery 흐름에서 조사한다. 원문 포착은 서비스·수집 정책·권한에 의존한다. 범용 trace annotation queue와 모델 품질 평가의 동등 기능은 이 조사에서 **미확인**이다. [보호 기능 범위](https://learn.microsoft.com/en-us/purview/ai-microsoft-purview), [수집 전제](https://learn.microsoft.com/en-us/purview/dspm-for-ai-considerations) | 자료 참조 ID와 대화/행동 ID를 연결하되 원문 수집과 분리한다. source별로 가능한 필드·권한·연결 여부·마지막 수신을 표시한다. 파일 참조가 있다는 사실만으로 내용이나 당시 접근 권한을 확인했다고 표시하지 않는다. |

## 2. 권한·배포·라이선스와 독립 증적 경계

| 제품 | 역할·접근 제어 | Self-host / 라이선스 | EvidScope 요구에서 별도로 확인할 것 |
|---|---|---|---|
| Langfuse | 사용자/organization/project 역할. API key는 project에 연결된다. 상세 project-level RBAC 등 Enterprise 기능 경계가 존재한다. [RBAC](https://langfuse.com/docs/administration/rbac) | core MIT, self-host 가능. Enterprise의 project-level RBAC·감사 로그·보존 정책 등은 별도 상용 조건. [공식 라이선스 설명](https://langfuse.com/handbook/chapters/open-source), [self-host 요금/기능](https://langfuse.com/pricing-self-host) | 관측용 API key를 업무 AI의 제출 전용 자격으로 간주하면 안 된다. 제출·조회·수정·삭제 분리, 독립 결과 출처, export 외부 검증은 별도 설계·시험 대상이다. |
| LangSmith | organization/workspace 역할 및 Enterprise custom role. [RBAC](https://docs.langchain.com/langsmith/rbac) | self-host는 Enterprise 부가 기능으로 license key가 필요하다. 플랫폼을 무상 OSS라고 가정하지 않는다. [공식 self-host 문서](https://docs.langchain.com/langsmith/self-hosted) | self-host 구성에 playground·code execution backend 등이 포함되므로 운영 감사 영역에 그대로 합쳐서는 안 된다. 개발 관측 영역과 EvidScope 증적 영역을 분리할 필요가 있다. |
| Phoenix | admin/member/viewer; UI와 API 권한을 역할로 제한한다. [RBAC](https://arize.com/docs/phoenix/settings/access-control-rbac) | self-host 문서 제공. 저장소 LICENSE는 **Elastic License 2.0 (ELv2)**이다. MIT로 표기하지 않는다. 제3자에게 상당한 기능을 hosted/managed service로 제공하는 제한 등이 있어 재배포·서비스화 조건은 도입 방식에 맞춰 검토해야 한다. [self-host](https://arize.com/docs/phoenix/self-hosting), [공식 LICENSE](https://github.com/Arize-ai/phoenix/blob/main/LICENSE) | member 권한을 독립 감사의 제출 전용 권한으로 대신하지 않는다. artifact/tenant 단위 격리의 적합성과 증적 변경권한은 실제 배포 시험으로 확인해야 한다. |
| watsonx.governance | IAM platform/service role과 workspace collaborator role을 구별한다. inventory·use case 접근을 관리한다. [거버넌스 역할](https://www.ibm.com/docs/en/ws-and-kc?topic=cases-collaboration-roles-governance) | 상용 SaaS 및 software 제공. IBM은 SaaS와 software 기능 동등성을 보장하지 않는다고 명시한다. 이번 조사에서 실제 계약·SKU별 사용권은 미확인이다. [공식 구매/배포 구분](https://www.ibm.com/products/watsonx-governance/pricing) | factsheet의 공급자/담당자 설명은 독립 실행 증거와 분리한다. 한국법 조항별 적용성·원본 출처·충분성·법률 검토를 우리 사례에 자동 충족한다고 간주하지 않는다. |
| Purview | 조사·콘텐츠 열람·관리 권한과 기능별 라이선스가 필요하다. 테넌트 감사 활성화 및 지원 서비스별 전제가 있다. [배포 고려사항](https://learn.microsoft.com/en-us/purview/dspm-for-ai-considerations), [서비스/사용권 설명](https://learn.microsoft.com/en-us/office365/servicedescriptions/microsoft-365-service-descriptions/microsoft-365-tenantlevel-services-licensing-guidance/microsoft-purview-service-description) | Microsoft 상용 서비스. 여기서 조사한 Purview SaaS와 동등한 로컬 self-host 배포판은 **미확인**이다. 가격이나 보유 사용권을 가정하지 않는다. | Microsoft 공급자 로그는 중요한 출처지만 전체 행위의 무손실 독립 관측은 아니다. 구독·연동·보존·서비스 범위에 따른 공백을 표시하고, 실제 토큰으로 읽기 검증 전에는 연결 완료로 표시하지 않는다. |

어느 제품에 대해서도 이 공개 문서 조사만으로 **EvidScope가 요구하는 독립 신뢰점 기반 변조·누락 export 검증, 당시 권한/위임/철회의 역사적 대조, 업무 AI의 증적 조회·변경 금지**가 모두 충족된다고 확인하지 않았다. 이는 경쟁 제품에 해당 기능이 없다는 단정이 아니라 이번 확인의 한계다. 제품의 “governance”, “immutable”, “complete trace” 표현을 우리 보안 보장의 증거로 옮겨 적지 않는다.

## 3. 개발 우선순위와 재사용 경계

다음은 위 문서와 현재 소스의 조사 결과에서 도출한 **EvidScope 설계 권고**다. 구현 완료 목록이 아니다. 현재 확인한 코드 기준으로 `src/model.mjs`에는 event source·trace/action·권한 범위 및 결과 대조가 있고, `public/app.js`에는 이벤트 검색·행동 타임라인·사건·거버넌스 검토가 있다. `src/analysis.mjs`는 분석 증거 참조를 작업 범위 안으로 제한한다. 이 조사 시점에는 공급자별 실제 adapter를 확인하지 않았다. 실제 변경과 검증 상태는 [진행표](progress-matrix.md)·시험 결과를 기준으로 판단한다.

1. **참고자료를 행동 옆에 먼저 보이게 한다.** Langfuse/Phoenix의 단계 구분과 Purview의 자료 참조 구분을 적용한다. 자료 종류, 식별자, 버전, 용도(입력/검색/출력), 제출 출처, 자료를 뒷받침하는 이벤트를 표시한다. 원문 대신 최소 메타데이터를 기본으로 하며 출처가 보고한 참조와 독립 도구가 관측한 참조를 나란히 비교한다. 현재 타임라인/검색/원본 상세를 확장하고 새로운 범용 trace 제품을 처음부터 복제하지 않는다. `version` 또는 hash가 같아도 읽기·사용·내용의 진실성을 자동 증명하지 않는다.

2. **기존 관측 제품은 수집·개발 디버깅 경계에서 재사용한다.** 향후 Langfuse나 Phoenix의 OTLP/OpenInference·SDK instrumentation을 활용하면 모든 프레임워크별 trace 수집기를 새로 만들 필요가 줄어든다. LangSmith를 이미 쓰는 조직은 기존 run/thread ID를 유지한다. 다만 이것은 연동 후보이며 현재 호환 adapter가 아니다. adapter는 원문·secret 최소화, source credential 분리, replay/dedupe, reference 연결, 수집 누락 표시를 시험한 뒤 사용한다. 개발 제품의 실행기·playground·감사 AI를 증적 영역으로 가져오지 않는다.

3. **사람의 판단 흐름을 기존 사건·거버넌스 기능에 연결한다.** LangSmith/Langfuse의 담당자·검토대상·상태 패턴을 참고해 선택한 행동과 자료 근거를 사건 의견·보완 과제로 연결한다. 자동 룰 일치, 증거 부족, 인간 판단, 법률 검토 상태를 별도로 유지한다. LLM judge나 위험 점수를 사람이 내린 승인·준수 결론으로 쓰지 않는다. dataset·prompt experimentation을 새로 개발하는 일보다 “왜 이 결론을 내렸는가”를 원본 참조와 함께 남기는 흐름이 우선이다.

4. **시스템 문서와 운영 증거를 한 조사 화면에서 이어 준다.** watsonx.governance의 use case/factsheet 패턴을 현재 시스템·요구사항·통제·담당자·재검토 모델에 적용한다. 문서 버전과 사건/시험/event 참조의 존재·확인 수준을 표시한다. 조직에 기존 GRC나 문서 저장소가 있다면 그것을 다시 만들기보다 versioned reference와 사람이 기록한 검토 근거를 연결한다. 외부 문서 URL을 자동 fetch하지 않으며 링크 등록을 내용 검증으로 취급하지 않는다.

5. **독립 증적과 출처별 공백은 EvidScope의 필수 책임으로 유지한다.** 앞선 제품이 처리하는 개발 trace 탐색·평가를 중복 구현하는 범위를 줄이고, 수집 자격·원본/사본 분리·외부 승인/도구 기록 대조·서명 export·재검토 이력을 강화한다. 화면에 마지막 수신·미연결 source·연결되지 않은 참고자료·누락된 권한/결과를 각각 드러낸다. 내부 chain-of-thought, 제공되지 않은 입력/출력, 실제로 받지 않은 자료 원문을 만들어내지 않는다. source의 자기보고만 있는 상황과 서로 다른 출처의 모순은 다른 상태다.

## 4. 이 조사로 완료되지 않은 것

- 제품 계정·라이선스 확보, 설치와 실제 API 수집, provider field coverage·개인정보 최소화·권한 분리·보존 정책·성능 시험은 미실행이다.
- 문서의 현재 화면·기능이 특정 릴리스에 모두 포함된다는 검증은 미실행이다. IBM 자료는 표기한 SaaS 및 2.3.x 범위를 구별했고 다른 제품의 가변 문서·main LICENSE도 확인일 기준이다.
- 실제 데이터를 연결할 때 조직이 허가한 환경에서 합성 fixture부터 시작해 source별 권한·누락·재전송·참조 버전 불일치를 시험해야 한다. 그 전까지 화면에는 합성 데이터와 미연동 상태를 유지한다.
- 이 비교는 법률 준수 또는 제품 인증 판정이 아니다. 현재 제품에 대한 구매 권고나 유료 서비스를 사용하겠다는 결정도 아니다.
