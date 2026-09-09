![EvidScope Architecture and Engineering](docs/assets/document-cover.svg)

# EvidScope

**[클릭하며 읽는 문서 뷰어](docs/viewer.html)** — 구성도와 네 단계 행동 추적 예시로 이해하기. `node scripts/preview-docs.mjs` 실행 후 [로컬 뷰어 열기](http://127.0.0.1:9097/docs/viewer.html). GitHub에서는 HTML 소스가 표시되며, 자세한 실행 안내는 [문서 안내](docs/README.md)에 있습니다.

[아키텍처 초안](docs/architecture-draft.md) · [개발 가이드](docs/development-guide.md) · [전체 문서](docs/README.md) · [개선 계획](docs/service-improvement-plan.md)

**[설계·개발 요약서 PDF 보기](output/pdf/evidscope-design-handbook.pdf)** — 구성도, 신뢰 경계, 개발 시작, 검증 범위와 개선 순서를 7쪽으로 정리했습니다.

AI 행동·권한 가시성, SIEM 조사, 독립 증적, 인간 거버넌스 검토를 연결하는 실행 가능한 로컬 파일럿입니다. 실행 차단·도구 중개·AI 실행 승인 발급·감사 LLM 기능은 없습니다. 실제 공급자와 개인정보 없이 합성 사례를 실행합니다.

**상태:** 로컬 구현과 실제 HTTP 검증, 전용 Kubernetes의 Service 분산·HPA·Pod 복구 관측을 제공합니다. 부하 timeout·장애 중 실패·CNI 검증 한계는 [실행 결과](reports/kubernetes-runtime-20260908.md)에 보존했습니다. 외부 LoadBalancer·저장소 HA·운영 적합성 인증 완료를 주장하지 않습니다.

**가시성 그래프:** 메뉴에서 AI 행동의 결과·참고자료·검토 상태를 비교하고 항목을 눌러 조사합니다. 행동 상세에는 근거 연결도가 있습니다. Kubernetes 탭은2026-09-08 합성 실험의 고정 스냅샷으로, 현재 테넌트 데이터 및 실시간 운영 상태와 구분합니다. 이 공개 실험 탭만 인증 없이 볼 수 있고 실제 AI 행동은 감사자 인증이 필요합니다. 그래프용 자료는 `node scripts/build-k8s-chart-data.mjs`로 원 보고서에서 재생성합니다.

**에이전트 목록:** 출처+에이전트별 행동, 관측 정책 준수율과 평가 범위, 근거 누락, 인간 검토를 비교하고 행동별 산정 근거를 엽니다. 미확인·대기·예외 및 0분모를 준수로 계산하지 않습니다. `docs/agent-policy-metrics.md`에 산정 기준이 있습니다. 차트는 확대·축소, 시간축 이동과 최신 따라가기, 넓게 보기를 지원합니다.

**운영 고도화:** 24시간·7일·30일·전체 기간, 위반·근거 부족·재검토 필터, 에이전트별 추이 구간 선택과 행동 전체 페이지 조회를 지원합니다. [개선 계획과 비용 원칙](docs/service-improvement-plan.md), [1단계 검증](reports/service-improvement-stage1.md)을 확인하세요. 집계와 정책 점검에 상시 AI 추론을 사용하지 않습니다.

**실제 로컬 AI 시험:** Qwen3 0.6B가 도구를 호출해 합성 안내 자료를 읽고 답변한 1차 시험과 4개 수집 기록의 서명 검증을 완료했습니다. 초기 도구 미호출 실패도 보존했습니다. `docs/local-ai-pilot.md`의 실행 방법과 검증 한계를 확인하세요.

**자동 모니터링:** 기본은 최근 1시간의 수신 기록을 1분 단위로 집계하고 1분마다 갱신합니다. 일간은 5분 집계·갱신, 주간은 1시간 집계·15분 갱신, 상세 조사는 30초 집계·갱신을 선택합니다. 화면 조회 주기이며 이벤트 수집·worker 분석 주기를 변경하지 않습니다. 오류 시 마지막 자료와 조회 실패 상태를 유지하고 재시도 간격을 늘립니다. 일시정지·숨김 탭·화면 이탈 시 자동 조회를 중단합니다. 출처의 최근 수신 여부는 별도 표시하며, 0건은 미수신·미활동을 구별하는 증거가 아닙니다. 용도별 기준과 한계는 `docs/monitoring-cadence.md`에 기록합니다.

## 실행

Node **24.15.x**가 필요합니다. npm 패키지 설치는 필요하지 않습니다. PowerShell에서:

```powershell
node scripts/init.mjs
node scripts/local.mjs
```

별도 터미널에서 합성 데이터를 만듭니다:

```powershell
node scripts/demo.mjs
```

[감사 화면](http://127.0.0.1:8082)을 엽니다. 로컬 `.local/config.json`의 `alpha-auditor` token을 비밀번호 입력란에 붙여 넣습니다. 룰 작성·시험은 `alpha-reviewer`, 별도 승인은 `alpha-admin` token으로 로그인합니다. 토큰은 화면에서 메모리에만 유지됩니다. 개발 프로파일의 파일 자격은 운영 SSO를 대체하지 않습니다. 비밀 파일을 커밋하거나 공유하지 마세요. 데모를 다시 실행하면 새로운 actionId로 사례가 추가됩니다.

포트: vault 8080, 수집 전용 8081, 감사 8082, worker health 8083. 모두 기본 loopback에만 바인딩합니다. `Ctrl+C`로 로컬 실행기를 종료합니다. 비 loopback 바인딩은 TLS 인증서 설정 없이 시작하지 않습니다.

## 조사 흐름

1. 종합 현황에서 미연결·수집중·오래된 source와 backlog를 확인합니다. 전체 가시성 백분율을 만들지 않습니다.
2. “행동과 근거 조사”에서 `demo-` 또는 actionId를 검색합니다. 요청·실행·결과·권한과 참고자료 ID/버전/해시를 나란히 비교합니다. AI의 product-guide v2 자기보고와 도구의 v1 참조가 다른 합성 사례를 제공합니다.
3. 독립 승인 대상 `case-OTHER`와 실제 대상 `case-42`, 성공 자기보고와 독립 실패 결과, 차단 등록과 미확인 중단을 대조합니다.
4. 행동 조사함에서 사건을 열어 원본 근거를 선택하고 사람의 판단·범위·한계·다음 검토 일시를 남깁니다. 새 증거와 분석 변경, 기한 만료는 재검토로 표시됩니다. 담당자·의견·조치 과제·종결 사유도 관리합니다.
5. 제한된 룰을 작성하고 최대 1,000건에 시험합니다. 다른 검토자가 버전을 승인하면 재평가합니다. 한시 예외는 작성자·소유자와 다른 검토자가 승인합니다.
6. 거버넌스에서 생성형 고객안내와 대출심사 보조 AI 사례를 엽니다. 실제 요구사항·합성 증거·누락·담당자·재검토 보고서를 확인합니다. 고영향 분류는 후보, 법률 검토는 미완료입니다.
7. 사건 보고서의 서명 JSON·읽기용 Markdown을 받습니다. 사건 서명은 `scripts/verify-case-report.mjs`, 전체 증적 체인은 `scripts/verify.mjs`와 별도 공개키로 검증합니다.
8. 보존 탭에서 목적·기간·hold·미종결 사건을 확인합니다. 기간이 지난 합성 이벤트의 구체 파기 계획을 다른 검토자가 승인한 뒤 관리자가 명시 실행할 수 있습니다. 기존 export·backup 파기와 운영 개인정보 처리 적합성은 별도입니다.

```powershell
node scripts/verify.mjs <export.json> .local/trust-anchor.pem
node scripts/verify.mjs <export.json> <별도보관-public-key.pem> <별도보관-checkpoint.json>
```

키는 export 안에서 가져오지 않습니다. `.local/trust-anchor.pem`은 개발용 최초 신뢰점이며 운영에서는 별도 신뢰 경로로 전달해야 합니다. checkpoint를 별도 보관하지 않으면 정상 서명된 과거 snapshot으로의 rollback은 검출하지 못합니다.

## 검증과 운영 자료

```powershell
node --test --test-concurrency=1 test/*.test.mjs
node scripts/benchmark.mjs
node scripts/k8s-static.mjs
node scripts/validate.mjs
```

- [검증 계획](docs/validation-plan.md), [실측 보고](reports/validation.md), [성능 원자료](reports/benchmark-latest.json)
- [구조·위협·한계](docs/architecture.md), [수집/API 계약](docs/contract.md), [운영·Kubernetes](docs/operations.md)
- [Kubernetes 로드밸런싱 구성·실제 분산 시험·저장소 고가용성 경계](docs/kubernetes-load-balancing.md)
- [철학·인용](docs/philosophy.md), [공식 법적 출처와 미확인 범위](docs/legal-sources.md)
- [Langfuse·LangSmith·Phoenix·watsonx.governance·Purview 비교와 참고한 설계](docs/product-reference.md)
- [실무 감사자 안내 · 행동 조사함과 서명 보고서](docs/audit-workbench.md), [완제품의 실무 검토 흐름에서 참고한 기준](docs/practitioner-workflow.md)
- [요구사항 데이터](data/requirements.json), [두 합성 거버넌스 사례](data/governance-examples.json)

프로젝트는 외부 npm 의존성 0개입니다. Node 자체의 SQLite 바인딩은 이 런타임에서 실험적 상태이므로 Node 버전을 고정하고 업그레이드 시 검증해야 합니다. TLS·OpenSSL·SQLite는 런타임의 번들 구성요소입니다. Docker base image는 가변 태그이며 운영 승격 전에 승인된 digest와 SBOM·취약점 검토가 필요합니다. 실행 가능한 파일럿 범위와 운영 미완료 항목은 보고서에 구분합니다.
