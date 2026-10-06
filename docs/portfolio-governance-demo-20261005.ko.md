# EvidScope 취업용 검증 데모 — 공급사 증거와 변경 재검토

이 자료는 기존 제품 기능을 재사용한 **합성 재현 하네스·테스트·설명 자료**다. 오늘 제품 전체를 새로 구현하거나 금융 업무를 연결한 작업이 아니다. 실제 법률 판단과 사람의 증거 내용 검토는 완료하지 않았다.

## 설명할 문제와 구조

공급사 문서가 있어도 현재 사용하는 모델·목적과 최초 공급 범위가 달라졌다면 예전 평가를 그대로 믿기 어렵다. EvidScope는 제출된 사실과 증거의 버전을 대조하고, 바뀐 평가를 의무별 재검토로 돌린다. 사람 감독의 수행 기록이 없으면 문서가 있다는 이유만으로 과제를 종결하지 못한다.

```text
합성 도구·권한 서비스 기록
  → 출처 자격·HMAC 확인, 허용 메타데이터 정규화
  → SQLite 접수 영수증·암호화 이벤트·서명 원장 저장
  → worker의 결정론적 권한·승인·결과 검사
  → 요구사항별 문서/이벤트 연결, 변경·누락·재검토
  → 합성 사람 평가 기록 + 서명 보고서·원장 내보내기
```

이 데모는 `createService.handle()`을 같은 프로세스에서 직접 호출한다. URL 객체는 경로를 전달하는 용도이며 서버·소켓을 열지 않는다. HMAC 접수, 실제 SQLite 저장, 기존 worker 평가와 보고서 서명 코드는 재사용한다. HTTP/TLS나 별도 호스트의 출처 신뢰 경계는 시험하지 않는다.

핵심 검사는 [model.mjs의 evaluate](../src/model.mjs), [worker](../src/worker.mjs), [governance-policy](../src/governance-policy.mjs), [service의 technicalEvidenceState/report](../src/service.mjs)에서 수행한다. `model.mjs`라는 이름은 LLM이 검사한다는 뜻이 아니다. 선택형 Foundation-Sec 초안은 기본 OFF인 [별도 보조 경로](../src/assistance-runner.mjs)다. 공개 한국어 QA QLoRA 실험도 이 규칙 검사와 분리돼 있으며 이번 데모에서는 학습·추론을 실행하지 않았다.

## 재현

Node 24.15.x와 저장소의 기존 의존성이 필요하다. 저장소 루트에서 다음을 실행한다. 설치·서버 시작·모델 활성화는 이 명령에 포함되지 않는다.

```powershell
$portfolioReport = Join-Path $env:TEMP ('evidscope-portfolio-' + [Guid]::NewGuid().ToString('N') + '.json')
node scripts/portfolio-governance-demo.mjs --output $portfolioReport
$portfolioResult = Get-Content -LiteralPath $portfolioReport -Raw -Encoding utf8 | ConvertFrom-Json
$portfolioResult.cases | Select-Object id, passed, supplierIssues
```

각 실행은 새 임시 폴더에 합성 데이터만 생성한다. 기존 `.local` 설정·사용자 데이터·API 키를 읽지 않고 기존 파일을 덮어쓰지 않는다. 개인 서명키와 출처 토큰을 출력·산출물 파일에 저장하지 않는다. 합성 DB와 공개 증거 파일은 삭제하지 않고 임시 폴더에 보존한다. `--output`에 이미 있는 파일을 지정하면 거절한다.

새 테스트와 관련 기존 회귀의 재현 명령:

```powershell
node --check scripts/portfolio-governance-demo.mjs
node --check test/portfolio-governance-demo.test.mjs
node --test --test-concurrency=1 test/portfolio-governance-demo.test.mjs test/finance-evidence.test.mjs test/governance-policy.test.mjs test/governance-applicability-binding.test.mjs test/governance-document-evidence.test.mjs test/human-oversight-evidence.test.mjs test/model.test.mjs
```

새 테스트는 fetch, HTTP/HTTPS 요청, TCP/TLS 연결과 서버 listen을 금지한 상태에서 6개 시나리오를 실행하고 호출 시도 0을 확인한다. CLI 산출물 생성과 기존 출력 보존도 확인한다.

## 실제 관찰한 여섯 가지 분기

`human_evidence_assessed`는 시험용 사람이 입력한 평가 기록의 상태다. 실제 사람의 법률 판단이나 자동 준수 PASS가 아니다. 모든 합성 법률 검토는 `pending`으로 시작한다.

| 분기 | 위험관리 RISK | 문서 DOCUMENT | 사람 감독 OVERSIGHT | 확인한 동작 |
|---|---|---|---|---|
| 기준 | 사람 증거 평가 기록 | 사람 증거 평가 기록 | 사람 증거 평가 기록 | 권한·승인·도구 결과의 규칙 findings 0, 분석 backlog 0 |
| 현재 모델 v2 변경 | 재검토 | 재검토 | 재검토 | 공급사 모델·최초 공급 모델 불일치, 공급사 근거의 충분 평가 거절 |
| 목적 변경, 현재 공급사 목적도 갱신 | 재검토 | 재검토 | 재검토 | 현재 목적끼리는 일치하지만 최초 공급 목적 불일치, 충분 평가 거절 |
| 공급사 문서 개정 | 재검토 | 기존 평가 유지 | 기존 평가 유지 | 연결된 위험관리 근거만 오래됨, 공급사 개정 과제 생성 |
| 자체 감독 계획 개정 | 기존 평가 유지 | 재검토 | 재검토 | 문서 버전·snapshot 변경과 연결 평가 재검토 |
| 감독 수행 기록 누락 | 기존 평가 유지 | 기존 평가 유지 | 증거 불충분 | 계획만으로 감독을 확인하지 않으며 과제 종결 거절 |

누락 분기는 처음부터 감독 수행 이벤트를 제출하지 않는 별도 시험이다. 기존 원본을 삭제해 누락을 만드는 방식이 아니다. 목적 불일치는 자동으로 법적 중대 변경을 확정하지 않는다.

최종 로컬 실행: **6/6 시나리오, 87개 확인 항목 통과**. 각 분기에서 기존 서명 보고서 보존, 변경된 보고서의 서명 확인, 보고서·원장 변조 거절, 현재 fixture 체크포인트와 맞지 않는 과거 정상 서명 export 거절을 함께 확인했다. 최종 관련 회귀는 **46/46**, 두 새 파일의 `node --check`도 통과했다. [최종 결과 JSON](../reports/portfolio-governance-demo-20261005/result.json), [최종 회귀 로그](../reports/portfolio-governance-demo-20261005/regression-final.log).

첫 회귀는 **52/53**이었다. 이름 필터가 기존 HTTP 시험을 제외하지 못했고 해당 시험은 `.test-runs` 폴더 생성 `EPERM`으로 서버 시작 전에 실패했다. 이 실패를 [초기 로그](../reports/portfolio-governance-demo-20261005/regression-initial.log)에 보존했다. 최종 46개는 그 HTTP 시험이 포함된 파일을 제외한 관련 프로세스 내부 회귀다. 전체 제품 회귀·HTTP/TLS·부하·장애 복구를 모두 통과했다고 주장하지 않는다. 저장소에 별도 lint/typecheck 명령이 없어 이번에는 Node 구문 검사와 테스트만 수행했다.

## 3분 시연 순서

1. **0:00–0:30:** “공급사 문서의 존재와 현재 모델·목적에 맞는 증거라는 판단은 다릅니다.” 위 흐름을 설명하고 규칙 검사·선택 LLM 초안·사람 법률 판단을 구분한다.
2. **0:30–1:00:** 재현 명령을 실행하고 `passedCases: 6`, `modelCalls: 0`과 새 합성 실행 폴더를 보여준다.
3. **1:00–1:50:** 결과의 `purpose-changed`에서 `SUPPLIED_PURPOSE_MISMATCH`, `supplier-document-revised`의 의무별 `after` 상태를 비교한다. 전체를 무조건 재검토시키는 것과 연결된 의무만 재검토시키는 것의 차이를 설명한다.
4. **1:50–2:20:** `oversight-record-missing`의 `oversight_review_record_missing`과 과제 종결 거절 결과를 보여준다. 문서 보관과 감독 수행을 별개로 확인한다고 설명한다.
5. **2:20–3:00:** 아래 독립 CLI 검증을 보여주고, 서명이 출처의 진실이나 법 준수를 보장하지 않는다는 한계로 마친다.

이번에 보존한 합성 기준 원장의 검증 명령:

```powershell
node scripts/verify.mjs reports/portfolio-governance-demo-20261005/baseline/ledger-export.json reports/portfolio-governance-demo-20261005/baseline/public-key.pem reports/portfolio-governance-demo-20261005/baseline/checkpoint.json
```

키와 체크포인트는 시험 fixture에서 고정한 신뢰점이다. 같은 폴더의 파일이라는 이유만으로 운영에서 독립 신뢰점이 되는 것은 아니다. 실제 배포에서는 별도 신뢰 경로와 외부 보관이 필요하다.

`finance-before.json`, `finance-after.json`, `ledger-export.json`, `supplier-export.json`, `public-key.pem`, `checkpoint.json`은 별개의 파일이다. 이 데모는 이를 자동 준수 인증서나 단일 완결 증거 패키지라고 부르지 않는다. [artifact-index.json](../reports/portfolio-governance-demo-20261005/artifact-index.json)은 보존 사본의 SHA-256을 나열하며 외부 인증을 발급하지 않는다.

## 국문 이력서 초안과 본인 확인

다음은 **AI 협업 범위를 공개한 초안**이다. 본인이 실행하고 설명한 뒤 사용한다.

> AI 코딩 도구와 협업하여 기존 Node.js/SQLite 기반 EvidScope의 공급사 증거·모델·목적 변경과 의무별 재검토 흐름을 재현하는 합성 검증 하네스 및 설명 자료를 구성했습니다. 6개 시나리오의 상태 전환, 감독 증거 누락 시 종결 차단, 서명 이력 보존과 변조 거절을 확인했으며 관련 회귀 46개를 통과했습니다.

오늘 추가한 것은 재현 스크립트·테스트·설명·실행 증거다. 기존 제품 기능 전체를 오늘 새로 개발했다고 쓰지 않는다. 코드 초안과 자동 검증은 AI가 수행했으며, 본인의 독립적인 법률 검토나 사용자 실험은 수행하지 않았다.

면접 전에 본인이 확인할 내용:

- 재현 명령을 직접 실행하고 공급사 개정·목적 변경·감독 누락의 차이를 자신의 말로 설명한다.
- `service.mjs`의 `report`/`technicalEvidenceState`, `finance-evidence.mjs`의 `verify`/`staleEvidence`와 하네스 호출 위치를 따라간다.
- 핵심 worker가 LLM을 호출하지 않는 이유와 선택형 AI 초안이 사람 판단을 대체하지 않는 이유를 설명한다.
- 무엇을 합성 데이터로 검증했고 무엇을 검증하지 않았는지 밝힌다. 실제 금융 연동·법 준수·상용 제품 우월성·취업 확정을 주장하지 않는다.

일반 거버넌스 문서의 원문·버전·복구 검증은 구현돼 있지만 공급사 금융 재사용 경로는 여전히 `synthetic:true`만 허용한다. 이번 작업은 그 제한을 해제하지 않았다. 법적 요구사항의 내용은 기존 catalog를 그대로 사용했으며 법률 판단은 사람에게 남겼다.
