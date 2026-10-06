# 한국 AI 기본법 · 대출·신용평가 AI 증거 검토

첫 대상은 외부 AI를 도입한 금융사의 감사 담당자다. 금융 업무라는 사실만으로 고영향을 확정하지 않는다. 공급사의 이행 조치가 지금 운영하는 모델·목적에 해당하는지, 당시 승인과 실제 실행·결과가 일치하는지를 검토한다. 현재 파일·사례는 합성 자료이며 실제 금융사 연동이나 경쟁 우위를 입증하지 않는다.

## 화면과 API

거버넌스 → 시스템 등록에서 한국 사업자 역할, 심사 영향, 공급사, 모델 식별자·버전, 공급받은 목적과 중대한 변경 여부를 입력한다. 기존 schema 1~3은 schema 4로 이관되며 새 사실은 미확인으로 남고 재검토 과제가 생긴다. 이전 평가와 원장 기록은 남는다. 외부 AI 서비스를 그대로 이용하는 은행은 AI이용자일 수 있으므로 이용사업자 역할을 자동 부여하지 않는다. 국내 영향·실제 사업자 역할·제공 시각과 추가 조치 시험은 [한국법 증거 계약](kr-governance-evidence.md)을 따른다.

시스템 행의 **금융 증거 대조**에서 관련 조치 → 공급사 근거 → 실제 운영 기록과 충돌·누락 → 담당자 판단 순으로 검토한다.

| 경로 | 동작 |
|---|---|
| `POST /api/governance/systems` | 기존 등록에 `krRoles`, `supplierId`, `modelId`, `decisionInfluence`, `suppliedModelVersion`, `suppliedPurpose`, `substantialModification` 추가 |
| `POST /api/governance/bundles` | 검토자/관리자가 합성 증빙 JSON 가져오기. 문서 바이트 해시 검사, 암호화 로컬 보관 |
| `GET /api/governance/bundles/{id}/export` | 같은 테넌트 문서를 복구·검증한 후 JSON 반환. 복구 실패 시 409 |
| `GET /api/governance/finance?systemId=...` | 현재 문서·모델·목적 대조, 명시적인 시스템 연결 이벤트, 분석·보완 과제 |
| `POST /api/governance/finance/report` | `{systemId}`의 법령·시스템·증거·사람 판단 snapshot을 서명·저장 |
| `GET /api/governance/finance/reports/{id}` | 변경하지 않은 과거 snapshot과 서명 조회 |

증빙 입력 예시는 `reports/finance-supplier-example.json`이다. `id`, `systemId`, `synthetic:true`, `supplierId`, `modelId`, `modelVersion`, `purpose`, `testScope`, `measures`, `documents`를 받는다. 각 문서는 `id`, `name`, `sha256`, `contentBase64`를 포함한다. 문서는 1~10개, 전체 decoded bytes 64KiB, HTTP JSON 128KiB 한도다. 사용자가 보낸 파일명은 저장 경로로 사용하지 않는다. 임의 URL·파일 경로를 읽지 않는다.

조치별 기존 평가에 `type:document`, `ref:supplier-bundle:<id>`를 지정하면 수신한 증빙 해시를 서버가 연결한다. 대상 시스템과 조치 범위가 달라지거나 문서를 검증할 수 없으면 충분 평가를 거절한다. 증빙 revision·모델·목적·법령·시스템 변경은 재검토 대상으로 표시한다. `KR-34-RISK`, `KR-34-EXPLAIN`, `KR-34-PROTECT`만 공급사 활용 후보로 받는다. 인간 감독·문서 보관은 자동 승계하지 않는다. 법률상 간주 인정은 사람이 판단한다.

공급 당시 모델 버전·사용 목적이 없거나 현재 시스템·증빙과 일치하지 않으면 `SUPPLIED_*_UNKNOWN/MISMATCH` 재검토 지점을 남기며 충분 평가를 차단한다. 이 불일치 자체로 법 위반이나 중대한 기능 변경을 결정하지 않는다.

문서 암호화는 로컬 vault 키에 결합되므로 DB·문서 디렉터리·해당 키를 함께 보호하고 복구해야 한다. [로컬 백업·복구](vault-recovery.md)는 과거 문서·서명 보고서와 실제 HTTP 복구를 검증했다. 원격 DMS/5년 운영 실적은 미검증이다. 5년은 해당 조치 근거 문서의 보관 정책이며 모든 이벤트·원문 프롬프트의 보존기간이 아니다. 보고서 서명은 별도로 고정한 공개키로 확인한다. 보고서에 포함된 공개키만 믿으면 키 대체를 탐지할 수 없다.

## 승인과 출처 연결

`POST /api/assets`는 당시 정책의 `approvalRequired:true|false|unknown`을 저장한다. 정책 버전별 별도 등록 ID와 유효기간을 사용한다. `false`이면 건별 승인 누락을 내지 않고, 정책이 없으면 `APPROVAL_REQUIREMENT_UNKNOWN`으로 남긴다. 법적 인간 감독과 조직의 건별 사전 승인 정책은 별개다.

이벤트에 `systemId`, `requestId`, `attemptId`, `modelId`, `modelVersion`, `clockUncertaintyMs`를 추가할 수 있다. 한쪽에만 문맥이 있거나 값이 다르면 승인·실행을 일치시켜 통과하지 않는다. `clockUncertaintyMs:'unknown'` 또는 겹치는 오차 범위는 순서를 확정하지 않는다. 과거 이벤트에 오차 필드가 없으면 기존 보고 시각을 사용하되 신뢰된 시각이라는 주장은 하지 않는다.

AGT 입력 변환은 `src/agt-approval-adapter.mjs`에 있다. `scripts/collect-agt-approval.mjs --receipt <receipt.json> --collector <trusted-collector.json>`은 기본 미리보기이며 `--send --config <config.json> --base <ingress-origin>`으로 기존 HMAC 수집 경로에 제출한다. collector의 scope/context/actionDigest는 승인 시스템에서 확인한 값이어야 한다. 업무 에이전트가 보낸 값을 그대로 복사해 신뢰 설정으로 취급하지 않는다. 상위 AGT의 서명·hash-chain 재계산·승인자 신원·실제 실행은 이 변환기에서 검증하지 않는다.

## 실행과 검증

```powershell
npm run finance:pilot
npm run test:finance
$env:EVIDSCOPE_TEST_HOST='::1'
node --test test/finance-http.test.mjs test/integration.test.mjs
```

금융 실증은 별도 네 프로세스가 서명한 합성 이벤트를 기존 수집 인증과 worker claim/complete 경로로 처리한다. 재실행마다 별도 `.test-runs/finance-*`에 데이터·키를 둔다. `reports/finance-pilot-latest.json`에 기대 결과와 실행 범위를 기록한다. 여기의 시간은 프로그램의 조회 시간이며 감사자의 검토 시간은 측정하지 않았다. HTTP 시험은 별도로 실제 vault/ingress/audit 프로세스를 사용한다.

이 Windows 환경에서 IPv4 loopback `listen/connect EFAULT`가 관측되어 테스트만 명시적으로 IPv6 loopback을 선택할 수 있게 했다. 기본 제품 바인딩과 TLS 경계는 변경하지 않았다. 시험 통과는 실제 은행 연동, Kubernetes 네트워크 격리, 장기 보관이나 법률 준수 보증이 아니다.

학습 준비·중단/재개·산출물 검증·동일 베이스 평가 경로와 실제 실행 조건은 [학습 전달 문서](training-delivery-20260922.md)를 따른다. 사람이 검토하지 않은 후보를 승인 데이터로 승격하지 않는다.
