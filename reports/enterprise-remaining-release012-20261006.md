# 0.1.2 이후 엔터프라이즈·한국법 지원 독립 감사

2026-10-06. 현재 코드, 출시 사본, 배포 JSON, 공식 법령 원문을 읽고 한 개의 작은 합성 서비스에서 정상 문서·무결성·백업 경로를 실제 실행했다. 제품, 실행 중인 서비스, 학습 자료, 클러스터는 변경하지 않았다. 전체 회귀와 GPU 작업은 실행하지 않았다. 아래 세 항목은 목표를 파일럿으로 축소하기 위한 완료 선언이 아니라 다음 구현·실증의 우선순위다.

## 1. P1: 허용된 거버넌스 문서가 전체 무결성 검사와 백업을 막는다

`src/governance-documents.mjs:8`은 실제 파일을 최대 4MiB까지 받는다. 그러나 `src/document-integrity.mjs:15`의 `addReference`는 finance/governance를 구분하지 않고 64KiB 초과를 거부한다. 이 검사는 `/api/integrity`와 `createVaultBackup`의 전체 파일 검증에 모두 사용된다(`src/service.mjs:244`, `src/vault-recovery.mjs:66`). 법적 보관을 위해 문서를 접수하는 정상 사용자 흐름이 이후 증적 검증·복구를 막는다. 고영향 문서의 크기를 64KiB로 다시 줄이는 해결은 이미 제공한 4MiB 계약을 파괴한다.

실행 근거: Node 24.15.0, 임시 디렉터리의 독립 SQLite service, 임시 Ed25519 키, 단일 합성 테넌트, GPU·네트워크 없음. 합성 시스템 등록 후 `Buffer.alloc(256*1024,0x47)`의 SHA-256과 정규 base64를 `/api/governance/documents`에 제출했다. 실제 결과(2026-10-06T07:22:07.821Z)는 다음과 같다.

```json
{
  "document": {"bytes": 262144, "version": 1},
  "retrieval": {"status": "hash_verified_and_retrievable"},
  "integrity": {
    "valid": false,
    "error": "Document file metadata is invalid",
    "failureRecorded": true
  },
  "backup": {"error": "Document file metadata is invalid"}
}
```

첫 sandbox 실행은 임시 암호문 rename의 Windows `EPERM`으로 이 경로에 도달하지 못했다. 동일 코드의 승인된 실제 Windows 실행에서 위 결과를 재현했다. 실패를 제품 메타데이터 오류와 혼동하지 않았다. 서비스 종료 후 자신의 임시 디렉터리만 절대경로 검증 뒤 제거했다.

출시 사본과 현재 파일의 SHA-256을 각각 대조했으며 두 파일 모두 일치한다. 따라서 아직 배포되지 않은 코드만의 문제가 아니다.

- `src/document-integrity.mjs`: `9abfbbeee179ec11bcb5b391ba99372bf1088b18e755a0ac2dd3a84012861c62`
- `src/governance-documents.mjs`: `adfbb9e9c94f32dcc3d427b834fc19a0a0a621ceb6d0d91661f18d2249b65d3a`

기존 `test/governance-documents.test.mjs:69`의 256KiB와 `:132`의 실제 HTTP 4MiB 검사는 수신·조회까지 검증한다. 같은 문서를 전체 무결성·백업·복구까지 보내지 않아 이 불일치를 찾지 못했다. 백업 검사는 작은 문서만 사용한다(`:144`). 901개 회귀 통과가 이 흐름의 완료 근거가 아니었음을 보여준다.

다음 구현: 문서 종류별 상한을 분리하고 governance는 기존 `MAX_GOVERNANCE_DOCUMENT_BYTES`를 재사용한다. supplier의 기존 64KiB 상한, 전체 파일 수·전체 plaintext byte cap, historical revision 검사, tenant/AAD·해시·파일 변조 검사는 유지한다.

완료 조건: 64KiB·64KiB+1·256KiB·4MiB governance 문서를 실제 HTTP로 받는 동일 시험에서 `/api/integrity` 성공, 백업 생성, 새 경로 복구, 복구 서비스의 정확한 원본 바이트 조회를 확인한다. 과거 256KiB revision과 현재 revision을 모두 복원하고, 4MiB+1 거부·supplier 초과 거부·타 테넌트 거부·암호문 변조 거부를 함께 확인한다. 출시 아카이브는 덮어쓰지 않고 후속 패치의 변경·검증 근거를 따로 발급한다.

## 2. 조직 인증이 필요한 배포의 연결과 준비 판정이 아직 하나의 검증 흐름이 아니다

실제 `deploy/kubernetes.json`의 vault 라벨에 매칭되는 Egress NetworkPolicy를 Node로 계산했다. 결과는 `deny-all`, `egress: []` 한 개였다. `deploy/render-manifests.mjs:33`은 전체 ingress/egress deny, `:34`는 vault **수신**만 허용하며 DNS/IdP로의 vault 발신은 제공하지 않는다. 정책을 집행하는 CNI에서 기본 배포 그대로는 vault의 OIDC discovery·JWKS·token 요청을 허용할 수 없다. 이는 정적 정책 분석이며 이번 감사에서 실제 CNI 패킷 차단을 재실행한 것은 아니다.

`src/identity.mjs:25`는 enterprise profile에서 OIDC를 요구하고, `:53`에서 첫 로그인 때 discovery를 수행한다. 반면 `/healthz`는 DB `SELECT 1`, `/readyz`는 서비스 준비 상태를 확인하므로 조직 로그인 연결 실증을 대체하지 않는다(`src/server.mjs:62–68`). `docs/oidc-authentication.md:38`도 운영 overlay와 CNI 실증 미완료를 명시한다. 기존 합성 IdP/TLS/세션 회수·테넌트 검사를 부정하는 발견이 아니라, 그 구현을 실제 조직 배포로 연결하는 공백이다.

다음 구현: 조직별 issuer/실제 endpoint origin/신뢰 CA와 검증된 이미지 digest를 입력받는 검토 가능한 enterprise overlay 및 배포 사전 검사. 기본 deny-all을 넓게 풀지 않고 승인된 IdP/DNS만 연결한다. 외부 IdP는 일반 Kubernetes NetworkPolicy의 FQDN 지원 부재도 고려하여 확정된 endpoint/CNI 정책 또는 egress gateway로 명시한다. IdP 실측 상태는 저장소 준비와 별도로 표시하고, 법적 이행·증적 건강으로 오인하지 않는다.

완료 조건: 승인된 별도 실험 namespace에서 discovery/JWKS/token의 예상 경로가 허용되고 미승인 origin/무라벨 Pod/직접 vault 접근은 거부됨을 각각 TCP/TLS/HTTP 단계로 구별한다. 실제 브라우저에서 로그인→서버 소유 tenant/role→세션 변경 CSRF→다른 테넌트 거부→회수 후 기존 cookie 거부→재시작 후 로그인 재발급을 검증한다. 실제 조직 IdP가 제공되지 않으면 합성 운영 overlay 검증으로 정확히 표시하고 조직 MFA/계정 회수까지 완료했다고 쓰지 않는다.

이후 별도 운영 수락 항목은 단일 writer의 원격 백업·외부 anchor·KMS/키 회전과 측정 RPO/RTO다. `docs/vault-recovery.md:35`는 현재 로컬 복구가 이를 입증하지 않는다고 명시한다. 인증 overlay 완료만으로 HA·원격 DR를 완료 처리하지 않는다.

## 3. 대출심사의 다른 법령 이행 인정은 안내 문구에서 검증 가능한 검토 경로로 이어지지 않는다

공식 법 [제34조제3항](https://www.law.go.kr/LSW/lsSideInfoP.do?docCls=jo&joBrNo=00&joNo=0034&lsiSeq=282791&urlMode=lsScJoRltInfoR)과 시행령 [제27조제5항](https://www.law.go.kr/LSW/lsSideInfoP.do?docCls=jo&joBrNo=00&joNo=0027&lsiSeq=288781&urlMode=lsScJoRltInfoR)은 다른 법령의 조치 인정 경로를 별도로 둔다. 같은 제27조제3항의 공급사 조치 활용은 제34조제1항제1~3호와 중대한 변경 없음의 조건이다. 두 근거를 동일한 공급사 증빙 하나로 대체해서는 안 된다. 원문을 2026-10-06 다시 확인했다.

현재 등록 내용은 이 구별을 이미 담고 있다. `data/requirements.json:366,411–412`는 대출 설명과 신용정보법, `:430,475–477`은 금융소비자보호법과 범위 구별을 사람이 검토하도록 안내한다. 그러나 실행 가능한 `krGovernanceCheckDefinitions`에서 KR34 위험·설명·보호의 대안은 자체 조치와 supplier reliance의 여섯 종류뿐이다(`src/kr-governance-evidence.mjs:42–53`). `normalizeGovernanceCheck(:115)`는 미등록 측정 종류를 거부한다. 별표1에 따른 대출 설명·이용자 보호 이행 근거를 구조적으로 연결하고 승인·현재 업무 결과와 대조하는 별도 경로는 이 목록에 없다. 일반 문서나 자유 서술로 남길 수 있음과 typed 검증 대안으로 지원됨은 구별한다.

이번 브라우저에서 공식 별표1 본문이 동적 페이지에 노출되지 않아 금융 하위조문의 현행 전체 내용은 새로 확정하지 않았다. 검색에 나온 비공식 복제·과거 하위법령집을 현행 법적 근거로 사용하지 않았다. 따라서 registry의 금융 인정 안내를 사람 검토 완료 또는 최신 법령 대조 완료로 재분류하지 않는다.

다음 제품 slice: 공식 별표1의 해당 항목·법률 버전·유효 시점·대출심사 범위를 먼저 고정한 뒤 **다른 법령 이행 인정 검토 묶음**을 추가한다. 원본 법적 근거, 실제 이행 조치, 승인한 담당자, 관련 증거와 동일 모델·목적·배포 시점·업무 결과를 연결한다. 단순 인증 보유나 PIPA 조치로 위험/설명/보호/사람 감독/문서 보관 전체를 자동 인정하지 않는다.

완료 조건: 동일 대출 사건에서 직접 조치·공급사 활용·다른 법령 인정 후보를 독립적으로 표시한다. 다른 시스템/모델/목적·기간·불완전 조치·철회 승인·변조 문서로는 근거를 충족시키지 못한다. 대응 조치의 일부만 이행하면 그 범위만 남기고, 미검토 법적 인정은 보류한다. 다른 법령에 따라 별도로 발생하는 의무도 삭제하지 않는다. 사람의 적용·충분성 판단과 기술적 기록 대조를 각각 보존한 signed snapshot이 필요하다.

공식 MSIT QA를 새 학습 정답으로 바로 넣는 것도 같은 범위 검토가 필요하다. 정규화된 FAQ16/사례19는 공급사 책무 중복 이행을 넓게 설명하지만 현재 시행령의 명시 범위는 제1~3호다. 두 원문 행은 `currentLawRevalidationPerformed=false`, `trainingReady=false`를 유지하고 있다. 원문을 고치거나 사람 검토 완료로 표시하지 않았다. 검색 기반 출처 제공 때도 당시 공식 설명과 현행 조문의 범위 차이를 따로 보여줘야 한다.

## 수락 순서

문서 접수→무결성→백업→복구의 확인된 결함을 먼저 고친다. 이어 대출심사의 다른 법령 검토 경로를 증거·사람 판단과 연결하고, 운영 인증 overlay·실제 배포 수락 및 원격 복구 실증을 진행한다. 0.1.2의 10회 파일럿 검증은 보존하되 이 세 항목과 실제 금융 고객 연동·원격 HA·장기 보존·조직별 성능/복구 SLA의 완료 증거로 확대하지 않는다.
