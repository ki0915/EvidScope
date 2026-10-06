# EvidScope 파일럿 설치·사용 안내

한국 AI 기본법 적용 후보와 운영 증거를 연결해 담당자가 이행 근거를 검토하는 통제된 로컬/폐쇄망 파일럿이다. 인증된 기록, 보관 문서, 현재 시스템·모델·정책·법령 버전을 대조하고 부족·충돌·재검토 상태를 남긴다. 법률 충분성 판단은 사람이 수행한다.

## 배포본과 설치

설치 ZIP·디렉터리의 버전과 검증 근거는 각 배포본의 `release-manifest.json`에서 확인한다. `verification.evidenceDirectory`의 `verification.json`은 해당 버전의 10회 결과와 소스·로그 해시를 담는다. 아래 v0.1.0 수치는 최초 출시 당시 이력이며 후속 버전의 새 검사를 대신하지 않는다. 외부 GitHub·레지스트리에 공개 게시하는 출시는 아니다. 배포본에는 소스·화면·법령 목록·실행/검증 도구·잠금 파일·사용 안내·검증 결과와 고정한 `node_modules`를 포함하고, 개인키·자격 파일·로컬 DB·훈련 가중치는 포함하지 않는다. Node 실행 파일은 별도로 설치한 **24.15.x**를 사용한다. 동봉 의존성을 사용하는 ZIP 설치는 npm 네트워크 설치가 필요 없으며, 소스만 받은 설치는 승인된 잠금 의존성을 별도로 설치한다.

새 파일럿은 별도 디렉터리에 압축을 풀고 그 root에서 다음을 실행한다. 기존 운영 `.local`을 새 파일럿으로 복사하지 않는다. 초기화는 고유한 합성 자격과 Ed25519 키를 생성하며 기존 설정을 자동 교체하지 않는다.

```powershell
node --version
# 소스만 받은 경우: npm ci --ignore-scripts --no-audit --no-fund
# 이 PC의 IPv4 loopback 오류를 피할 필요가 있을 때 선택한다.
$env:EVIDSCOPE_LOCAL_HOST='::1'
npm start
```

IPv6 감사 화면은 `http://[::1]:8082`, 기본 IPv4는 `http://127.0.0.1:8082`다. 네 포트는 vault 8080, ingress 8081, audit 8082, worker 8083이며 실제 시작 메시지의 주소를 확인한다. `EVIDSCOPE_LOCAL_DIR`로 별도 자격·키·데이터 경로, `EVIDSCOPE_LOCAL_PORT_BASE`로 시작 포트를 선택할 수 있다. 기준 `0`의 자동 포트는 시험용이다. 로컬 실행기는 loopback HTTP로 제한하며 `TLS_CERT_FILE` 또는 `TLS_KEY_FILE`을 상속하면 시작을 거부한다. 기존 TLS 구성이 있다면 별도 배포 경로를 사용한다. 모델·GPU·학습 Job은 실행하지 않는다.

## 로그인과 한국법 검토

선택한 로컬 경로의 `config.json`에서 해당 역할의 token을 확인해 화면에 직접 입력한다. 터미널·보고서·공유 화면에 전체 설정이나 토큰을 출력하지 않는다. `alpha-auditor`는 읽기·조사, `alpha-reviewer`는 시스템·문서 등록과 사람 검토, `alpha-admin`은 별도 승인·관리 동작에 사용한다. 다른 테넌트의 자격은 그 테넌트 자료에 접근할 수 없다. 파일 자격은 조직 SSO의 대체물이 아니며 조직 OIDC 도입은 [인증 안내](oidc-authentication.md)의 별도 설정과 실증을 따른다.

1. 거버넌스에서 사용 목적, 실제 사업자 역할, 국내 영향, 고영향 판단 사실, 모델·정책 버전과 제공 시각을 등록한다. 금융 업무라는 이유만으로 고영향이나 AI이용사업자를 확정하지 않는다.
2. 원본 근거 문서를 업로드한다. 일반 거버넌스 문서는 파일당 **4MiB**, JSON 요청은 **6MiB**다. 공급사 묶음은 별도 계약으로 decoded 합계 **64KiB**, JSON **128KiB**다. 파일명은 저장 경로가 되지 않으며 실제 해시·복구·테넌트·버전을 검사한다.
3. 신뢰 설정을 가진 수집 출처가 HMAC으로 조치 시험 기록을 제출한다. AI 에이전트 자기보고는 한국법 조치 시험 근거를 발급할 수 없다. 18개 한국법 요구사항과 23개 시험 유형의 필드는 [증거 계약](kr-governance-evidence.md)을 따른다.
4. 요구사항 → 공급사/문서 근거 → 실제 기록 → 누락·충돌 → 담당자 판단을 검토한다. 기술 근거와 사람의 적용성·충분성 판단을 각각 기록한다. `sufficient`를 입력해도 부족한 기술 근거가 자동 충족되지는 않는다.
5. 보완 과제를 처리하고 현재 근거로 종결한다. 모델·목적·문서·법령 변경, 만료, 미확인 시계와 다른 명령의 대응 기록은 재검토 또는 종결 차단의 사유다. 고정 보고서는 당시 버전을 보존하고 이후 기록으로 바꾸지 않는다.

`npm run finance:pilot`은 별도 합성 프로세스 실증이다. 실제 금융 고객 자료·기관 연동이 아니며 감사자의 수동 검토 시간을 측정하지 않는다. `npm run demo`는 실행기와 같은 `EVIDSCOPE_LOCAL_HOST`·`EVIDSCOPE_LOCAL_DIR`·`EVIDSCOPE_LOCAL_PORT_BASE` 설정을 별도 터미널에 지정하여 실행한다. 기준 `0`의 자동 포트는 데모 CLI 대상이 아니다. 데모를 실행하면 기존 데이터에 새로운 합성 사례가 추가된다.

## 보고서와 독립 검증

화면에서 사건 보고서 또는 금융 증거 보고서와 전체 원장을 내보낸다. vault 공개키는 export 내부에서 고르지 않고 별도의 신뢰 경로로 확보한다. checkpoint도 별도 보관해야 정상 서명된 과거 snapshot으로의 rollback을 검사할 수 있다.

```powershell
node scripts/verify.mjs EXPORT.json TRUSTED_PUBLIC_KEY.pem EXTERNAL_CHECKPOINT.json
node scripts/verify-case-report.mjs CASE_REPORT.json TRUSTED_PUBLIC_KEY.pem EXTERNAL_CHECKPOINT.json
node scripts/verify-finance-report.mjs FINANCE_REPORT.json TRUSTED_PUBLIC_KEY.pem EXTERNALLY_PINNED_REPORT_SHA256
```

두 번째 명령은 사건 보고서 형식만 받는다. 세 번째 명령은 금융/거버넌스 고정 보고서의 canonical snapshot SHA-256과 Ed25519 서명을 검증한다. 금융 snapshot은 원장 checkpoint를 포함하지 않으므로 선택 인자는 별도 신뢰 경로에서 고정한 64자리 보고서 SHA-256이다. 외부 해시를 생략하면 `rollbackChecked:false`이며 서명만으로 과거 정상 보고서 재사용을 탐지하지 못한다. 전체 원장과 체크포인트는 첫 번째 명령으로 별도 검증한다. 서명과 해시 일치는 기록의 변경 여부를 검사하며 출처 주장의 진실성·법적 증거능력·준수 인증을 보증하지 않는다.

## 백업, 복구, 종료와 재시작

백업과 anchor의 부모 디렉터리를 먼저 만들고 각각 새 경로를 사용한다. 기본 경로 예시는 다음과 같으며 사용자 지정 로컬 경로를 선택했다면 함께 바꾼다. 원래 개인키, 독립 공개키, 외부 anchor는 서로의 신뢰 경로와 OS 접근 통제를 유지한다.

```powershell
New-Item -ItemType Directory -Force -Path .test-runs | Out-Null
node scripts/vault-backup.mjs create .local/data .test-runs/vault-backup-001 .local/signing-private.pem .local/trust-anchor.pem .test-runs/vault-anchor-001.json
node scripts/vault-backup.mjs restore .test-runs/vault-backup-001 .test-runs/vault-restored-001 .local/signing-private.pem .local/trust-anchor.pem .test-runs/vault-anchor-001.json
```

실행 중 DB 파일 하나만 복사하지 않는다. 도구는 일관된 SQLite snapshot과 문서를 암호화 백업하고 새 데이터 경로에만 복원한다. 정상 복원 결과를 확인한 뒤 별도 구성의 vault 서버에서 `DATA_DIR`을 복원 경로, `CONFIG_FILE`과 `SIGNING_KEY_FILE`을 승인한 기존 자격·키 경로로 지정하고 역할·문서·과거 보고서를 재검증한다. 새 설치의 초기화와 기존 자료 복구는 서로 다른 작업이다. 복원 도구는 자동 트래픽 전환이나 기존 DB 덮어쓰기를 하지 않는다. 상세 계약과 원격 백업·5년 보존의 미검증 범위는 [복구 안내](vault-recovery.md)를 따른다.

실행 터미널에서 `Ctrl+C`로 네 자식 프로세스를 종료하고 종료를 확인한 뒤 같은 경로로 `npm start`를 다시 실행한다. 포트가 다른 프로세스에 점유되어 있으면 그 프로세스를 임의 종료하지 말고 별도 시작 포트를 선택한다. 기존 자격·키·DB는 재시작으로 교체되지 않는다.

## v0.1.0 검증 이력과 후속 범위

설치 복사본에서 **10회 연속, 매회 38개·총 380개** 실제 검사를 통과했다. 배포된 전체 검사 **756/756**, 읽기 전용·network none·CPU 2·RAM 1GiB Linux 이미지 검사 **38/38**도 통과했다. 회차별 시작·종료·소스와 로그 해시는 `reports/first-release-20261006/verification.json`에 있다. 합성 입력을 실제 독립 프로세스·파일·HTTP에 제출했으며 실제 금융 고객 자료는 쓰지 않았다. 정상 실행, 출처 인증·테넌트·4MiB 문서 상한·복구·잘못된 근거의 종결 거부·서명·시작 실패·재시작/복구·자식 종료를 확인했다. 결과는 [출시 보고서](../reports/first-release-20261006.md)를 따른다.

개발 PC의 비공개 학습·평가 이력에 의존하는 학습 실험 3개 테스트 파일의 8개 검사는 배포하지 않는다. 그중 6개가 최초 설치 검사에서 자료 누락으로 실패했다. 모델 훈련·후보 품질 승격은 이번 출시 범위 밖이며 로컬 자격·개인키·모델 가중치를 넣어 해당 실험을 통과시킨 것이 아니다. 제외 목록과 근거는 release-manifest.json에 있다. 최초 설치 실패와 분리 진단도 보존했다. 기존 Windows 759개·Linux 257개 검사는 [이전 검증 보고서](../reports/kr-ai-basic-governance-verification-20261006.md)에 당시 버전의 결과로 남긴다.

최종 고시 전체 확인, 실제 기관·금융사 연동, 원격 DMS/KMS/WORM·저장소 HA·장기 5년 보관 실적, 회사 단위 대표인 사례 관리와 조직별 운영 SLA는 후속이다. 모델은 공개 인간 주석 데이터로 추가 optimizer 갱신 20회를 마쳤지만 새 후보의 생성 답변 평가·품질 승격은 미완료다. 출시 패키지가 모델 품질 승인이나 법적 준수 인증을 포함하지 않는다.
