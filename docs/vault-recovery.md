# 감사 증적 백업과 복구

`scripts/vault-backup.mjs`는 실행 중인 로컬 vault의 SQLite snapshot, 과거 revision을 포함한 공급사 문서, 서명된 원장과 보고서를 함께 보존한다. 원본 vault를 종료하거나 수정하지 않는다. SQLite backup API로 일관된 DB snapshot을 만든 뒤 검증한다. 실행 중인 `evidence.db` 파일만 복사하는 방식이 아니다. [Node SQLite backup API](https://nodejs.org/download/release/latest-v24.x/docs/api/sqlite.html#sqlitebackupsourcedb-path-options), 확인 2026-09-22.

백업 DB는 별도 도메인으로 파생한 키와 AES-256-GCM으로 암호화한다. 공급사 문서는 기존 암호화 형태로 복사하고, 복호화·원본 해시 일치를 실제 확인한다. 백업 manifest는 vault 키로 서명한다. 원래 개인키와 별도로 신뢰한 공개키를 모두 제공해야 하며, 백업 안에서 공개키를 골라 신뢰하지 않는다. 개인키와 서버 `config.json`은 복사하지 않는다.

## 실행

출력 디렉터리와 anchor 파일은 새 경로여야 한다. 부모 디렉터리는 운영자가 먼저 준비한다. 아래 `.test-runs`는 로컬 복구 실험 예시다. 운영 백업·개인키·anchor는 각각 승인된 저장 위치와 접근 통제를 사용해야 한다.

```powershell
node scripts/vault-backup.mjs create .local/data .test-runs/vault-backup-001 .local/signing-private.pem .local/trust-anchor.pem .test-runs/vault-anchor-001.json
node scripts/vault-backup.mjs restore .test-runs/vault-backup-001 .test-runs/vault-restored-001 .local/signing-private.pem .local/trust-anchor.pem .test-runs/vault-anchor-001.json
```

위의 기본 복구는 `verified:true`, `activationAccepted:false`인 **격리된 snapshot**을 만든다. 서비스는 쓰기 연결을 열기 전에 기동을 거부한다. 백업 이후의 파기와 접근 중지가 없는지 snapshot 자체만으로 확인할 수 없기 때문이다. 기동 가능한 복구에는 현재 원본의 서명된 안전 상태와 독립적으로 보존한 최신 pin, 사용할 자격 설정이 필요하다.

```powershell
node scripts/vault-backup.mjs frontier .local/data .local/signing-private.pem .local/trust-anchor.pem .test-runs/vault-anchor-001.json .local/config.json .test-runs/frontier-001.json .test-runs/frontier-anchor-001.json
node scripts/vault-backup.mjs restore .test-runs/vault-backup-001 .test-runs/vault-accepted-001 .local/signing-private.pem .local/trust-anchor.pem .test-runs/vault-anchor-001.json .test-runs/frontier-001.json .test-runs/frontier-anchor-001.json .local/config.json
```

Frontier 생성도 SQLite backup API로 현재 상태를 고정한 뒤 원장·검색 사본·문서를 검사한다. 이전 backup checkpoint가 현재 원장의 정확한 앞부분인지 확인하고, 최신 `identity_access` 상태와 실행된 파기 계획, 백업에 남아 있는 파기 대상 이벤트의 참조를 별도 도메인으로 서명한다. 프롬프트나 복호화된 이벤트 본문, 설정의 자격 정보는 frontier에 넣지 않는다. 설정은 해시로 연결한다.

복구 중에는 해당 이벤트의 키와 검색 사본을 다시 제거하고, 원래 역사·수집 영수증을 보존하며 적용 근거를 추가한다. 접근을 다시 허용한 최신 상태도 반영한다. 완료 marker는 실제 복구 checkpoint와 설정에 연결된다. marker 삭제·변조, 다른 설정, 완료 checkpoint 이전으로의 DB rollback은 기동을 차단한다. 이후 정상적으로 추가된 서명 기록은 허용한다. 모든 명령은 서비스를 자동 시작하지 않는다.

복구 디렉터리의 부모에는 `.<복구 디렉터리 이름>-recovery-pin.json`을 새 파일로 생성하고 완료 marker 해시·절대 경로를 서명해 고정한다. 같은 복구 경로에서 DB와 marker를 함께 이전 상태로 바꾸는 경우도 검사한다. 이 pin은 데이터 디렉터리 밖에서 별도 접근 통제로 보존해야 한다. pin까지 삭제하거나 원래 DB를 다른 새 경로로 옮겨 정상 설치로 가장하는 관리자의 행동은 로컬 파일만으로 식별할 수 없다. 디렉터리 이동·트래픽 전환은 pin 재등록과 조직의 최신 상태 대조를 포함한 별도 운영 절차다. 이 로컬 pin은 원격 불변 저장소나 OS 관리자에 대한 방어를 대신하지 않는다. 출판 실패 후 외부 pin이 남아 있다면 같은 경로를 자동 덮어쓰지 않고 운영자가 실패 staging과 함께 확인한다.

**최신성은 독립 pin 보관 절차에 달려 있다.** 오래된 frontier와 그때의 일치하는 pin을 함께 제공하면 서명만으로 더 최신 상태의 존재를 알아낼 수 없다. 원본 상실에 대비해 각 접근 변경·파기 이후 최신 frontier를 별도 저장소에 보존하고, 복구 시 조직의 최신 상태와 대조해야 한다. 원본이 없고 최신 pin도 없으면 격리 복구를 유지한다. 운영 설정을 바꾸려면 변경한 설정에 연결된 frontier를 새로 생성·고정한다.

첫 명령은 백업 외부에 manifest hash와 테넌트별 signed checkpoint를 담은 anchor를 생성한다. 이 파일을 독립된 저장소로 전달·보존해야 rollback 검사가 의미를 갖는다. 같은 관리자에게 백업·개인키·anchor를 함께 바꿀 수 있는 권한이 있으면 이 설계만으로 위조를 막지 못한다. 최신 anchor를 덮어쓰지 않고 회차별로 보존한다.

복구는 새 디렉터리에서만 수행한다. 기존 운영 경로를 덮어쓰지 않으며 서비스·모델·학습 Job을 시작하지 않는다. 대상 시스템의 자격 설정을 재사용하거나 새로 발급하는 작업과 트래픽 전환은 별도의 운영 절차다. 정상 종료의 `verified:true`는 아래 snapshot 복구 검사 범위의 결과다.

## 검사 범위

- SQLite 구조 무결성, 원장 순서·해시·서명, SQL 테넌트와 서명 테넌트의 연결
- 독립 anchor의 전체 테넌트·체크포인트·manifest hash
- 유지된 이벤트와 수집 영수증, 검색 인덱스·사본 일치. snapshot 이전 파기는 유지되며, 이후 파기는 기동 승인용 frontier로 다시 적용한다.
- 현행 객체·평가 및 개발 실행 기록의 원장 대조: 사본 변경·삭제·추가 거부
- 과거·현재 공급사 문서의 존재·복호화·해시, 원래 서명 보고서 보존
- 백업 파일 누락·추가·변조, 잘못된 키, 이전 회차 anchor, symlink/junction과 기존 복구 경로 거부

검증 실패 시 완료 manifest 또는 최종 복구 경로를 발급하지 않는다. 실패 staging 디렉터리의 알려진 평문 DB 파일은 삭제하고 암호문은 진단용으로 남길 수 있다. 이는 디스크 잔존물의 물리적 소거 보장은 아니다. 백업 생성 중 DB snapshot과 성공 복구 후 DB는 기존 vault와 같은 평문 검색 사본·이벤트 키를 포함하므로 해당 작업 디렉터리의 OS 접근 통제와 디스크 암호화가 필요하다. POSIX mode 설정은 Windows ACL 검증을 대체하지 않는다.

## 실측과 남은 운영 과제

`EVIDSCOPE_TEST_HOST=::1`에서 `node --test test/vault-recovery.test.mjs`로 실제 SQLite WAL 상태 백업, CLI 실행, 두 테넌트 복구, HTTP vault 기동 후 문서 조회와 타 테넌트 접근 거부를 시험했다. GPU·실제 금융 고객 데이터는 사용하지 않았다.

로컬 검증은 원격 불변 백업, KMS/키 회전, 백업 보존·파기 승인, 장기간 5년 보존, 대용량 RPO/RTO, 저장소 HA를 입증하지 않는다. 원래 보관된 백업 파일은 이후의 이벤트 키 파기나 복구본의 frontier 적용으로 소거되지 않는다. 별도 보존·파기 절차가 필요하다. 원격 재해복구·조직별 운영 SLA는 별도 검증이 남아 있다.
