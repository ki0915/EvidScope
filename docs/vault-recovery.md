# 감사 증적 백업과 복구

`scripts/vault-backup.mjs`는 실행 중인 로컬 vault의 SQLite snapshot, 과거 revision을 포함한 공급사 문서, 서명된 원장과 보고서를 함께 보존한다. 원본 vault를 종료하거나 수정하지 않는다. SQLite backup API로 일관된 DB snapshot을 만든 뒤 검증한다. 실행 중인 `evidence.db` 파일만 복사하는 방식이 아니다. [Node SQLite backup API](https://nodejs.org/download/release/latest-v24.x/docs/api/sqlite.html#sqlitebackupsourcedb-path-options), 확인 2026-09-22.

백업 DB는 별도 도메인으로 파생한 키와 AES-256-GCM으로 암호화한다. 공급사 문서는 기존 암호화 형태로 복사하고, 복호화·원본 해시 일치를 실제 확인한다. 백업 manifest는 vault 키로 서명한다. 원래 개인키와 별도로 신뢰한 공개키를 모두 제공해야 하며, 백업 안에서 공개키를 골라 신뢰하지 않는다. 개인키와 서버 `config.json`은 복사하지 않는다.

## 실행

출력 디렉터리와 anchor 파일은 새 경로여야 한다. 부모 디렉터리는 운영자가 먼저 준비한다. 아래 `.test-runs`는 로컬 복구 실험 예시다. 운영 백업·개인키·anchor는 각각 승인된 저장 위치와 접근 통제를 사용해야 한다.

```powershell
node scripts/vault-backup.mjs create .local/data .test-runs/vault-backup-001 .local/signing-private.pem .local/trust-anchor.pem .test-runs/vault-anchor-001.json
node scripts/vault-backup.mjs restore .test-runs/vault-backup-001 .test-runs/vault-restored-001 .local/signing-private.pem .local/trust-anchor.pem .test-runs/vault-anchor-001.json
```

첫 명령은 백업 외부에 manifest hash와 테넌트별 signed checkpoint를 담은 anchor를 생성한다. 이 파일을 독립된 저장소로 전달·보존해야 rollback 검사가 의미를 갖는다. 같은 관리자에게 백업·개인키·anchor를 함께 바꿀 수 있는 권한이 있으면 이 설계만으로 위조를 막지 못한다. 최신 anchor를 덮어쓰지 않고 회차별로 보존한다.

복구는 새 디렉터리에서만 수행한다. 기존 운영 경로를 덮어쓰지 않으며 서비스·모델·학습 Job을 시작하지 않는다. 대상 시스템의 자격 설정을 재사용하거나 새로 발급하는 작업과 트래픽 전환은 별도의 운영 절차다. 정상 종료의 `verified:true`는 아래 snapshot 복구 검사 범위의 결과다.

## 검사 범위

- SQLite 구조 무결성, 원장 순서·해시·서명, SQL 테넌트와 서명 테넌트의 연결
- 독립 anchor의 전체 테넌트·체크포인트·manifest hash
- 유지된 이벤트와 수집 영수증, 검색 인덱스·사본 일치, 승인된 파기로 삭제된 키가 복원되지 않음
- 현행 객체·평가 및 개발 실행 기록의 원장 대조: 사본 변경·삭제·추가 거부
- 과거·현재 공급사 문서의 존재·복호화·해시, 원래 서명 보고서 보존
- 백업 파일 누락·추가·변조, 잘못된 키, 이전 회차 anchor, symlink/junction과 기존 복구 경로 거부

검증 실패 시 완료 manifest 또는 최종 복구 경로를 발급하지 않는다. 실패 staging 디렉터리의 알려진 평문 DB 파일은 삭제하고 암호문은 진단용으로 남길 수 있다. 이는 디스크 잔존물의 물리적 소거 보장은 아니다. 백업 생성 중 DB snapshot과 성공 복구 후 DB는 기존 vault와 같은 평문 검색 사본·이벤트 키를 포함하므로 해당 작업 디렉터리의 OS 접근 통제와 디스크 암호화가 필요하다. POSIX mode 설정은 Windows ACL 검증을 대체하지 않는다.

## 투명성 로그를 켠 vault의 복구 (tlog epoch)

`TRANSPARENCY_CONFIG_FILE`로 투명성 로그를 켠 vault는 복구 시 항상 새 origin base로 넘어간다. 오래된 백업을 기존 origin으로 이어 쓰면 witness가 이미 서명한 이력과 다른 갈래(fork)를 vault 키로 서명하게 되므로, 같은 base를 쓰는 복구와 epoch 없이 복구된 원장의 기동은 모드와 관계없이 거부된다. 복구는 테넌트마다 서명된 `tlog_epoch` 원장 레코드(`evidscope-tlog-epoch-v1`)를 쓴다. 레코드에는 이전 origin, 복구 크기와 root, 이전 checkpoint, witness가 cosign한 이전 heads checkpoint, 잃은 범위(`lostRange`, `lostHeadsRange`)와 freshness 판정 또는 `acceptLoss` 사유가 들어간다. 이 레코드는 `recovery_restore` 바인딩과 분리되어 있다.

```sh
# 1. 복구 전, 가능한 한 원본 vault에서 frontier와 heads checkpoint companion을 만든다.
node scripts/vault-backup.mjs frontier DATA_DIR KEY.pem TRUST.pem ARCHIVE_ANCHOR.json config.json FRONTIER.json FRONTIER_ANCHOR.json \
  --transparency-config CURRENT.json --transparency-out FRONTIER_TRANSPARENCY.json
# 2. 새 epoch 설정을 만들고 출력된 witnessctl 명령으로 새 heads origin을 각 witness에 등록한다.
node scripts/transparency.mjs new-epoch --config CURRENT.json --origin vault.example/evidscope-e2 --out NEW.json --key KEY.pem --db litewitness.db
# 3. 새 epoch로 복구한다. 이전 origin의 witness quorum에 freshness를 확인한다.
#    이전 설정·pin은 선택이다. 이전 설정이 없으면 새 설정의 witness 목록으로 이전 heads origin을 조회한다.
node scripts/vault-backup.mjs restore BACKUP_DIR NEW_DATA_DIR KEY.pem TRUST.pem ARCHIVE_ANCHOR.json FRONTIER.json FRONTIER_ANCHOR.json config.json \
  --transparency-config NEW.json --previous-transparency-config CURRENT.json --previous-pin OLD_PIN.json \
  --frontier-transparency FRONTIER_TRANSPARENCY.json
# freshness를 확인할 수 없으면(witness 불통, witness가 백업보다 앞섬) 복구는 거부된다. 손실을 승인할 때만 사유를 기록한다.
#   ... --accept-loss "승인 번호와 사유"
# 4. NEW.json을 TRANSPARENCY_CONFIG_FILE로 지정해 기동하고 상태를 확인한다.
node scripts/transparency.mjs status --config NEW.json --key KEY.pem --data-dir NEW_DATA_DIR --probe
```

`freshnessEstablished:true`는 이전 heads origin의 witness quorum이 응답했고, 그들이 cosign한 크기가 백업 또는 frontier companion heads 크기 이하임을 뜻한다. 그 외에는 `--accept-loss`가 필요하며 잃은 범위의 상한은 알 수 없음(`null`)으로 기록된다. 기동 검사는 epoch 레코드의 서명·연결, 복구 root와 이전 checkpoint의 prefix 일치, 이전 pin이 승인된 손실 범위 안에 있는지 확인한다. export는 `transparency.epochs`로 epoch 연결을 보여 주고, 이전 origin base를 고정한 감사자는 `scripts/verify.mjs EXPORT KEY --origin-base OLD_BASE --witness VKEY`로 새 origin의 export를 검증한다. 복구 지점 이후의 이전 checkpoint를 최소 checkpoint로 주면 잃은 범위와 승인 여부를 포함한 rollback 오류가 난다.

남은 제약: case report에는 epoch 정보가 없어 이전 origin base를 고정한 보고서 검증은 실패한다. 마지막 epoch보다 오래된 백업(백업의 origin이 현재 설정의 직전 base가 아님)의 복구는 거부된다. mode `off`로 복구한 vault에 나중에 투명성을 켜려면 다시 복구해야 한다.

## 실측과 남은 운영 과제

`EVIDSCOPE_TEST_HOST=::1`에서 `node --test test/vault-recovery.test.mjs`로 실제 SQLite WAL 상태 백업, CLI 실행, 두 테넌트 복구, HTTP vault 기동 후 문서 조회와 타 테넌트 접근 거부를 시험했다. GPU·실제 금융 고객 데이터는 사용하지 않았다.

로컬 검증은 원격 불변 백업, KMS/키 회전, 백업 보존·파기 승인, 장기간 5년 보존, 대용량 RPO/RTO, 저장소 HA를 입증하지 않는다. 기존 백업은 이후의 이벤트 키 파기로 소거되지 않는다. 별도 보존·파기 절차 없이 과거 백업을 운영으로 되돌리지 않는다. 원격 재해복구·조직별 운영 SLA는 별도 검증이 남아 있다.
