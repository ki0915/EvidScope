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

복구 중에는 해당 이벤트의 키와 검색 사본을 다시 제거하고, 원래 역사·수집 영수증을 보존하며 적용 근거를 추가한다. 접근을 다시 허용한 최신 상태도 반영한다. 완료 marker는 실제 복구 checkpoint와 설정에 연결된다. marker 삭제·변조, 서명된 config rebinding 없이 바꾼 설정, 완료 checkpoint 이전으로의 DB rollback은 기동을 차단한다. 이후 정상적으로 추가된 서명 기록은 허용한다. 모든 명령은 서비스를 자동 시작하지 않는다.

복구 디렉터리의 부모에는 `.<복구 디렉터리 이름>-recovery-pin.json`을 새 파일로 생성하고 완료 marker 해시·절대 경로를 서명해 고정한다. 같은 복구 경로에서 DB와 marker를 함께 이전 상태로 바꾸는 경우도 검사한다. 이 pin은 데이터 디렉터리 밖에서 별도 접근 통제로 보존해야 한다. pin까지 삭제하거나 원래 DB를 다른 새 경로로 옮겨 정상 설치로 가장하는 관리자의 행동은 로컬 파일만으로 식별할 수 없다. 디렉터리 이동·트래픽 전환은 pin 재등록과 조직의 최신 상태 대조를 포함한 별도 운영 절차다. 이 로컬 pin은 원격 불변 저장소나 OS 관리자에 대한 방어를 대신하지 않는다. 출판 실패 후 외부 pin이 남아 있다면 같은 경로를 자동 덮어쓰지 않고 운영자가 실패 staging과 함께 확인한다.

**최신성은 독립 pin 보관 절차에 달려 있다.** 오래된 frontier와 그때의 일치하는 pin을 함께 제공하면 서명만으로 더 최신 상태의 존재를 알아낼 수 없다. 원본 상실에 대비해 각 접근 변경·파기 이후 최신 frontier를 별도 저장소에 보존하고, 복구 시 조직의 최신 상태와 대조해야 한다. 원본이 없고 최신 pin도 없으면 격리 복구를 유지한다. 복구 전에 운영 설정을 바꾸려면 변경한 설정에 연결된 frontier를 새로 생성·고정한다. 기동 승인된 복구 이후의 설정 변경은 아래 config rebinding 절차를 따른다.

첫 명령은 백업 외부에 manifest hash와 테넌트별 signed checkpoint를 담은 anchor를 생성한다. 이 파일을 독립된 저장소로 전달·보존해야 rollback 검사가 의미를 갖는다. 같은 관리자에게 백업·개인키·anchor를 함께 바꿀 수 있는 권한이 있으면 이 설계만으로 위조를 막지 못한다. 최신 anchor를 덮어쓰지 않고 회차별로 보존한다.

복구는 새 디렉터리에서만 수행한다. 기존 운영 경로를 덮어쓰지 않으며 서비스·모델·학습 Job을 시작하지 않는다. 대상 시스템의 자격 설정을 재사용하거나 새로 발급하는 작업과 트래픽 전환은 별도의 운영 절차다. 정상 종료의 `verified:true`는 아래 snapshot 복구 검사 범위의 결과다.

## 기동 승인된 복구 이후의 설정 변경 (config rebinding)

기동 승인된 복구본은 복구 때 사용한 설정 파일 전체의 해시(`configHash`)에 묶인다. 이미 회수한 토큰이 들어 있는 이전 설정으로 되돌려 기동하는 일을 막기 위해서다. 따라서 토큰 1개 회전이나 principal 추가처럼 정상적인 변경도 `config.json`만 바꾸면 vault가 `credential/config binding changed`로 기동을 거부한다. 이 경우 vault 서명키로 서명한 rebinding 기록을 남겨야 새 설정으로 기동할 수 있다.

```sh
# 1. vault를 멈춘다. 지금 묶여 있는 설정 파일은 그대로 두고 새 설정 파일을 만든다(토큰 회전, principal 추가 등).
# 2. 지금 묶인 설정, 새 설정, 변경 사유를 지정해 서명된 rebinding을 기록한다.
node scripts/vault-backup.mjs rebind DATA_DIR KEY.pem TRUST.pem CURRENT_CONFIG.json NEW_CONFIG.json --reason "변경 승인 번호와 사유"
# 3. CONFIG_FILE을 NEW_CONFIG.json으로 바꾸고 vault를 기동한다. 기동하면서 원장에 rebinding 레코드가 추가된다.
```

`rebind`는 먼저 지금 묶인 설정으로 기동 검사 전체(marker, 외부 복구 pin, 원장, 기존 rebinding)를 통과하는지 확인한다. 개인키가 별도로 신뢰한 공개키와 짝인지도 확인한다. 지금 묶인 설정이 아닌 파일, 이미 묶인 설정과 같은 새 설정, 빈 사유, 짧거나 중복된 토큰처럼 형식이 잘못된 자격은 거부하며 아무 파일도 쓰지 않는다. 격리된 복구본은 기동할 수 없고 복구하지 않은 vault는 설정 해시에 묶이지 않으므로 둘 다 rebinding을 거부한다. 출력에는 설정 해시만 있고 토큰은 없다.

기록은 세 곳에 남는다.

- 데이터 디렉터리의 `vault-config-rebinding.json`: vault 키로 서명한 항목의 연쇄다. 항목마다 순번, 복구 `restoreId`와 완료 marker 해시, 이전·새 설정 해시, 이전 항목의 해시, 사유, 시각이 들어간다. 첫 항목은 marker의 `configHash`에서 시작한다.
- 복구 디렉터리 부모의 `.<복구 디렉터리 이름>-config-rebinding-pin.json`: 연쇄의 마지막 항목 해시·순번과 데이터 디렉터리 절대 경로를 서명한 외부 pin이다. 복구 pin처럼 데이터 디렉터리 밖에서 별도 접근 통제로 보존한다.
- 다음 기동 때 복구된 모든 tenant의 서명 원장에 추가되는 `recovery_config_rebinding` 레코드(`evidscope-config-rebinding-v1`)다. export, `/api/integrity`, 투명성 로그가 이 레코드를 다른 원장 레코드와 똑같이 다룬다. 사유는 복구된 모든 tenant의 원장과 export에 들어가므로 비밀이나 다른 tenant의 정보를 쓰지 않는다.

기동 검사는 연쇄의 서명·순번·해시 연결과 같은 복구(`restoreId`, marker 해시)에 속하는지를 확인한다. 외부 pin이 연쇄의 마지막 항목과 일치하는지 확인한 뒤 마지막 항목의 설정 해시를 현재 설정과 비교한다. 변조된 항목, 다른 복구본의 기록이나 pin, pin 없는 기록, 기록 없는 pin은 기동을 거부한다. 원장에 이미 기록된 rebinding보다 오래된 상태로 돌아가면 `config rebinding rollback`으로 거부한다. 오래된 기록과 그 pin을 함께 되돌린 경우와 두 파일을 모두 지우고 복구 당시 설정으로 기동하는 경우가 여기에 해당한다. 기록을 쓴 뒤 pin을 쓰기 전에 명령이 중단되면 vault는 `config rebinding not pinned`로 기동을 거부한다. 같은 `rebind` 명령을 다시 실행하면 빠진 pin만 쓰고, 다른 새 설정으로 실행하면 거부한다.

한계: rebinding은 vault 서명키를 가진 사람의 승인이다. 키를 가진 관리자는 어떤 설정이든 묶을 수 있다. 사유와 승인 번호는 기록되지만 vault가 그 진위를 확인하지는 않는다. 키 보관과 변경 승인은 조직의 통제 절차에 달려 있다. rebinding 뒤 첫 기동 전에 기록·pin·설정 파일을 함께 지우거나 이전 상태로 되돌리는 OS 관리자의 행동은 로컬 파일만으로 식별할 수 없다. 원장 기록 이후 DB 전체를 그 이전 상태로 되돌리는 경우도 마찬가지다. 투명성 로그를 켠 vault에서는 witness가 cosign한 이력으로 DB rollback을 확인한다. 복구 전에 설정을 바꿀 수 있다면 rebinding 대신 바뀐 설정에 연결된 frontier를 새로 만들어 복구한다.

## 검사 범위

- SQLite 구조 무결성, 원장 순서·해시·서명, SQL 테넌트와 서명 테넌트의 연결
- 독립 anchor의 전체 테넌트·체크포인트·manifest hash
- 유지된 이벤트와 수집 영수증, 검색 인덱스·사본 일치. snapshot 이전 파기는 유지되며, 이후 파기는 기동 승인용 frontier로 다시 적용한다.
- 현행 객체·평가 및 개발 실행 기록의 원장 대조: 사본 변경·삭제·추가 거부
- 과거·현재 공급사 문서의 존재·복호화·해시, 원래 서명 보고서 보존
- 백업 파일 누락·추가·변조, 잘못된 키, 이전 회차 anchor, symlink/junction과 기존 복구 경로 거부
- 기동 승인된 복구본의 설정 해시: 서명·외부 pin으로 고정한 config rebinding 연쇄와 원장의 `recovery_config_rebinding` 기록 대조

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

`EVIDSCOPE_TEST_HOST=::1`에서 `node --test test/vault-recovery.test.mjs`로 실제 SQLite WAL 상태 백업, CLI 실행, 두 테넌트 복구, HTTP vault 기동 후 문서 조회와 타 테넌트 접근 거부를 시험했다. GPU·실제 금융 고객 데이터는 사용하지 않았다. `test/recovery-config-rebinding.test.mjs`는 복구 후 토큰 회전·principal 추가 rebinding, 변조·다른 복구본·rollback·중단 후 재실행, CLI, enforce 모드 투명성 vault의 원장 기록을 시험한다.

로컬 검증은 원격 불변 백업, KMS/키 회전, 백업 보존·파기 승인, 장기간 5년 보존, 대용량 RPO/RTO, 저장소 HA를 입증하지 않는다. 원래 보관된 백업 파일은 이후의 이벤트 키 파기나 복구본의 frontier 적용으로 소거되지 않는다. 별도 보존·파기 절차가 필요하다. 원격 재해복구·조직별 운영 SLA는 별도 검증이 남아 있다.
