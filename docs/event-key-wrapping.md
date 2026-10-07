# 이벤트 키 감싸기와 키 epoch 운영 가이드

> 2026-10-07 개선 2라운드에서 감사 보고서 S3을 고친 내용입니다. 데이터 키는 [데이터 암호화 키 분리 가이드](data-key-separation.md),
> 백업과 복구는 [감사 증적 백업과 복구](vault-recovery.md)를 함께 보세요.

## 무엇을 막는가

이벤트 본문은 이벤트마다 다른 키로 암호화하고, 보존 기간이 끝나면 그 키를 지워 원장 암호문을 읽을 수 없게 만듭니다(crypto-shredding).
2라운드 감사(S3)는 이 파기가 두 군데에서 새는 것을 지적했습니다.

- **확인 가능한 커밋먼트:** 원장 이벤트 레코드에는 `payloadHash = sha256(canonical(event))`, 수집 영수증에는 원문 본문의 SHA-256
  (`fingerprint`)이 서명되어 남았습니다. 키를 지워도 값의 범위가 좁은 이벤트(상태 코드, 예/아니오, 짧은 메모)는 원장이나 export를 가진
  사람이 후보를 하나씩 해시해 보면 무엇이었는지 확인할 수 있었습니다.
- **감싸지 않은 이벤트 키:** `event_keys`가 `evidence.db` 안에 그대로 있어, DB 사본이나 vault 백업을 가진 사람은 그때 보관 중이던 모든
  이벤트를 열 수 있었습니다. 나중에 키를 지워도 이전 사본과 백업에는 키가 그대로 남았습니다.

## 바뀐 점

1. **숨기는 커밋먼트(이벤트 봉투 v2).** 새 이벤트는 `evidscope-encrypted-event-v2`로 저장합니다. 이벤트마다 32바이트 무작위 salt `r`을
   만들고, 원장에는 `commitmentAlg: "evidscope/payload-commitment/v2"`와
   `payloadCommitment = HMAC-SHA256(r, "evidscope/payload-commitment/v2\0" ‖ canonical(event))`만 서명합니다. `r`은 이벤트 키 옆에만
   보관하고(`키 ‖ r`, 64바이트) 키와 함께 지웁니다. 같은 내용의 두 이벤트도 커밋먼트가 다릅니다. 암호화 전 평문은 64바이트 단위로 공백을
   채우므로 암호문 길이는 본문 길이를 64바이트 단위로만 드러냅니다.
2. **키 있는 영수증 지문.** 새 수집 영수증의 `fingerprint`는 `fp2:<YYYY-MM>:<HMAC>`입니다. 원문 본문의 SHA-256을 이벤트가 속한 키 epoch의
   지문 키로 HMAC한 값이라, epoch 비밀 없이는 추측한 본문과 비교할 수 없습니다. 같은 ID의 재전송은 영수증에 적힌 epoch의 키로 비교하므로
   이벤트를 파기한 뒤에도, 다른 epoch로 넘어간 뒤에도 중복으로 인식합니다.
3. **키 epoch.** 이벤트는 tenant마다 `retainUntil`의 UTC 월(`YYYY-MM`)을 키 epoch로 갖습니다(v2 봉투의 `keyEpoch`). epoch마다 32바이트
   비밀이 하나 있습니다. 그 달이 끝나고 epoch의 모든 이벤트가 파기되면 비밀 자체를 파기할 수 있습니다.
4. **이벤트 키 감싸기(키스토어).** `EVENT_KEYSTORE_DIR`를 설정하면 epoch 비밀을 `DATA_DIR` 밖의 파일로 옮기고 데이터 키로 봉인합니다.
   `event_keys`에는 `키 ‖ r`을 그 이벤트의 epoch 비밀로 감싼 값만 남습니다. epoch 비밀을 파기하면 그 epoch의 이벤트 키는 어느 DB 사본과
   vault 백업에서도 다시 열 수 없습니다.

v1 레코드(업그레이드 전에 쓴 이벤트와 영수증)는 그대로 둡니다. 서명된 원장을 고쳐 쓸 수 없기 때문입니다. 검증기는 v1을 이전과 똑같이,
v2는 salt를 공개한 커밋먼트로 확인합니다. export는 보관 중인 v2 이벤트마다 `disclosures[].salt`를 함께 싣고, 파기된 이벤트의 평문이나
salt를 다시 공개하면 `verifyBundle`이 거부합니다. v1 체크포인트 형식은 바뀌지 않았습니다.

## 키 계층

```text
DATA_KEY_FILE (32바이트 루트 데이터 키)
 └─ HKDF-SHA256 "evidscope/data-key/v1/event-key-epoch" → epoch 파일 봉인 키 (AES-256-GCM, AAD: keystore id·tenant·epoch·생성 시각·키 ID)
     └─ EVENT_KEYSTORE_DIR/epochs/t-<tenant 해시>/<YYYY-MM>.json : 키 epoch 비밀 (tenant × retainUntil 월, 32바이트)
         ├─ HKDF "evidscope/event-key-epoch/v1/event-key-wrap" → 감싸기 키
         │    └─ event_keys.key = "EKW1" ‖ 길이 ‖ iv ‖ AES-256-GCM(DEK ‖ r) ‖ tag   (AAD: tenant·keyId·seq·keyEpoch)
         │         ├─ DEK (32바이트): 원장 암호문의 AES-256-GCM 키
         │         └─ r (32바이트): payloadCommitment의 HMAC 키
         └─ HKDF "evidscope/event-key-epoch/v1/receipt-fingerprint" → 영수증 지문 키
              └─ fingerprint = "fp2:<YYYY-MM>:" ‖ HMAC-SHA256(지문 키, "evidscope/receipt-fingerprint/v2\0" ‖ sha256(원문 본문))
```

감싼 키의 AAD는 tenant, key ID, 원장 순번, epoch에 묶여 있어 두 이벤트의 감싼 키를 바꿔 넣으면 무결성 검사가 실패합니다. 감싼 키 길이
(v1 65바이트, v2 97바이트)는 감싸지 않은 키(32·64바이트)와 겹치지 않습니다.

## 두 가지 저장 방식

| | 데이터베이스 모드 (`EVENT_KEYSTORE_DIR` 없음) | 키스토어 모드 |
|---|---|---|
| epoch 비밀 | `evidence.db`의 `event_key_epochs` 테이블 | `DATA_DIR` 밖의 파일, 데이터 키로 봉인 |
| 이벤트 키 | 감싸지 않은 `DEK ‖ r` | epoch 비밀로 감싼 `DEK ‖ r` |
| `keySeparation.eventKeys.storage` | `same_database_unwrapped` | `keystore_wrapped` (옮기는 중이면 `keystore_migration_pending`) |
| epoch 파기가 닿는 범위 | 현재 DB뿐 | 모든 DB 사본과 vault 백업의 원장 암호문·영수증 지문 |
| vault 백업의 평문 검색 사본 | 포함 | 제외하고 복구 때 원장에서 다시 만듦 |

데이터베이스 모드도 1·2·3은 그대로 적용됩니다. 숨기는 커밋먼트와 키 있는 지문은 export·원장만 가진 사람에 대한 보호이고, 키스토어는
DB 사본·백업을 가진 사람에 대한 보호입니다.

## 공격자별로 남는 것

| 가진 것 | 데이터베이스 모드 | 키스토어 모드 |
|---|---|---|
| export 또는 원장 행만 | v2 이벤트는 파기 뒤 추측을 확인할 수 없습니다. v1 레코드는 여전히 확인됩니다. | 같음 |
| `evidence.db` 사본 | 사본 시점에 보관 중이던 이벤트를 모두 읽고, epoch 비밀로 영수증 추측도 확인합니다. | 데이터 키와 키스토어 없이는 감싼 키와 영수증 지문을 쓸 수 없습니다. 다만 사본 시점에 보관 중이던 이벤트의 **평문 검색 사본(`events` 테이블)**은 읽힙니다. |
| vault 백업 + 데이터 키 | 백업 시점의 DB와 같습니다. 백업을 지우기 전까지 계속 읽힙니다. | 평문 검색 사본이 없고 키는 감싸져 있습니다. 현재 키스토어가 있어야 읽히며, 그 뒤 파기한 epoch는 읽을 수 없습니다. |
| 데이터 키 + 현재 키스토어 + 오래된 DB 사본·백업 | (해당 없음) | 아직 파기하지 않은 epoch는 읽힙니다. 파기한 epoch는 읽히지 않습니다. |
| 키스토어 백업 + 데이터 키 + DB 사본·백업 | (해당 없음) | 키스토어 백업 시점에 있던 epoch는 모두 읽힙니다. 키스토어 백업을 짧게 보관해야 하는 이유입니다. |
| vault 호스트(root) | 모두 읽습니다. | 모두 읽습니다. 데이터 키·키스토어·서명 키를 같은 프로세스가 쓰고, 읽은 epoch 비밀은 메모리에 남습니다. |

## 설정

**새 로컬 설치:** `npm run init`이 `.local/event-keystore/`를 만들고 `npm start`가 `EVENT_KEYSTORE_DIR`로 넘깁니다.

**기존 로컬 설치:** `npm start`를 멈추고 업그레이드합니다. 4단계 `event_keystore`가 키스토어를 만들고 감싸지 않은 키를 옮깁니다.

```powershell
npm run upgrade:local -- --dry-run   # event_keystore: would_create_and_migrate, rawEventKeys 확인
npm run upgrade:local                # event_keystore: created, migration.wrappedKeys
npm start
```

**운영 환경:**

```powershell
node scripts/event-keys.mjs init /secure/event-keystore          # DATA_DIR 밖, 다른 사용자 접근 없는 디렉터리
$env:DATA_KEY_FILE='/secure/data-encryption.key'
$env:EVENT_KEYSTORE_DIR='/secure/event-keystore'
node scripts/event-keys.mjs migrate /data /keys/signing-private.pem   # vault를 멈춘 상태. vault 기동 때도 같은 일을 합니다.
```

- 키스토어는 `DATA_KEY_FILE`이 있어야 쓸 수 있고 `DATA_DIR` 안에 둘 수 없습니다. Windows가 아닌 OS에서는 다른 사용자 접근 권한이 있으면
  거부합니다.
- 키스토어 하나는 vault 하나만 섬깁니다. 처음 붙을 때 서명 키의 해시를 `vault.json`에 적고, 다른 vault가 같은 디렉터리를 쓰면 거부합니다.
  tenant 이름이 같은 두 vault가 epoch를 공유하면 한쪽의 파기가 다른 쪽의 보관 중인 이벤트를 지우기 때문입니다. 복구한 vault는 같은 vault입니다.
- `evidence.db`는 사용하는 키스토어 ID를 `event_keystore_usage`에 기록합니다. 그 뒤로 vault, 백업·frontier·복구, `data-key.mjs migrate`,
  `event-keys.mjs`는 키스토어 없이 또는 다른 키스토어로 실행하면 거부합니다. 감싼 키 옆에 감싸지 않은 키가 다시 쌓이는 일을 막기 위해서입니다.
- 이전(migrate)은 데이터베이스 모드에서 만든 epoch 비밀과 파기 기록을 그대로 키스토어로 옮깁니다. 기존 영수증 지문은 계속 비교됩니다.
  감싸지 않은 키는 자기 서명 이벤트를 실제로 열어 본 뒤 감싸고, 덮어쓴 페이지는 `secure_delete`와 WAL checkpoint로 정리합니다.
  첫 이전이 끝나면 `event_keystore_usage.moved_at`에 기록하고, 그 뒤 `evidence.db`에 생긴 epoch 행은 가져오지 않습니다. DB에 쓸 수 있는
  공격자가 알려진 비밀이나 살아 있는 epoch의 파기 기록을 심어 키스토어로 들여보내는 것을 막기 위해서입니다.
- **이전 뒤에는 새 vault 백업을 만들고 이전 백업과 DB 사본을 폐기 절차에 넣으세요.** 이전 것에는 감싸지 않은 키가 그대로 있습니다.
- Kubernetes 매니페스트는 아직 키스토어 볼륨을 마운트하지 않습니다. 그 배포는 데이터베이스 모드로 동작합니다.

## 파기 운영

**이벤트 단위 파기(기존):** 두 사람이 승인한 보존 계획이 이벤트의 `event_keys` 행과 평문 검색 사본을 지웁니다. 원장에는 암호문과
커밋먼트만 남고, 키스토어 모드에서는 지운 행이 감싼 키였으므로 이전 사본의 같은 행도 epoch 비밀 없이는 열리지 않습니다.

**epoch 파기:** epoch의 달이 끝났고(새 이벤트가 더는 들어올 수 없음), 그 epoch의 모든 이벤트가 파기되었고, 그 epoch의 키로 만든 영수증
중 보관 중인 이벤트의 것이 없을 때만 허용합니다. vault를 멈추고 실행합니다.

```powershell
node scripts/event-keys.mjs list /data /keys/signing-private.pem alpha        # epoch별 보관·파기 이벤트 수, destroyable
node scripts/event-keys.mjs destroy /data /keys/signing-private.pem alpha 2026-09 "보존 계획 RP-123 완료"
```

`destroy`는 먼저 서명된 `event_key_epoch_destroyed` 레코드(`evidscope-event-key-epoch-destruction-v1`, `basis: all_events_disposed`)를
원장에 쓰고, 파기 기록(tombstone)을 남긴 뒤 epoch 파일을 0으로 덮어쓰고 지웁니다. 되돌릴 수 없습니다. 파기 뒤 그 epoch에 속한 이벤트
ID로 재전송이 오면 내용 비교를 할 수 없으므로 중복으로 받지 않고 409로 거부합니다. 키 출력은 어느 명령에도 없습니다.

## 백업

**vault 백업:** 키스토어 vault의 `vault-backup.mjs create`·`frontier`·`restore`에는 `DATA_KEY_FILE`과 `EVENT_KEYSTORE_DIR`를 함께 줍니다.
백업에는 키스토어가 들어가지 않고(`eventKeystoreIncluded:false`), 평문 검색 사본도 비워서 넣습니다. `EVENT_KEYSTORE_DIR`를 줬는데 vault가
아직 키를 옮기지 않았다면 감싸지 않은 키가 든 백업을 만들지 않도록 거부합니다. manifest의
`eventProjection: "excluded_rebuilt_on_restore"`와 `eventKeystore.id`가 이를 서명으로 밝힙니다. 복구는 원장과 키스토어로 검색 사본을
다시 만듭니다. 백업 이후 파기된 epoch에 아직 파기되지 않은 이벤트가 백업에 있으면 복구를 거부합니다. 그 이벤트의 파기 이후에 만든
백업으로 복구하세요.

**키스토어 백업:** 키스토어 없이는 어떤 이벤트도 읽을 수 없으므로 따로 백업해야 합니다. 다음을 권장합니다.

1. `EVENT_KEYSTORE_DIR` 전체(작은 JSON 파일, 데이터 키로 봉인됨)를 vault 백업·데이터 키와 다른 저장소에 복사합니다.
2. 새 epoch는 새 `retainUntil` 달의 첫 이벤트가 들어올 때 생깁니다. 키스토어 백업을 매일처럼 자주 만들어 새 epoch를 놓치지 않습니다.
3. 키스토어 백업은 짧게 보관합니다. epoch를 파기하면 새 키스토어 백업을 만들고 그 이전의 키스토어 백업을 모두 폐기합니다. 오래된
   키스토어 백업은 파기한 epoch 비밀을 그대로 갖고 있습니다.
4. 파기 이전의 키스토어 백업을 복원하면 파기한 epoch가 되살아납니다. 원장에 파기 기록이 있는 epoch의 파일이 다시 보이면
   `/api/integrity`가 `present again`으로 실패하고 `event-keys.mjs list`가 `presentAgain: true`를 표시합니다. 같은 `destroy` 명령을 다시
   실행하면 기존 파기 기록 아래에서 파일을 다시 지웁니다.

## 데이터 키 교체

`data-key.mjs migrate`는 `EVENT_KEYSTORE_DIR`가 있으면 epoch 파일을 새 데이터 키로 다시 봉인하고 `resealedEpochs`로 수를 알려 줍니다.
키스토어 vault에서 `EVENT_KEYSTORE_DIR` 없이 실행하면 거부합니다. 이전 데이터 키로 봉인한 키스토어 백업을 보관하는 동안에는 그 키도
오프라인에 보관하세요.

## KMS·서명 프로세스 연동 지점

SDK 의존성 없이 두 경계를 열어 두었습니다. 어느 쪽도 아직 KMS 구현은 없습니다.

- **봉인기(sealer):** `seal(aad, secret)`, `unseal(aad, sealed)`, `kid`. 기본은 데이터 키(`dataKeySealer`)이며, KMS의 KEK wrap/unwrap으로
  바꾸면 epoch 파일을 KMS 키로 봉인합니다(`src/event-keystore.mjs`).
- **epoch 저장소 인터페이스:** `kind`, `wrapsEventKeys`, `available`, `present`, `ensure`, `destroyed`, `destroy`, `list`, `tombstones`, `mac`,
  `wrap`, `unwrap`(`src/event-keys.mjs` 머리말). 데이터베이스와 키스토어가 두 구현이고, KMS·HSM 구현은 epoch 비밀을 프로세스 밖에 둔 채 감싸기와
  HMAC을 원격으로 할 수 있습니다. `Store.transaction`이 동기식이므로 호출도 동기식이어야 합니다. 원격 KMS는 로컬 캐시나 동기 helper가 필요합니다.

## `/api/integrity`

`keySeparation.eventKeys`가 tenant별 상태를 숨김 없이 보고합니다.

- `storage`, `keys.wrapped`/`keys.unwrapped`: 키가 실제로 감싸져 있는지
- `commitments.saltedV2`/`unsaltedV1`, `receiptFingerprints.keyed`/`unkeyed`: 파기 뒤에도 확인 가능한 v1 레코드가 몇 개 남았는지
- `epochs.storage`/`stored`/`destroyed`, `epochDestructionReachesOldCopies`, `vaultBackupEventProjection`. 파기 기록이 있는 epoch가 다시
  보이거나, 키스토어 vault의 `evidence.db`에 epoch 행이 생기면 검사 전체가 실패합니다. 후자는 검토한 뒤 행을 지웁니다.
- `confidentialityAgainstDatabaseReader: false`, `liveProjectionPlaintext: true`: 두 모드 모두 현재 DB에는 보관 중인 이벤트의 평문 검색 사본이 있습니다.

## 남은 한계

- v1 레코드는 salt 없는 `payloadHash`와 원문 해시 영수증을 계속 갖습니다. 업그레이드 전에 파기한 이벤트도 추측 확인이 가능합니다.
  `/api/integrity`의 `unsaltedV1`·`unkeyed` 수로 범위를 확인할 수 있습니다.
- 현재 `evidence.db`에는 보관 중인 이벤트의 평문 검색 사본이 있습니다. 볼륨 스냅샷이나 파일 복사처럼 백업 명령을 거치지 않은 사본은
  복사 시점의 평문을 갖고, epoch 파기로도 지워지지 않습니다. 디스크 암호화와 사본 관리가 필요합니다.
- 데이터베이스 모드에서는 epoch 비밀과 이벤트 키가 DB 안에 있어 파기가 현재 DB에만 닿습니다. 이전 사본과 백업은 별도 폐기가 필요합니다.
- 실행 중인 vault는 읽은 epoch 비밀을 메모리에 둡니다. 이전과 epoch 파기는 vault를 멈추고 실행합니다. 키스토어 없이 실행 중이던 vault는
  이전 뒤 다음 요청에서 원장과 사본이 맞지 않아 거부하며, 이전된 DB에는 감싸지 않은 키를 쓰지 않습니다. 실행 중인 vault를 알아내는 잠금은 없습니다.
- epoch 파일은 덮어쓴 뒤 지우지만 저널링 파일 시스템과 SSD는 이전 블록을 남길 수 있습니다. 데이터 키 교체 때 다시 봉인한 파일은
  덮어쓰지 않고 교체합니다(이전 파일은 이전 데이터 키로 봉인되어 있음).
- 백업 이후 파기된 epoch의 미파기 이벤트를 가진 백업은 복구할 수 없습니다. frontier로 파기를 먼저 적용한 뒤 검색 사본을 다시 만드는
  복구 경로는 다음 단계입니다.
- tenant 전체를 보존 기간과 관계없이 지우는 epoch 파기(tenant offboarding)는 없습니다. 지금은 `all_events_disposed` 근거만 허용합니다.
- 암호화하지 않는 원장 기록(평가, 객체, 개발 실행 이벤트 등)은 평문이며 키스토어와 관계없이 사본·백업에 남습니다.
- 원장에는 tenant, 순번, 시각, `actionId`, `policyVersion`, `retainUntil`, `keyEpoch`와 64바이트 단위의 본문 길이가 보입니다.

## 시험

- `test/event-commitments.test.mjs`: 파기한 저엔트로피 이벤트를 원장·export로 확인하는 공격(기준 커밋 9177cee에서 실패), v2 salt 공개와 변조 거부
- `test/event-key-epochs.test.mjs`: 키 있는 영수증의 중복 판정, epoch 파기 조건, 기준 커밋 vault의 v1 레코드와 v2 레코드 병행 검증
- `test/event-key-wrapping.test.mjs`: 감싸기와 기동 조건, 이전 DB 사본·이전 vault 백업에 대한 epoch 파기, 되살아난 epoch 탐지와 재파기,
  기준 커밋 vault의 기동 시·명령 이전, 데이터베이스 모드 epoch 이전, 데이터 키 교체, HTTP 기동
