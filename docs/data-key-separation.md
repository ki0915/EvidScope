# 데이터 암호화 키 분리 가이드

> 2026-10-06 개선 1라운드에서 감사 보고서 S2·S4를 고친 내용입니다.

## 바뀐 점

- **이전:** 문서·백업 암호화 키를 Ed25519 서명 키에서 유도했습니다. 서명 키 하나가 새면 서명 위조와 복호화가 함께 가능했습니다(S2).
- **이후:** 32바이트 무작위 루트 키(`DATA_KEY_FILE`)에서 용도별 키를 HKDF-SHA256으로 나눠 씁니다
  (거버넌스 문서, 금융 문서, vault 백업, 2라운드에 추가한 이벤트 키 epoch 봉인). 문서 봉투 v2와 백업 manifest v2는 키 ID(`dk1-…`)를
  AAD에 묶습니다.
- 예전 방식으로 암호화된 자료는 그대로 읽히며(`legacy-signing-v1`), 이전 작업으로 새 키로 다시 암호화합니다.
- 삭제(erasure) 뒤 SQLite가 지운 페이지를 남기지 않도록 `PRAGMA secure_delete=ON`과 `wal_checkpoint(TRUNCATE)`를 적용했습니다(S4).

`/api/integrity`의 `keySeparation.status`가 현재 상태를 알려 줍니다.

| 값 | 의미 |
|---|---|
| `not_separated` | 데이터 키가 설정되지 않았습니다. 예전 방식으로 동작합니다. |
| `migration_pending` | 데이터 키는 있지만 예전 방식으로 암호화된 문서가 남아 있습니다. |
| `separated` | 모든 참조 문서가 데이터 키로 암호화되어 있습니다. |

`enterprise` 프로필은 데이터 키 없이 시작하지 않습니다. 로컬 프로필은 새로 설치하면 `.local/data-encryption.key`를 자동으로 만들고,
이미 있는 설치는 아래 업그레이드로 옮깁니다.

vault가 `DATA_KEY_FILE`로 한 번 시작하면(문서가 아직 없어도) 그 키 ID를 `evidence.db`에 기록합니다. 그 뒤로는 키 없이
vault를 시작하거나, 백업(`vault-backup.mjs create`)·복구 frontier를 만들 수 없습니다. 서명 키에서 유도한 v1 백업 키는 보관된
모든 이벤트 키를 풀 수 있기 때문입니다. `migrate`로 은퇴한 키 ID는 더 이상 요구하지 않습니다. `enterprise` 프로필은 백업 시
`CONFIG_FILE`을 주면 데이터 키 없는 백업을 처음부터 거부합니다. 이미 만든 v1 백업은 계속 검증·복구할 수 있습니다.

## 기존 로컬 설치 옮기기

`npm start`를 멈춘 뒤 실행합니다. 바꾸는 파일은 먼저 `.local/upgrade-backup-<시각>/`에 복사합니다.

```powershell
npm run upgrade:local -- --dry-run   # 무엇을 바꿀지 먼저 확인
npm run upgrade:local                # OTLP 원칙 추가 + 데이터 키 생성 + 문서 재암호화
npm start
```

결과 JSON의 `data_key.migration.reencryptedFrom`에 다시 암호화한 문서 수가 나옵니다. 이후 새 vault 백업을 만드세요.
업그레이드 뒤 백업·복구 명령에는 데이터 키를 함께 줘야 합니다. 키 없이 실행하면 서명 키 유도 백업으로 내려가지 않도록 거부합니다.

```powershell
$env:DATA_KEY_FILE='.local/data-encryption.key'
$env:EVENT_KEYSTORE_DIR='.local/event-keystore'   # 이벤트 키스토어를 쓰는 설치(새 설치와 upgrade:local 이후)
node scripts/vault-backup.mjs create .local/data <새 백업 폴더> .local/signing-private.pem .local/trust-anchor.pem <새 앵커 파일>
```
예전 백업은 서명 키로 계속 복구할 수 있으므로 서명 키를 보관하는 동안에는 예전 백업도 유효합니다.

## 운영 환경

```powershell
node scripts/data-key.mjs generate /secure/data-encryption.key     # 키 생성(키 내용은 출력하지 않음)
node scripts/data-key.mjs id /secure/data-encryption.key           # 키 ID 확인
$env:DATA_KEY_FILE='/secure/data-encryption.key'
node scripts/data-key.mjs migrate /data /keys/signing-private.pem  # vault를 멈춘 상태에서 실행
```

- 키 파일은 정확히 32바이트여야 하며 `DATA_DIR` 안에 둘 수 없습니다(같은 볼륨 스냅샷에 키와 암호문이 함께 남는 것을 막음).
  Linux에서는 그룹 쓰기·기타 사용자 접근이 있으면 거부합니다.
- Kubernetes 매니페스트는 `vault-data-key` Secret을 `/data-key/data-encryption.key`로 마운트합니다.
- **키 교체:** 새 키를 `DATA_KEY_FILE`, 예전 키를 `DATA_KEY_PREVIOUS_FILES`(경로 구분자로 여러 개)에 두고 `migrate`를 실행합니다.
  더 이상 참조되지 않는 키 ID는 `retiredKeyIds`로 표시됩니다. 그 키로 봉인한 백업을 보관하는 동안에는 키도 오프라인에 보관하세요.
  이벤트 키스토어를 쓰는 vault는 `EVENT_KEYSTORE_DIR`도 함께 줘야 하며, `migrate`가 epoch 파일을 새 키로 다시 봉인합니다(`resealedEpochs`).

## 남은 한계

- 서명 키와 데이터 키는 다른 비밀이지만 같은 vault 프로세스가 둘 다 읽습니다. vault 호스트를 장악한 공격자는 둘 다 얻습니다.
  HSM·KMS 연동은 다음 단계입니다.
- 이벤트별 crypto-shredding 키(`event_keys`)는 `EVENT_KEYSTORE_DIR`를 설정하지 않으면 같은 DB에 감싸지 않은 채 저장됩니다. 키스토어를
  쓰면 데이터 키로 봉인한 키 epoch 비밀로 감싸며, epoch 파기가 이전 DB 사본과 vault 백업에도 닿습니다([이벤트 키 감싸기와 키 epoch 운영 가이드](event-key-wrapping.md)).
  두 모드 모두 현재 DB에는 보관 중인 이벤트의 평문 검색 사본이 있으므로 DB 열람자에 대한 기밀성은 보장하지 않습니다.
