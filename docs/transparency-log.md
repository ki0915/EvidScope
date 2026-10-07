# 투명성 로그·위트니스 운영 가이드

> 2026-10-06 개선 1라운드에서 추가한 기능입니다. 설계 배경과 차별점은 [증거 계층 아키텍처](evidence-layer.md)를 보세요.

## 무엇을 막는가

서명 원장만으로는 **운영자나 호스트 공격자가 DB를 예전 사본으로 되돌리거나(rollback), tenant 하나를 통째로 지우는 것**을
알아챌 수 없었습니다(감사 보고서 S1·S2). 서명 키를 가진 공격자는 갈라진 이력을 새로 서명할 수도 있습니다.

투명성 로그는 이를 외부 관찰자에게 묶습니다.

1. tenant마다 원장 레코드 해시를 잎으로 하는 **RFC 6962 Merkle 트리**를 유지하고, 커밋할 때만 **C2SP signed note** 체크포인트에 서명합니다.
2. 모든 tenant의 머리(크기·루트)를 모은 **heads 로그** 하나를 따로 두고, 이 heads 체크포인트를 위트니스에 제출합니다.
   tenant 이름은 SHA-256으로 가려져 위트니스 목록에 노출되지 않습니다.
3. 위트니스는 **C2SP tlog-witness** 규약으로 일관성 증명을 확인한 뒤에만 공동서명합니다. 이전보다 작은 크기(rollback)나
   갈라진 이력(fork)에는 서명하지 않으므로, 서명 키를 훔친 공격자도 위트니스 몰래 **heads 로그**를 되돌리거나 갈라놓을 수 없습니다.
   다만 heads 잎은 vault 키로만 서명되므로, heads 로그만 맡기면 그 안의 tenant별 크기가 줄지 않는지는 vault가 스스로 확인합니다.
   설정에 `signer`를 넣으면 heads 체크포인트는 vault 밖의 [heads 서명기](signer.md)가 서명합니다. 서명기는 tenant 로그가 빠지거나 줄거나
   갈라지는 잎에는 서명하지 않으므로, vault 호스트 전체를 장악해도 그런 잎에 공동서명을 받을 수 없습니다.
4. `witnessTenantLogs`를 켜면 tenant 로그도 각자의 origin(`<origin>/t/<hash>`)으로 위트니스에 제출합니다. 위트니스가 tenant 로그마다
   앞으로만 자라는지 직접 확인하므로, 서명 키를 가진 공격자의 tenant 단위 되돌리기도 위트니스가 거부합니다. 남는 범위는 아래 한계의 첫 항목을 읽어 주세요.

위트니스는 직접 만들지 않고 표준 구현을 씁니다. 운영 환경은 [litewitness](https://github.com/FiloSottile/torchwood)나
[OmniWitness](https://github.com/transparency-dev/witness)를 권장합니다. 저장소의 `scripts/witness.mjs`는 개발·시험용이며
운영자와 같은 신뢰 경계에 있으므로 실제 보증에는 쓰지 않습니다.

## 모드

설정 파일은 `config.json`과 분리된 `TRANSPARENCY_CONFIG_FILE`(JSON)입니다. 복구 시 `config.json` 해시가 고정되므로 위트니스를 바꿔도
복구 바인딩이 깨지지 않도록 분리했습니다.

| 모드 | 동작 |
|---|---|
| 파일 없음 또는 `off` | 기존과 같습니다. `/api/integrity`는 `notChecked:["rollback","truncation","tenant_removal"]`로 확인하지 못한 범위를 밝힙니다. |
| `monitor` | Merkle 트리·heads 로그·위트니스 제출을 수행하고 위반을 보고하지만 서비스를 막지 않습니다. 파일이 있으면 기본값입니다. |
| `enforce` | 시작 시 pin 파일과 위트니스를 확인해 rollback·fork·tenant 삭제가 보이면 시작을 거부합니다. 실행 중 발견하면 격리(quarantine)되어 쓰기와 조회 API가 503을 돌려주고 `/api/integrity`만 원인을 보고합니다. |

```json
{
  "origin": "evidscope.example.com/prod",
  "mode": "monitor",
  "witnesses": [
    {"vkey": "witness-a.example.com+1a2b3c4d+AW...", "url": "https://witness-a.example.com/"},
    {"vkey": "witness-b.example.com+5e6f7a8b+AW...", "url": "https://witness-b.example.com/"}
  ],
  "quorum": 1,
  "intervalMs": 2000,
  "maxStalenessSeconds": 3600
}
```

- `origin`: 배포 단위의 기준 이름입니다. heads 로그 origin은 `<origin>/heads`, tenant 로그는 `<origin>/t/<hash>`가 됩니다.
- `witnesses[].vkey`: 위트니스 운영자가 알려준 검증 키, `url`: tlog-witness 제출 주소(`add-checkpoint`의 접두사)입니다.
- `quorum`: 공동서명이 몇 개 모여야 rollback 검사를 "확인함"으로 볼지 정합니다.
- `witnessTenantLogs`(기본 `false`): `true`이면 바뀐 tenant 로그의 체크포인트도 tenant origin으로 위트니스에 제출하고, 공동서명된 체크포인트를
  내보내기와 사건 보고서에 `transparency.tenantCosigned`로 싣습니다(보고서에는 보고서 체크포인트까지의 일관성 증명 포함). 바뀐 tenant부터
  한 라운드에 최대 64개, 동시에 4개까지 보내고, 바뀌지 않은 tenant는 `refreshSeconds`마다 다시 공동서명을 받습니다. 방금 heads 체크포인트에
  응답한 위트니스에만 보내므로 위트니스 하나가 멈춰도 pump가 막히지 않습니다. 켜기 전에 모든 tenant origin을 모든 위트니스에 등록합니다(아래).
  등록되지 않은 origin은 위반이 아니라 `status().tenantLogs`의 `attention`으로 보고하고 `refreshSeconds` 뒤에 다시 시도합니다. 시작할 때 모든
  tenant 로그를 위트니스에 조회하므로 tenant 수에 비례해 시작이 느려지고, 위트니스는 해시로 가린 tenant 수와 tenant별 기록 수 변화를 보게 됩니다.
- `signer`(선택): heads 서명기 연결(`socket`·`pipe`·`url`, `tokenFile`, `publicKeyFile` 등). 있으면 heads 체크포인트를 서명기가 서명하고
  위트니스 등록·pin·내보내기의 heads 키가 서명기 키가 됩니다. tenant 로그와 원장 체크포인트는 그대로 vault 키로 서명합니다. [heads 서명기](signer.md)를 보세요.
- `pinFile`: 마지막으로 공동서명된 heads 체크포인트를 기록하는 파일입니다. 기본값은 데이터 디렉터리 옆
  `.<data>-transparency-pin.json`이며 `TRANSPARENCY_PIN_FILE`로 다른 볼륨에 둘 수 있습니다. 데이터 볼륨과 다른 곳에 두어야
  DB와 pin을 함께 되돌리는 공격을 막을 수 있습니다.

## 로컬에서 켜기

```powershell
npm run upgrade:local -- --transparency   # .local/transparency.json 생성(monitor, 위트니스 없음)
npm start                                  # 런처가 .local/transparency.json을 자동으로 읽습니다
```

이 설정은 같은 폴더의 pin 파일만 기준으로 삼으므로 **기능 확인용**입니다. 실제 보증에는 아래처럼 독립 위트니스를 추가합니다.

## 위트니스 등록

위트니스는 운영자가 등록한 origin만 받습니다. 등록 명령은 도구가 만들어 줍니다.

```powershell
node scripts/transparency.mjs vkeys      --config transparency.json --key .local/signing-private.pem
node scripts/transparency.mjs witnessctl --config transparency.json --key .local/signing-private.pem --db litewitness.db
```

출력된 `witnessctl add-log`, `add-key` 두 줄을 위트니스 운영자에게 전달합니다. 위트니스의 vkey를 받아 설정 파일에 넣고
vault를 다시 시작합니다. 공개 위트니스 네트워크(witness-network.org)에는 heads 로그 origin 하나만 등록하면 됩니다.

`witnessTenantLogs`를 켜면 tenant origin도 위트니스마다 등록합니다. `--data-dir`을 주면 원장에 있는 모든 tenant의 등록 줄을, `--tenant NAME`을
주면 그 tenant의 등록 줄을 heads origin 줄과 함께 출력합니다. 새 tenant는 등록되기 전까지 heads 잎으로만 묶이므로 tenant를 만들 때 등록도
함께 합니다. origin이 tenant 수만큼 늘어나므로 tenant 로그는 운영자와 독립된 전용 위트니스(litewitness 등)에 맡기고, 공개 위트니스 네트워크에는
heads origin만 등록하는 구성을 권장합니다.

```powershell
node scripts/transparency.mjs witnessctl --config transparency.json --key .local/signing-private.pem --db litewitness.db --data-dir .local/data
node scripts/transparency.mjs tenants    --config transparency.json --key .local/signing-private.pem --data-dir .local/data
```

`tenants`는 tenant별 origin, 로그 키, 서명된 크기, 위트니스별 마지막 공동서명 크기를 보여 줍니다. 공동서명 크기가 `null`이면 그 위트니스에서
아직 공동서명을 받지 못한 것이며, 대개 등록이 빠진 경우입니다.

## 상태 확인과 검증

```powershell
node scripts/transparency.mjs status --config transparency.json --key .local/signing-private.pem --data-dir .local/data --probe
```

- `ok`, `headsSize`, `pin`, `violations`, 위트니스별 마지막 공동서명 크기를 보여 줍니다. enforce로 거부된 vault도 읽기 전용으로 점검할 수 있습니다.
- `/api/integrity`의 `transparency.rollbackChecked`가 `true`가 되려면 정족수 이상의 신선한 공동서명이 있고 실행 중 위반이 없어야 합니다.
- `transparency.rollbackCheckedAgainst`는 그 확인이 누구를 상대로 성립하는지 밝힙니다. heads 공동서명만으로 확인했으면 `database_tamper`
  (DB만 조작하는 공격자, S1), 고정한 origin base의 tenant 로그를 정족수의 위트니스가 `maxStalenessSeconds` 안에 공동서명했으면
  `signing_key_holder`(서명 키를 가진 공격자, S2까지), 검증자가 `--heads-key`로 고정한 heads 서명기 키가 `--origin-base`로 고정한
  origin base의 heads 체크포인트에 서명했고 신선한 정족수가 있으면 `vault_host`(vault 호스트 전체를 장악한 공격자, [heads 서명기](signer.md))입니다.
  `--require-heads-signer`는 `--origin-base`가 필요합니다. 신선한 공동서명이 없으면 `null`입니다. `--min-checkpoint`만으로 확인한 경우
  `rollbackChecked`는 `true`지만 검증자가 준 체크포인트 기준이므로 이 값은 `null`입니다.

내보낸 묶음은 운영자를 믿지 않고 오프라인으로 검증합니다.

```powershell
node scripts/verify.mjs export.json trust-anchor.pem --witness "<위트니스 vkey>" --quorum 1 --origin-base evidscope.example.com/prod --require-transparency
node scripts/verify-case-report.mjs report.json trust-anchor.pem --witness "<위트니스 vkey>" --quorum 1 --origin-base evidscope.example.com/prod
node scripts/verify.mjs export.json trust-anchor.pem --witness "<위트니스 vkey>" --quorum 1 --origin-base evidscope.example.com/prod --require-tenant-witness
```

`--require-tenant-witness`는 결과가 `signing_key_holder`가 아니면 실패하고 이유를 밝힙니다. tenant 공동서명이 없거나, 정족수에 못 미치거나,
`--max-staleness`(기본 86400초)보다 오래됐거나, `--origin-base`를 고정하지 않았거나, 고정한 것과 다른 origin base(복구 epoch 이후)인 경우입니다.
`verify.mjs`, `verify-case-report.mjs`, `replay-findings.mjs`가 같은 플래그를 씁니다.

기존 사용법(`verify.mjs EXPORT KEY [CHECKPOINT]`)은 그대로 동작합니다. 투명성 자료가 없는 예전 묶음도 검증되며, `tenantCosigned`가 없는 묶음은
heads 공동서명이 신선해도 `database_tamper`로 보고합니다.

표준 도구로 확인하려는 감사인에게는 [표준 영수증](receipts.md)을 줍니다. `GET /api/receipts/record?seq=N`(또는 `scripts/receipts.mjs record`)은
레코드 하나가 tenant 로그 체크포인트에 들어 있다는 `c2sp.org/tlog-proof@v1`을 위트니스 공동서명과 함께 내고, `scripts/receipts.mjs policy`는
tenant 로그의 `c2sp.org/tlog-policy`를 냅니다. 내보내기와 사건 보고서의 `?attest=intoto` 증명에도 같은 증명이 들어 있어 torchwood
`VerifyProof`나 별도 배포 검증기 `evidscope-verify`로 확인할 수 있습니다. `witnessTenantLogs`가 꺼져 있으면 정책은 `quorum none`입니다.

heads 모니터는 DB 사본에서 heads 로그 전체를 다시 접어 봅니다. 공개 키만 있으면 되므로 감사인도 돌릴 수 있습니다.

```powershell
node scripts/transparency.mjs monitor --config transparency.json --key signing-public.pem --data-dir .local/data
```

각 행이 앞 행을 잇고 서명된 체크포인트와 맞는지, tenant 크기를 줄이거나 tenant를 빼거나 같은 크기에서 루트를 바꾸는 잎이 없는지, heads 잎·서명된
tenant 체크포인트·위트니스가 공동서명한 tenant 체크포인트가 모두 원장의 접두사인지 확인해 JSON으로 보고합니다(위반이 있으면 종료 코드 2).
DB 안의 이력만 보므로, 그 이력이 위트니스가 공동서명한 heads 로그와 같은지는 `status --probe`로 함께 확인합니다.

## 사고 대응

| 보고 | 의미 | 조치 |
|---|---|---|
| `rollback` | 위트니스나 pin이 기억하는 크기보다 DB의 heads 로그가 짧습니다. | DB를 되돌린 경위를 조사합니다. 정상 복구라면 새 epoch로 복구합니다(아래). |
| `fork` (위트니스 422) | 같은 크기에서 다른 이력이 제출되었습니다. 서명 키 유출을 의심합니다. | 서명 키 교체와 사고 기록, 위트니스 운영자와 대조합니다. |
| `tenant_removal` | 공동서명된 heads에 있던 tenant가 DB에 없습니다. | 삭제 경위를 조사합니다. |
| `rollback` (tenant 로그) | 위트니스가 DB의 tenant 로그보다 큰 크기를 공동서명했습니다. heads 로그와 pin이 맞아도 tenant 하나가 되돌려졌다는 뜻이며, 서명 키를 가진 공격자도 의심합니다. | DB를 되돌린 경위와 서명 키 노출을 조사하고, 그 tenant의 최신 내보내기와 대조합니다. |
| `monitor`의 `rollback`·`tenant_removal`·`fork` | DB의 heads 이력 안에 tenant를 줄이거나 빼거나 바꾸는 잎이 있습니다. vault 키 없이는 만들 수 없는 잎입니다. | 서명 키 유출로 보고 fork와 같이 대응합니다. |
| 위트니스 4xx/5xx | 연결·등록 문제입니다. 격리하지 않고 보고만 합니다. tenant origin 미등록(`unregistered`)은 `status().tenantLogs`의 `attention`에 나옵니다. | 등록 상태와 네트워크를 확인합니다. |

## 현재 한계

- **서명 키까지 가진 공격자(S2)의 tenant 단위 되돌리기.** heads 잎은 vault 키로만 서명되므로 heads 로그만 위트니스에 맡기는 기본 구성에서는,
  키를 가진 공격자가 tenant 하나를 예전 크기로 되돌린 heads 잎을 붙여 공동서명을 받을 수 있습니다(적대적 재검토 F1). 그래서 heads 공동서명만으로
  확인한 결과는 `rollbackChecked:true`여도 `rollbackCheckedAgainst:"database_tamper"`, 즉 **DB만 조작하는 공격자(S1)** 기준으로 보고합니다.
  `witnessTenantLogs`를 켜면 위트니스가 tenant 로그마다 되돌리기를 거부하고(재검토 PoC는 `test/transparency-tenant-witness.test.mjs`로 옮겨
  litewitness 상호운용과 함께 확인), 신선한 tenant 공동서명이 있는 증거만 `signing_key_holder`로 보고되며 `--require-tenant-witness`로 요구할 수
  있습니다. heads 서명기를 쓰면 이 공격은 서명 단계에서 막히고(litewitness 시험: 서명기 422, 위트니스 403), 서명기 키와 origin base를 고정한 검증자는
  `vault_host`를 받습니다([heads 서명기](signer.md)). 서명기 없이 `witnessTenantLogs`만 쓰면 다음 범위가 남습니다.
  - 마지막 tenant 공동서명 이후 `maxStalenessSeconds` 안의 되돌리기는 막지 못합니다. 그 사이에 받은 예전 내보내기는 아직 신선한 공동서명을 갖고 있습니다.
  - 복구 epoch는 vault 키만으로 서명되므로, 검증자가 새 origin base를 확인한 뒤 `--origin-base`로 다시 고정해야 `signing_key_holder`가 됩니다.
  - 아직 위트니스에 등록되지 않은 tenant origin은 등록될 때까지 heads 잎으로만 묶입니다.
  - tenant 삭제는 여전히 heads 잎으로만 확인합니다. 키를 가진 공격자가 heads 잎에서 tenant를 빼고 pin까지 다시 쓰면 vault 시작 검사는 통과하며,
    `scripts/transparency.mjs monitor`로 DB의 heads 이력을 다시 읽어야 드러납니다. 이 모니터를 정기적으로 돌리는 운영 경로는 아직 없습니다.
- 오프라인 검증기는 마지막 공동서명 이후 `maxStalenessSeconds` 안에서 일어난 rollback은 알 수 없습니다. 실행 중인 vault는 위트니스 조회로 잡습니다.
- 백업에서 복구하면 위트니스가 본 마지막 크기보다 짧아지므로 enforce 모드에서는 새 origin epoch가 필요합니다. 진행 상황은 [개선 라운드 기록](improvement-rounds.md)에 남깁니다.
- tenant별 고객 위트니스, 타일(tlog-tiles) 배포, ML-DSA 공동서명은 다음 라운드 범위입니다.
