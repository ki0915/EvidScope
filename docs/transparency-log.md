# 투명성 로그·위트니스 운영 가이드

> 2026-10-06 개선 1라운드에서 추가한 기능입니다. 설계 배경과 차별점은 [증거 계층 아키텍처](evidence-layer.md)를 보세요.

## 무엇을 막는가

서명 원장만으로는 **운영자나 호스트 공격자가 DB를 예전 사본으로 되돌리거나(rollback), tenant 하나를 통째로 지우는 것**을
알아챌 수 없었습니다(감사 보고서 S1·S2). 서명 키를 가진 공격자는 갈라진 이력을 새로 서명할 수도 있습니다.

투명성 로그는 이를 외부 관찰자에게 묶습니다.

1. tenant마다 원장 레코드 해시를 잎으로 하는 **RFC 6962 Merkle 트리**를 유지하고, 커밋할 때만 **C2SP signed note** 체크포인트에 서명합니다.
2. 모든 tenant의 머리(크기·루트)를 모은 **heads 로그** 하나를 따로 두고, 이 heads 체크포인트만 위트니스에 제출합니다.
   tenant 이름은 SHA-256으로 가려져 위트니스 목록에 노출되지 않습니다.
3. 위트니스는 **C2SP tlog-witness** 규약으로 일관성 증명을 확인한 뒤에만 공동서명합니다. 이전보다 작은 크기(rollback)나
   갈라진 이력(fork)에는 서명하지 않으므로, 서명 키를 훔친 공격자도 위트니스 몰래 이력을 바꿀 수 없습니다.

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

## 상태 확인과 검증

```powershell
node scripts/transparency.mjs status --config transparency.json --key .local/signing-private.pem --data-dir .local/data --probe
```

- `ok`, `headsSize`, `pin`, `violations`, 위트니스별 마지막 공동서명 크기를 보여 줍니다. enforce로 거부된 vault도 읽기 전용으로 점검할 수 있습니다.
- `/api/integrity`의 `transparency.rollbackChecked`가 `true`가 되려면 정족수 이상의 신선한 공동서명이 있고 실행 중 위반이 없어야 합니다.

내보낸 묶음은 운영자를 믿지 않고 오프라인으로 검증합니다.

```powershell
node scripts/verify.mjs export.json trust-anchor.pem --witness "<위트니스 vkey>" --quorum 1 --origin-base evidscope.example.com/prod --require-transparency
node scripts/verify-case-report.mjs report.json trust-anchor.pem --witness "<위트니스 vkey>" --quorum 1 --origin-base evidscope.example.com/prod
```

기존 사용법(`verify.mjs EXPORT KEY [CHECKPOINT]`)은 그대로 동작합니다. 투명성 자료가 없는 예전 묶음도 검증됩니다.

## 사고 대응

| 보고 | 의미 | 조치 |
|---|---|---|
| `rollback` | 위트니스나 pin이 기억하는 크기보다 DB의 heads 로그가 짧습니다. | DB를 되돌린 경위를 조사합니다. 정상 복구라면 새 epoch로 복구합니다(아래). |
| `fork` (위트니스 422) | 같은 크기에서 다른 이력이 제출되었습니다. 서명 키 유출을 의심합니다. | 서명 키 교체와 사고 기록, 위트니스 운영자와 대조합니다. |
| `tenant_removal` | 공동서명된 heads에 있던 tenant가 DB에 없습니다. | 삭제 경위를 조사합니다. |
| 위트니스 4xx/5xx | 연결·등록 문제입니다. 격리하지 않고 보고만 합니다. | 등록 상태와 네트워크를 확인합니다. |

## 현재 한계

- 오프라인 검증기는 마지막 공동서명 이후 `maxStalenessSeconds` 안에서 일어난 rollback은 알 수 없습니다. 실행 중인 vault는 위트니스 조회로 잡습니다.
- 백업에서 복구하면 위트니스가 본 마지막 크기보다 짧아지므로 enforce 모드에서는 새 origin epoch가 필요합니다. 진행 상황은 [개선 라운드 기록](improvement-rounds.md)에 남깁니다.
- tenant별 고객 위트니스, 타일(tlog-tiles) 배포, ML-DSA 공동서명은 다음 라운드 범위입니다.
