# heads 서명기(heads signer) 운영 가이드

> 2026-10-07 개선 2라운드(WP-S)에서 추가한 기능입니다. 투명성 로그 전반은 [투명성 로그·위트니스 운영 가이드](transparency-log.md)를,
> 실행·배포 구조는 [실행·배포·복구](operations.md)를 보세요.

## 무엇을 막는가

1라운드까지는 vault 프로세스가 Ed25519 vault 키 하나로 원장 체크포인트, tenant 로그 체크포인트, **heads 체크포인트**, 복구 epoch를
모두 서명했습니다. 위트니스는 로그마다 앞으로만 자라는지만 확인하므로, vault 호스트를 장악한 공격자(키·DB·네트워크를 모두 가진 사람)는
다음을 할 수 있었습니다.

1. tenant 하나를 예전 내보내기의 크기로 되돌린 heads 잎을 만들고(다른 tenant는 그대로) vault 키로 서명합니다.
2. heads 로그 자체는 한 잎 자랐을 뿐이므로 위트니스가 공동서명합니다.
3. 예전 내보내기에 이 체크포인트를 앵커로 붙이면 검증자는 **신선한 위트니스 앵커**를 보고 그 tenant의 최신 기록이 사라진 것을 모릅니다.

이 공격은 실제 litewitness로 재현됩니다(`test/litewitness-interop.test.mjs`, `test/support/heads-attack.mjs`). cf45e19에서는 위트니스가
200으로 공동서명하고 예전 내보내기가 `rollbackChecked: true`로 검증됩니다.

heads 서명기는 heads 로그 키를 vault 밖의 별도 프로세스로 옮깁니다. 서명기는 **사후 탐지가 아니라 서명 전에** 다음을 스스로 확인합니다.

- 새 heads 잎에 직전 잎의 모든 tenant 로그가 그대로 있는지(빠지면 `tenant_removal`)
- 크기가 줄지 않았는지(`rollback`), 같은 크기면 루트도 같은지(`fork`)
- 커진 tenant 로그마다 직전에 서명한 (크기, 루트)에서 이어지는 RFC 6962 일관성 증명이 맞는지(없거나 틀리면 `fork`)
- 새 tenant 로그는 허용합니다. 바뀐 것이 없는 잎은 `unchanged`로 거부합니다.

서명할 루트는 vault가 주지 않습니다. 서명기가 자신이 보관한 compact range(frontier)에 잎을 붙여 루트를 직접 계산하고, 그 체크포인트에만
서명합니다. 위트니스에는 heads origin의 키로 서명기 키만 등록하므로, vault 키로 서명한 heads 체크포인트는 위트니스가 403으로 거부합니다.

| vault 호스트 장악 공격 | 이전 | 서명기 + 위트니스 등록 + 검증자 `--heads-key` |
|---|---|---|
| tenant를 되돌린 heads 잎에 공동서명 받기 | 가능 | 서명기가 `rollback`으로 거부, 위트니스는 vault 키 체크포인트에 403 |
| heads 잎에서 tenant 빼기 | 가능 | `tenant_removal` 거부(운영자가 서명기에서 승인한 epoch만 허용) |
| 같은 크기에서 다른 heads 이력(fork) | 가능 | 서명기가 같은 크기에 두 번 서명하지 않음 |
| 새 origin base로 몰래 복구 epoch | vault 키로 가능 | 서명기 쪽 `authorize-epoch` 없이는 새 origin에 서명하지 않음 |
| 내보내기에 다른 키로 서명한 heads 앵커 | — | `--heads-key`를 고정한 검증자가 거부 |

## vault 호스트를 장악당해도 여전히 할 수 있는 일

서명기는 heads 로그의 **의미**를 지킬 뿐 vault를 대신하지 않습니다. vault 호스트를 장악한 공격자는 여전히 다음을 할 수 있습니다.

- **vault 키로 서명하는 모든 것.** 원장 v1 체크포인트와 tenant 로그 체크포인트는 커밋마다 동기적으로 vault 키로 서명합니다(빈도가 높고
  `Store.transaction` 안에서 끝나야 하므로 옮기지 않았습니다). 공격자는 갈라진 tenant 이력에 서명할 수 있지만, 그 이력은 서명기가 이미 서명한
  heads 항목에서 이어지는 일관성 증명을 만들 수 없으므로 heads 로그에 들어가지 못합니다.
- **앵커를 멈추기.** 새 heads 잎을 보내지 않고 마지막 체크포인트를 위트니스에서 계속 다시 공동서명 받을 수 있습니다. 그러면 마지막 heads 잎
  이후에 vault가 받은 기록은 보호받지 못합니다. `vault_host`는 "위트니스가 그때까지 본 heads 잎보다 뒤로 되돌릴 수 없다"는 뜻이지,
  앵커되지 않은 기록이 남아 있다는 뜻이 아닙니다. 멈춘 heads 크기는 위트니스와 `status --probe`, 모니터에서 보입니다.
- **정상적인 성장에 서명받기.** 공격자가 만든 기록을 덧붙인 잎도 규칙상 정상 성장이므로 서명기가 서명합니다. 기록 위조 자체는 vault 키 서명
  체인의 문제로 남습니다.
- **서명기 거부·지연.** 요청 폭주는 속도 제한(`rate_limited`)에, 잘못된 잎은 거부 감사 줄에 남습니다. 서명기를 멈추게 할 수는 없지만
  서명을 늦출 수는 있습니다.
- **복구 epoch 요청.** 승인은 서명기 쪽 운영자가 합니다. `epoch-claims`가 출력하는 복구 범위는 vault가 주는 값이므로, 운영자는
  `authorize-epoch`가 출력하는 `losses`(잃는 tenant 로그와 크기)를 확인한 뒤 승인해야 합니다. 검토 없이 승인하면 손실을 정당화하게 됩니다.
- 기록 내용 열람, 데이터 키 사용 등 서명기와 상관없는 모든 일.

서명기가 vault와 같은 호스트(로컬 런처, Kubernetes sidecar의 노드)에 있으면 그 호스트의 장악은 서명기 키까지 닿습니다. 로컬 런처는
프로세스만 나누고, sidecar는 vault **컨테이너** 장악만 막습니다. 노드 장악까지 막으려면 별도 Deployment(다른 노드)나 별도 호스트,
ssh-agent의 하드웨어 키·클라우드 KMS를 씁니다.

## 검증 결과: `vault_host`

`rollbackCheckedAgainst`에 가장 강한 수준 `vault_host`를 추가했습니다.

| 값 | 조건 | 상대할 수 있는 공격자 |
|---|---|---|
| `vault_host` | 검증자가 `--heads-key`로 고정한 서명기 키가 서명한 heads 체크포인트에 `maxStalenessSeconds` 안의 정족수 공동서명이 있고, 그 체크포인트가 `--origin-base`로 고정한 origin base의 heads origin인 경우 | vault 호스트 전체(vault 키·DB)를 가진 공격자도 이 tenant를 그 시각까지 위트니스가 본 heads 항목보다 뒤로 되돌린 내보내기를 보일 수 없습니다. |
| `signing_key_holder` | 고정한 origin base의 tenant 로그 공동서명이 신선한 경우 | vault 서명 키를 가진 공격자의 tenant 되돌리기 |
| `database_tamper` | heads 공동서명만 신선한 경우 | DB만 조작하는 공격자 |

- 내보내기는 서명기 키를 `transparency.heads.logVkey`로 함께 싣지만, 이 키는 증거가 아닙니다. 검증자가 고정하지 않으면 `database_tamper`로
  보고하고 `heads.signedBy: "heads_key"`, `heads.headsKeyPinned: false`로 밝힙니다.
- 고정한 키와 다른 키로 서명한 heads 체크포인트는 거부합니다. vault 키로 서명한 예전 체크포인트는 예전과 같이 검증하며 `signedBy: "vault_key"`로
  보고합니다. 키를 고정하지 않은 검증은 vault 키 체크포인트에 대해 이전과 같은 결과를 냅니다.
- `--require-heads-signer`는 결과가 `vault_host`가 아니면 이유와 함께 실패합니다. `--origin-base` 없이 주면 사용법 오류입니다
  (`evidscope-verify`는 종료 코드 2, `scripts/verify*.mjs`는 오류 메시지와 종료 코드 1).
- `vault_host`에는 `--origin-base` 고정이 필요합니다. 위트니스는 이미 본 체크포인트를 다시 받으면 새 시각으로 공동서명하므로, 복구 epoch로
  은퇴한 heads origin의 마지막 체크포인트도 계속 신선해질 수 있습니다. 2라운드 검증기는 base를 고정하지 않아도 `vault_host`를 주었기 때문에
  epoch 이전 내보내기가 그대로 `vault_host`로 통과했습니다(3라운드 재감사, `test/heads-signer-retired-origin.test.mjs`). 이제 base를 고정하지
  않으면 그 아래에서 성립하는 수준(heads 공동서명만 신선하면 `database_tamper`)을 보고합니다. 예전 base를 계속 고정한 검증자는 오프라인으로
  구별할 수 없으므로 [복구 epoch](#복구-epoch) 6·7단계를 따릅니다.

```powershell
node scripts/signer.mjs vkey --state-dir /signer/state --origin-base evidscope.example.com/prod   # 검증자에게 전달할 heads 키
node scripts/verify.mjs export.json trust-anchor.pem --witness "<위트니스 vkey>" --quorum 1 --origin-base evidscope.example.com/prod `
  --heads-key "<서명기 vkey>" --require-heads-signer
```

`verify.mjs`, `verify-case-report.mjs`, `replay-findings.mjs`가 같은 플래그를 씁니다. 키를 교체했다면 `--heads-key`를 키마다 반복합니다.

## 구성 요소

- `src/signer.mjs`: 정책 검사, 상태, 감사 로그, HTTP 서버. `src/signer-backends.mjs`: 키 백엔드. `src/signer-client.mjs`: vault 쪽 클라이언트.
  `scripts/signer.mjs`: 운영 CLI(파일 머리말에 전체 사용법).
- 상태 디렉터리(서명기 볼륨에만 둠)
  - `state.json`: heads origin마다 서명한 크기·루트, 최신 잎 직전의 frontier, 최신 잎의 tenant 항목 전체, 서명한 노트. 쓰기는 fsync 뒤 원자적
    rename이며, 읽을 때 최신 잎과 frontier가 저장된 루트로 접히는지, 노트 서명이 맞는지 다시 확인합니다.
  - `audit.log`: 서명·거부마다 한 줄(시각, origin, 이전·새 크기, 루트, 이유)의 해시 체인 JSONL. `signer.mjs audit --verify`로 확인합니다.
  - `authorizations/`: 운영자 승인(1회용). 쓰면 `used/`, 취소하면 `revoked/`로 옮깁니다.
- 상태 디렉터리가 vault 데이터 디렉터리 안이거나(`DATA_DIR`), 위쪽 디렉터리에 `evidence.db`가 있으면 시작을 거부합니다.
- 상태 파일은 서명기 프로세스만 씁니다. 실행 중에 다른 파일로 바뀌면(같은 상태를 쓰는 두 번째 서명기, 복원한 사본) 서명을 거부합니다
  (`state_changed`). 서명기는 상태 디렉터리 하나에 하나만 실행합니다.
- 연결: Unix 소켓(기본 권한 600), Windows named pipe, loopback TCP, TLS TCP. TCP와 named pipe는 32자 이상의 bearer token 파일이 필수이고
  loopback이 아닌 주소는 TLS가 필수입니다. 요청은 기본 8 MiB, 서명 분당 60회(버스트 10), 요청 분당 600회로 제한하며, 모든 서명은
  origin에 상관없이 한 줄로 직렬화합니다.
- 키 백엔드는 시작할 때 고정 벡터에 서명하고 설정된 공개 키로 검증합니다. 다른 키이거나 prehash 변형이면 시작하지 않습니다.
- 서명기에 연결할 수 있는 사람은 vault 대신 잎을 보낼 수 있습니다. 규칙을 지키는 성장 잎이라도 vault 원장과 맞지 않으면 vault가 그 잎을
  `fork`로 보고 멈추므로, 소켓 권한과 token은 vault만 갖게 합니다. token 파일과 키 파일은 소유자가 읽는 사용자이면 600이어야 합니다.

## vault 설정

`TRANSPARENCY_CONFIG_FILE`에 `signer`를 넣으면 켜집니다. 없으면 아무것도 바뀌지 않습니다.

```json
{
  "origin": "evidscope.example.com/prod",
  "mode": "enforce",
  "witnesses": [{"vkey": "witness-a.example.com+1a2b3c4d+AW...", "url": "https://witness-a.example.com/"}],
  "quorum": 1,
  "signer": {"socket": "/run/heads-signer/signer.sock", "publicKeyFile": "/heads-signer-public/signer-public.pem"}
}
```

- `socket` | `pipe` | `url` 중 하나: Unix 소켓 경로, named pipe 이름(`\\.\pipe\...` 또는 이름만), `http://127.0.0.1:포트`(loopback만) 또는 `https://...`.
- `tokenFile`: bearer token 파일(소켓 외에는 필수). `caFile`: TLS 서명기를 발급한 CA. `timeoutMs`: 기본 10000.
- `publicKeyFile`(필수): 서명기 공개 키(SPKI PEM, `signer.mjs public-key`). `previousPublicKeyFiles`: 교체 전 키들.

켜면 바뀌는 것: heads 체크포인트를 서명기에서 받습니다(라운드마다 잎 하나, 성장한 tenant 로그마다 일관성 증명). 위트니스 등록 줄
(`transparency.mjs vkeys`·`witnessctl`), pin, 내보내기의 heads 키가 서명기 키가 됩니다. `/api/integrity`의 `verificationScope.checks`에
`heads_signer`가, `status().signer`에 서명기 상태가 나옵니다. 시작 검사는 서명기의 head를 가장 강한 pin으로 씁니다. DB의 heads 로그는 서명기가
서명한 것과 같거나 정확히 한 잎 뒤여야 하고(서명 직후 vault가 멈춘 경우, 첫 라운드에 그 잎을 받아 저장), 서명기보다 짧으면 `rollback`,
길면 `inconsistent`, 갈라지면 `fork`입니다.

## 처음 설치

서명기 호스트(또는 컨테이너)에서 실행합니다. vault 데이터 볼륨은 마운트하지 않습니다.

```bash
node scripts/signer.mjs keygen --out /signer/signer-key.pem --public-out /signer/signer-public.pem
node scripts/signer.mjs init --state-dir /signer/state --backend file --key-file /signer/signer-key.pem
node scripts/signer.mjs authorize-genesis --state-dir /signer/state --origin-base evidscope.example.com/prod
node scripts/signer.mjs serve --state-dir /signer/state --backend file --key-file /signer/signer-key.pem --socket /run/heads-signer/signer.sock
# TCP: --host 0.0.0.0 --port 8443 --tls-cert tls.crt --tls-key tls.key --token-file token   (token: node scripts/signer.mjs token --out token)
```

위트니스 등록 줄은 vault 쪽에서 `signer`가 들어간 설정으로 만듭니다(heads origin은 서명기 키, tenant origin은 vault 키).

```powershell
node scripts/transparency.mjs witnessctl --config transparency.json --key signing-private.pem --db litewitness.db
```

## vault 키 heads 로그를 서명기로 넘기기(handover)

이미 vault 키로 서명한 heads 로그가 있으면 같은 origin을 서명기가 이어 갑니다. 예전 내보내기는 예전과 똑같이 검증됩니다.

1. vault를 멈춥니다.
2. 최신 heads 체크포인트와 공동서명을 받습니다(위트니스에 한 번 제출합니다).
   `node scripts/transparency.mjs heads-checkpoint --config transparency.json --key signing-private.pem --data-dir /data --out heads.json`
3. 서명기를 `init`한 뒤 그 체크포인트에 묶인 승인을 만듭니다. 최근 24시간(`--max-age`) 안의 공동서명이 정족수만큼 있어야 합니다.
   `node scripts/signer.mjs authorize-handover --state-dir /signer/state --checkpoint heads.json --vault-key signing-public.pem --witness "<위트니스 vkey>"`
4. 위트니스마다 서명기 vkey를 heads origin에 **추가**합니다(`witnessctl add-key`). vault 키는 아직 지우지 않습니다.
5. 설정에 `signer`를 넣고 vault를 시작합니다. 서명기의 첫 잎은 마지막 vault 키 잎의 항목을 다시 담아 서명기 키로 다시 앵커합니다.
6. 첫 서명기 체크포인트가 공동서명되면(`status().witnesses`가 `consistent`) 위트니스에서 vault 키를 **지웁니다**(`witnessctl del-key`,
   개발용 위트니스는 `scripts/witness.mjs del-key`). 이 단계 전까지는 vault 키 체크포인트도 공동서명되므로 공격 창이 열려 있습니다.
   서명기 키를 고정한 검증자는 그 체크포인트를 받아들이지 않지만, 위트니스가 그 잎을 먼저 받으면 서명기 이력과 갈라져 heads 로그가 막힙니다.
7. 검증자에게 서명기 vkey를 `--heads-key`로 배포합니다. 핸드오버 이전 내보내기는 `--heads-key`를 줘도 vault 키 서명이므로 `vault_host`가 아닙니다.

litewitness로 이 순서를 시험합니다(`test/litewitness-interop.test.mjs`의 두 번째 공격 시험). 넘긴 뒤에는 같은 공격에 litewitness가 403을,
서명기가 422 `rollback`을 돌려줍니다.

## 키 백엔드

| 백엔드 | 인수 | 쓰임 |
|---|---|---|
| `file` | `--key-file KEY.pem` | 서명기 볼륨의 PKCS#8 PEM. 파일 소유자가 서명기 사용자이면 600이어야 합니다(OpenSSH와 같은 규칙). Kubernetes Secret처럼 root 소유·그룹 읽기(0440) 파일은 받아들이므로 그 볼륨은 서명기 컨테이너에만 마운트합니다. |
| `ssh-agent` | `--fingerprint SHA256:... [--agent-socket 경로]` | ssh-agent 프로토콜(RFC 9987). `ssh-ed25519` 키만, 지문으로 고릅니다. OpenSSH agent + PKCS#11, sigsum-agent + YubiHSM, YubiKey, OS 키 저장소로 가는 길입니다. |
| `command` | `--public-key PUB.pem --command '["prog","arg"]' [--command-output auto\|raw\|base64] [--command-timeout-ms N]` | 셸 없이 execFile로 실행하고 메시지를 stdin으로 주며, stdout의 64바이트 서명(raw 또는 base64)을 받습니다. 기본 제한 시간 15초. |

`init`·`serve`·`rotate-key`는 같은 백엔드 인수를 받습니다. ssh-agent와 command 백엔드는 공개 키를 agent·명령에서 받아 상태에 기록하므로,
vault의 `publicKeyFile`은 `node scripts/signer.mjs public-key --state-dir /signer/state --out signer-public.pem`으로 만듭니다.

### ssh-agent 준비

Linux:

```bash
eval "$(ssh-agent -s)"                       # 또는 systemd user 서비스의 SSH_AUTH_SOCK
ssh-keygen -t ed25519 -f signer-ed25519 -N ''  # 소프트웨어 키. 하드웨어는 아래 줄
ssh-add signer-ed25519                        # PKCS#11: ssh-add -s /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so
ssh-keygen -lf signer-ed25519.pub             # SHA256:... 지문
node scripts/signer.mjs init --state-dir /signer/state --backend ssh-agent --fingerprint SHA256:...
```

Windows(OpenSSH Authentication Agent 서비스, `\\.\pipe\openssh-ssh-agent`가 기본값):

```powershell
Get-Service ssh-agent | Set-Service -StartupType Automatic; Start-Service ssh-agent   # 관리자 PowerShell
ssh-keygen -t ed25519 -f $HOME\.ssh\evidscope-signer
ssh-add $HOME\.ssh\evidscope-signer
ssh-keygen -lf $HOME\.ssh\evidscope-signer.pub
node scripts/signer.mjs init --state-dir C:\evidscope-signer\state --backend ssh-agent --fingerprint SHA256:...
```

agent는 같은 사용자의 다른 프로세스도 서명에 쓸 수 있습니다. 서명기를 vault와 다른 계정·호스트에서 실행하고, 하드웨어 키는 터치 확인을
끄지 않으면 서명마다 사람이 눌러야 하므로 무인 운영에는 맞지 않습니다.

### 클라우드 KMS 명령 예시(실제 서비스로 시험하지 않음)

아래 두 예시는 공식 CLI의 문서에 맞춰 적었지만 **실제 AWS·GCP 서비스로 실행해 보지 않았습니다.** 시작할 때의 자기 시험이 잘못된 알고리즘과
키를 걸러 내므로, 먼저 `init`으로 확인합니다. 서명기 호스트에서 KMS 엔드포인트로 나가는 통신이 필요합니다.

AWS KMS(`ECC_NIST_EDWARDS25519` 키, 순수 Ed25519는 `ED25519_SHA_512` + `--message-type RAW`만 씁니다. prehash인
`ED25519_PH_SHA_512`나 `DIGEST`는 자기 시험에서 실패합니다):

```bash
aws kms get-public-key --key-id "$KEY_ARN" --query PublicKey --output text | base64 -d > signer-public.der
openssl pkey -pubin -inform DER -in signer-public.der -out signer-public.pem
node scripts/signer.mjs init --state-dir /signer/state --backend command --public-key signer-public.pem --command-output base64 \
  --command '["aws","kms","sign","--key-id","'"$KEY_ARN"'","--message","fileb:///dev/stdin","--message-type","RAW","--signing-algorithm","ED25519_SHA_512","--query","Signature","--output","text"]'
```

GCP Cloud KMS(`EC_SIGN_ED25519`, 보호 수준 SOFTWARE, 다이제스트가 아니라 데이터 자체에 서명):

```bash
gcloud kms keys versions get-public-key 1 --key heads-signer --keyring evidscope --location global --output-file signer-public.pem
node scripts/signer.mjs init --state-dir /signer/state --backend command --public-key signer-public.pem --command-output raw \
  --command '["gcloud","kms","asymmetric-sign","--version","1","--key","heads-signer","--keyring","evidscope","--location","global","--input-file","/dev/stdin","--signature-file","/dev/stdout"]'
```

## 키 교체

같은 heads origin을 유지하고 키만 바꿉니다.

1. 새 키를 만듭니다(파일, agent, KMS).
2. 위트니스마다 새 vkey를 heads origin에 추가합니다(`signer.mjs vkey --public-key NEW.pem --origin-base ...`로 확인).
3. 서명기를 멈추고 `node scripts/signer.mjs rotate-key --state-dir /signer/state <새 백엔드 인수>`를 실행한 뒤 새 백엔드로 `serve`합니다.
4. vault 설정의 `publicKeyFile`을 새 키로, `previousPublicKeyFiles`에 예전 키를 넣고 vault를 다시 시작합니다.
5. 새 키 체크포인트가 공동서명되면 위트니스에서 예전 vkey를 지웁니다.
6. 검증자는 `--heads-key`에 새 키와 예전 키를 함께 줍니다(예전 내보내기용).

## 복구 epoch

백업에서 복구하면 새 origin base로 epoch를 엽니다([vault 복구](vault-recovery.md)). 서명기는 운영자의 승인 없이 새 origin에 서명하지 않으며,
첫 잎을 서명할 때 예전 heads origin을 은퇴(`retired`)시킵니다. 은퇴한 origin을 이어 쓰려는 예전 vault는 시작 검사에서 `fork`로 거부됩니다.

1. 서명기의 예전 origin head를 받습니다: `node scripts/signer.mjs head --state-dir /signer/state --origin-base OLD --out signer-head.json`
2. 복구할 때 `--signer-head signer-head.json`을 줍니다. 서명기 head가 아카이브의 heads 크기와 같으면 그것만으로 신선도를 확인하고, 더 크면
   `--frontier-transparency`(복구 frontier의 companion)가 그 크기를 덮어야 합니다. 아카이브보다 작거나 같은 크기에서 루트가 다르면 거부합니다.
   head 파일에는 시각이 없으므로 복구 직전에 서명기에서 직접 받습니다. 오래된 head 파일은 신선도 확인을 속일 수 있지만, 4단계의
   `losses`와 감사 줄은 서명기의 현재 상태로 계산하므로 실제 손실은 승인할 때 드러납니다.
3. 복구된 데이터 디렉터리에서 tenant별 복구 범위를 뽑습니다:
   `node scripts/transparency.mjs epoch-claims --config NEW.json --key signing-private.pem --data-dir RESTORED --out claims.json`
4. 서명기에서 승인합니다. 출력의 `losses`(서명했던 크기보다 작게 복구된 tenant 로그)를 확인합니다.
   `node scripts/signer.mjs authorize-epoch --state-dir /signer/state --from-base OLD --to-base NEW --restored claims.json [--accept-loss "사유"] [--drop-log LOG_ID]`
   `claims.json`은 vault가 만든 값입니다. 그래서 `authorize-epoch`는 서명한 크기와 같은 크기에서 루트가 다른 주장을 `fork`로 거부하고,
   서명한 크기보다 큰 주장은 승인에 넣지 않습니다(그 로그는 서명한 항목에서 일관성 증명으로 이어져야 합니다). 서명기도 서명한 크기보다
   작은 복구 범위만 손실로 받아들입니다. `--restored` 없이 `--accept-loss`만 주면 모든 tenant 로그가 어떤 이력으로든 다시 시작할 수 있으므로
   `losses`에 모든 로그가 `restoredSize: null`로 나옵니다. 2라운드에는 두 경우 모두 `losses: []`로 보였습니다(3라운드 재감사,
   `test/signer-epoch-claims.test.mjs`).
5. 새 heads origin을 위트니스에 등록하고(서명기 vkey) 복구된 vault를 시작합니다. 승인 전에는 `status().signer.status`가 `unauthorized`이고
   `epochFrom`에 예전 origin base가 나오며, 승인 뒤 다음 시도(`refreshSeconds`)에 이어집니다.
6. 검증자는 `--origin-base NEW`로 다시 고정합니다. 서명기 키는 origin 이름과 상관없이 인정하므로 `--heads-key`는 그대로 씁니다.
7. 새 origin의 첫 서명기 체크포인트가 공동서명되면 위트니스마다 예전 heads origin에서 서명기 키를 지웁니다
   (`witnessctl del-key -origin OLD/heads -key <예전 origin 이름의 서명기 vkey>`, 개발용 위트니스는 `scripts/witness.mjs del-key`).
   위트니스는 이미 본 크기의 체크포인트를 다시 받으면 새 시각으로 공동서명하므로, 지우지 않으면 vault 호스트 장악자가 은퇴한 origin의
   마지막 체크포인트를 언제든 신선하게 만들어 epoch 이전의 내보내기를 아직 예전 base를 고정한 검증자에게 `vault_host`로 보일 수
   있습니다(3라운드 재감사에서 재현, base를 고정하지 않은 검증은 이제 `vault_host`를 주지 않습니다). 지운 뒤 `maxStalenessSeconds`(기본 24시간)가 지나면 예전
   origin의 앵커는 더 이상 신선하지 않습니다.

서명기가 예전 origin을 서명한 적이 없으면(핸드오버 이전 백업 등) `authorize-epoch` 대신 `authorize-genesis --origin-base NEW`로 새 origin을
시작할 수 있습니다(코드 경로만 있고 별도 시험은 없습니다). 이때 예전 origin과의 연결은 vault 키로 서명한 epoch 기록만 보증합니다.

## 배포

### Kubernetes

`deploy/kubernetes.json`은 그대로 두고 그 위에 정적 overlay를 렌더링합니다(배포·클러스터 검증은 하지 않습니다).

```powershell
node deploy/heads-signer-overlay.mjs --variant sidecar --output deploy/rendered-heads-signer.json
node deploy/heads-signer-overlay.mjs --variant deployment --output deploy/rendered-heads-signer.json
```

- 두 방식 모두 vault에 `TRANSPARENCY_CONFIG_FILE`(Secret `vault-transparency`), 데이터 PVC와 다른 pin PVC(`vault-transparency-pin`),
  서명기 공개 키(ConfigMap `heads-signer-public`)를 붙입니다. 서명기는 자기 상태 PVC(`heads-signer-state`)와 키 Secret(`heads-signer-key`)만
  마운트하고, vault 데이터·서명 키·데이터 키·설정 Secret은 마운트하지 않습니다. 렌더러가 이 분리를 출력물에서 다시 확인합니다.
- `sidecar`: vault Pod 안의 `heads-signer` 컨테이너(uid 1001)입니다. 두 컨테이너만 마운트하는 메모리 emptyDir의 Unix 소켓으로 연결합니다.
  vault 컨테이너 장악은 막지만 노드 장악은 막지 못합니다.
- `deployment`: replica 1·Recreate의 별도 Deployment로, vault와 같은 노드에 놓이지 않도록 anti-affinity를 겁니다. TLS(`heads-signer-tls`,
  SAN `heads-signer.evidscope.svc`)와 bearer token(`heads-signer-token`)으로 연결하고, NetworkPolicy가 vault Pod의 8443 접속만 엽니다.
  서명기는 나가는 통신이 없습니다(KMS 명령 백엔드를 쓰면 그 목적지를 따로 열어야 합니다). cluster-admin·etcd 장악은 여전히 키에 닿습니다.
- init 컨테이너가 `signer.mjs init --if-missing`으로 처음 한 번 상태를 만들고, 이후에는 키가 상태와 같은지만 확인합니다. 승인은 실행 중인
  서명기에서 만듭니다: `kubectl -n evidscope exec deploy/vault -c heads-signer -- node scripts/signer.mjs authorize-genesis --state-dir /signer-state --origin-base ...`
- 렌더 결과(receipt)가 만들어야 할 Secret·ConfigMap 이름과 `transparency.json`의 `signer` 조각을 알려 줍니다. vault에서 위트니스로 나가는
  egress는 이 overlay가 열지 않습니다.
- kubelet은 fsGroup이 있으면 Secret 파일을 `root:fsGroup 0440`으로 만들기 때문에 `defaultMode`로 0400을 강제할 수 없습니다. 그래서 키 볼륨을
  서명기 컨테이너에만 마운트하고, 별도 Deployment는 자기 uid·gid·fsGroup(1001)을 씁니다.

### 로컬(Windows 파일럿)

```powershell
npm run upgrade:local -- --heads-signer                          # 또는 --heads-signer-port 8090 (loopback TCP + token)
npm start                                                         # 서명기를 vault보다 먼저 시작하고 함께 멈춥니다
```

`upgrade-local`은 `.local/signer/`에 키·상태·승인을 만들고(heads 로그가 비어 있으면 genesis, 아니면 handover), `.local/transparency.json`에
`signer`를 넣고, 런처가 읽는 `.local/signer/serve.json`을 씁니다. Linux·macOS는 Unix 소켓, Windows는 named pipe와 token을 기본으로 씁니다.
`serve.json`의 인수를 `--backend ssh-agent --fingerprint SHA256:...`로 바꾸면 Windows OpenSSH agent의 키를 씁니다. 같은 PC·같은 계정에서
도는 서명기는 프로세스만 나눌 뿐 호스트 장악을 막지 못합니다. 기능 확인용입니다.

## 장애와 운영

| 보고 | 의미 | 조치 |
|---|---|---|
| `signer.status: unreachable` | 서명기에 연결하지 못했습니다. heads 체크포인트가 늘지 않습니다. 격리하지 않습니다. | 서명기 프로세스·소켓·token·TLS를 확인합니다. |
| `unauthorized` | 처음 보는 heads origin에 대한 승인이 없습니다. `refreshSeconds`마다 다시 묻습니다. | `authorize-genesis`·`authorize-handover`·`authorize-epoch` 중 맞는 것을 만듭니다. |
| `out_of_sync` | vault와 서명기가 아는 heads 크기가 다릅니다. 서명기가 한 잎 앞이면 그 잎을 받아 저장합니다(응답을 잃은 경우). | 그 밖의 차이는 DB나 서명기 상태가 되돌려진 것입니다. 경위를 조사합니다. |
| `rollback`·`fork`·`tenant_removal` | 서명기가 vault의 잎을 거부했습니다. 위반으로 기록하며 enforce 모드는 격리합니다. | DB 변조나 vault 호스트 장악을 의심합니다. 서명기 감사 로그와 대조합니다. |
| 시작 거부: `behind the heads signer ... (rollback)` | DB의 heads 로그가 서명기보다 짧습니다. 예전 DB 사본입니다. | 정상 복구라면 복구 epoch로 엽니다. |
| 시작 거부: `holds no state ... although the heads log carries its checkpoints` | 서명기 상태를 잃었습니다. | 서명기 상태를 백업에서 복원합니다. 새로 `init`하지 않습니다. |
| `retired` | 복구 epoch 뒤 은퇴한 origin을 이어 쓰려 했습니다. | 은퇴한 vault를 멈춥니다. |
| `state_changed` | 서명기 상태 파일이 실행 중 바뀌었습니다. | 같은 상태를 쓰는 다른 서명기를 멈추고 이 서명기를 다시 시작합니다. |
| `backend` | 키 백엔드가 서명하지 못했거나 서명이 공개 키로 검증되지 않았습니다. | agent·KMS 상태를 확인합니다. |
| `rate_limited`·`too_large` | 속도·크기 제한입니다. | 정상 운영에서는 나오지 않습니다. 반복되면 vault 호스트를 의심합니다. |

- 상태 확인: `node scripts/signer.mjs status --state-dir ...`(origin별 크기·대기 승인), `node scripts/transparency.mjs status ... --probe`(vault 쪽
  `signer: {known, status, size}`), `node scripts/signer.mjs audit --state-dir ... --verify`(감사 로그 해시 체인).
- **서명기 상태 백업.** `state.json`, `audit.log`, `authorizations/`를 서명기 쪽 저장소에 백업합니다. 오래된 백업으로 복원하면 서명기가 vault보다
  뒤에 있어 vault가 `inconsistent`로 시작을 거부합니다. 최신 백업을 쓰거나 복구 epoch로 엽니다. 상태를 잃은 채 `init`을 다시 하면 이전 origin을
  이어 서명할 수 없습니다. `init`은 `audit.log`가 남아 있으면 새로 만들기를 거부합니다.
- 승인은 `signer.mjs authorizations`로 보고 `revoke --id`로 취소합니다. 같은 origin에 대기 승인이 둘 이상이면 서명기가 둘 다 쓰지 않습니다.

## 한계

- 서명기는 앵커된 이력만 지킵니다. 장악된 vault가 앵커를 멈추면 그 뒤 기록은 보호받지 못합니다(위 "여전히 할 수 있는 일").
- 핸드오버는 vault 키로 서명된 마지막 heads 체크포인트에서 시작합니다. 핸드오버 전에 이미 vault 호스트가 장악되어 공동서명된 되돌리기는
  되돌리지 못합니다. 보호는 핸드오버 시점부터입니다.
- 서명과 거부마다 감사 줄을 남기므로, 장악된 vault는 속도 제한(기본 분당 60건) 안에서 서명기 볼륨의 감사 로그를 계속 키울 수 있습니다.
  볼륨 사용량을 감시합니다. 디스크가 차면 서명이 멈출 뿐 잘못된 서명은 나오지 않습니다.
- tenant 로그와 원장 체크포인트는 여전히 vault 키로 서명합니다. tenant 단위로 위트니스까지 묶으려면 `witnessTenantLogs`를 함께 씁니다.
- 1라운드 검증기(cf45e19)는 vault 키 서명만 heads 앵커로 받아들이므로, 서명기로 서명한 새 내보내기는 이 라운드의 검증기로 검증해야 합니다.
  vault 키로 서명된 예전 내보내기는 두 검증기 모두에서 예전과 같습니다.
- 위트니스에서 vault 키를 지우지 않으면 vault 키 heads 체크포인트도 계속 공동서명됩니다. 고정 검증자는 거부하지만 heads 로그가 갈라질 수 있습니다.
- named pipe 경로는 Linux에서 시험하지 못했습니다(소켓·loopback TCP·TLS는 시험). KMS 예시는 실제 서비스로 시험하지 않았습니다. Kubernetes
  overlay는 정적 렌더링만 확인했습니다.
- 복구 epoch의 복구 범위는 vault가 주는 값이며 서명기는 운영자 승인에 묶인 범위만 받아들입니다. 승인의 타당성은 운영자의 검토에 달려 있습니다.
