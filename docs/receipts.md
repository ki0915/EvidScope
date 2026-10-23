# 표준 영수증: DSSE in-toto 증명과 c2sp.org/tlog-proof

> 2026-10-07 개선 2라운드에서 추가한 기능입니다. 투명성 로그와 위트니스는 [투명성 로그·위트니스 운영 가이드](transparency-log.md)를 먼저 보세요.

## 무엇을 위한 것인가

감사인이나 규제기관이 EvidScope 증거를 **이미 신뢰하는 형식과 도구로, 운영자를 믿지 않고, EvidScope 스택을 설치하지 않고**
확인하게 하는 출력입니다. 기존 출력(`evidscope-checkpoint-v1`, 내보내기 묶음, `evidscope-case-report-v1`)과 그 서명은 바뀌지 않습니다.
같은 바이트를 표준 봉투로 한 번 더 감싸거나, 레코드 하나를 표준 포함 증명으로 떼어 주는 추가 출력이며 요청할 때만 만듭니다.

| 출력 | 얻는 곳 | 형식 |
|---|---|---|
| 내보내기 증명 | `GET /api/export?attest=intoto` | `evidscope-attested-file-v1`: `file`(이름·SHA-256·내용)과 DSSE 봉투 |
| 사건 보고서 증명 | `GET /api/cases/:id/report?attest=intoto` | 같음 |
| 레코드 영수증 | `GET /api/receipts/record?seq=N`, `node scripts/receipts.mjs record` | `evidscope-record-receipt-v1`: 레코드 본문, `c2sp.org/tlog-proof@v1`, `c2sp.org/tlog-policy` |
| tenant 로그 정책 | `node scripts/receipts.mjs policy` | `c2sp.org/tlog-policy` |
| 검증기 | `scripts/evidscope-verify.mjs`, 별도 배포 묶음 `evidscope-verify-<버전>.tar.gz` | 의존성 없는 Node.js 24 CLI |

API는 다른 조회와 같이 auditor·reviewer·admin만 부르며 접근 기록에 남습니다. `attest`에 `intoto` 말고 다른 값을 주면 400입니다.

## DSSE in-toto 증명

봉투는 [DSSE v1](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md)이고 내용은
[in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md)입니다.

```json
{"payloadType": "application/vnd.in-toto+json", "payload": "<base64(statement)>",
 "signatures": [{"keyid": "<vault 공개키 SPKI DER의 SHA-256 hex>", "sig": "<base64(Ed25519)>"}]}
```

- 서명은 vault 서명 키(Ed25519)로 PAE `DSSEv1 <len(type)> <type> <len(body)> <body>`에 합니다. `keyid`는 보고서의
  `publicKeyFingerprint`와 같은 관례이지만 힌트일 뿐이며, 검증자는 밖에서 받은 키로만 확인합니다.
- 서명은 `src/attestation-signer.mjs`의 함수 하나를 거칩니다. 별도 서명 프로세스가 생기면 그 함수만 바꾸면 되고, vault는 돌려받은
  서명을 공개키로 다시 확인한 뒤에만 응답합니다.
- statement는 키를 정렬한 canonical JSON입니다. `subject`는 하나이고 `name`은 파일 이름(`evidscope-export-<레코드 수>.json`,
  `evidscope-case-<사건 ID>-<레코드 수>.json`), `digest.sha256`은 응답 `file.content`의 UTF-8 바이트 SHA-256입니다. 이 바이트는 같은
  요청을 `attest` 없이 보냈을 때의 응답 본문과 같은 직렬화입니다.
- predicate의 값은 `issuedAt`(내보내기)과 `tlogProofs`를 빼면 모두 대상 파일에서 다시 계산되는 사실입니다. 검증기는 다시 계산해
  하나라도 다르면 거부하고, 아래 표에 없는 필드가 있어도 거부합니다.

<a id="export-v1"></a>

### 내보내기: `https://github.com/ki0915/EvidScope/blob/main/docs/receipts.md#export-v1`

| 필드 | 내용 |
|---|---|
| `tenant`, `checkpoint`, `records` | 묶음의 tenant, `evidscope-checkpoint-v1` 그대로, 레코드 수 |
| `requirementResults` | 시스템·요구사항별 최신 서명 `assessment` 레코드(seq, recordHash, applicability, assessment, legalReview, nextReviewAt)와 그 평가의 최신 `governance_legal_review`(seq, recordHash, decision). 사람이 기록한 평가이며 자동 판정이 아닙니다. |
| `policyVersion` | `applicability`(최신 `catalog` 레코드의 policyVersion·catalogHash·requirementsHash·seq·recordHash), `rules`(룰별 최신 레코드와 active 버전), `evaluationEngines` |
| `tlog` | `origin`, `checkpoint`(내보낼 때의 tenant 로그 체크포인트 note), `cosignedCheckpoint`(위트니스가 공동서명한 가장 새로운 tenant 체크포인트 note, 공동서명 포함) 또는 `null` |
| `tlogProofs` | `[{seq, hash, proof}]`: 공동서명 체크포인트와 최신 체크포인트 각각의 마지막 레코드에 대한 `c2sp.org/tlog-proof@v1` |
| `issuedAt` | vault 시계로 적은 발급 시각. 대상 파일로 확인할 수 없는 유일한 값입니다. |

<a id="case-report-v1"></a>

### 사건 보고서: `https://github.com/ki0915/EvidScope/blob/main/docs/receipts.md#case-report-v1`

| 필드 | 내용 |
|---|---|
| `tenant`, `caseId`, `actionId`, `checkpoint` | 보고서 스냅샷의 값 |
| `issuedAt` | 보고서 `snapshot.exportedAt` |
| `reportHash` | `canonical({format, snapshot})`의 SHA-256. 보고서 서명이 덮는 바이트입니다. |
| `requirementResults` | `review`(검토 상태, contextHash, 최신 판단의 id·conclusion·nextReviewAt)와 `evaluations`(id, version, status, authority, effect, findings의 code·severity) |
| `policyVersion` | `evaluationEngines`, `rules`(평가 재현 입력의 룰 id·version), `eventPolicyVersions`, `analysis` |
| `tlog`, `tlogProofs` | 내보내기와 같은 형식. 행동의 이벤트 레코드마다, 그리고 보고서 체크포인트의 head 레코드에 대한 증명 |

`tlogProofs`의 증명은 레코드가 위트니스 공동서명 체크포인트에 들어 있으면 그 체크포인트를, 아니면 최신 체크포인트를 씁니다.
투명성 로그가 꺼져 있으면 `tlog`는 `null`이고 `tlogProofs`는 빈 배열입니다.

## 레코드 영수증

`GET /api/receipts/record?seq=N`은 요청한 tenant 원장의 레코드 하나에 대한 영수증입니다. 투명성 모드가 `off`이면 409, 아직 서명된
tenant 로그에 들어가지 않은 seq는 404입니다.

| 필드 | 내용 |
|---|---|
| `record` | 원장 `body` 그대로(canonical JSON, `hash` 필드 없음). 이 텍스트의 SHA-256이 레코드 해시입니다. |
| `proof` | `c2sp.org/tlog-proof@v1`. 잎은 RFC 6962 `SHA-256(0x00 ‖ 레코드 해시)`, index는 `seq - 1`입니다. |
| `policy` | 이 배포의 tenant 로그 `c2sp.org/tlog-policy` |
| `checkpointSize`, `quorum`, `quorumMet`, `witnessed`, `cosignatures` | vault가 정책으로 검증한 결과 요약. 감사인은 다시 계산합니다. |

체크포인트는 레코드를 포함하는 가장 새로운 위트니스 공동서명 tenant 체크포인트(정족수를 채운 것 우선)를 쓰고, 없으면 vault가 서명한
최신 tenant 체크포인트를 씁니다. vault는 상태 행과 레코드 해시, 원장 잎이 서명된 루트로 접히는지 확인하고, 만든 영수증을 정책으로
검증한 뒤에 응답합니다. 맞지 않으면 409이며 영수증을 만들지 않습니다.

운영자는 같은 영수증을 데이터 디렉터리에서 읽기 전용으로 만들 수 있습니다. 공개키만 있으면 되고, 결과 파일은 API 응답을 푼 것과
바이트 단위로 같습니다.

```powershell
node scripts/receipts.mjs record --config transparency.json --key signing-public.pem --data-dir .local/data --tenant <tenant> --seq 17 --out receipts
node scripts/receipts.mjs policy --config transparency.json --key signing-public.pem --tenant <tenant>
```

### tlog-policy

vault가 내는 정책은 [c2sp.org/tlog-policy](https://c2sp.org/tlog-policy) 형식입니다.

```text
# c2sp.org/tlog-policy for the EvidScope tenant log evidscope.example.com/prod/t/<tenant 해시>
# Compare these keys with ones obtained out of band: a policy received from the vault is not a trust anchor.
log evidscope.example.com/prod/t/<tenant 해시>+<key id>+<vault 키>
witness witness-1 <위트니스 vkey>
quorum witness-1
```

- 위트니스가 둘 이상이면 `group witnesses <정족수> witness-1 witness-2 ...`와 `quorum witnesses`를 씁니다.
- `witnessTenantLogs`가 꺼져 있으면 위트니스는 heads 로그만 공동서명합니다. heads 공동서명은 tlog-proof에 담을 수 없으므로 정책은
  `quorum none`이고, 영수증은 vault 키 서명만 증명합니다.
- 검증기의 정책 해석은 명세를 따릅니다. 명세는 "나열한 로그 중 origin과 키 이름이 같은 하나"의 서명을, torchwood `ParsePolicy`는
  "모든 로그"의 서명을 요구합니다. vault 정책은 로그를 하나만 적으므로 양쪽 결과가 같습니다. 로그 키는 Ed25519(0x01)만 받습니다.
- vault가 준 정책은 신뢰 기준이 아닙니다. 감사인은 밖에서 받은 vault 키·위트니스 키로 정책을 직접 쓰거나 대조합니다.

## 무엇을 증명하고 무엇을 증명하지 않는가

| 영수증 | 증명하는 것 | 증명하지 않는 것 |
|---|---|---|
| DSSE 내보내기 | 고정한 vault 키가 정확히 이 바이트를 발급했다. 묶음의 해시 체인·서명·체크포인트가 맞다. predicate의 요구사항 결과·정책 버전·체크포인트 참조는 묶음에서 다시 계산한 값이다. 정족수를 채운 증명이 있으면 위트니스가 본 체크포인트까지 레코드가 들어 있다. | 레코드 내용이 사실인지(출처가 보고한 내용입니다), 체크포인트 이후의 기록, `issuedAt`의 정확성, 사람 평가·법적 판단의 옳고 그름 |
| DSSE 사건 보고서 | 위와 같고, `reportHash`로 보고서 서명 대상과 묶인다. | 위와 같고, 보고서에 들어가지 않은 이벤트 |
| 레코드 영수증 | 레코드 본문이 vault가 서명한 tenant 로그 체크포인트에 들어 있다. 정족수를 채웠으면 위트니스가 그 체크포인트를 공동서명했으므로 같은 크기의 다른 이력을 보여 주는 분기를 위트니스 몰래 만들 수 없다. | 레코드 내용이 사실인지, 그 뒤 다른 레코드가 무엇인지. `quorum none`이면 vault 서명 키를 가진 사람의 분기 |

DSSE 서명만 확인하는 일반 도구는 "vault 키가 이 바이트와 predicate를 발급했다"까지만 보여 줍니다. predicate가 대상 파일과
맞는지, 묶음 자체의 체인이 맞는지는 아래 검증기가 다시 계산해야 확인됩니다.

## 감사인 절차

### 묶음 검증기

1. 별도 배포 묶음과 그 SHA-256을 vault와 다른 경로로 받고 `sha256sum -c`로 확인합니다. 묶음 안의 `README.md`(한국어)와
   `README.en.md`(영어)가 같은 절차를 설명합니다.
2. vault 공개키, 위트니스 vkey와 정족수, origin base를 밖에서 받습니다.
3. API 응답을 JSON 파일로 저장해 풀고 검증합니다. 종료 코드는 0 확인됨, 1 확인되지 않음, 2 사용법 오류입니다.

```powershell
node evidscope-verify.mjs unpack export-response.json --out evidence
node evidscope-verify.mjs dsse evidence/evidscope-export-42.json.intoto.json evidence/evidscope-export-42.json vault-public.pem `
  --witness "<위트니스 vkey>" --quorum 1 --origin-base evidscope.example.com/prod --require-witnessed
node evidscope-verify.mjs unpack record-response.json --out evidence
node evidscope-verify.mjs tlog-proof evidence/<이름>.tlog-proof evidence/<이름>.json --key vault-public.pem `
  --witness "<위트니스 vkey>" --quorum 1 --origin-base evidscope.example.com/prod
node evidscope-verify.mjs bundle export.json vault-public.pem --attestation export.json.intoto.json --replay
```

- `dsse`는 서명, subject digest, 대상 파일 검증(`bundle`/`report`와 같은 검사), predicate 재계산, 포함된 tlog-proof를 차례로
  확인합니다. `--policy 파일`을 주면 그 정책으로, 아니면 `--witness`·`--quorum`으로 만든 정책으로 증명을 확인하고,
  `--require-witnessed`는 정족수를 채운 증명이 하나도 없으면 실패합니다.
- `tlog-proof`는 `--policy` 또는 `--key`(+ `--witness`, `--quorum`) 중 하나가 필요합니다. 둘 다 주면 정책이 그 origin에 적은 로그 키가
  모두 고정한 키여야 합니다. 2라운드 검증기는 첫 로그 줄만 비교해서, 같은 origin에 다른 키를 한 줄 더 적은 정책과 그 키로 서명한 가짜
  레코드를 받아들였습니다(3라운드 재감사, `test/tlog-policy-pinned-key.test.mjs`). 레코드 파일은 영수증의 `record` 텍스트 그대로여야
  하며, 공백 하나만 바뀌어도 거부합니다.
- 저장소의 `scripts/evidscope-verify.mjs`도 같은 명령입니다. 기존 `scripts/verify.mjs`와 `scripts/verify-case-report.mjs`도
  `--attestation <파일>.intoto.json`을 받고, 주지 않으면 출력이 예전과 같습니다.

### 다른 도구로 확인하기

응답에서 파일을 꺼낼 때는 바이트를 바꾸지 않아야 합니다.

```sh
jq -j .file.content export-response.json > evidscope-export-42.json   # sha256sum 값이 file.sha256, subject digest와 같아야 합니다
jq .envelope export-response.json > evidscope-export-42.json.intoto.json
jq -j .record record-response.json > record.json
jq -j .proof record-response.json > record.tlog-proof
```

- DSSE: PAE와 Ed25519를 지원하는 어떤 DSSE 구현으로도 서명을 확인할 수 있습니다. 표준 라이브러리만 쓰는 독립 구현 예는
  `test/fixtures/interop-go/dsse-verify`입니다.
- tlog-proof: [torchwood](https://pkg.go.dev/filippo.io/torchwood)의
  `VerifyProof(ParsePolicy(정책), tlog.RecordHash(SHA-256(record.json)), proof)`. 예는 `test/fixtures/interop-go/tlog-verify`입니다.
- 체크포인트 note: [`golang.org/x/mod/sumdb/note`](https://pkg.go.dev/golang.org/x/mod/sumdb/note)의 `note.Open`과
  `note.NewVerifier(<tenant 로그 vkey>)`, 위트니스 공동서명은 torchwood `NewCosignatureVerifier`로 확인합니다.

`EVIDSCOPE_GO_BIN`(그리고 그 Go의 `GOPATH`·`GOMODCACHE`·`GOCACHE`)을 설정하면 `test/receipts-interop.test.mjs`가 두 Go 프로그램을
오프라인(`GOPROXY=off`)으로 빌드해 vault가 낸 영수증과 변조본을 확인합니다. Go가 없으면 건너뛰고, torchwood 모듈이 로컬 캐시에
없으면 그 시험만 건너뜁니다.

## 검증기 묶음 만들기

```powershell
node scripts/package-verifier.mjs --out releases
```

`releases/evidscope-verify-<버전>/` 폴더와 `.tar.gz`, `.tar.gz.sha256`을 만들고 이미 있으면 덮어쓰지 않습니다. `src/`,
`deploy/verifier/`, `package.json`에 커밋하지 않은 변경이 있으면 거부합니다(`--allow-dirty`로만 허용). 폴더에는 진입점
`evidscope-verify.mjs`, `src/verify-cli.mjs`가 가져오는 모듈만, 의존성 없는 `package.json`, `deploy/verifier/`의 README 두 개,
`sha256sum -c` 형식의 `SHA256SUMS`가 들어갑니다. 포함 모듈은 import를 따라가며 정하고, 네트워크·프로세스 모듈(`net`, `http`,
`child_process` 등)과 동적 import는 거부합니다. tar 항목의 소유자·권한·시각(`SOURCE_DATE_EPOCH`, 기본 0)을 고정하므로 같은 소스를
같은 Node.js 버전으로 묶으면 같은 압축 파일이 나옵니다.

`test/verifier-package.test.mjs`는 압축 파일을 풀어 저장소 밖 임시 폴더에서 실행합니다. Node.js 권한 모델로 묶음과 증거 파일만
읽게 하고, 환경 변수를 비우고, 네트워크 사용 시 프로세스를 끝내는 가드를 먼저 올린 상태에서 정상·변조 영수증을 확인합니다.
`package.json`은 공개 배포 전까지 `private: true`, `license: UNLICENSED`입니다. 공개하려면 저장소 소유자가 라이선스를 정해야 합니다.

## COSE 영수증(RFC 9942)을 만들지 않은 이유

RFC 9942 영수증은 CBOR·COSE 인코더와 검증기를 의존성 없이 새로 써야 하고, 이 환경에는 상호운용을 확인할 도구가 없습니다.
같은 포함 증명은 tlog-proof가 표준 형식으로 제공하므로 이번 라운드에서는 만들지 않았습니다.

## 현재 한계

- 내보내기 predicate의 `issuedAt`은 vault 시계입니다. 외부 시각 봉인이 아닙니다.
- 증명은 내보내거나 요청한 시점의 체크포인트까지만 다룹니다. 그 뒤 레코드가 지워지지 않았다는 것은 위트니스가 공동서명한 이후
  체크포인트와의 일관성으로 따로 확인합니다([투명성 로그](transparency-log.md)).
- `witnessTenantLogs`가 꺼진 배포의 영수증은 `quorum none`입니다. 위트니스 보증이 필요하면 tenant 로그 공동서명을 켜야 합니다.
- 서명은 지금 vault 프로세스 안의 키로 합니다. 별도 서명 프로세스로 옮기는 작업은 `src/attestation-signer.mjs`의 함수 하나만 바꾸면
  되도록 분리해 두었습니다.
