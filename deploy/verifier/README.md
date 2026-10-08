# EvidScope 오프라인 검증기 {{version}}

EvidScope vault가 내준 증거를 **운영자를 믿지 않고, EvidScope를 설치하지 않고, 네트워크 없이** 확인하는 도구입니다.
Node.js 24.15 이상만 있으면 됩니다. 외부 패키지 의존성이 없고, 이 폴더의 파일과 Node.js 내장 모듈만 씁니다.
내장 모듈 중 네트워크·프로세스 실행 모듈(`net`, `http`, `child_process` 등)은 쓰지 않습니다. English: [README.en.md](README.en.md)

확인할 수 있는 것:

| 입력 | 명령 |
|---|---|
| 내보내기 묶음·사건 보고서와 짝을 이루는 DSSE in-toto 증명(`*.intoto.json`) | `dsse` |
| 레코드 하나의 `c2sp.org/tlog-proof@v1` 영수증과 `c2sp.org/tlog-policy` | `tlog-proof` |
| 기존 내보내기 묶음(`GET /api/export`)과 사건 보고서(`GET /api/cases/<id>/report`) | `bundle`, `report` |
| vault API 응답(`?attest=intoto`, `/api/receipts/record`)을 파일로 풀기 | `unpack` |
| 감사인용 증거 묶음(`scripts/evidence-pack.mjs build`가 만든 폴더나 `.tar.gz`) | `pack` |

형식과 URI, 각 영수증이 증명하는 범위는 [docs/receipts.md](https://github.com/ki0915/EvidScope/blob/main/docs/receipts.md)에 있습니다.

## 1. 받은 검증기 확인

압축 파일의 SHA-256은 vault가 아닌 다른 경로(배포 페이지, 서면 등)로 받은 값과 비교하세요. 풀고 나서는 목록으로 파일마다 확인합니다.

```sh
sha256sum -c evidscope-verify-{{version}}.tar.gz.sha256
tar -xzf evidscope-verify-{{version}}.tar.gz && cd evidscope-verify-{{version}}
sha256sum -c SHA256SUMS
```

`SHA256SUMS`는 이 폴더의 모든 파일(자기 자신 제외)을 나열합니다. 같은 소스를 같은 Node.js 버전으로 다시 묶으면 압축 파일까지
바이트 단위로 같습니다(`node scripts/package-verifier.mjs`).

## 2. 신뢰 기준은 밖에서 받습니다

검증 결과는 아래 값을 **vault와 다른 경로로** 받았을 때만 의미가 있습니다. vault가 함께 보낸 정책이나 키는 신뢰 기준이 아닙니다.

- vault 공개키(PEM). DSSE 서명의 `keyid`는 이 키 SPKI DER의 SHA-256입니다:
  `openssl pkey -pubin -in vault-public.pem -outform DER | sha256sum`
- 위트니스 공개키(`--witness`, C2SP vkey)와 정족수(`--quorum`), 또는 이 값을 담은 `c2sp.org/tlog-policy` 파일
- origin base(`--origin-base`, 예: `evidscope.example.com/prod`). tenant 로그 origin은 `<origin base>/t/<tenant 해시>`입니다.

## 3. 사용법

vault API 응답을 저장했다면 먼저 파일로 풉니다. 풀기는 내용의 해시만 확인하며, 기존 파일은 덮어쓰지 않습니다.

```sh
node evidscope-verify.mjs unpack export-response.json --out evidence/
#   evidence/evidscope-export-42.json, evidence/evidscope-export-42.json.intoto.json
node evidscope-verify.mjs unpack record-response.json --out evidence/
#   evidence/evidscope-record-<id>-17.json, .tlog-proof, .tlog-policy
```

DSSE in-toto 증명과 그 대상 파일:

```sh
node evidscope-verify.mjs dsse evidence/evidscope-export-42.json.intoto.json evidence/evidscope-export-42.json vault-public.pem \
  --witness '<WITNESS_VKEY>' --quorum 1 --origin-base evidscope.example.com/prod --require-witnessed
```

레코드 영수증(정책 파일 또는 키·위트니스 플래그 중 하나):

```sh
node evidscope-verify.mjs tlog-proof evidence/evidscope-record-<id>-17.tlog-proof evidence/evidscope-record-<id>-17.json \
  --policy my-policy.tlog-policy --key vault-public.pem --origin-base evidscope.example.com/prod
node evidscope-verify.mjs tlog-proof R.tlog-proof R.json --key vault-public.pem --witness '<WITNESS_VKEY>' --quorum 1
```

기존 형식(`--attestation`으로 짝 증명도 함께 확인):

```sh
node evidscope-verify.mjs bundle export.json vault-public.pem [CHECKPOINT.json] [--attestation export.json.intoto.json] [--replay]
node evidscope-verify.mjs report report.json vault-public.pem [CHECKPOINT.json] [--attestation report.json.intoto.json]
```

감사인용 증거 묶음([docs/evidence-pack.md](https://github.com/ki0915/EvidScope/blob/main/docs/evidence-pack.md)). 묶는 사람의 공개키도
vault 키처럼 묶음과 다른 경로로 받습니다. 검증기는 검증한 증거에서 색인과 두 요약을 다시 만들어 대조하고, 스스로 확인한 검사만
인정합니다.

```sh
node evidscope-verify.mjs pack pack-2026q3.tar.gz vault-public.pem --pack-key builder-public.pem [CHECKPOINT.json] [--tenant T]
```

투명성 플래그(선택): `--witness VKEY`(반복) `--quorum N` `--origin-base BASE` `--max-staleness 초` `--require-transparency`
`--require-tenant-witness` `--heads-key VKEY`(반복, [heads 서명기](https://github.com/ki0915/EvidScope/blob/main/docs/signer.md) 키) `--require-heads-signer`(`--origin-base` 필요).
`vault_host`는 `--origin-base`를 고정했을 때만 나옵니다.
`node evidscope-verify.mjs help`가 전체 사용법을 보여 줍니다.

결과는 표준 출력에 JSON으로 나옵니다. 종료 코드는 `0` 확인됨, `1` 확인되지 않음(이유는 표준 오류), `2` 사용법 오류입니다.

Node.js 권한 모델로 읽을 수 있는 경로를 이 폴더와 증거 폴더로 묶어 실행할 수도 있습니다(`unpack`은 출력 폴더 쓰기 허용 필요).

```sh
node --permission --allow-fs-read="$PWD" --allow-fs-read=/path/to/evidence evidscope-verify.mjs dsse ...
```

## 4. 증명하는 것과 증명하지 않는 것

- `dsse`: 고정한 vault 키가 대상 파일의 정확한 바이트(SHA-256)를 subject로 하는 in-toto Statement에 서명했고, 파일의 기존 서명·해시
  체인·체크포인트가 맞으며, predicate의 요구사항 결과·정책 버전·체크포인트 참조가 파일에서 다시 계산한 값과 같습니다. 포함된
  tlog-proof는 해당 레코드가 서명된 tenant 로그 체크포인트에 들어 있음을 보이고, `--require-witnessed`는 위트니스 정족수가 그
  체크포인트를 공동서명했어야 통과시킵니다.
- `tlog-proof`: 레코드 파일(원장 레코드 본문 그대로)의 SHA-256이 서명된 tenant 로그 체크포인트에 포함되고, 정책의 정족수만큼
  위트니스가 그 체크포인트를 공동서명했습니다.
- `pack`: 묶는 사람의 키가 묶음의 모든 파일과 해시를 이름 붙인 in-toto Statement에 서명했고, 안의 내보내기·사건 보고서가 위와 같이
  검증되며, 색인과 요약이 이 검증기가 그 증거에서 만든 것과 정확히 같습니다. "증거 있음"은 요구사항 충족 판정이 아니고 대응표는
  사람 검토 전 초안입니다.
- 증명하지 않는 것: 기록된 일이 실제로 그렇게 일어났는지(기록은 출처가 보고한 내용입니다), 체크포인트 이후의 기록, 내보내기
  predicate의 `issuedAt`(vault 시계로 스스로 적은 값), 법적 판단의 옳고 그름. 정족수가 `none`이면 vault 서명 키를 가진 사람이 갈라진
  이력을 만들어도 이 검사만으로는 알 수 없습니다.

torchwood, `golang.org/x/mod/sumdb/note`, 일반 DSSE 도구로 같은 파일을 확인하는 방법은 위 문서에 있습니다.
