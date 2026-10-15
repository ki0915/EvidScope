# 감사인용 증거 묶음

> 2026-10-08 개선 6라운드에서 추가하고 7라운드에서 기간 묶음, 레코드 영수증, 서명기 서명, 대응표 버전을 더했습니다. 서명 원장·영수증의
> 형식은 [표준 영수증과 검증기](receipts.md), 위트니스는 [투명성 로그](transparency-log.md), 서명기는 [heads 서명기](signer.md),
> ISMS-P 정렬표는 [ISMS-P 참고 정렬](isms-p-alignment.md)을 보세요.

## 무엇을 해결하는가

거버넌스 도구의 보고서는 대개 **도구 공급자나 운영자를 믿어야** 읽을 수 있습니다. 표에 "로그 보관: 충족"이라고 적혀 있어도
감사인은 그 문장이 어떤 기록에서 나왔는지, 기록이 나중에 바뀌지 않았는지를 혼자 확인할 수 없습니다.

증거 묶음은 감사인이 받는 **파일 하나(또는 폴더 하나)** 입니다. 그 안의 모든 문장은 색인 항목으로, 모든 색인 항목은 서명 원장의
특정 레코드로 이어지며, 감사인은 [오프라인 검증기](../deploy/verifier/README.md) 하나로 그 연결을 처음부터 끝까지 다시 계산합니다.

- 묶음을 만드는 쪽(운영자)은 묶음에 서명하지만, 검증기는 그 서명을 믿고 색인을 받아들이지 않습니다. 색인과 요약을 **검증한 증거에서
  다시 만들어 바이트 단위로 대조**하므로, 묶는 사람이 자기 키로 다시 서명해도 증거보다 많은 주장은 통과하지 못합니다.
- 요약은 "증거 있음"이라고만 씁니다. 요구사항을 충족했다는 판정은 하지 않으며, 대응표 자체가 사람 검토 전 초안입니다.

## 감사인이 받는 것

| 파일 | 내용 | 형식 |
|---|---|---|
| `pack.intoto.json` | 아래 모든 파일을 subject로 하는 서명 | [DSSE](https://github.com/secure-systems-lab/dsse) 봉투, [in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md), predicate [Simple Verification Result v0.2](https://github.com/in-toto/attestation/blob/main/spec/predicates/svr.md) |
| `SHA256SUMS` | 나머지 파일의 SHA-256 | `sha256sum -c` 형식 |
| `evidence/export.json` | vault가 내준 서명 내보내기, 받은 바이트 그대로(원장 전체 묶음만) | `evidscope-export-v2` (체크포인트·투명성 노트·위트니스 공동서명 포함) |
| `evidence/period.json` | 기간 묶음만: 기간 구간, v1 체크포인트, tenant 로그 증명 자료, 구간 안 이벤트의 공개본 | `evidscope-evidence-pack-period-v1` (아래 [기간 묶음](#기간-묶음)) |
| `evidence/receipts.json` | 색인이 가리키는 레코드(기간 묶음은 구간의 모든 레코드)마다 표준 영수증 | `evidscope-evidence-pack-receipts-v1`, 항목마다 레코드 본문과 `c2sp.org/tlog-proof@v1` |
| `evidence/export.json.intoto.json` | 내보내기의 vault 증명(있을 때) | [표준 영수증](receipts.md)의 DSSE in-toto 증명과 tlog-proof |
| `evidence/case-reports/case-N.json`(`.intoto.json`) | 서명된 사건 보고서와 그 증명(있을 때) | `evidscope-case-report-v1` |
| `mapping.json` | 이 묶음이 쓴 요구사항 대응표(`version` 필드가 대응표 버전) | `evidscope-evidence-pack-mapping-v1` |
| `index.json` | 항목별 증거 위치(원장 seq)·검증 결과·사람 판단 | `evidscope-evidence-pack-index-v2` (6라운드 묶음은 `-v1`) |
| `summary.ko.md`, `summary.en.md` | 색인에서 생성한 한국어·영어 요약 | Markdown, 항목마다 한 줄 |

하나의 파일로 받을 때는 위 폴더를 `evidence-pack/` 아래에 담은 ustar `.tar.gz`입니다. `tar -xzf`로 풀어도 되고, 검증기는
압축 파일을 그대로 읽습니다(일반 파일과 폴더만 허용, 링크·`..`·중복 경로는 거부).

### 형식을 고른 이유

새 봉투를 만들지 않았습니다. 서명은 EvidScope가 이미 쓰는 DSSE와 in-toto Statement v1이고, 일반 DSSE 도구와 `sha256sum`으로도
파일 무결성은 확인됩니다. predicate는 in-toto가 심사한(vetted) 목록에서 골랐습니다(2026-10-08 [목록](https://github.com/in-toto/attestation/blob/main/spec/predicates/README.md) 확인).

- **Simple Verification Result v0.2**(`https://in-toto.io/attestation/svr/v0.2`)를 씁니다. "검증자가 어느 시점에 subject를 정책에 대해
  확인했고 통과한 속성은 이것들이다"를 적는 형식이며, 묶는 쪽이 하는 일이 정확히 그것입니다. `verifier.id`는
  `…/docs/evidence-pack.md#builder-v1`, `verifier.policies`는 `mapping.json`(이름·URI·SHA-256), `properties`는 묶는 쪽이 실제로 통과한
  검사(`EVIDSCOPE_EXPORT_SIGNATURE_AND_CHAIN_VERIFIED`, `EVIDSCOPE_EVALUATION_REPLAY_MATCHED`, 이력·투명성·사건 보고서 검사 등)입니다.
- SCAI v0.3의 "evidence collection"도 맞아 보였지만 속성마다 증거를 하나씩 붙이는 구조라 색인과 겹치고, 검증 결과를 담을 자리가
  없습니다. SLSA VSA v1은 SLSA 트랙 수준(`verifiedLevels`)을 위한 형식이며, 그 문서도 단순한 결과에는 SVR을 권합니다.
  Test Result v0.1은 테스트 실행 하나를 위한 형식입니다.

## 묶음 만들기

```sh
node scripts/evidence-pack.mjs build --framework eu-ai-act-logging --tenant alpha \
  --key vault-public.pem --signing-key builder-private.pem --out pack-2026q3.tar.gz \
  --export evidscope-export-1234.json [--attestation evidscope-export-1234.json.intoto.json] \
  [--case-report case.json]... [--from 2026-07-01T00:00:00Z --to 2026-10-01T00:00:00Z [--period-only]] [--checkpoint CHECKPOINT.json] \
  [--witness VKEY --quorum 1 --origin-base evidscope.example.com/prod]
# 서명기 프로세스로 서명(--signing-key 대신):
#   --signer-socket /run/pack-signer/signer.sock --signer-public-key pack-signer-public.pem
#   --signer-url https://pack-signer.internal:8443 --signer-token-file token --signer-ca ca.pem --signer-public-key pack-signer-public.pem
# vault API에서 직접(감사자 토큰, https 또는 loopback만):
node scripts/evidence-pack.mjs build --framework isms-p --tenant alpha --key vault-public.pem --signing-key builder-private.pem \
  --out pack/ --api https://evidscope.example.com --token-file auditor.token --case <caseId>...
```

- `--framework`: `eu-ai-act-logging`, `kr-ai-basic-act`, `isms-p`.
- `--export`, `--case-report`는 일반 파일이나 vault의 `?attest=intoto` 응답 파일을 받습니다. `--api`는 `GET /api/export?attest=intoto`와
  `GET /api/cases/<id>/report?attest=intoto`를 읽습니다. 토큰은 파일이나 `EVIDSCOPE_AUDITOR_TOKEN`으로 주며 명령줄에 쓰지 않습니다.
- 쓰기 전에 `scripts/verify.mjs`와 같은 검사를 모두 통과해야 합니다: 서명·해시 체인·체크포인트, 투명성 노트(있거나 플래그를 준 경우),
  레지스트리·승인·정지 명령의 서명 이력, 평가 재계산(`replay`, 불일치 0). 사건 보고서는 같은 tenant여야 하고, 보고서의 체크포인트
  head와 보고서에 담긴 모든 이벤트·사람 판단이 내보내기의 레코드와 같아야 합니다. 하나라도 어긋나면 아무 파일도 쓰지 않습니다.
- `--tenant`는 내보내기의 tenant와 같아야 합니다. 마지막으로 만든 묶음을 감사인과 같은 방법으로 검증한 뒤에야 씁니다.
  기존 파일·폴더는 덮어쓰지 않습니다.
- `--from`/`--to`는 vault가 서명한 `recordedAt` 기준의 반열린 구간 `[from, to)`입니다. 색인은 구간 안의 레코드만 셉니다.
  `--period-only`가 없으면 묶음에는 **원장 전체**(내보내기)가 들어가고, 있으면 기간의 원장 구간만 들어갑니다([기간 묶음](#기간-묶음)).
- 기간을 정하면 서명 원장 검증(`signed_ledger`)은 그 기간의 증거로 세지 않습니다. 이 검사는 원장 전체를 대상으로 하므로, 6라운드에는
  구간 안에 로그 기록이 하나도 없어도 제12조제1항·제19조제1항·제26조제6항(ISMS-P 2.9.4, KR-34-DOCUMENT 포함)이 "증거 있음"으로
  요약되었습니다(7라운드 재감사). 이제 그런 항목은 구간 안의 다른 기록이 있어야 "증거 있음"이고, 없으면 "기록된 증거 없음"(기간 묶음은 "묶음 안에 증거 없음")입니다. 색인의
  `signed_ledger` 항목(전체 원장 건수)은 그대로 남습니다. 기간 없는 묶음은 바뀌지 않습니다. 6라운드에 만든 기간 묶음 가운데 원장 검증만으로
  "증거 있음"이 된 항목이 있는 것은 새 검증기에서 `Index differs`로 거부됩니다.
- `--signing-key`는 묶는 사람의 Ed25519 개인키입니다. vault 키와 다른 키를 쓰고, 공개키는 묶음과 다른 경로로 감사인에게 줍니다.
  키 파일 대신 서명기 프로세스를 쓸 수 있습니다([서명기로 서명하기](#서명기로-서명하기)).

## 묶음 검증하기

```sh
node evidscope-verify.mjs pack pack-2026q3.tar.gz vault-public.pem --pack-key builder-public.pem \
  [CHECKPOINT.json] [--tenant alpha] [--witness VKEY --quorum 1 --origin-base evidscope.example.com/prod]
# 저장소에서는 같은 명령이 node scripts/verify.mjs pack … 또는 node scripts/evidence-pack.mjs verify … 입니다.
```

검증기는 네트워크 없이 다음을 모두 확인하고, 하나라도 어긋나면 종료 코드 1로 끝납니다.

1. `pack.intoto.json`의 DSSE 서명(`--pack-key`, 없으면 vault 키), in-toto Statement v1과 SVR predicate의 형식.
2. statement가 이름 붙인 파일과 묶음의 파일이 정확히 같고(추가·누락·제자리가 없는 파일 거부), 파일마다 SHA-256이 맞으며,
   `SHA256SUMS`도 같습니다.
3. `mapping.json`이 이름 붙인 대응표 버전을 이 검증기가 싣고 있고, 그 버전과 바이트 단위로 같습니다([대응표 버전](#대응표-버전)).
   싣지 않은 버전이거나 다르면 `--mapping-from-pack`을 줄 때만 묶음의 대응표를 쓰고, 결과에 `mapping.source: "package"`로 밝힙니다.
   statement의 정책 digest도 같아야 합니다.
4. 내보내기와 사건 보고서를 위와 같은 검사로 다시 검증합니다. 함께 든 vault 증명(`.intoto.json`)도 확인합니다. 기간 묶음은
   내보내기 대신 기간 구간을 [아래](#기간-묶음)와 같이 검증합니다. `evidence/receipts.json`의 영수증을 하나하나 영수증으로 확인하고,
   원장 전체 묶음에서는 내보내기에서 다시 만든 영수증과 바이트 단위로 대조합니다.
5. 검증한 증거·대응표·기간에서 `index.json`을 다시 만들어 바이트 단위로 비교하고, 모든 seq가 구간 안의 올바른 종류 레코드인지,
   사람 판단이 서명된 평가 레코드인지 확인합니다.
6. 두 요약을 색인에서 다시 만들어 비교합니다. 항목 절의 모든 줄은 색인 항목 하나를 정확히 가리키고 그 항목의 상태를 그대로
   적어야 합니다(색인에 없는 문장, 중복, 빠진 항목, 다른 상태는 거부).
7. statement의 `properties`는 이번 검증이 스스로 확인한 것만 허용합니다. 예를 들어 묶는 쪽이 위트니스로 되돌리기를 확인했다고
   적었다면(`EVIDSCOPE_ROLLBACK_CHECKED`) 감사인도 같은 위트니스 키나 외부 체크포인트를 줘야 통과합니다.

신뢰 기준(vault 공개키, 묶는 사람의 공개키, 위트니스 키, 외부 체크포인트)은 묶음과 **다른 경로**로 받아야 합니다.
묶음 안의 어떤 파일도 신뢰 기준이 아닙니다.

## 색인

`index.json`의 항목 하나는 다음과 같습니다(값은 예시).

```json
{"id": "EU-AIA-14-4-E", "citation": "Regulation (EU) 2024/1689, Article 14(4)(e)", "sourceStatus": "text_read",
 "status": "evidence_present",
 "evidence": [{"type": "record", "name": "agent_stop_order", "status": "present", "count": 1, "seqs": [41],
   "recordedAt": {"from": "…", "to": "…"}, "verification": "signed_hash_chain"}],
 "humanJudgement": null}
```

- 항목 상태: `evidence_present`(대응한 증거 종류 중 하나 이상이 기록됨), `no_evidence_recorded`(기록 없음), `not_in_export`(내보내기에
  담기지 않는 API 응답·저장소 파일만 지정됨), 기간 묶음에서만 `no_evidence_in_package`(이 묶음에 증거 없음, 부재는 증명하지 않음).
- 증거 상태는 [ISMS-P 보고서](isms-p-alignment.md)와 같은 `present`, `none_recorded`, `not_in_export`에 더해, 이 묶음이 원장 전체를
  검증했음을 뜻하는 `verified_by_this_package`(`signed_ledger`)가 있습니다. 증거 종류(`record`, `eventKind`, `checkType`, `finding`,
  `integrityCheck`, `api`, `file`)와 세는 방법은 ISMS-P 보고서와 같은 코드(`src/evidence-inventory.mjs`)입니다.
- `seqs`는 원장 순번입니다. 항목당 1,000개까지 적고 나머지는 `seqsOmitted`로 셉니다. 색인이 적은 모든 seq(증거 위치, 사람 판단과
  그 법률 검토, 사건 보고서의 이벤트·판단)의 영수증이 `evidence/receipts.json`에 들어 있습니다([레코드 영수증](#레코드-영수증)).
- v2 색인은 `framework.mappingVersion`, `scope.kind`(`ledger` 또는 `period`), `evidence.receipts`(파일, 영수증 수, 덮지 못한 수
  `notCovered`, 증명에 쓴 체크포인트 크기)를 더 적습니다. 기간 묶음은 `evidence.export` 대신 `evidence.period`(구간, 체크포인트, 공개·삭제·
  미공개 이벤트 수, 재계산 요약과 재계산 불가 사유)와 `scope.packageRecords`, `scope.absence: "not_established_by_a_period_package"`를 적습니다.
- `humanJudgement`: 인공지능기본법 항목은 같은 요구사항 ID로 기간 안에 서명된 마지막 사람 평가와 그 법률 검토 기록입니다
  ([증거 계약](kr-governance-evidence.md)). EvidScope 요구사항 목록에 없는 항목은 `null`입니다. 사건의 사람 판단은 `case_decision`
  증거로 나오고, 그 판단을 담은 사건 보고서 파일이 `caseReports`로 연결됩니다.

## 기간 묶음

`--period-only`로 만든 묶음은 기간에 해당하는 **원장 구간만** 담습니다. 한 분기의 감사인이 다른 분기의 기록과 메타데이터를 받지 않게
하려는 것입니다. 증명 형식은 새로 만들지 않았습니다. 레코드마다 [표준 영수증](receipts.md)의 레코드 본문과
`c2sp.org/tlog-proof@v1`을, 체크포인트 사이는 RFC 6962 일관성 증명을 쓰며, 묶는 쪽은 `src/tlog.mjs`와 `src/receipts.mjs`의
함수로 만들고 검증기는 사건 보고서와 같은 `verifyReportTransparency`로 확인합니다.

### 담는 것

- **구간**: vault가 서명한 `recordedAt`이 기간 안인 첫 레코드부터 마지막 레코드까지의 연속한 seq 구간 `range.first`–`range.last`.
  시계가 뒤로 간 경우처럼 구간 가운데에 기간 밖 레코드가 끼면 그것도 담지만(연속성을 보이기 위해) 색인에는 세지 않습니다.
  구간의 첫 레코드와 마지막 레코드는 반드시 기간 안이어야 하며, 기간 앞뒤로 넓힌 묶음은 거부합니다.
- **레코드 영수증**(`evidence/receipts.json`): 구간의 모든 레코드. 영수증의 체크포인트는 `/api/receipts/record`와 같은 규칙으로
  고릅니다. 위트니스가 공동서명한 tenant 체크포인트가 레코드를 덮으면 그것, 아니면 내보낼 때의 최신 tenant 체크포인트입니다.
- **`evidence/period.json`**: 기간, 구간, 내보내기의 `evidscope-checkpoint-v1`, tenant 로그 자료(사건 보고서와 같은
  `evidscope-transparency-v1` 형식: 최신 tenant 체크포인트, head 레코드의 포함 증명, 공동서명 체크포인트와 heads 항목에서 최신
  체크포인트로 가는 일관성 증명), 구간 안 암호화 이벤트의 공개본. 알려진 필드만 허용합니다.
- 내보내기의 tenant 로그 체크포인트가 모든 레코드를 덮어야 만들 수 있습니다(투명성 모드가 꺼져 있으면 기간 묶음을 만들 수 없음).
  한 묶음은 레코드 200,000개까지이며, 더 크면 기간을 나눕니다.

### 검증기가 확인하는 것

1. v1 체크포인트의 vault 서명. 외부 체크포인트를 주면 정확히 같아야 합니다(`verifyBundle`과 같은 비교).
2. tenant 로그 자료: 최신 tenant 체크포인트가 고정한 vault 키로 서명되었고 크기가 v1 체크포인트와 같으며 head 레코드를 포함하는지,
   공동서명 체크포인트와 heads 항목이 일관성 증명으로 그 체크포인트에 이어지는지, 위트니스 플래그를 주면 정족수·신선도까지
   (`rollbackCheckedAgainst`를 포함해 사건 보고서와 같은 결과). `--min-checkpoint`는 원장 전체가 필요하므로 기간 묶음에서는 거부합니다.
3. 영수증: 구간의 seq마다 정확히 하나, 레코드 파일이 해시 필드 없는 canonical 본문이고 그 SHA-256이 레코드 해시이며 tenant·seq가 맞는지,
   tlog-proof가 위 규칙의 체크포인트(바이트 단위로 같은 노트)에 포함을 보이는지. 체크포인트 서명은 감사인의 정책(고정한 vault 키,
   `--witness`·`--quorum`)으로 확인합니다.
4. 이웃 레코드의 해시 연결(`previous`)과 구간이 seq 1에서 시작하면 첫 레코드의 `previous`가 0인지, 구간이 체크포인트 끝까지 가면 마지막
   레코드가 head인지.
5. 공개본: 내보내기 검증과 같은 규칙(바인딩, 약속값, 삭제 순서)을 구간 안에서 적용합니다. 구간 뒤의 `retention_disposition`은 묶음에
   없으므로, 공개본 없는 암호화 이벤트는 나중에 삭제된 것인지 묶는 쪽이 뺀 것인지 구별할 수 없어 `undisclosedEvents`로 셉니다.
6. 이 구간만으로 색인과 두 요약을 다시 만들어 바이트 단위로 대조합니다.

### 감사인이 결론 낼 수 있는 것과 없는 것

| 결론 | 기간 묶음 | 원장 전체 묶음 |
|---|---|---|
| 색인이 가리키는 레코드가 vault가 서명한 tenant 로그에 들어 있고 내용이 서명된 그대로다 | 예 | 예 |
| 구간 안에서 빠진 레코드가 없다(seq 연속, 해시 연결) | 예 | 예(원장 전체) |
| 기간 안에 어떤 증거가 **없다** | **아니오** | 원장 안에서는 예(수집의 완전성은 별개) |
| 구간 첫 레코드 앞, 마지막 레코드 뒤에 기간 안 레코드가 더 없다 | 아니오 | 예 |
| 레지스트리·승인·정지 명령의 서명 이력이 처음부터 맞다 | 아니오 | 예 |
| 평가를 다시 계산해 같은 결과가 나온다 | 구간이 seq 1에서 시작할 때만 | 예 |
| 되돌리기가 없다(위트니스·외부 체크포인트를 준 경우) | 예 | 예 |

- 부재를 증명하지 못하므로 기간 묶음의 색인은 `none_recorded`·`no_evidence_recorded`를 쓰지 않고 `none_in_package`·
  `no_evidence_in_package`(요약: "이 묶음에 증거 없음(부재는 증명하지 않음)")를 씁니다. 검증기는 부재를 주장하는 기간 묶음 색인을 거부하고,
  `scope.absence`에 `not_established_by_a_period_package`를 적습니다. 요약의 "이 묶음이 증명하지 않는 것"에도 두 줄이 더 붙습니다.
- 평가 재계산은 그 평가보다 앞선 모든 레코드(자산, 룰, 예외, 레지스트리, 이전 이벤트)가 필요합니다. 구간이 seq 1에서 시작하면 그 접두가
  모두 있으므로 원장 전체와 같은 재계산을 하고, 아니면 구간의 모든 평가를 `not_replayable`(사유 `prior_records_not_in_package`)로 표시합니다.
  일치했다고도 불일치했다고도 하지 않으며, statement의 `EVIDSCOPE_EVALUATION_REPLAY_MATCHED`는 실제로 재계산한 경우에만 인정합니다.
  이력 검증도 같은 이유로 `not_verifiable_from_a_period_package`입니다. `finding` 증거는 서명된 평가 기록의 내용이며, 재계산 여부를
  `replay.notReplayable`로 함께 적습니다.
- 사건 보고서는 vault 서명으로 따로 검증하고, 보고서가 보여 주는 모든 이벤트와 사람 판단이 구간의 레코드와 같아야 합니다. 구간 밖
  이벤트·판단을 보여 주는 보고서는 기간 묶음에 넣을 수 없습니다(원장 전체 묶음을 쓰거나 기간을 넓힙니다). 보고서의 head는 구간 안에 있을
  때만 대조합니다.
- statement 속성은 `EVIDSCOPE_EXPORT_SIGNATURE_AND_CHAIN_VERIFIED` 대신 `EVIDSCOPE_PERIOD_RECORDS_INCLUDED_IN_SIGNED_TENANT_LOG`입니다.

## 레코드 영수증

`evidence/receipts.json`은 레코드마다 `{seq, hash, type, record, proof}`를 담습니다. `record`는 `/api/receipts/record`의 `record`와 같은
원장 본문(해시 필드 없는 canonical JSON), `proof`는 `c2sp.org/tlog-proof@v1`입니다. 파일에서 꺼내면 다른 도구로도 확인됩니다.

```sh
jq -j '.receipts[0].record' evidence/receipts.json > r.json
jq -j '.receipts[0].proof' evidence/receipts.json > r.tlog-proof
node evidscope-verify.mjs tlog-proof r.tlog-proof r.json --key vault-public.pem [--witness VKEY --quorum 1 --origin-base BASE]
```

- 원장 전체 묶음: 색인이 가리키는 모든 seq 가운데 내보내기의 tenant 체크포인트가 덮는 것. 검증기는 내보내기에서 같은 영수증을 다시 만들어
  바이트 단위로 대조하고, 각 영수증도 위처럼 확인합니다. 내보내기에 tenant 로그 자료가 없으면 영수증 파일이 없고 색인의
  `evidence.receipts.reason`이 `export_has_no_tenant_log_checkpoint`입니다.
- 기간 묶음: 구간의 모든 레코드. 기간 묶음에서는 영수증이 곧 증거입니다.
- 영수증 정책 파일(`.tlog-policy`)은 담지 않습니다. 정책은 신뢰 기준이 아니므로 감사인이 밖에서 받은 vault 키와 위트니스 키로 만듭니다.
  vault가 보고하는 요약 필드(`quorumMet` 등)도 담지 않으며, 검증 결과의 `receipts`(영수증 수, 정족수, 정족수를 채운 영수증 수)가 그 역할을 합니다.

## 서명기로 서명하기

묶음 서명 키를 파일 대신 서명기 프로세스([heads 서명기](signer.md)와 같은 `scripts/signer.mjs`)에 둘 수 있습니다.

```sh
node scripts/signer.mjs keygen --out pack-signer-key.pem --public-out pack-signer-public.pem
node scripts/signer.mjs init --state-dir /pack-signer/state --backend file --key-file pack-signer-key.pem
node scripts/signer.mjs serve --state-dir /pack-signer/state --backend file --key-file pack-signer-key.pem \
  --socket /run/pack-signer/signer.sock --sign-pack-statements
node scripts/evidence-pack.mjs build ... --signer-socket /run/pack-signer/signer.sock --signer-public-key pack-signer-public.pem
```

- `--sign-pack-statements`를 준 서명기만 `POST /v1/sign-statement`를 엽니다. 서명기는 받은 DSSE PAE를 직접 풀어, payload type이
  `application/vnd.in-toto+json`이고 본문이 canonical in-toto Statement v1이며 predicate가 SVR v0.2, `verifier.id`가 이 문서의
  `#builder-v1`인 것만 서명합니다. 그 밖의 바이트(체크포인트 노트, 다른 predicate, 들여쓰기한 JSON)는 `not_allowed`·`invalid_request`로
  거부하고 감사 로그에 남깁니다. 서명과 거부 모두 서명기 감사 로그(`statement_signed`, `refused`)에 남고, 서명 속도 제한을 heads 서명과
  함께 씁니다. 키 백엔드(file, ssh-agent, command/KMS)도 heads 서명기와 같습니다.
- canonical JSON에는 줄바꿈이 없으므로 statement의 PAE에는 줄바꿈이 없고, 체크포인트 노트 본문은 줄바꿈으로 끝납니다. 그래서 한 키가 둘 다
  서명해도 서로를 대신할 수 없습니다. 그래도 **묶음용 서명기는 heads 서명기와 다른 인스턴스·상태 디렉터리·키로** 운영하기를 권합니다.
  heads 서명기의 token을 묶는 사람에게 주면 그 사람이 heads 잎도 보낼 수 있기 때문입니다.
- 서명기는 statement가 증거와 맞는지는 보지 않습니다. 서명기에 닿는 사람은 키 파일을 가진 사람처럼 묶음에 서명할 수 있으므로 소켓 권한과
  token을 묶는 사람에게만 줍니다. 그래도 감사인의 검증기는 증거에서 색인과 요약을 다시 만들므로, 서명만으로 증거보다 많은 주장이 통과하지는 않습니다.
- 묶는 쪽은 `--signer-public-key`로 서명기 공개키를 고정합니다. 서명기가 거부하거나, 돌려준 서명이 그 키로 검증되지 않거나, 완성된 묶음이
  그 키로 검증되지 않으면 아무 파일도 쓰지 않습니다(키 파일로 서명할 때와 같은 규칙). `--signer-url`은 https이거나 loopback http만
  받고, token·CA는 heads 서명기 연결과 같습니다. 감사인은 이 공개키를 `--pack-key`로 줍니다.

## 대응표 버전

대응표가 바뀌면 예전 묶음이 새 검증기에서 통과하지 못하던 문제를 버전으로 풉니다.

- 새 묶음의 `mapping.json`은 `version`(지금은 4)을 적고, v2 색인의 `framework.mappingVersion`도 같은 값입니다. `version`이 없는 대응표는
  버전 1(6라운드 묶음)입니다. 버전 1과 2의 차이는 이 필드뿐이고 항목은 같습니다.
- 버전 3(2026-10-15)은 AI 코딩 에이전트 위험 규칙([에이전트 행동 감시](agent-monitoring.md))의 발견사항을 증거로 더합니다. 발견사항은
  테넌트 룰이라 코드가 `CUSTOM:<룰 ID>:v<버전>`이므로, 증거 항목이 `code` 대신 `codePrefix`를 씁니다(`CUSTOM:risk.out.`은 그 묶음의 모든 룰,
  `CUSTOM:risk.defense.defender:`는 그 룰의 모든 버전). 더한 곳: ISMS-P 2.11.3(모든 묶음), 2.6.7(외부 전송), 2.10.1(백신·방화벽·iptables·SELinux
  변경), 2.9.4(로그·명령 기록 삭제, 감시 설정 접근), AI 기본법 KR-32-MONITOR·KR-34-RISK, EU AI Act 12(2)(a)·14(4)(a). 버전 2의 증거는 그대로입니다.
  거버넌스 매핑 모델의 카탈로그는 학습한 어댑터와 같은 digest를 쓰도록 버전 2에 고정합니다(`CATALOG_MAPPING_VERSION`).
- 버전 4(2026-10-15)는 평가 엔진 v5의 여러 행동 이상 징후([에이전트 행동 감시](agent-monitoring.md#여러-행동을-엮은-이상-징후-평가-엔진-v5))를
  `code`로 더합니다. 다섯 코드 모두 ISMS-P 2.11.3, AI 기본법 KR-32-MONITOR·KR-34-RISK, EU AI Act 12(2)(a)·14(4)(a)에, 그리고
  `SEQ_SENSITIVE_THEN_OUTBOUND`는 2.6.7, `SEQ_RISK_THEN_TAMPER`는 2.9.4, `SEQ_DEFENSE_OFF_THEN_ACTION`은 2.10.1에도 셉니다. 버전 3의
  증거는 그대로입니다.
- 검증기는 배포한 모든 버전을 `data/evidence-pack-mappings/<framework>-v<N>.json`(묶음의 `mapping.json`과 같은 바이트)으로 싣고,
  `src/evidence-pack-frameworks.mjs`의 `MAPPING_VERSIONS`에 각 파일의 SHA-256을 적습니다. 묶음이 이름 붙인 버전과 바이트 단위로 같으면
  `--mapping-from-pack` 없이 통과하고, 결과에 `mapping.version`을 적습니다. 싣지 않은 버전은 예전처럼 거부합니다.
- 묶는 쪽은 데이터 파일(`data/requirements.json`, `data/isms-p-alignment.json`)에서 만든 대응표가 현재 버전 파일과 같을 때만 묶음을
  만듭니다. 데이터가 바뀌면 같은 버전 번호로 다른 바이트를 내지 않고, 새 버전 파일과 digest를 추가해야 합니다(`test/evidence-pack-period.test.mjs`가
  확인). 6라운드 검증기는 v2 색인과 영수증 파일을 모르므로, 새 묶음은 이 라운드 이후의 검증기로 검증합니다. 6라운드 묶음은 새 검증기에서
  예전과 똑같이 검증됩니다.

## 대응표와 출처

대응표는 **어떤 EvidScope 기록이 그 조항을 검토할 때 볼 자료인지**만 적습니다. 법 해석이 아니며 모두
`draft_requires_human_review`입니다. 원문을 읽은 조항만 인용했고, 읽은 방법과 확인 수준을 `sourceStatus`에 남겼습니다.

### EU AI Act(Regulation (EU) 2024/1689): `eu-ai-act-logging`

2026-10-08에 집행위원회 [AI Act Service Desk](https://ai-act-service-desk.ec.europa.eu/en/ai-act)의 조문 페이지에서 읽었습니다
(공식 원문은 [EUR-Lex](https://eur-lex.europa.eu/eli/reg/2024/1689/oj), 작업 환경에서는 열리지 않음). 페이지는 2024-06-13 관보 원문
또는 2026-07-27 통합본을 보여 줍니다. Article 12에는 Digital Omnibus로 **개정되었으나 표시 본문은 아직 반영 전**이라는 안내가 있고,
Article 72에도 개정 표시가 있어 해당 항목은 `text_read_amendment_unverified`로 남깁니다. 개정된 본문은 읽지 않았습니다.

| 항목 | 조항(읽은 내용 요지) | 볼 증거 |
|---|---|---|
| `EU-AIA-12-1` | Art. 12(1): 고위험 AI 시스템은 수명 동안 이벤트(로그)를 자동 기록할 수 있어야 함 | `signed_ledger`, `event`, `event_receipt` |
| `EU-AIA-12-2-A` | Art. 12(2)(a): Art. 79(1)의 위험 또는 실질적 변경 상황 식별 | `evaluation`, `agent_registry`, `agent_transition`, `safety_alert`, `agent_stop_order` |
| `EU-AIA-12-2-B` | Art. 12(2)(b): Art. 72 시판 후 모니터링 지원 | `evaluation`, `heartbeat`, `gap`, `COLLECTION_GAP` |
| `EU-AIA-12-2-C` | Art. 12(2)(c): Art. 26(5) 운영 모니터링 | `intent`, `execution`, `result`, `policy_decision`, `guardrail_decision` |
| `EU-AIA-19-1` | Art. 19(1): 제공자가 통제하는 자동 생성 로그를 목적에 맞는 기간, 최소 6개월 보관 | `signed_ledger`, `retention_policy`, `retention_hold`, `retention_disposition` |
| `EU-AIA-26-6` | Art. 26(6): 배포자가 통제하는 자동 생성 로그를 최소 6개월 보관 | 위와 같음 |
| `EU-AIA-72-1-2` | Art. 72(1)(2): 시판 후 모니터링 체계가 성능 자료를 수집·문서화·분석 | `evaluation`, `case`, `case_decision`, `safety_alert` |
| `EU-AIA-14-4-A` | Art. 14(4)(a): 감독자가 운영을 모니터링하고 이상·오작동을 탐지 | `case`, `case_decision`, `human_oversight_review` |
| `EU-AIA-14-4-D` | Art. 14(4)(d): 사용하지 않거나 출력을 무시·무효화·되돌리기로 결정 | `approval_request`, `human_approval`, `human_oversight_review`, `case_decision` |
| `EU-AIA-14-4-E` | Art. 14(4)(e): 정지 버튼 등으로 개입·중단해 안전한 상태로 멈춤 | `agent_stop_order`, `stop_requested`, `block_registered`, `stop_confirmed`, `STOP_UNCONFIRMED`, `EXECUTION_AFTER_STOP_REQUEST` |

대응하지 않은 조항: Art. 12(3)·14(5)(부속서 III 1(a) 원격 생체 식별의 지정 로그와 2인 확인), Art. 19(2)·26(6) 둘째 문단(금융기관의
금융 법령 문서 보관), Art. 14(4)(b)(c)(자동화 편향 인식·출력 해석은 설계·교육 조치). 보관 기간이 "목적에 맞는지", 시스템이 고위험인지,
누가 제공자·배포자인지는 사람이 판단합니다. 보관 항목에서 `signed_ledger`는 기록이 남아 있는 범위를 보여 줄 뿐 6개월 이상 보관을
뜻하지 않습니다.

### 인공지능기본법: `kr-ai-basic-act`

`data/requirements.json`에 이미 등록된 한국 요구사항 18개를 그대로 씁니다. 조항 번호와 원문 URL은 그 목록의 값이며
(법률 제21311호, 시행령 제36580호, `verifiedAt` 2026-10-06), 이번 작업에서 law.go.kr 원문을 다시 읽지는 않았습니다(작업 환경에서
열리지 않음). 그래서 `sourceStatus`는 `requirements_catalog_<원래 확인 수준>_<확인일>`입니다. 새 조항 번호는 추가하지 않았습니다.

볼 증거는 [증거 계약](kr-governance-evidence.md)의 조치 시험 유형(`governance_check`의 `checkType`)과, 일부 항목에 붙인 원장 기록입니다.

| 항목 | 조치 시험 유형 외에 붙인 증거 |
|---|---|
| `KR-32-RISK`, `KR-34-RISK` | `evaluation`, `agent_registry_policy` |
| `KR-32-MONITOR` | `evaluation`, `case`, `case_decision`, `safety_alert` |
| `KR-34-OVERSIGHT` | `approval_request`, `human_approval`, `human_oversight_review`, `case_decision`, `agent_stop_order` |
| `KR-34-DOCUMENT` | `governance_document`, `retention_policy`, `signed_ledger` |
| `KR-40-ORDER` | `agent_stop_order`, `stop_requested`, `block_registered`, `stop_confirmed` |

`KR-40-ORDER`의 정지 명령은 EvidScope 안의 운영 정지이며 기관의 명령 자체가 아닙니다. 요구사항 목록이 적은 "변경·중지의 독립
운영 결과"를 볼 자료일 뿐입니다. `checkType` 증거는 서명된 측정 기록의 개수이며, 그 측정이 증거 계약의 기술 검사를 통과했는지는
`GET /api/governance/report`가 따로 판단합니다.

### ISMS-P: `isms-p`

`data/isms-p-alignment.json`의 27개 정렬 항목을 그대로 씁니다. 법적 출처는 「정보보호 및 개인정보보호 관리체계 인증 등에 관한
고시」(개인정보보호위원회고시 제2024-8호) [별표 7]이고, 항목 번호·명칭의 확인 수준은 정렬표의 `verifiedLevel`을 따릅니다.
정렬하지 않은 74개 항목과 그 이유, 출처 파일의 해시는 [ISMS-P 참고 정렬](isms-p-alignment.md)에 있습니다.

## 이 묶음이 증명하지 않는 것

- **법적 요구사항의 충족이나 인증 적합성.** "증거 있음"은 대응한 종류의 기록이 있다는 뜻입니다. 대응표는 사람 검토 전 초안입니다.
- **수집의 완전성.** EvidScope에 보내지 않은 행동·출처는 보이지 않습니다. 0건은 통제가 없다는 뜻이 아니고, 증거가 있어도 모든
  행동이 기록되었다는 뜻이 아닙니다.
- **출처가 스스로 보고한 내용의 진실성.** `occurredAt`, 상태, 측정값은 출처의 주장입니다. 서명은 vault가 그 기록을 받았음을 보증합니다.
- **되돌리기·잘라내기의 부재.** 외부 체크포인트나 위트니스 없이 검증하면 서명 키를 가진 호스트가 만든 짧은 원장을 구별하지 못합니다.
- **기간 묶음에서 기간 안 증거의 부재.** 위 [표](#감사인이-결론-낼-수-있는-것과-없는-것)를 보세요.
- **묶는 사람이 고른 범위의 적절성.** 어떤 사건 보고서를 넣을지, 어떤 기간을 볼지는 묶는 사람이 정합니다. 검증기는 넣은 것이
  맞는지를 확인할 뿐 빠진 사건이 없는지는 알 수 없습니다.

## 한계와 다음 단계

- 기간 묶음은 부재를 증명하지 못합니다. 구간 바로 앞뒤의 기간 밖 레코드 하나씩을 "울타리"로 담으면 `recordedAt`이 단조로운 원장에서는
  구간 경계를 증명할 수 있지만, 다른 기간의 기록을 보이게 되고 vault가 `recordedAt` 단조성을 서명으로 보장하지 않으므로 넣지 않았습니다.
- 기간 묶음은 구간 앞 기록이 필요한 재계산과 서명 이력을 확인하지 않습니다. 필요한 앞선 기록만 골라 담는 방식은 재계산 입력이 레코드 종류마다
  달라 이번에 정의하지 않았습니다.
- 복구 epoch 뒤의 내보내기로 만든 기간 묶음은 epoch 기록을 담지 않으므로, 감사인은 새 origin base를 고정해야 합니다(예전 base 고정은 거부).
- 묶는 쪽이 `--checkpoint`로 확인한 되돌리기 검사는 감사인도 같은 체크포인트를 줄 때만 인정됩니다(묶음에 체크포인트를 넣으면 신뢰 기준이
  되지 못하므로). 감사인이 받은 체크포인트가 묶음의 것보다 새로우면 기간 묶음은 정확히 같은 체크포인트만 비교하므로 통과하지 않습니다.
- 대응표의 버전 1과 2는 `version` 필드만 다릅니다. 실제 항목을 고친 첫 버전은 아직 없습니다.
- EU 항목의 Digital Omnibus 개정 본문, 인공지능기본법 원문은 이번에 다시 읽지 못했습니다. 사람이 원문으로 확인할 때까지
  `sourceStatus`가 그 상태를 밝힙니다.
- 대응은 `src/evidence-pack-frameworks.mjs`, 묶음 형식과 검증은 `src/evidence-pack.mjs`, 기간 묶음과 영수증은 `src/evidence-pack-period.mjs`,
  시험은 `test/evidence-pack.test.mjs`(8b3af6c 시점 내보내기 `test/fixtures/pack-export-8b3af6c.json`으로 만든 묶음 포함)와
  `test/evidence-pack-period.test.mjs`(d7413a0이 만든 묶음 `test/fixtures/pack-d7413a0/`, 만든 스크립트
  `test/fixtures/make-pack-d7413a0-fixture.mjs` 포함)에 있습니다.
