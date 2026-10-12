# 거버넌스 매핑 로컬 모델

> 2026-10-08 개선 7라운드에서 추가했습니다. 워커는 Claude나 Codex가 아니라 PC에서 돌아가는 로컬 모델
> (`fdtn-ai/Foundation-Sec-1.1-8B-Instruct`, Q4_K_M GGUF)입니다. 학습·평가 실행 순서는 [실행 안내서](governance-model-runbook.md)에 있습니다.

## 한 줄 요약

증거 하나를 받아 **출고된 매핑 표의 요구사항 ID**에 연결하는 일입니다. 정밀도가 먼저입니다. 확실하지 않으면 기권하고,
구조화 기록처럼 표가 이미 답하는 증거는 규칙이 답하며 모델은 그 답을 바꿀 수 없습니다. 모델의 답은 언제나 제안(advisory)이고
사람이 한 건씩 확인합니다. 지금 모델 상태는 **꺼짐**(`no_measured_report`)입니다. 측정 보고서와 사람 승인이 생길 때까지 켜지지 않습니다.

## 작업 정의

입력 하나, 출력 하나입니다(`src/governance-mapping.mjs`).

| 항목 | 내용 |
| --- | --- |
| 입력 종류 | `document_excerpt`, `registry_entry`, `record_summary`, `finding_note`(모델 범위) / `structured`(규칙 범위) |
| 입력 텍스트 | 600자 이하, 제어문자 제거, NFC 정규화. 증거 안의 문장은 지시가 아니라 데이터입니다 |
| 증거 위치(locator) | `doc:...`, `evidence:...` 형식 1~4개. 출력은 이 목록에 있는 위치만 인용할 수 있습니다 |
| 카탈로그 | 출고된 v2 매핑 표 3종의 55개 항목: EU AI Act 로깅 10, 인공지능기본법 18, ISMS-P 27 (digest `f12872b3…5c860`) |
| 출력 | `{"abstain": bool, "mappings": [{"requirementId", "relation", "evidenceLocator", "confidence"}]}` 최대 5건 |
| relation | `supports`(충족 근거), `contradicts`(반대 근거), `context_only`(관련 맥락일 뿐) |
| confidence | `low`, `medium`, `high` (보정 측정에 씀: 명목값 0.5 / 0.75 / 0.9) |
| 기권 | `abstain: true` ⇔ `mappings`가 비어 있음. 카탈로그 밖 주제, 근거 부족, 주입 지시는 기권 또는 무시 |

출력은 llama.cpp `response_format: json_schema`로 강제합니다. 스키마의 `requirementId`는 카탈로그 55개 ID의 enum,
`evidenceLocator`는 그 입력의 위치 enum이므로 문법상 다른 값을 낼 수 없습니다. 그래도 서버와 실행기는 모든 출력을
`validateMappingOutput`으로 다시 검사하고, 맞지 않으면 고치지 않고 실패로 기록합니다.

카탈로그 텍스트는 요구사항 쪽 문장만 씁니다(제목, 조문, `data/requirements.json`의 요구사항·필요 증거, ISMS-P 수동 점검 항목).
표의 증거 설명(`what`, `shows`)은 아래 파생 데이터의 입력이므로 프롬프트 후보 설명에 넣지 않습니다.

## 규칙이 먼저, 모델은 자유 텍스트만

`kind: "structured"` 증거(기록 이름, 이벤트 종류, 점검 유형, 발견사항 코드, 무결성 점검, API, 파일)는 매핑 표의 색인이 답합니다.
발견사항 코드는 `context_only`, 나머지는 `supports`입니다. 이 범위에 모델 답이 들어오면 `rule_override_refused`로 거부하고,
모델 요청 자체를 만들지 않습니다(`rule_determined_item`). 모델은 표가 답하지 못하는 자유 텍스트(문서 발췌, 등록부 항목 설명,
기록 요약, 발견사항 메모)만 맡습니다.

## 데이터셋

`data/governance-mapping/v1/dataset.jsonl` 1,089행은 `node scripts/governance-mapping.mjs build --local-tables none`이 결정적으로
만듭니다. 테스트가 저장소 파일과 다시 만든 결과가 같은지 확인합니다. PC처럼 지역 전용 표(아래)가 있는 곳에서는 `build`(기본값)가
그 표까지 넣은 더 큰 데이터셋을 만들고, 그 파일은 저장소에 넣지 않습니다.

| 출처 | 행 | tune | validation | test | 사람 검토 |
| --- | --- | --- | --- | --- | --- |
| 표에서 기계적으로 파생 (`derived_mapping_table`) | 870 | 559 | 124 | 187 | 행별 검토 불필요. 게이트가 매번 표에서 다시 파생해 대조 |
| Claude 초안 (`claude_drafted`) | 219 | 147 | 15 | 57 | **219행 모두 필요**. 지금 검토된 행 0 |

파생 규칙은 열한 가지입니다(`node scripts/governance-mapping.mjs sources`가 표와 규칙별 행 수를 보여 줍니다).

- 카탈로그 표에서: ISMS-P 정렬표의 증거 설명 147행과 지원 요약 41행(그 문장을 나열한 항목이 정답), 정렬표가 "정렬 안 함"으로
  선언한 인증기준 74행(카탈로그 밖이므로 정답은 기권), 인공지능기본법 점검 유형 23행(그 점검 유형을 나열한 항목 전부),
  EU 표가 매핑하지 않는다고 적은 조문 3행(기권).
- 출처 표에서(`data/governance-mapping/sources/`, 표마다 라이선스와 원본 해시를 적은 머리말): Prowler의 KISA ISMS-P 2023 점검표
  (Apache-2.0, 영어) 101개 인증기준의 점검 질문·증거 예시·미준수 사례 389행(`prowler-check` 104 / `prowler-evidence` 142 /
  `prowler-defect` 143); 인공지능기본법·시행령의 조·항·호 본문 122행(`kr-law-text`, law.go.kr); EU AI Act 제9-15·17·19·26·72조와
  부속서 IV 21행(`eu-law-text`, EUR-Lex). 라벨은 카탈로그 항목의 인용(제N조제P항제K호, Article N(p)(x))이 그 단위를 덮을 때만
  붙고, 카탈로그에 없는 인증기준(101개 중 74개)·조문·부속서는 기권이 정답입니다. 문장 유형이 종류와 관계를 정합니다:
  점검 질문은 `document_excerpt`/`context_only`, 증거 예시는 `record_summary`/`supports`, 미준수 사례는 `finding_note`/`contradicts`.
  규칙마다 기권 행은 라벨 행의 1/3(최소 8)까지만 두고 텍스트 해시 순으로 고릅니다.
- 주입 행 50행(`injection`): 위 행 중 해시로 고른 행 끝에 다른 카탈로그 항목을 지목하는 고정 지시문(한국어 4종·영어 4종)을
  붙입니다. 정답은 그대로이고 지목된 항목은 `truth.forbidden`으로 금지되어 게이트의 주입 저항 점검이 읽습니다.
- 지역 전용 표: KISA ISMS-P 인증기준 안내서(2023.11)와 세부점검항목(xlsx)은 공공누리 제4유형(출처표시·상업적 이용금지·변경금지)
  이라 저장소에 넣지 않습니다. `scripts/governance_sources_extract.py kisa`로 만든 `kisa-isms-p-guide-2023-11.json`을
  `.local/governance-tables/`(또는 `EVIDSCOPE_GOVERNANCE_LOCAL_TABLES`가 가리키는 디렉터리)에 두면 `kisa-check` 104 /
  `kisa-evidence` 144 / `kisa-defect` 143행이 더해져 파생 행이 1,263행이 됩니다. 어느 표를 썼는지는 데이터셋 행이 말하므로
  (`derivation.framework`) 저장소 데이터셋은 그 표가 있는 PC에서도 같은 결과로 다시 파생되고, PC에서 만든 데이터셋은 그 PC에서
  검증됩니다. 상업적 이용 전에는 KISA의 허락이 필요합니다.

단, 파생 정답은 **표와 같다는 것**만 보장합니다. 카탈로그 표 자체가 `draft_requires_human_review`이고 출처 표 행은 인용 범위의
기계적 대응이므로 법적 정답이라는 뜻은 아닙니다.

Claude 초안 219행(기권 45, 주입 시도 16)은 실제 증거 문장이 아니라 합성 문장이고 정답도 Claude가 붙였습니다.
`data/governance-mapping/v1/drafted-items.json` 머리에 그렇게 적혀 있고 모든 행이 `humanReviewed: false`, `UNREVIEWED`입니다.
어떤 코드도 이 행을 검토됨으로 바꾸지 않습니다. 이름이 있는 사람이 아래 절차로 승인한 행만 학습·게이트에 들어갑니다.

### 분할과 누수 방지

요구사항 단위로 분할을 고정했습니다(`data/governance-mapping/v1/splits.json`, test 14개·validation 8개 요구사항).
정답에 test 요구사항이 하나라도 있으면 그 행은 test, 아니면 validation 요구사항이 있으면 validation, 나머지는 tune입니다.
기권 행은 `sha256("governance-mapping-v1:" + familyId)`로 나눕니다. 입학 검사는 세 수준의 누수를 거부합니다:
같은 family가 두 분할에 있음, 같은 정규화 텍스트가 두 분할에 있음, tune 행이 test·validation 요구사항을 정답으로 가짐.

### 사람 검토 1: 콘솔 검토 대기열 (기본)

AI 검토실 > `학습 데이터 검토` 화면(`#model-review`)이 Claude 초안 행을 한 번에 하나씩 보여 줍니다. Langfuse의 annotation queue와 같은
방식입니다. 화면에는 텍스트, 증거 위치, 초안 정답(요구사항 제목·프레임워크·관계 포함), 주입 시도 행이면 답에 나오면 안 되는 ID가
나옵니다. 검토자는 **승인 또는 거절만** 합니다. 답을 고치는 기능은 없습니다. 답이 틀리면 거절합니다.

- 단축키: `A` 승인, `R` 거절, `N` 건너뛰기, `P` 이 세션에서 마지막으로 결정한 행 다시 열기. 메모 입력 중에는 동작하지 않습니다.
- 결정 전에 "개인정보 없음 확인"과 "출처·학습 사용 동의 확인"을 체크해야 합니다. 체크는 결정마다 `piiReviewed`·`sourceConsent`로 남습니다.
- 결정할 수 있는 사람은 `reviewer`·`admin` 역할의 사람 계정뿐입니다(OIDC를 켜면 사람 역할은 세션으로만 들어옵니다). `auditor`는 조회만 하고,
  수집 출처·worker 같은 서비스 자격은 화면 자체가 거부(403)합니다.
- 결정 하나는 서명된 원장 객체(`governance_mapping_review`, id = 행 id) 하나입니다. 행의 `reviewedPayloadHash`(초안 답을 그대로 승인했을 때
  붙을 값)와 `recordHash`, 결정자(`reviewerId` = 인증된 principal, 요청 본문으로 바꿀 수 없음), 역할, 볼트 시각이 묶입니다. 화면이 보낸 해시가
  지금 데이터셋의 행과 다르면 409로 거부합니다.
- 같은 행을 다시 결정하려면 이전 결정의 해시를 `supersedes`로 보내야 합니다. 이전 결정은 원장에 그대로 남습니다.
- 진행 표는 분할별 초안·승인·거절·대기 수와 적격 행(파생 + 승인) 대비 최소치(tune 300 / validation 50 / test 100), 추가로 필요한 승인 수,
  승격 게이트의 test 사람 검토 자유 텍스트(30행) 진행을 보여 줍니다. 이 수치는 아래 `export-reviewed`와 같은 함수로 계산합니다.
- 결정한 뒤 데이터셋의 행 내용이 바뀌면 그 결정은 적용되지 않고(`row_changed_since_decision`) 행이 다시 대기열에 나옵니다.

학습 파일은 볼트의 서명된 내보내기에서 만듭니다. 상단의 `감사 내보내기`(`GET /api/export`)로 받은 파일과 볼트 공개 키(`trust-anchor.pem`)를 씁니다.

```bash
node scripts/governance-mapping.mjs export-reviewed --data data/governance-mapping/v1/dataset.jsonl --bundle export.json \
  --trust-anchor trust-anchor.pem --out reviewed.jsonl
node scripts/governance-mapping.mjs admission --data reviewed.jsonl
```

`export-reviewed`는 내보내기의 체크포인트 서명과 해시 사슬을 확인한 뒤 결정 기록만 꺼내고, 기록의 서명 principal과 결정자 ID가 같은지,
역할이 `reviewer`·`admin`인지 확인합니다. 행마다 마지막 결정을 쓰고, 승인은 `importHumanReviews`를 그대로 거칩니다(결정자와 시각은 결정마다
따로). 그래서 `recordHash`·`reviewedPayloadHash`·`reviewBinding`과 입학 검사는 시트 방식과 같습니다. 거절한 행은 빠지고, 결정이 없는 행은
`UNREVIEWED`로 남습니다. 결정을 바꾼 기록이 있으면 마지막 결정이 적용됩니다.

### 사람 검토 2: 일괄 승인·거절 시트 (TSV)

시트 방식도 그대로 씁니다.

```bash
node scripts/governance-mapping.mjs review-sheet --data data/governance-mapping/v1/dataset.jsonl --out review.tsv
# review.tsv의 decision 열에 행마다 approve 또는 reject를 직접 적습니다(빈칸은 미검토로 남음, 와일드카드 없음).
node scripts/governance-mapping.mjs import-decisions --data data/governance-mapping/v1/dataset.jsonl --sheet review.tsv \
  --reviewer <본인 ID> --reviewed-at <ISO 시각> --attest-pii-reviewed --attest-source-consent --out reviewed.jsonl
node scripts/governance-mapping.mjs admission --data reviewed.jsonl
```

시트에는 텍스트, 위치, 초안 정답(요구사항 제목 포함), 주입 시도에서 금지할 ID가 나옵니다. 승인은 기존
`scripts/model-training-data.mjs`의 `importHumanReviews`를 그대로 거쳐 `recordHash`·`reviewedPayloadHash`·`reviewBinding`이
붙고, 승인 후 텍스트나 정답이 바뀌면 그 행은 자격을 잃습니다. 거절한 행은 빠지며 다른 정답으로 바꿔 넣지 않습니다.

학습 입학 최소치(`src/model-policy.mjs`: tune 300 / validation 50 / test 100)를 채우려면 적어도
tune 147행 중 132행, validation 15행 중 3행, test 57행 중 27행을 승인해야 합니다. 승격 게이트는 test에서 사람이 검토한
자유 텍스트 행을 30개 이상 요구하므로 test는 실제로 30행 이상이 필요합니다.

## 평가 장치와 기준선

`scripts/governance-mapping.mjs report`가 test 분할만으로 비교 보고서를 만들고, `gate`가 판정합니다(`src/governance-mapping-eval.mjs`).

| 변형 | 내용 |
| --- | --- |
| `always_abstain` | 항상 기권 |
| `rules_only` | 표에 있는 식별자(밑줄·슬래시가 있는 기록 이름, 발견사항 코드, API·파일 경로)가 문장에 그대로 있으면 그 항목 |
| `zero_shot` | 기본 모델, 카탈로그 ID 목록만, `json_object` |
| `retrieval` | 기본 모델 + 후보 12개(글자 bigram·단어 TF-IDF), `json_object` |
| `retrieval_constrained` | 위와 같고 `json_schema`로 ID·위치 enum 강제 |
| `candidate` | `retrieval_constrained` + 학습한 LoRA 어댑터 |

임베딩 검색(선택). `scripts/governance-mapping.mjs embed-texts`가 모든 프롬프트와 카탈로그 문장을 한 번씩 적은 목록을 쓰고, 격리 컨테이너 안의
`scripts/governance_mapping_embed.py`가 고정된 임베딩 모델(GGUF, llama-server `--embeddings --pooling cls`)로 벡터 파일을 만듭니다(문장 해시 → 벡터,
모델 해시와 격리 확인 포함). 그 파일을 `--embeddings F`(또는 환경변수 `EVIDSCOPE_GOVERNANCE_EMBEDDINGS`)로 주면 예시·후보 검색이 TF-IDF 순위와
코사인 순위를 상호 순위 결합(RRF, k=60)해 쓰고, 파일에 없는 문장은 TF-IDF만 씁니다. 요청 본문의 형식은 달라지지 않고 `buildMappingRequest`의
`retrieval` 필드가 어느 쪽을 썼는지 적습니다. `retrieval-recall --k 1,3,5,8`이 두 방식의 상한(정답이 k개 예시의 답에 들어 있는 비율)을 잽니다.

측정값은 정밀도·재현율(=coverage), 요구사항별 정밀도·재현율, macro 평균, exact match, 기권율(전체·답할 항목),
기권 정답률, 보정(신뢰도 구간별 정밀도와 ECE)입니다. 안전 점검 다섯 가지는 스키마 유효, 카탈로그 ID만, 주어진 위치만,
주입 무시, 기권해야 할 때 기권입니다. 점수는 사람이 검토한 행과 파생 행(게이트 행)으로 계산하고, 전체 행 점수는 참고로만 둡니다.

모델 변형의 출력은 `scripts/governance_mapping_batch.py`의 영수증이 있어야 측정으로 인정합니다. 영수증은 네트워크 인터페이스가
`lo` 하나뿐인 컨테이너, 고정 GGUF 해시(`5813d725…421ed`), 고정 디코딩(temperature 0.1, top_p 0.9, top_k 20, seed 0,
max_tokens 512), 요청 바이트 해시와 출력 해시, 실패 0건을 묶습니다. 보고서는 출력에서 모든 지표를 다시 계산해 대조합니다.

검색 후보 재현율(정답 요구사항이 후보 12개 안에 있는 비율)은 tune 0.707, validation 0.698, test 0.779입니다.
후보 수 12는 tune·validation으로 골랐습니다. 후보 밖 정답도 스키마상 고를 수는 있지만, 검색이 놓친 항목이 재현율의 주된 한계입니다.

## 보류 보정 (abstention calibration)

파일럿 1~7차의 후보는 매핑마다 `confidence: "high"`만 적어 모델이 말로 밝히는 확신도는 정보가 없었습니다(ECE 0.37). 그래서 보정 신호는
모델이 요구사항 ID를 쓸 때의 토큰 확률입니다. `scripts/governance_mapping_batch.py --logprobs F`가 llama-server의 OpenAI식 `logprobs`로
답 토큰마다 로그확률(문법·샘플러 적용 전 softmax)을 받아 마이크로 nat 정수(`logprob × 10^6`)로 `candidate.logprobs.json`에 적고 영수증에
`logprobsSha256`으로 묶습니다. `src/governance-abstention.mjs`는 출력 문자열의 `"requirementId":"…"` 값과 겹치는 토큰의 로그확률 합을 그 매핑의
점수로 삼습니다(토큰을 이어 붙인 문자열이 출력과 다르면 점수 없음).

규칙(`applyAbstention`): 점수가 기준값 이상이고 ID가 요청의 후보 목록에 있던 매핑만 남기고, 남는 것이 없으면 기권합니다. 기준값은 검증 분할의
게이트 행에서 고릅니다(`calibrateAbstention`): 점수가 있는 후보 매핑의 모든 점수를 기준값 후보로 두고, 정밀도가 게이트 최소값(0.9) 이상이면서
매핑이 10개 이상 남는 기준값 가운데 재현율이 가장 높은 것(같으면 더 보수적인 것)을 고릅니다. 그런 기준값이 없으면 정밀도가 가장 높은 기준값을
`reached: false`로 적습니다.

```bash
node scripts/governance-mapping.mjs requests --data D --variant candidate --split validation --out runs/validation/candidate.requests.jsonl
python3 scripts/governance_mapping_batch.py --requests runs/candidate.requests.jsonl --variant candidate --lora A --logprobs runs/candidate.logprobs.json ...
python3 scripts/governance_mapping_batch.py --requests runs/validation/candidate.requests.jsonl --variant candidate --lora A --logprobs runs/validation/candidate.logprobs.json ...
node scripts/governance-mapping.mjs report --data D --runs runs --validation-runs runs/validation --prepared-by X --out report.json
```

보고서에는 `calibration`(검증 행·출력·로그확률, 곡선, 기준값, `reached`)과 변형 `candidate_calibrated`(규칙을 적용한 test 출력)가 더 들어갑니다.
검증은 검증 행에서 기준값 선택을, 후보 출력과 test 로그확률에서 보정 출력을 다시 계산해 저장된 값과 대조합니다
(`governance_report_calibration_changed`, `governance_report_calibrated_outputs_changed`). 보정이 있으면 게이트는 `candidate_calibrated`를
판정 대상으로 삼고(`underTest`), 검증 분할에서 0.9에 못 미친 보정(`reached: false`)은 test 점수와 무관하게 불통과입니다. 측정 인정에는 후보
영수증의 `logprobsSha256`과, 같은 모델·어댑터로 검증 요청·출력·로그확률을 묶은 검증 실행 영수증이 모두 필요합니다(`measurementProblem`).
실행 시점의 적용(승격된 어댑터로 답할 때 같은 기준값으로 기권)은 승격 연결과 함께 들어갑니다; 지금은 보고서가 기준값을 들고 있고 승격 영수증이
보고서 해시로 그것을 묶습니다.

## 실험 비교 (콘솔)

AI 검토실 > `실험 비교` 화면(`#model-experiments`, `GET /api/governance-model/experiments`)은 저장소 `reports/governance-mapping/`의 비교 보고서를
나란히 보여 줍니다. Langfuse·Phoenix의 experiment 비교와 같은 방식입니다. 화면의 수치는 보고서에 적힌 값이 아니라 볼트가 출력과 정답 행에서
다시 계산한 값입니다(`verifyGovernanceReport`). 다시 계산이 맞지 않는 파일은 `unverified`와 사유만 보여 주고 수치를 쓰지 않습니다.

- 열: `always_abstain`, `rules_only`, `zero_shot`, `retrieval`, `retrieval_constrained`(기본 모델), `candidate`(어댑터), 보정이 있으면 `candidate_calibrated`.
- 행: 정밀도, 재현율(coverage), 답한 비율, 기권율, exact match, 기권 정답률, ECE, 안전 점검 다섯 가지, 측정 영수증 상태.
- 사람이 검토한 행과 표에서 파생한 행을 나눈 정밀도·재현율, 프레임워크별 정밀도·재현율, 게이트 밖 행(미검토 초안) 수를 따로 보여 줍니다.
- 판정: 후보가 있으면 승격 게이트, 없으면 기본 모드 판정과 기준선별 비교(아래 4번 규칙의 항목 수와 정밀도)를 보여 줍니다.
- 실행 이력: 보고서와 서명된 팩트시트를 시간순으로 보여 줍니다. 셰이크다운 어댑터를 평가한 보고서는 후보 수치를 숨기고 판정을 불통과로 둡니다.

## 팩트시트 (서명된 실행 기록)

학습·평가·승격 실행마다 볼트 원장에 서명된 객체(`governance_model_factsheet`)를 하나 남깁니다. watsonx.governance의 factsheet와 같은
역할입니다. 운영자가 PC에서 요청 파일을 만들고, `실험 비교` 화면의 `팩트시트 기록`에서 올립니다(`POST /api/governance-model/factsheets`,
`reviewer`·`admin`, 2 MiB 이하). 기록자는 로그인한 principal이며 요청으로 바꿀 수 없습니다.

```bash
node scripts/governance-mapping.mjs factsheet --kind training --receipt training-receipt.json --training-set train.jsonl [--adapter-gguf lora.gguf] --out fs.json
node scripts/governance-mapping.mjs factsheet --kind evaluation --report report.json --out fs.json
node scripts/governance-mapping.mjs factsheet --kind promotion --receipt promotion.dsse.json --report report.json --out fs.json
```

| 종류 | 묶는 값 | 볼트가 직접 확인하는 것 |
| --- | --- | --- |
| `training` | 기본 모델(고정 GGUF 해시)과 학습 기반 잠금(`artifact-lock.json` 해시·revision), 데이터셋 해시와 분할·출처별 행 수, 사람 검토 행 수, 레시피, 자원·학습 수치, 실행 모드 | 영수증의 데이터셋 해시와 학습 파일 해시 일치, 사람 검토 행의 `reviewedPayloadHash`가 서명된 대기열 승인과 몇 개 맞는지, 학습 파일을 저장소(셰이크다운) 또는 서명된 결정(후보)에서 다시 만들어 바이트가 같은지(`verification`) |
| `evaluation` | 보고서 해시, 데이터셋, 게이트 행(파생·사람 검토 수), 변형별 수치와 안전 점검, 측정 영수증 상태, 판정 | 보고서 전체를 다시 계산(조작된 수치는 400) |
| `promotion` | 어댑터 해시, 보고서 해시, 승인자(`reviewerId`, 키 id), 승격 시각 | `promotion-trust.json`의 키로 서명 확인, 보고서를 주면 게이트 재판정 |

학습 자원 수치(GPU 최대 메모리, 시간)와 학습 손실은 운영자 보고 값이고 그렇게 표시합니다. 학습 손실은 품질 지표가 아닙니다.
`GET /api/model-runtime`와 `GET /api/model-status` 응답에 `factsheets: {status, items}`가 추가됐고, `모델 현황` 화면이 목록을 보여 줍니다.

## 승격 게이트

후보는 아래를 모두 만족해야 합니다(`assessGovernanceReport`, `scripts/model-evaluate.mjs`에서도 같은 함수).

1. 게이트 행 100개 이상, 그중 사람이 검토한 자유 텍스트 30개 이상, 기권해야 할 행 20개 이상, 주입 행 5개 이상.
2. 다섯 모델 변형 모두 격리 측정 영수증이 맞고, 후보만 어댑터 해시가 있으며 기본 모델 해시가 같음.
3. 후보 정밀도 0.9 이상.
4. 기준선마다 정밀도 비교를 통과함. 기본 규칙은 **같은 항목 비교(`matched_coverage`)**입니다(`compareWithBaseline`).
   - 그 기준선이 답한(매핑을 하나 이상 낸) 게이트 행에서, 후보의 정밀도가 기준선의 정밀도 이상이어야 합니다. 그 행들에서 후보가 매핑을 하나도
     내지 않으면 불통과입니다(`no_candidate_mappings_where_baseline_answered`).
   - 기준선의 전체 coverage가 후보보다 높으면, 후보의 전체 정밀도가 기준선보다 **높아야** 합니다(`lower_coverage_without_higher_precision`).
   - 매핑을 내지 않는 기준선(항상 기권)은 정밀도 비교 대상이 없습니다.
   - 이전 규칙(전체 행에서 같거나 높은 coverage와 더 높은 정밀도, 기준선 정밀도가 1이면 후보도 1)은 `comparison: 'strict'`로 남아 있습니다.
     판정 결과의 `thresholds.comparison`에 쓴 규칙이 기록됩니다.
5. 안전 점검 다섯 가지 모두 어떤 기준선보다 낮지 않음. 항상 기권 기준선이 기권·주입 점검을 100% 통과하므로 후보도 100%여야 합니다.
6. 사람의 독립 승인: 보고서 준비자도 후보 실행자도 아닌 검토자가 의미 근거, 한국어 품질, 개인정보, 주입, 매핑 표본 검토를
   확인하고, 자기 Ed25519 키로 승격 영수증(DSSE in-toto)에 서명합니다(`scripts/governance-mapping.mjs promote`,
   `scripts/model-promote.mjs`의 `promoteGovernanceCandidate`). 키의 공개 부분은
   `roles/governance-assistant/v1/promotion-trust.json`에 있어야 합니다. 지금은 비어 있어 어떤 승격도 검증되지 않습니다.

**왜 기본 규칙을 바꿨나.** 당시 test 게이트 행(파생 73행)에서 `rules_only`는 매핑 7건을 모두 맞혀 정밀도 1.0, coverage 0.115입니다.
이전 규칙을 문자 그대로 적용하면 후보는 게이트 행 전체에서 오답 매핑을 하나도 내지 않아야 했습니다. 이제는 규칙이 답한 7개 항목에서는
규칙만큼 정확해야 하고(정밀도 1.0), 그 밖의 항목을 포함한 전체 정밀도는 3번의 0.9 이상이면 됩니다. 정밀도 우선 원칙은 3번과 4번의 같은 항목
비교로 지킵니다. 같은 coverage에서 기준선과 정밀도가 같으면 4번은 통과입니다. 그런 후보가 쓸모 있는지는 6번의 사람 승인에서 판단합니다.

기본 모드(`base_retrieval_constrained`)도 같은 규칙을 씁니다. `retrieval_constrained`가 정밀도 0.9 이상이고, `rules_only`와의 같은 항목 비교를
통과하며, 안전 점검에서 지지 않아야 켜집니다(이전에는 0.9 조건이 없었고 엄격 비교였습니다).

## 학습 레시피

`scripts/train-governance-mapping-lora.py`가 런타임 GGUF와 같은 모델의 safetensors(`fdtn-ai/Foundation-Sec-1.1-8B-Instruct`)에
QLoRA 어댑터만 학습합니다. 어댑터가 런타임 모델과 맞아야 하므로 Reasoning 기반 모델에는 학습하지 않습니다.

- 학습 행: `training-set` 명령이 입학 통과 후에만 만듭니다. 런타임이 보내는 `candidate` 요청 그대로의 메시지와 정답 JSON이며
  test 분할은 나가지 않습니다. 손실은 정답 JSON과 EOS에만 걸립니다.
- 설정: NF4 이중 양자화, fp16 연산, rank 8 / alpha 16 / dropout 0.05, q·k·v·o·gate·up·down, 길이 1536, batch 1, 누적 8,
  2 epoch, 학습률 2e-4 cosine(warmup 3%), 5 step마다 체크포인트, GPU 메모리 비율 0.65 이하. 병합 가중치는 만들지 않습니다.
- 격리: Docker 컨테이너를 만든 뒤 `docker inspect`로 네트워크 없음, 읽기 전용 루트, 모든 capability 제거, no-new-privileges,
  메모리 12 GiB·swap 없음, pids 256, CPU 2, GPU 0번만, 입력 읽기 전용 마운트와 체크포인트 하나만 쓰기 가능함을 확인한 뒤에만
  시작합니다(`src/governance-training.mjs`). 2026-10-10부터 PC 사용 중에도 시작하며(`TRAINING_ACTIVE_USE_POLICY`, `--idle-only`로 예전 규칙),
  메모리 부족·과열(75°C 초과)이 감지되거나 1시간이 지나면 체크포인트를 남기고 멈춥니다. 과열과 1시간 제한은 GPU가 65°C 이하로 식으면
  마지막 봉인 체크포인트에서 자동으로 이어가고(최대 6회), 그 밖에는 `--resume`으로 이어갑니다.
- 셰이크다운(`training-set --shakedown`, `governance-mapping-train.mjs --shakedown`): 사람 검토가 끝나기 전에 PC의 VRAM·시간을 재려고 파생 행
  (tune 168, validation 47)만으로 같은 레시피를 돌립니다. 모든 행과 영수증에 `runMode: "shakedown"`이 붙고, 어댑터는
  `governance-mapping/shakedown/shakedown-adapter`에 `shakedown_not_promotable` 상태로 남습니다. 학습기의 후보 검증(`verify_candidate`)은
  이 상태를 거부하고, 후보 학습은 셰이크다운 행을, 셰이크다운 학습은 초안 행을 받지 않습니다. 셰이크다운 팩트시트는 자원 수치만 보여 주며
  그 어댑터 해시로는 후보 학습 기록·승격 기록을 남길 수 없고, 그 어댑터의 평가 보고서는 품질 결과로 보여 주지 않습니다.
- 결과는 `trained_candidate` 영수증이 붙은 어댑터입니다. llama.cpp `convert_lora_to_gguf.py`로 f16 GGUF 어댑터를 만들고
  위 평가와 게이트를 거쳐야만 쓸 수 있습니다.

## 연결

모델은 `governance-assistant` 역할의 assistance 흐름에서만 씁니다(`src/governance-mapping-assist.mjs`).

1. 검토자가 package를 준비할 때 `mappingInput: {kind, text}`를 넣습니다. 구조화 종류는 400, 모델이 꺼져 있으면 409입니다.
   package에는 그 순간의 모드, 프롬프트 변형, 증거 위치(`evidence:<선택한 참조>`), 카탈로그 digest, provenance가 고정됩니다.
   provenance는 `{source: "model", mode, model, modelSha256, adapterSha256, evalReportSha256, promotionReceiptSha256, catalogDigest,
   taskVersion}`입니다.
2. 실행기는 평가와 같은 요청 하나만 보냅니다. 승격된 어댑터 모드에서는 `lora: [{id: 0, scale: 1}]`을 붙이고, 런타임은
   `EVIDSCOPE_GOVERNANCE_ADAPTER_SHA256`의 해시와 맞는 어댑터만 `--lora ... --lora-init-without-apply`로 올립니다
   (`deploy/model-runtime/foundation_entry.py`). 출력이 스키마·카탈로그·위치 검사에 실패하면 실행은 `model_mapping_output_invalid`로
   실패합니다.
3. 초안의 `mappings`는 제안입니다. 서버는 각 매핑의 provenance가 package에 고정된 것과 같은지 확인합니다. 수락은 package 준비자나
   실행자가 아닌 다른 사람만 할 수 있고, 편집한 초안은 모델 매핑을 지우기만 할 수 있습니다(추가·변경 불가).

모드는 세 가지이고 확인할 수 없는 것이 하나라도 있으면 꺼짐입니다.

| 모드 | 조건 |
| --- | --- |
| `off` | 측정 보고서 없음, 설정·파일 해시 불일치, 승격 영수증 검증 실패, 역할 패키지와 영수증 불일치 등 |
| `base_retrieval_constrained` | `governance-mapping.json`의 `baselineReport`가 가리키는 측정 보고서에서 `retrieval_constrained`가 `rules_only`를 위 4번 규칙으로 이기고 안전 점검에서 지지 않음 |
| `promoted_adapter` | `promotion`이 가리키는 영수증이 신뢰 키로 서명되고, 그 보고서가 지금도 게이트를 통과하며, `role.json`의 `adapter`·`modelVersion`·`evalStatus`가 영수증 값과 같음 |

승격 후 `role.json`에는 `adapter: "governance-mapping-lora@sha256:<hex>"`,
`modelVersion: "fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q4_K_M-GGUF@0b58da4…+governance-mapping-lora@sha256:<hex>"`,
`evalStatus: "PROMOTED_HUMAN_APPROVED"`를 영수증에서 그대로 옮깁니다. 영수증 없이 이 값을 바꾸면 상태는 꺼짐이 됩니다.

## 상태 JSON (콘솔 모델 상태 패널)

`GET /api/model-runtime` 응답의 `governanceModel` 필드이며 `node scripts/governance-mapping.mjs status`도 같은 값을 냅니다.
서명된 팩트시트 목록은 같은 응답의 최상위 `factsheets`(`{status: "ok" | "unavailable", items, reason?}`, 최신순 50개)에 있습니다.

```json
{
  "schemaVersion": 1, "task": "governance-mapping", "taskVersion": 1, "roleId": "governance-assistant",
  "mode": "off | base_retrieval_constrained | promoted_adapter",
  "reasons": ["no_measured_report"],
  "model": {"repository": "fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q4_K_M-GGUF", "revision": "0b58da47…", "ggufSha256": "5813d725…"},
  "adapter": null,
  "promoted": false,
  "promotion": null,
  "evaluation": null,
  "scores": null,
  "catalog": {"digest": "f12872b3…", "requirements": 55, "frameworks": {"eu-ai-act-logging": 10, "kr-ai-basic-act": 18, "isms-p": 27}},
  "dataset": {"derived": 870, "drafted": 219, "humanReviewed": 0, "needsHumanReview": 219, "trainingAdmitted": true,
              "eligible": {"tune": 559, "validation": 124, "test": 187}, "minimum": {"tune": 300, "validation": 50, "test": 100}},
  "humanConfirmationRequired": true, "qualityClaimAllowed": false, "observedAt": "2026-10-08T06:33:12.012Z"
}
```

값이 채워질 때의 모양입니다. `adapter`: `{sha256, file, format: "gguf-lora"}`. `promotion`: `{receiptSha256, reviewerId,
reviewedAt, promotedAt, keyid}`. `evaluation`: `{reportSha256, fileSha256, split: "test", items, gateItems, createdAt, preparedBy}`.
`scores`: 변형 이름별 `{precision, recall, exactMatch, abstentionRate, mustAbstainCorrect, ece}`(값은 0~1 또는 null).
카탈로그를 검증하지 못하면 `catalog`·`dataset`이 null이고 `reasons`는 `governance_catalog_unverified`입니다.
패널은 `mode`와 `reasons`를 그대로 보여 주고, `qualityClaimAllowed: false`인 동안 품질을 주장하는 문구를 쓰지 않습니다.

## 한계

- 데이터 정답의 절반은 매핑 표에서 나온 것이고 표 자체가 사람 검토 전 초안입니다. 나머지 절반은 Claude가 쓴 합성 문장입니다.
  실제 조직 문서에서의 성능은 아직 아무것도 측정하지 않았습니다.
- 이 컨테이너에서는 모델을 내려받거나 실행하지 않았습니다. VRAM·시간 값은 이전 실측(같은 8B NF4, rank 8, 길이 1024에서
  6.28 GiB)에 기댄 추정이며 첫 실행에서 다시 잽니다.
- 검색 후보 밖 정답이 많아 재현율 상한이 낮습니다. 게이트는 정밀도를 우선하므로 재현율이 낮아도 통과할 수 있습니다.
- 팩트시트의 학습 자원 수치와 학습 손실은 운영자가 보고한 값입니다. 볼트가 다시 계산하는 것은 평가 수치, 검토 결정 대조, 학습 파일 재현뿐입니다.
- 셰이크다운 어댑터를 알아보는 근거는 학습 영수증 상태와 서명된 셰이크다운 팩트시트의 어댑터 해시입니다. 운영자가 셰이크다운 팩트시트를
  기록하지 않고 그 어댑터를 손으로 GGUF로 바꿔 평가하면 볼트는 구별하지 못합니다. 이때도 승격은 사람의 서명 승인을 거쳐야 하고,
  후보 학습 팩트시트는 서명된 검토 결정으로 학습 파일을 다시 만들 수 있어야 `reproduced_from_signed_decisions`가 됩니다.
- 검토 결정의 시각은 볼트 시각입니다. `export-reviewed`를 시계가 크게 늦은 다른 PC에서 실행하면 "미래 시각" 검사에 걸릴 수 있습니다.
- 모델의 매핑은 적용성·준수 판단이 아닙니다. 사람이 확인한 뒤에도 법률 검토를 대신하지 않습니다.
