# 감사 세션 데이터셋

> 2026-10-18에 추가했습니다. 판정 모델(JEV-9B, Qwen3-4B)은 바뀌어도 데이터셋과 채점기는 남는다는 원칙으로,
> 학습·평가에 쓰는 모든 라벨 세션을 모델과 상관없는 한 형식으로 모읍니다. 코드는 `src/audit-dataset.mjs`,
> 빌더는 `scripts/audit-dataset.mjs`입니다.

## 한 줄 요약

에이전트 세션 하나가 레코드 하나입니다. 레코드에는 **무슨 일이 있었는지**(단계, 돌아온 결과, 규칙 소견), **정답**(위반 여부,
유형, 근거 단계, 서명된 대응표에서 계산한 조항), **출처와 라이선스**, **라벨을 누가 정했는지**가 들어 있고 프롬프트는 없습니다.
모델별 학습 형식은 변환기가 만듭니다. 새 모델이 나오면 변환기만 붙이면 됩니다.

## 레코드 형식 (`evidscope.audit-session/1`)

| 필드 | 내용 |
| --- | --- |
| `id` | 출처 접두어가 붙은 고유 id (`designed:…`, `assebench:…`, `rjudge:…`) |
| `source` | `kind`(designed / public), `dataset`, `license`, 원본 id |
| `family` | 분할 단위. 같은 계열은 학습과 시험에 동시에 들어가지 않습니다 |
| `split`, `fold` | train / validation / test와 그 분할의 이름(`data/threat-scenarios/v1/round-splits.json`의 r6~r9) |
| `agent`, `language`, `request` | 에이전트 종류, 언어, 사용자 요청(공개 세트) |
| `steps[]` | `ref`(a1, a2…), `kind`, `action`, `target`, `destination`, `status`, `note`, `result`, `findings[]` |
| `label` | `verdict`, `type`, `evidence`(단계 ref), `requirementIds`, `knownRuleGap`, `ambiguous` |
| `labelSource` | `by_construction`(설계 때 고정), `dataset_label`(공개 세트의 라벨), `human_reviewed`(사람이 확인, 스크립트는 쓰지 않음) |
| `attributes` | 원본 분류 체계(위험 출처, 실패 유형 등) |
| `hash` | 레코드 전체의 sha256. 라벨이나 단계가 바뀌면 바뀝니다 |

## 변환기

| 형식 | 쓰임 |
| --- | --- |
| `chat` | 지금 판정 모델이 학습하는 대화 행. 회차 빌더(`judge-round.mjs prepare`)의 행과 바이트까지 같습니다(테스트로 확인) |
| `classification` | 평문 + 0/1 라벨. 분류기나 가드 모델용 |
| `pairs` | 정답과 반대 판정의 짝. 선호 학습(DPO 등)용 |

## 채점

`score`는 어떤 모델의 답이든 `{id, verdict, type, evidence}` JSONL로 받아 같은 기준으로 채점합니다. 정답률, 놓친 위협, 오경보,
유형 정확도, 근거 단계 F1을 출처별로 냅니다. 기권은 답하지 않은 것으로 셉니다.

## 원칙

- **오염 방지**: R-Judge는 시험 전용입니다. 다른 공개 세트에서 R-Judge와 겹치는 기록(같은 요청, 같은 행동, 요청 단어 겹침 0.6 이상)은
  빌드 때 빠지고 개수가 남습니다. R-Judge의 원천인 InjecAgent, ToolEmu, AgentMonitor 계열 데이터는 학습에 넣지 않습니다.
- **라벨 출처를 숨기지 않음**: 공개 세트의 라벨은 그 세트가 정한 것이고, 일부는 LLM이 만들었습니다. 설계 시나리오만큼 확실하다고
  말하지 않습니다.
- **실제 기록**: 사용자 PC에서 모은 실제 세션은 사람이 검토한 것만 이 형식에 들어갈 수 있고, 그 PC를 떠나지 않습니다.
- **재현**: 매니페스트는 레코드 해시를 id 순서로 이은 해시(`recordsHash`)를 남깁니다. 학습 회차는 이 값으로 자기가 쓴 데이터를 가리킵니다.

## 실행

```
node scripts/audit-dataset.mjs build --out DIR --fold r7 --per-threat 30 --per-benign 30 \
  --public assebench=AgentJudge-security.json --public-test 'assebench:Legal, Compliance & Audit|…' --rjudge data.csv
node scripts/audit-dataset.mjs export --in DIR --format chat --split train --out train.jsonl --mask-share 0.3 --strip-share 0.3
node scripts/audit-dataset.mjs score --in DIR --answers answers.jsonl --split test
```
