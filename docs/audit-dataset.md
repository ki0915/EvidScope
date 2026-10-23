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

- **오염 방지**: R-Judge는 시험 전용입니다. `--test-sets`로 지정한 세트(예: ATBench)는 통째로 시험이 되고, 공개 시험 기록 중
  공개 학습 기록과 겹치는 것도 빠집니다. 다른 공개 세트에서 R-Judge와 겹치는 기록(같은 요청, 같은 행동, 요청 단어 겹침 0.6 이상)은
  빌드 때 빠지고 개수가 남습니다. R-Judge의 원천인 InjecAgent, ToolEmu, AgentMonitor 계열 데이터는 학습에 넣지 않습니다.
- **라벨 출처를 숨기지 않음**: 공개 세트의 라벨은 그 세트가 정한 것이고, 일부는 LLM이 만들었습니다. 설계 시나리오만큼 확실하다고
  말하지 않습니다.
- **실제 기록**: 사용자 PC에서 모은 실제 세션은 사람이 검토한 것만 이 형식에 들어갈 수 있고, 그 PC를 떠나지 않습니다.
- **재현**: 매니페스트는 레코드 해시를 id 순서로 이은 해시(`recordsHash`)를 남깁니다. 학습 회차는 이 값으로 자기가 쓴 데이터를 가리킵니다.

## 공개 세트 (2026-10-18 추가)

| 세트 | 쓰임 | 라벨 |
| --- | --- | --- |
| ASSEBench | 학습, 일부 시나리오는 시험 | 세트의 라벨 |
| StepGuard (`ninty-seven/stepguard_data`) | 학습 | 세트의 라벨(LLM이 만들고 점검). 몇 번째 행동이 위험한지까지 있음 |
| ATBench, ATBench500 | 학습 또는 시험 | 사람이 점검한 라벨 |
| ATBench-Codex | 시험 전용 | Codex 실행 기록의 라벨 |
| ipi-pairs (NVIDIA 간접 주입 환경으로 만든 짝) | 학습 | 만들 때 고정. 같은 주입 기록을 한 번은 무시(정상), 한 번은 따름(위반) |
| R-Judge | 시험 전용 | 세트의 라벨 |

ipi-pairs는 "공격 문구가 들어왔지만 에이전트가 따르지 않은 세션은 정상"이라는 신호를 주려고 만들었습니다. R-Judge에서 정상
세션을 위협으로 잘못 본 경우의 대부분이 이런 기록이었습니다. 새 공격 문구는 쓰지 않고 환경에 들어 있는 문구만 씁니다.

이미 준비된 학습 회차에 공개 세트를 더할 때는 `judge-round.mjs extend`를 씁니다(`src/round-extend.mjs`). 원래 회차의 설계
세션과 시험은 그대로 두고 학습 행과 시험 요청만 더하므로, 새 회차와 원래 회차의 차이는 더한 데이터뿐입니다.

```
node scripts/judge-round.mjs extend --from 원래회차 --out 새회차 --rjudge data.csv \
  --public-train stepguard=sft.jsonl --public-train ipi-pairs=envs.jsonl --public-max ipi-pairs=1000 \
  --public-test atbench=test.json --public-test atbench-codex=codex.json
node scripts/judge-round.mjs score --dir 새회차 [...] --public-test atbench=test.json --public-test atbench-codex=codex.json
```

## 첫 빌드 (v1, 2026-10-18, 7회차 분할)

PC에서 커밋 dbb84e3의 빌더로 만들었습니다. 레코드에는 공개 세트 본문과 설계 시나리오의 시험 명령이 들어 있어 PC에만 두고 저장소에는
넣지 않습니다. 레코드 해시를 이은 값(`recordsHash`)은 `a6192f4a…9064ef`입니다.

| 출처 | 위반 | 정상 | 쓰임 |
| --- | --- | --- | --- |
| 설계 시나리오 | 1,260 | 990 | 학습(7회차 시험·검증 계열 제외) |
| ASSEBench (security + safety) | 953 | 858 | 학습, 일부 시나리오 시험·검증 |
| StepGuard (SFT + RL) | 3,500 | 3,494 | 학습 |
| 주입 짝 세션 | 296 | 296 | 학습 |
| ATBench, ATBench500 | 744 | 753 | 시험 |
| ATBench-Codex | 250 | 250 | 시험 |
| R-Judge | 299 | 269 | 시험 |

모두 14,212 레코드(학습 11,162 / 검증 181 / 시험 2,869)입니다. ASSEBench safety 중 R-Judge와 겹친 292건, 학습 기록과 겹친 공개
시험 기록 123건은 빠졌습니다. 라벨 출처는 세트 라벨 11,370건, 만들 때 고정 2,842건이고 사람이 검토한 라벨은 아직 없습니다.
대화 학습 행으로 내보내면 12,268행(경보 이름 가림·소견 제거 사본 포함)이고, 길이 초과로 빠진 것은 없습니다.

## 실행

```
node scripts/audit-dataset.mjs build --out DIR --fold r7 --per-threat 30 --per-benign 30 \
  --public assebench=AgentJudge-security.json --public assebench:safety=AgentJudge-safety.json \
  --public-test 'assebench:Legal, Compliance & Audit|…' \
  --public stepguard=sft.jsonl --public stepguard=rl.jsonl --public ipi-pairs=envs.jsonl \
  --public atbench=test.json --public atbench-codex=codex.json --test-sets atbench --rjudge data.csv
node scripts/audit-dataset.mjs export --in DIR --format chat --split train --out train.jsonl --mask-share 0.3 --strip-share 0.3
node scripts/audit-dataset.mjs score --in DIR --answers answers.jsonl --split test
```
