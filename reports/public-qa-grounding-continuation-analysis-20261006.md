# Grounding 생성 회귀 분석과 후속 학습 구현

이 기록은 기존 후보의 실제 생성 결과를 분석한 사실과 후속 학습의 가설을 분리한다. 후속 학습 완료나 품질 승격을 주장하지 않는다.

## 실제 생성 관측

입력은 기존에 관측한 한국어 KLUE-MRC 64건이다. `public-qa-diag-stage2-20261005-r1`과 `public-qa-gdiag-20261006-r4`의 실제 `responses.json`, `reports/public-qa-grounding-comparison-20261006-r4.json`을 행별로 대조했다.

| 지표 | 기존 stage2 | grounding |
|---|---:|---:|
| 전체 엄격 통과 | 16/64 | 25/64 |
| 답변 가능 엄격 통과 | 12/32 | 9/32 |
| 답변 불가능 엄격 통과 | 4/32 | 16/32 |
| 답변 가능 문항의 기권 | 2/32 | 13/32 |

향상은 14건(답변 가능 2건, 불가능 12건), 회귀는 5건이다. 회귀 5건은 모두 이전 정답을 빈 답변·빈 인용·`abstained=true`로 바꾼 경우다.

| 회귀 ID 접미사 | 인간 정답 |
|---|---|
| dev_00001 | 프랑스 |
| dev_00005 | 22 또는 22석 |
| dev_00025 | 이마 |
| dev_00034 | 6억여 엔 |
| dev_00066 | 1975 또는 1975년 |

답변 가능 향상은 `dev_00022`의 `2004→2004년`, `dev_00024`의 `인적 성과→물적 성과`이다. 모든 ID는 `klue-mrc-v1_` 접두사를 가진다. 이 비교는 새로운 미관측 수락 평가가 아니다.

## 확인한 학습 특성과 원인 후보

실제 저장된 runtime ConfigMap의 학습·평가 `SYSTEM` 값은 동일한 한국어 문자열이다. Python 문자열의 따옴표만 다르다. 두 입력은 `question`, `document`의 동일한 JSON 구조를 사용한다. 한국어 명령과 영어 평가 명령의 불일치는 확인되지 않았다.

기존 학습 320건은 가능 223·불가능 97(30.3%), source train 12,060건은 가능 8,359·불가능 3,701(30.7%)이다. grounding train 640건은 320·320(50%)이다. 불가능 문항 320개는 동일한 빈 JSON target을 사용한다. 가능한 target은 인간 정답의 첫 span이며 `answer == evidenceQuote`이다. 가능한 첫 span의 길이는 평균 5.83자, 최소 1자·최대 36자다. 동일 기권 target의 반복과 기권 비율 상향이 기권 prior를 증가시켰다는 가설은 결과와 일치하지만 인과가 입증되지는 않았다.

grounding 학습 원문은 약 505∼650자이며 가능 평균 578자, 불가능 평균 582자다. 실제 encoding receipt 704행은 원문 hash와 선택 context hash가 모두 같아 crop은 0건이다. 학습 token 수는 407∼579이다. 평가 64건 중 43건은 650자를 넘으며 답변 가능 32건 중 22건도 이 범위를 넘는다. 가능 문항의 기권은 짧은 10건 중 3건, 긴 22건 중 10건이다. 길이 분포 변화는 추가 원인 후보이며, 짧은 문항도 회귀했으므로 유일한 원인이라고 단정하지 않는다.

기존 grounding은 20 optimizer step·누적 16·epoch 0.5로 320건에 해당하는 작업을 수행했다. 원본 배열 끝 16건과 첫 320건은 각각 8:8·160:160이지만 기존 Trainer는 무작위 sampler를 사용하고 소비 순번을 저장하지 않았다. 실제 마지막 optimizer 묶음의 label 분포를 파일 배열의 끝으로 추정하지 않는다.

## 후속 실험 계약과 구현

새 단계 `public_qa_grounding_continuation_v1`은 원 source 비율에 가까운 11:5 묶음과 LR 0.00003을 시험한다. 원문·인간 정답·공개 주석을 변경하지 않으며, 전체 context 650자와 실제 tokenizer admission을 유지한다. 이는 기권 감소 가설의 실험이며 효과가 아직 검증되지 않았다.

- fresh train 640건: 가능 440·불가능 200. fresh validation 64건: 32·32.
- 기존 학습, grounding 704건, 관측 64건의 ID·family·context를 모두 제외한다.
- BF16/NF4·rank 8·batch 1·누적 16·20 optimizer step. 최초 20묶음의 소비량은 가능 220·불가능 100이다.
- source global step 20과 source adapter optimizer history 60을 분리한다. 새 global step 20 및 새 optimizer 20회가 완료되면 history는 80이다. 이전 optimizer·scheduler를 로드하지 않는다.
- deterministic SHA256 class shuffle과 group shuffle로 매 16건에 11:5를 강제한다. 실제 `training_step`의 `input_ids`, `attention_mask`, `labels` tensor를 기대 encoded row와 전부 대조하고 역전파가 반환된 뒤에만 소비를 기록한다.
- `training-exposure.json`은 누적 실제 소비, row ID, label, 순서, optimizer 묶음, 실제 입력 hash를 저장한다. checkpoint 10/20와 candidate에도 복사한 후 기존 inventory sealing에 포함한다. optimizer 확인과 forward/backward 완료를 분리한다.
- 기존 v1 helper·검증기·완성된 candidate·출시 ZIP은 변경하지 않는다. generic trainer의 v1·stage1/2 분기는 기존 동작을 유지한다.

구현 파일은 `scripts/train-public-qa.py`, `scripts/public-qa-grounding-continuation.py`, `test/test_public_qa_grounding_continuation.py`이다. Job·PVC·GPU 실행은 이 구현 작업에서 수행하지 않았다.

## 새로운 미관측 평가 분리

기존 관측 64개 ID만 제외하면 충분하지 않다. 동일 family를 공유하는 official dev 118개(동일 context는 77개)를 제외해야 한다. 기존 train·grounding train/validation·관측 64건을 ID·family·context로 제외하면 원 official dev 5,841건 중 5,723건이 남는다. 추가로 650자·질문 240자·기본 개인정보 패턴 필터를 적용한 후보는 1,024건(가능 670·불가능 354)이었다. 이 수치는 이번 후속 fresh 데이터 선택 이전의 재계산이다. 후속 평가를 고정할 때는 새 후속 train/validation 노출도 다시 제외하고 해시와 행별 출처를 고정해야 한다.

## 이 구현에서 수행한 검증

실제 fresh 데이터 `258ea70365b16ab31357467f3b32c66edca38b3ea0c6db46a11009ab79ed372b`의 704건이 원본·이전 노출·label 계약 admission을 통과했다. Python syntax compilation도 통과했다.

새 CPU 테스트 10개 중 9개가 통과했고, Windows에 torch가 없어 실제 CPU torch tensor 테스트 1개는 명시적으로 skip했다. 이 테스트는 고정 Linux 이미지에서 별도로 실행해야 한다. 기존 grounding Python 테스트 6/6, 기존 일반 QA Python 테스트 14/14도 통과했다. CPU fixture 검증은 실제 모델 학습이나 GPU 역전파 증명이 아니다.

초기 새 테스트에서 기존 `atomic_json`의 Windows `os.replace`가 `WinError 5`로 실패했다. 동일 실패가 sandbox 밖에서도 한 번 나타났다. 최소 두 번의 직접 `os.replace`와 기존 `atomic_json` 25회 재현 검사는 정상, 320건 소비 검사를 분리한 실행과 최종 전체 실행도 정상이다. 원인은 확정하지 않았으며 초기에 실패한 도구 출력은 보존했다. 저장 함수를 바꾸거나 guard를 완화하지 않았다. 기존 일반 QA 테스트의 기본 sandbox 임시 폴더 쓰기 거부는 sandbox 밖에서 같은 검사를 수행하여 14/14 통과한 것으로 분리했다.

실제 Linux CPU tensor·GPU 학습·checkpoint 및 candidate 독립 검증, 후속 생성 결과, 사람의 의미 검토는 이 보고서만으로 완료 처리하지 않는다. `qualityClaimAllowed=false`, `promotionAllowed=false`를 유지한다.
