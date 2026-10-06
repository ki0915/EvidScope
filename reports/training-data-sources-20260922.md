# 한국어 근거 정리 학습용 공개 자료 조사

확인일: 2026-09-22. 제작자 저장소·데이터 카드·논문·라이선스 발행자의 문서를 확인하고 **KLUE-MRC 원본을 실제 다운로드·검증했다.** 전체 레코드 개인정보 검토는 수행하지 않았으며, 사람 검토 상태나 학습 입장 정책을 변경하지 않았다.

**사용자가 선택한 즉시 진행 경로는 사람이 주석한 공개 데이터를 먼저 확보하는 것이다. KLUE-MRC 원본 QA를 우선 수집한다.** 한국어 근거 인용·답변 보류 능력을 보강하고, 직접 만든 금융 운영 충돌 사례는 별도 검토 상태로 유지한다. FinQA는 금융 문서 근거 추출 보조 자료다. 세 자료 중 한국 AI 기본법에 따른 공급사 증빙·배포 모델·승인·업무 결과 대조를 그대로 제공하는 자료는 확인되지 않았다.

| 자료 | 직접 확인한 구조·정답 출처 | 이용 조건 | EvidScope 사용 결정 |
|---|---|---|---|
| **KLUE-MRC** | 한국어 지문, 질문, 답변 위치, 답변 불가 표시. 원 논문은 작업자가 질문·답변을 작성하며 다문장 추론과 답변 불가 유형을 포함한다고 설명한다. [공식 데이터](https://github.com/KLUE-benchmark/KLUE/tree/main/klue_benchmark/klue-mrc-v1.1), [논문](https://datasets-benchmarks-proceedings.neurips.cc/paper/2021/file/98dce83da57b0395e163467c9dae521b-Paper-round2.pdf) | 제작자 [README](https://github.com/KLUE-benchmark/KLUE/blob/main/README.md)는 CC BY-SA 4.0. 출처·라이선스·변경사항 표시 및 개작 자료 재배포 시 동일조건 적용. 상업 이용 자체는 허용한다. [공식 조건](https://creativecommons.org/licenses/by-sa/4.0/) | **우선 수집 대상.** 정답 문자열의 원문 위치를 기계 검증할 수 있다. 한국법 정답으로 취급하지 않고 문서 읽기·인용·답변 보류 과제로 변환한다. 변환 데이터는 별도 CC BY-SA 파일로 관리한다. 가중치에 대한 동일조건 적용 여부를 여기서 단정하지 않는다. |
| **FinQA** | 금융 보고서 문장·표, `gold_inds` 근거, 계산 프로그램과 결과. 원 논문은 금융 전문가가 QA를 작성했다고 명시한다. [공식 구조 설명](https://github.com/czyssrs/FinQA), [원 논문](https://aclanthology.org/2021.emnlp-main.300/) | 저장소 [MIT LICENSE](https://github.com/czyssrs/FinQA/blob/main/LICENSE)는 저작권·허가문 보존을 요구한다. 공개 보고서라는 이유만으로 원문 전체의 저작권이 사라지는 것은 아니므로, 저장소 라이선스와 원 보고서 출처를 각각 기록한다. | **보조 수집 대상.** 정답 숫자와 인용 문장·표 행을 대조하는 데 적합하다. 한국어 번역·설명은 새 기계 생성물이므로 원문의 전문가 검토를 승계하지 않는다. 실제 차주의 개인정보나 신용평가 기록은 수집하지 않는다. |
| **FinanceBench** | 공개 기업 문서에 대한 질문·답변·근거 문자열. 공식 공개 표본은 **150건**이며 전체 세트가 아니다. [공식 카드](https://huggingface.co/datasets/PatronusAI/financebench/blob/main/README.md), [제작자 발표](https://www.patronus.ai/announcements/patronus-ai-launches-financebench-the-industrys-first-benchmark-for-llm-performance-on-financial-questions) | 공식 카드 CC BY-NC 4.0. 출처·변경사항 표시와 비영리 목적 조건이 있다. 사내 실험이라는 이유만으로 상업적 목적이 없다고 간주하지 않는다. [공식 조건](https://creativecommons.org/licenses/by-nc/4.0/) | **현재 상업 제품 지향 학습 묶음에서는 제외.** 별도 이용권이나 목적 적합성을 확인한 평가에만 사용한다. 150개를 10,000개 이상 공개 데이터로 표현하지 않는다. |

## 수집·변환 명세

다운로드 위치는 KLUE의 `klue_benchmark/klue-mrc-v1.1/klue-mrc-v1.1_train.json`·`klue-mrc-v1.1_dev.json`, FinQA의 [dataset 디렉터리](https://github.com/czyssrs/FinQA/tree/main/dataset)에 있는 `train.json`·`dev.json`·`test.json`이다. 실제 다운로드 시 `main` 대신 확인된 commit을 고정하고 원본 바이트의 SHA-256, 다운로드 시각, 제작자·논문·라이선스 링크를 manifest에 남긴다. 자료와 함께 제공된 코드를 실행할 필요는 없다.

즉시 사용할 원본 주소: [KLUE-MRC train JSON](https://raw.githubusercontent.com/KLUE-benchmark/KLUE/main/klue_benchmark/klue-mrc-v1.1/klue-mrc-v1.1_train.json), [KLUE-MRC dev JSON](https://raw.githubusercontent.com/KLUE-benchmark/KLUE/main/klue_benchmark/klue-mrc-v1.1/klue-mrc-v1.1_dev.json). 사람 주석 근거는 위 KLUE 논문 6쪽의 MRC 구축 절차다. 수집 단계에서는 원본 질문·지문·정답·위치를 그대로 보존하며 EvidScope 감사 정답으로 재명명하지 않는다.

1. **정답을 먼저 원문과 결합한다.** KLUE는 Unicode 문자 기준 답변 위치와 실제 문자열 일치, `is_impossible`와 정답 유무를 확인한다. FinQA는 `gold_inds`가 가리키는 문장·표 행만 근거로 연결하고 계산 결과는 허용된 산술 연산으로 별도 재계산한다. 불일치 레코드는 제외 사유와 함께 격리한다.
2. **설명은 생성하고 출처는 보존한다.** 원문 ID, 지문 해시, 인용 위치, 사용한 변환기 버전, 한국어 설명 생성 출처를 유지한다. 추출 답변·수치 검증 성공이 자유 서술의 의미 정확성을 보증하지 않는다. 설명은 근거 내에서 제한하고 확인 불가 사항을 명시한다.
3. **문서 단위로 분리한다.** 같은 보고서·지문 및 번역본을 서로 다른 학습·평가 split에 넣지 않는다. 기존 공개 평가 자료는 학습에 넣지 않고 외부 평가로 별도 유지한다. 공개 벤치마크가 기반 모델 사전학습에 포함되었을 가능성은 확인되지 않았다.
4. **개인정보가 필요 없는 표본을 고른다.** 계좌·주민번호·연락처·자격증명 패턴 및 민감한 개인 서술을 검사하고 발견된 행은 제외한다. 기업 재무 집계·일반 지식 지문을 우선한다. 자동 검사를 `piiReviewed:true`라는 사람 검토 사실로 기록하지 않는다.
5. **기계 검토와 사람 검토를 구별한다.** upstream의 작업자·전문가 주석 사실과 새 변환 결과의 검토 상태를 따로 저장한다. `humanReviewed:false`를 유지하고 기계 검사 결과·생성기·원본 해시를 별도 provenance로 기록한다. 기존 사람 검토 게이트를 통과했다고 표시하지 않는다.

## 지금 만들 수 있는 학습 묶음

아래와 같이 KLUE 원본 확보를 완료했다. 첫 자원 측정에 사용한다면 이 중 답변 가능·불가 유형이 균형을 이루는 작은 부분집합을 선택할 수 있다. FinQA는 이번에 다운로드하지 않았다. 공개 QA만으로 금융 운영 감사 목표를 대체하지 않도록 직접 작성한 금융 사건 묶음과 목적을 구별한다.

## 실제 확보 결과

실행 명령: `node scripts/prepare-public-training-data.mjs --acquire`. GitHub `main`의 commit을 조회한 뒤 **`3efd98708a40ff49251fddde35453f8fbb11f536`**에 고정된 train/dev/License.md/README.md를 내려받았다. 저장 디렉터리는 `.local/public-training/klue-mrc/3efd98708a40ff49251fddde35453f8fbb11f536/`이며 `.local/`의 Git 제외 상태도 확인했다.

| 산출물 | 확보·검증 결과 |
|---|---|
| 원본 `raw/klue-mrc-v1.1_train.json` | 17,554개 QA. 질문·지문·정답을 원본 그대로 보존 |
| 원본 `raw/klue-mrc-v1.1_dev.json` | 5,841개 QA. 공식 평가 자료 전체 보존 |
| `train.jsonl` | 12,060개, 그중 답변 불가 3,701개 |
| `validation.jsonl` | 1,345개, 그중 답변 불가 419개. 공식 train에서 문서·지문 가족 단위로 분리 |
| `heldout.jsonl` | 공식 dev 5,841개 전부, 그중 답변 불가 1,833개. 학습·파생 validation에 사용하지 않음 |
| `excluded.json` | 공식 dev와 동일 문서 제목 또는 정규화 지문으로 연결된 가족의 train 4,149개 제외. 직접 중복 질문 제거 건수는 이번 입력에서 0 |
| `raw/License.md`, `raw/README.md`, `manifest.json` | 고정 출처 URL, CC BY-SA 조건·제작자 정보, 해시·바이트 수, 변환 내용, 사람 주석 구축 근거 보존 |

최종 디스크 재검증에서 원본 4개와 파생 JSONL 3개의 **SHA-256 불일치 0건**, 합계 145,135,972바이트였다. 14,626개 문서·지문 가족이 split 경계를 넘지 않음을 확인했다. 원본에 QA가 없는 문단 17개(train 16, dev 1)는 빈 문단으로 유지되며 새 질문을 만들지 않았다. 질문·답변·원문은 바꾸지 않았고 `originalQa`도 보존했다.

검사는 답변 위치를 JavaScript UTF-16 인덱스가 아닌 **Unicode code point** 기준으로 대조한다. 답변 불가 표시와 정답 배열 불일치, 잘못된 답변 위치, 중복 ID는 실패한다. 보충 평면 문자가 포함된 회귀 사례와 split·중복·원본 보존 테스트 **4/4 통과**했다. 루트 작업에서 금융 데이터·기존 전달 경로와 합친 테스트 **10/10 통과**도 확인했다.

현재 확보 파일에는 `humanReviewed`나 `approvedOutput`을 새로 넣지 않았다. 대신 `upstreamAnnotation`에 원 제작자의 사람 주석 사실과 근거를 기록하고 `localHumanReviewPerformed:false`, `privacyStatus:not_reviewed`를 유지한다. 금융 감사용 JSON 출력으로 변환하거나 한국법 적용 정답으로 인정한 것은 아니다. 이 자료의 확보 완료와 기존 정식 금융 학습 게이트 통과는 별개이며, manifest의 `trainingRunAllowed`도 false다.

현재 금융 후보 540건은 원천 기록의 시간·정책·모델·해시 관계가 알려진 합성 사례이므로 참조 정합성 검사가 가능하다. 공개 문서 기반 QA를 함께 사용하면 반복된 7개 사건 템플릿만 학습하는 문제를 줄일 수 있다는 것이 이번 설계 판단이다. 품질 개선은 아직 측정되지 않았다.

**이 조사는 데이터 수집·작성 작업을 사용자에게 넘길 이유가 없음을 보여준다.** 수집, 라이선스 기록, 변환, 정답 위치·수치·split 검사는 에이전트가 진행할 수 있다. 다만 현재 코드가 요구하는 사람 검토를 기계 검사로 허위 충족시키지 않는다. 기계 검토 데이터로 별도 실험 학습을 허용하려면 그 실행 모드와 산출물의 제한을 명시적으로 구현·검증해야 하며, 사람 검토를 완료한 정식 데이터나 운영 품질 승인과 혼동하지 않는다.
