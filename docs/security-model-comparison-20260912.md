# 보안·감사 지원 모델 선택 비교

확인일: 2026-09-12 · 장비: RTX 3080 12GB / RAM 32GB · 상태: 사용자 선택 대기

이미 보안 도메인에 추가 가중치 학습을 수행한 공개 모델을 조사했다. 최신 공개일만으로 선택하지 않고 실제 과제·벤치마크·독립 후기·라이선스·로컬 자원을 함께 비교한다. **아직 어느 모델도 다운로드하거나 실행하지 않았다.** 모델을 선택하면 그 모델의 revision과 양자화본을 고정해 제한된 시험부터 진행한다.

## 바로 비교할 후보 3개

| 선택 후보 | 공개 시점과 이미 수행된 학습 | 보안 벤치마크: 해당 제작자의 동일 표 안에서 base → 후보 | 감사 업무에 맞는 점 | 확인해야 할 점 |
|---|---|---|---|---|
| **A. Foundation-Sec-1.1-8B-Instruct** | 2025-11-20. Llama 3.1 8B 기반 보안 특화 base에 instruction tuning·RLHF | CTI-MCQA **61.7→64.4%**, CTI-RCM **55.8→69.4%** | 사건 요약·증거 정리·통제 증거 검토가 공식 용도. 초기 제한된 출력 예산에 우선 시험할 후보 | 영어 지원. 한국어 감사는 미검증. 독립 품질 후기는 적음 |
| **B. Foundation-Sec-8B-Reasoning** | 2026-01-28. Llama 3.1 8B 기반 보안·추론 instruction tuning·RLHF | CTI-MCQA **60.7→69.1%**, CTI-RCM **53.1→75.3%** | 의심 시나리오·취약점 원인·CTI 관계 추론에 적합한 후보 | 추론 토큰·지연 부담을 측정해야 함. Q4/Q8 출력 태그 문제 사용자 보고 존재 |
| **C. RedSage-Qwen3-8B-DPO** | 2026-01 논문, 2026-02 모델 갱신. Qwen3 기반 보안 CPT·추가 pretraining·SFT·DPO | CTI-MCQ **62.76→70.84%**, CTI-RCM **54.00→70.60%** | 보안 지식·과제 성적이 유망하고 외부 동일 파이프라인 비교 자료 존재 | weights 사용·수정·배포 라이선스 미확정. 한국어·양자화 품질과 재현 자료 확인 필요 |

각 행의 공식 근거: [A 모델 카드·평가](https://huggingface.co/fdtn-ai/Foundation-Sec-1.1-8B-Instruct#evaluation), [B 모델 카드·평가](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Reasoning#evaluation), [C 모델 카드·평가](https://huggingface.co/RISys-Lab/RedSage-Qwen3-8B-DPO#performance--evaluation).

CTI-MCQ/MCQA는 보안 지식 객관식, CTI-RCM은 CVE를 CWE 원인 분류에 연결하는 과제다. **AI 법률 감사 정확도나 실제 침해 탐지율이 아니다.** Cisco 두 카드도 base 점수가 다르고 RedSage는 다른 평가 구성이므로 행 간 수치로 1~3위를 정하지 않는다. 이번 장비에서 직접 측정한 결과도 아니다.

## 외부 비교와 사용자 후기

외부 연구자의 [QCRI sayf-eval](https://github.com/qcri/sayf-eval#leaderboard)은 24개 하위과제·9개 계열을 같은 평가 파이프라인으로 비교했다. 공개 평균 strict-verdict 정확도는 RedSage-DPO **64.1%**, 구형 Foundation-Sec-8B-Instruct **57.4%**, Llama-Primus-Merged **54.7%**다. 단일 `gpt-5.4` judge에 의한 집계이며, **Foundation 1.1과 Reasoning은 포함되지 않았다.** 따라서 RedSage가 최신 Cisco보다 낫다는 결론은 내릴 수 없다.

| 후보 | 직접 확인한 사용자/외부 근거 | 선택에 반영할 내용 |
|---|---|---|
| A: 1.1 Instruct | [공개 community](https://huggingface.co/fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q8_0-GGUF/discussions)에서 구체적인 독립 품질 비교를 충분히 찾지 못함 | “후기가 가장 좋다”는 주장은 하지 않음. 업무 적합성과 공식 배포 지원에 근거한 후보 |
| B: Reasoning | [2026-02-15 사용자 issue](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q8_0-GGUF/discussions/1): Q4/Q8에서 여는 think 태그 누락 보고 | 정확한 양자화본·chat template·최종 JSON 분리를 시험. 재현 전 해결/미해결을 단정하지 않음 |
| C: RedSage | [평가 재현 자료 요청](https://github.com/RISys-Lab/RedSage/issues/13), [정확한 weights 라이선스 문의](https://github.com/RISys-Lab/RedSage/issues/15) | 성능 후보로 유지하되 라이선스 확인 전 반입·학습 보류. 문의 존재만으로 모든 자료가 미공개라고 확정하지 않음 |
| Lily 7B: 보조 비교군 | [500 QA 평가와 코드](https://huggingface.co/segolilylabs/Lily-Cybersecurity-7B-v0.2/discussions/2), [소규모 GGUF screening](https://github.com/KaspijaALT/gguf-security-llm-screening/blob/main/README.md) | 독립 경험 자료는 상대적으로 구체적이나 오래되거나 소규모이고 오류·스타일 한계도 보고됨. 최신 우수 후보로 선정하지 않음 |

좋아요·다운로드·홍보 글을 정확성 후기로 계산하지 않았다. 후보들의 **한국어 AI 기본법/국제 거버넌스 감사 성능을 비교한 독립 운영 후기**는 찾지 못했다. 따라서 이번 추천은 근거의 범위가 제한된 도입 우선순위다.

## 최신 모델 중 바로 채택하지 않은 것

| 모델 | 이유 |
|---|---|
| Antares-350M/1B, 2026-07 공개 | 최신 보안 특화 모델이지만 SFT/GRPO와 terminal 도구로 취약 파일 위치를 찾는 과제에 맞춰져 있다. 사용자가 금지한 직접 파일 접근을 허용해 범용 감사 모델로 바꾸지 않는다. 필요시 별도 고정 입력 평가 가능성을 조사할 보조 후보다. [Cisco 발표](https://blogs.cisco.com/ai/introducing-antares-the-most-efficient-open-weight-ai-models-for-vulnerability-localization), [논문](https://arxiv.org/html/2608.02407v1) |
| SecureBERT 2.0 | 보안 검색·NER·분류에 맞는 encoder로 감사 초안 생성 모델과 역할이 다름. [공식 카드](https://huggingface.co/cisco-ai/SecureBERT2.0-base) |
| Llama-Primus-Merged 8B | 실제 보안 학습·공개 성적은 있지만 2025년 계열이며 위 외부 비교에서 우선 후보보다 낮음. [공식 카드](https://huggingface.co/trend-cybertron/Llama-Primus-Merged) |
| SecGPT V2 | 보안 학습은 확인되지만 root artifact는 14B 계열이다. 표의 7B 성적과 다른 크기 모델을 혼동하지 않도록 정확한 artifact 확인이 먼저다. [공식 카드](https://huggingface.co/clouditera/secgpt) |

## 라이선스와 12GB 적합성

A/B는 공개 가중치이며 Llama 3.1 Community License와 Cisco 변경분 Apache-2.0 고지를 함께 검토해야 한다. 완전히 무제한인 Apache 모델이라고 표현하지 않는다. [A NOTICE](https://huggingface.co/fdtn-ai/Foundation-Sec-1.1-8B-Instruct/blob/main/NOTICE.md), [B NOTICE](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Reasoning/blob/main/NOTICE.md)

C는 Qwen 기반이라는 이유만으로 파생 weights에 동일 라이선스를 추정하지 않는다. 사용자가 C를 골라도 이용 조건 확인을 선행한다. 답변을 얻으려고 제3자에게 메시지를 보내는 것은 별도 사용자 요청 없이는 하지 않는다.

8B BF16 weights만 약 16GB이므로 RTX 3080 12GB에는 원본 전체 GPU 적재가 맞지 않는다. Q4는 원리상 weights가 약 4GB부터 시작하지만 실제 파일·KV cache·runtime이 추가된다. A/B는 공식 Q4_K_M 배포가 있고 C는 변환본의 계보·품질 확인이 필요하다. 어느 모델이든 실측 전 “12GB에서 검증 완료”라고 표시하지 않는다. Q4 추론 적합성과 QLoRA 학습 적합성은 별도다.

## 선택 권고와 사용 조건

**초기 추천은 A, Foundation-Sec-1.1-8B-Instruct다.** 사용자가 요청한 사건 정리·증거 검토에 공식 목적이 잘 맞고, 공식 Q4 배포가 있어 초기 성능 제한 아래 통합을 검증하기 쉽다는 판단이다. 최고 벤치마크 모델이라고 주장하는 추천은 아니다. 최신 추론 기능과 의심 시나리오 분석을 우선하면 B를 선택할 수 있고, 외부 비교에서 유망한 후보를 시험하려면 라이선스 확인을 조건으로 C를 선택할 수 있다.

선택 후에는 사용자가 고른 모델만 먼저 반입·시험한다. 다른 모델로의 교체나 복수 후보 추론 비교는 선택 범위를 넘으면 다시 묻는다. 초기 공통 제한은 다음과 같다.

| 항목 | 초기 설정안 |
|---|---|
| 추론 | Q4, context 2048, 총 생성 512 token, 동시 실행 1, 요청 120초, 자동 재시도 0 |
| CPU/RAM | inference CPU limit 2, RAM limit 8GiB; 로딩·작업 중 실측 |
| GPU | GPU 1개, VRAM 운영 목표 8GiB. GPU 수량을 VRAM 강제 상한으로 오해하지 않도록 사용량 감시·입장 제한 |
| 모델 배치 | dispatcher와 분리한 inference Pod, 새 egress 전부 차단, 인증한 내부 요청만 수신 |
| 파일/도구 | 업무 파일 mount·파일 API·shell·MCP·브라우저·임의 코드 실행 없음. weights RO, 제한된 임시 공간만 허용 |
| 종료 | 기본 OFF. test/dev 세션 종료·실패·Ctrl+C 즉시 해당 Pod 종료 및 GPU·endpoint 해제 확인 |
| 비정상 종료 | Job deadline·lease/orphan 회수·완료 후 TTL, 정리 실패 시 STOP_UNCONFIRMED |

Reasoning의 사고 토큰도 생성 상한에 포함한다. 짧은 예산으로 JSON이 완성되지 않으면 제한된 실행의 실패로 보고하고 숨겨서 예산을 늘리지 않는다. 실제 학습은 선택 모델의 라이선스·검토 데이터 admission·별도 GPU 시험을 통과한 뒤 진행한다.

[전체 실행 계획](first-release-execution-plan-20260912.md) · [상세 벤치마크 조사](../.planning/security-model-benchmarks-20260912.md) · [사용자 후기 조사](../.planning/security-model-user-feedback-20260912.md) · [격리·종료 검토](../.planning/model-isolation-lifecycle-20260912.md)
