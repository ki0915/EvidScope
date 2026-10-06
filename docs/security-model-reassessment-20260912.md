# 보안 감사 지원 모델 재검토 — 2026-09-12

검토 범위: 공개 모델 카드·제작자 논문·공식 저장소. 모델·브라우저·학습 코드를 실행하거나 가중치를 다운로드하지 않았다. GPU 적합성은 아래의 계산상 후보 판단이며 RTX 3080 12GB 실측 결과가 아니다.

## 판단

현재 `Foundation-Sec-1.1-8B-Instruct`를 최선으로 확정할 근거는 부족하다. **가장 직접적인 교체 평가 후보는 2026-01-28 공개된 Cisco `Foundation-Sec-8B-Reasoning`**이다. 같은 8B 계열의 추론 특화 후속이며 제작자가 Q4_K_M도 제공한다. 다만 더 높은 CTI 점수만으로 한국어 사건 감사·JSON 형식·응답 시간까지 개선됐다고 할 수 없다. [공식 카드](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Reasoning), [공식 Q4 저장소](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q4_K_M-GGUF/tree/main)

빠른 분류용 대안은 `CyberSecQwen-4B`, 공개 학습 자료를 활용할 대안은 `Llama-Primus-Reasoning`이다. `CyberPal2.0-20B`는 SOC 도메인과 점수 측면의 유력 비교 대상이지만 12GB 단일 GPU 우선안에는 부담이 크다. `SecGPT`는 실재하는 보안 모델이나 한국어 및 현재 기준 모델 대비 우월성을 뒷받침하는 직접 자료가 약하다. 아래 우선순위는 공개 근거에 대한 제안이며 성능 검증 결과가 아니다.

## 기준 모델과 직접 관련 후보 5개

| 모델·공개 시점 | 학습 도메인과 감사 업무 관련성 | 라이선스·한국어 근거 | 12GB 추론 판단·우선순위 |
|---|---|---|---|
| **기준: Foundation-Sec-1.1-8B-Instruct** — 2025-11-20 | 보안 기반 모델의 지시 이행·정렬. 사건 보고·CTI 문서 등 64K 문맥을 표방. 데이터 마감 2025-04-10. [카드](https://huggingface.co/fdtn-ai/Foundation-Sec-1.1-8B-Instruct) | 공식 지원 **영어**. 한국어 실무 감사 점수 미확인. Llama 계열 NOTICE 조건 확인 필요. | 현행 비교 기준으로 유지. 8B BF16은 가중치만 약 16GB이므로 12GB 전체 GPU 적재 대상으로 삼지 않는다. |
| **Foundation-Sec-8B-Reasoning** — 2026-01-28 | 보안 질의·추론 SFT와 검증 가능한 보상 학습. SOC 조사·CTI·취약점 분류·증거 정리에 직접 관련. 32K 문맥, 영어, 데이터 마감은 여전히 2025-04-10. [카드](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Reasoning), [논문](https://arxiv.org/html/2601.21051v1) | Cisco 변경분 Apache-2.0와 원본 Llama 3.1 Community License가 함께 적용된다. 단순 Apache 전용으로 표시하면 부정확하다. [NOTICE](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Reasoning/blob/main/NOTICE.md) | **교체 평가 1순위**. 공식 Q4 저장소 표시 크기 4.94GB. 짧은 문맥·동시 1건 추론 후보. 문맥·추론 토큰이 늘면 KV 캐시·시간 예산을 다시 측정해야 한다. [파일 목록](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q4_K_M-GGUF/tree/main) |
| **Llama-Primus-Reasoning 8B** — 현재 카드의 교체 갱신 2025-06-02 | Trend Micro 보안 사전학습·지시 학습과 o1-preview/DeepSeek-R1 증류. 경보 설명, 의심 명령 분석, 보안 이벤트 질의, 설정 평가 자료가 포함돼 목적에 가깝다. [카드](https://huggingface.co/trendmicro-ailab/Llama-Primus-Reasoning), [제작자 논문 §2.4](https://arxiv.org/html/2502.11191v3) | MIT + Llama 3.1 Community 조건. 공식 카드 영어. 한국어 평가 미확인. `trend-cybertron`의 이전 카드와 `trendmicro-ailab`의 갱신 카드가 다르므로 이름만으로 버전을 고정하지 않는다. | 4bit 변환 시 후보이나 공식 카드의 BF16 원본은 12GB 전체 적재에 부적합. **학습 자료·보조 비교 후보**. CTI-Bench 오염 주의가 특히 중요하다. |
| **CyberSecQwen-4B** — 2026 기술자료·공개 체크포인트 확인, 최초 공개일 미확인 | Qwen3-4B-Instruct-2507에 약 14,776개 CVE→CWE·CTI 합성 QA를 LoRA SFT. 주 업무는 CWE 분류와 CTI QA이며 일반 로그 조사 전반의 검증 모델은 아니다. [제작자 카드](https://huggingface.co/athena129/CyberSecQwen-4B), [학습·평가 코드](https://github.com/GPT-64590/CyberSecQwen-4B) | Apache-2.0. **이 체크포인트의 카드에는 영어만 명시**. Qwen 기반이라는 이유로 한국어 보안 감사 품질을 승계했다고 가정하지 않는다. | **경량 분류 평가 후보**. BF16 가중치 이론값 약 8GB, 4bit 약 2GB에 부가 메모리가 필요. 공식 재현 환경은 MI300X 192GB이므로 RTX3080 학습 성공 근거로 해석하면 안 된다. |
| **CyberPal2.0-20B** — 논문 2025-10-15, 공개 체크포인트 확인·최초 가중치 공개일 미확인 | gpt-oss-20b 기반, SecKnowledge 2.0 전문가 관여·문서 근거 기반 추론 자료. CTI, SOC/IR, IAM, 거버넌스·컴플라이언스 지원을 명시. 도구 사용은 미검증이라고 카드가 밝힌다. [카드](https://huggingface.co/cyber-pal-security/CyberPal2.0-20B), [논문](https://arxiv.org/html/2510.14113v1) | Apache-2.0, 영어 표시. 한국어 평가 미확인. 논문은 4B–20B 가족을 다루지만, 확인한 공식 조직 목록에는 **20B 하나만** 있어 4B/8B를 즉시 받을 수 있다고 추천하지 않는다. [공식 목록](https://huggingface.co/cyber-pal-security/models) | **상위 비교 대상·현재 GPU 우선안 제외**. 공식 저장소 41.9GB. 20B급 4bit도 가중치만 대략 10GB 이상이라 부가 메모리와 함께 12GB에 충분히 들어간다고 보장할 수 없다. [파일 목록](https://huggingface.co/cyber-pal-security/CyberPal2.0-20B/tree/main) |
| **Clouditera SecGPT V2 / 14B 계열** — 2025-04 | Qwen2.5·DeepSeek 계열 보안 학습. 로그·트래픽 추적, 명령 해석, 취약점·사건 분석을 명시. 현재 공개 `clouditera/secgpt`는 모델 트리상 Qwen2.5-14B-Instruct 파생이고 HF 표시 크기는 15B. [카드](https://huggingface.co/clouditera/secgpt), [공식 GitHub](https://github.com/Clouditera/secgpt) | Apache-2.0 표시, 중국어·영어. 한국어 특화·한국어 감사 평가 미확인. | 원본 F16은 12GB 부적합. 4bit 가중치 이론값 약 7–7.5GB로 문맥을 줄인 추론 후보지만 실제 여유·품질 미측정. **중국어·로그 분석 비교용 후순위**. |

## 점수의 비교 가능성

| 근거 | 확인된 결과 | 그대로 우열을 결정할 수 없는 이유 |
|---|---|---|
| Cisco 두 공식 모델 카드 | 1.1 Instruct: CTI-MCQA **0.644**, RCM **0.694**. Reasoning: **0.691**, **0.753**. [1.1 카드](https://huggingface.co/fdtn-ai/Foundation-Sec-1.1-8B-Instruct), [Reasoning 카드](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Reasoning) | 제작자 자기보고이며 두 카드의 공통 Llama 기준값도 다르다. 1.1의 정확한 현재 revision과 후속을 동일 설정에서 재실행한 독립 결과로 취급하지 않는다. |
| Cisco Reasoning 논문 Table 2·3·6 | 같은 연구의 `Foundation-Sec-8B-Instruct` 대비 Reasoning MCQA **0.650→0.691**, RCM **0.704→0.753**. 반대로 IFEval **0.861→0.837** 등 일부 하락도 보고. 5회 평균이며 instruct와 reasoning 샘플링 설정은 다르다. [논문](https://arxiv.org/html/2601.21051v1) | 비교 이름은 **1.1을 명시하지 않는 Instruct**다. 제작자 평가이며 전체 업무에서 단조롭게 개선된 모델도 아니다. 공개 추론 설명이 증거의 진실성을 입증하지 않는다. |
| Primus 카드·제작자 논문 | 갱신 Reasoning CISSP **0.8193**. 그러나 Primus-Reasoning 학습에 CTI-MCQ·RCM·VSP·ATE 문항에서 증류한 자료가 들어간다. [카드](https://huggingface.co/trendmicro-ailab/Llama-Primus-Reasoning), [논문 §2.5](https://arxiv.org/html/2502.11191v3) | CTI-Bench 그대로의 점수는 미학습 평가로 순위를 매기기에 부적절하다. CISSP 점수도 실제 사건 감사 정확도와 다르다. |
| CyberSecQwen 제작자 평가 | 5회 평균 MCQ **0.5868**, RCM **0.6664**; 연구 내 Foundation-Sec-Instruct는 **0.4996**, **0.6850**. 학습 중복 제거와 과거 오염 실패를 공개. [카드](https://huggingface.co/athena129/CyberSecQwen-4B) | 다른 프로토콜의 Cisco 숫자와 한 줄 순위로 합치면 안 된다. 작은 모델의 효율 근거이지 현재 1.1 모델 전면 교체 근거는 아니다. 이 모델 자체의 독립 재현은 확인하지 못했다. |
| CyberPal 논문과 다른 제작자의 재측정 | CyberPal2.0-20B 논문 MCQ **0.7571**, RCM **0.8740**. CyberSecQwen 제작자의 별도 프로토콜 단회 재측정은 **0.738**, **0.728**. [논문](https://arxiv.org/html/2510.14113v1), [재측정 연구노트](https://github.com/GPT-64590/CyberSecQwen-4B/blob/main/docs/RESEARCH_NOTES.md) | 외부 재측정이 존재하나 **다른 프롬프트·단회**다. 동일 프로토콜의 독립 재현으로 87.4%가 확정됐다고 말할 수 없다. 한국어·EvidScope 감사 평가도 아니다. |
| SecGPT 자기보고 | 14B CISSP **77.37**, CS-EVAL **86.12**. 동일 카드의 Qwen2.5-14B CS-EVAL **86.22**보다 모든 항목이 높지는 않다. [카드](https://huggingface.co/clouditera/secgpt) | Foundation-Sec-1.1과의 동일 프로토콜 독립 비교를 확인하지 못했다. 카드의 광범위한 개선 홍보 문구보다 실제 표를 우선한다. |

조사한 범위에서 **위 5개와 Foundation-Sec-1.1의 정확한 배포 revision을 동일한 한국어/영어 SOC·AI 감사 세트로 비교한 독립 검증은 확인되지 않았다**. 별도 2026-07 malware-analysis 연구는 Foundation-Sec와 소형 모델의 결합을 시험했지만, 현재 후보들의 동일 버전 비교가 아니고 도구가 포함된 실험도 있으므로 이 제품의 무도구 Pod 성능 보증으로 가져오지 않는다. [독립 연구](https://arxiv.org/html/2607.20216v1)

## 역할과 운용 조건

- **관측·수집은 수집기와 서명된 증거 경로의 역할**이다. 더 좋은 언어 모델이 미수집 암호화 트래픽·로컬 AI 호출을 자동으로 가시화하지 않는다. 모델은 전달받은 최소화 증거의 분류·가설·요약만 담당한다.
- CipherGuard 같은 민감정보 분류기, Llama Guard 같은 콘텐츠 가드와 위 SOC 모델은 역할이 다르다. 가드 점수를 사건 분석 성능으로 합산하거나 가드만으로 조사 모델을 대체하지 않는다. Cisco도 Reasoning 모델과 가드의 별도 배치를 설명한다. [Reasoning 카드](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Reasoning)
- 이름 혼동 주의: `llm-platform-security/SecGPT`는 **IsolateGPT 실행 격리 아키텍처**이며 Clouditera 보안 가중치와 다른 프로젝트다. [해당 공식 저장소](https://github.com/llm-platform-security/SecGPT)
- 표의 메모리 계산은 `파라미터 수 × 비트 수 / 8`의 가중치 최소값이다. 런타임, 양자화 메타데이터, KV 캐시, 디스플레이 점유와 여유 공간이 더 필요하다. **추론 적재 가능성과 LoRA 학습 가능성은 별도**이며 어떤 후보도 이 장비의 학습 성공을 확인하지 않았다.

## 변경 제안 — 실행은 하지 않음

1. 현행 모델은 기준으로 남기고 **Foundation-Sec-8B-Reasoning Q4**를 첫 비교 후보로 기록한다. 아티팩트 revision·해시·라이선스와 추론 파서/출력 스키마 호환성을 먼저 확정한다. 1.1의 지시 이행 장점이 있을 수 있으므로 일괄 대체하지 않는다.
2. 경량 보조 후보는 CyberSecQwen-4B, 학습 자료 후보는 Primus로 분리한다. Primus를 학습에 사용하면 원 CTI-Bench 문항과 파생 증류 항목을 평가 세트에서 제외하고 별도 시간 분리 세트를 만든다.
3. 동일한 한국어/영어/혼합 증거 묶음으로 근거 인용 정확도, 잘못된 단정, 미관측 시 판단 유보, 권한·결과 불일치, 주입문 저항, JSON 유효성, 처리시간·최대 VRAM을 비교한다. 한국어 법률 결론 자동화는 통과 기준이 아니다.
4. 공통 비교에서는 동일 시간·문맥·출력 예산을 적용하고, 별도 최적 설정 비교에는 각 모델이 쓴 토큰·시간을 함께 기록한다. Reasoning의 중간 생성 때문에 기존 512 토큰 한도에서 최종 답이 잘릴 가능성도 시험해야 한다.
5. 향후 실행이 승인되면 각각 독립 Pod·무도구·업무파일 마운트 없음·egress 차단·동시 1건을 유지하고 종료 후 Pod 부재/컨테이너 종료·자원 반환을 확인한다. 이번 재검토로 모델 설정이나 실행 정책을 변경하지 않았다.
