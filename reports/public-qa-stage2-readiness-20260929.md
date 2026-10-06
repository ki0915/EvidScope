# 공개 QA 2단계 학습 준비와 자원 차단 기록

2026-09-29. 기존 `public-qa-resume-20260928-r1/checkpoint-20`을 변경하지 않고, 새 대상 `public-qa-stage2-20260929-r1`에서 총 40 optimizer step까지 이어가는 계약을 구현했다. 새 단계는 추가 20 step이며 품질 승인이나 운영 승격을 의미하지 않는다.

## 고정된 실행 계약

- 베이스: `fdtn-ai/Foundation-Sec-8B-Reasoning` revision `63c930c82d7646226d33502bec5870019738400e`
- 원본 checkpoint marker SHA-256: `8aa6594ec8a86f13ad1593304de88b246d000b797e525d8bc9a8eed887fff81c`
- 새 trainer SHA-256: `6a0403c5315b5a5ad7d029f99b049d55526a98e7d3626b61afc669ce6cf417f2`
- stage-2 provenance SHA-256: `cd64980fd6aba6feadb934142bb57a66d34bc53b02778a01f48ac0035fe004b5`
- controller runtime SHA-256: `69e00d303d175b70f66e04f0117dc451d95059c80501aba8af09b7fee82112d5`
- 학습 데이터와 모델·이미지·rank 8·길이 1024·batch 1·누적 16은 기존 실행과 동일하다. 후보 identity의 변경은 trainer 해시와 stage·maxSteps뿐이다. 실행 runtime은 실제 source 9개 파일을 고정하고 `train-public-qa.py`, `public_qa_resume.py`, `resource-pilot.py`의 정확한 전후 해시만 별도로 허용한다. 나머지 6개는 byte-identical이어야 한다.

학습기는 `maxSteps=20`을 stage 1, `maxSteps=40`을 stage 2로만 인정한다. stage 2는 정확한 step-20 원본, optimizer·scheduler·RNG·scaler 파일, 새 출력 경로, provenance와 현재 runtime 파일 해시가 모두 일치해야 한다. 기존 출력 덮어쓰기와 임의 추가 연장은 거부한다. step 21~39의 learning rate가 0이거나 범위를 벗어나면 실패한다. 고정 이미지의 Transformers 4.51.3에서 실제 source scheduler를 40-step scheduler에 불러온 결과 step 20의 0에서 step 21의 `4.75e-05`로 다시 활성화됐다.

동적 패딩은 실제 384행의 문맥·정답·label·EOS를 보존하면서 입력 텐서 바이트를 9,437,184에서 5,892,456으로 37.56% 줄였다. 이는 입력 텐서 감소 수치이며 전체 GPU 또는 Windows commit 감소 측정값이 아니다.

## 실제 사전 검사

`controller-receipt.json`에 stage 2 요청과 위 provenance를 실행 전 고정한 뒤, 사용자 PC 사용 허용 조건으로 3회 측정했다.

| 표본 | Windows 물리 여유 | commit 여유 | commit 사용률 | guest 여유 | GPU 사용 / 전체 | GPU 사용률 | 온도 |
|---|---:|---:|---:|---:|---:|---:|---:|
| 1 | 5.380 GiB | 3.980 GiB | 91.686% | 12.246 GiB | 2801 / 12288 MiB | 39% | 56°C |
| 2 | 5.531 GiB | 4.223 GiB | 91.178% | 12.248 GiB | 2791 / 12288 MiB | 22% | 56°C |
| 3 | 5.508 GiB | 4.237 GiB | 91.148% | 12.252 GiB | 2791 / 12288 MiB | 23% | 55°C |

결과는 `blocked_resources`, 이유는 `windows_memory_start_pressure`다. 이전 모델 적재 실패를 재발시키지 않기 위한 commit 여유 14 GiB 기준을 낮추지 않았다. Job·Pod·candidate·active lease는 생성되지 않았으며 `trainingRunCompleted`, `qualityClaimAllowed`, `promotionAllowed`는 모두 false다.

재부팅 이후 기존 DLP 컨테이너 6개는 저장된 동일 ID와 `unless-stopped` 정책으로 실행 중이고 세 Kubernetes 노드는 Ready다. 학습 전용 노드는 정지 상태다.

## 검증

- 고정 학습 이미지의 전체 공개-QA Python 테스트: 69/69
- v2 resume 계보 집중 테스트: 25/25
- Node controller·자원 정책·stage-2 workload 테스트: 25/25
- 실제 checkpoint·전체 runtime 파일·provenance 검증: 통과
- Python 구문 검사: 통과

현재 완료된 것은 안전하게 다시 시작할 수 있는 고정 실행 경로다. 호스트 commit 여유가 3회 연속 14 GiB 이상일 때 0-learning-rate GPU 파일럿을 먼저 실행하고, 실제 peak와 종료·GPU 회수를 확인한 뒤 같은 provenance로 stage 2를 시작해야 한다.
