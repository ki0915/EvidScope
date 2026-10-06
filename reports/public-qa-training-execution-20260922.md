# 공개 한국어 데이터 학습 실행 결과

## 실제 결과

**Foundation-Sec-8B-Reasoning의 가중치 학습을 실행했고 5 optimizer step 체크포인트를 보존했다. 계획한 20 step과 학습 후 평가는 완료하지 못했다.**

사용자가 승인한 PC 동시 사용 조건으로 실행했다. 합성 금융 감사 데이터의 사람 검토를 임의로 승인하지 않았으며, KLUE MRC 원본의 사람이 작성한 질문·정답 위치를 사용했다. 이는 한국어 근거 추출 기반 학습이고 한국법·금융 감사 품질 검증은 아니다.

| 항목 | 확인 결과 |
|---|---|
| 베이스 | `fdtn-ai/Foundation-Sec-8B-Reasoning` |
| revision | `63c930c82d7646226d33502bec5870019738400e` |
| 공개 데이터 | KLUE MRC, commit `3efd98708a40ff49251fddde35453f8fbb11f536`, CC BY-SA 4.0 |
| 입력 분할 | 학습 320 / 검증 64; 공식 heldout 미사용 |
| 설정 | NF4 QLoRA, rank 8, 최대 길이 1024, batch 1, 누적 16, CPU 2, RAM hard limit 12Gi |
| GPU 파일럿 | 학습률 0으로 역전파 32회 통과; 파일럿을 가중치 학습 완료로 세지 않음 |
| 실제 학습 | r2 체크포인트 global step 5, epoch 0.25, 유효 학습 예제 80개 |
| 실제 optimizer | 256개 Adam 상태 모두 step 5; CPU 격리 환경에서 확인 |
| adapter | 27,297,032 bytes; LoRA B 행렬 128개, 원소 2,621,440개 모두 유한값·0이 아님 |
| SHA256 | `d8c6c157142863fe37b1398a148e2d9e76f459a37971f5a2f3d6187bb75b9f8b` |
| 체크포인트 무결성 | optimizer·scheduler·RNG·scaler·adapter 등을 포함한 9개 파일 해시 일치 |
| 동일 베이스 검증 손실 | 1.2852251529693604; 학습 후 평가는 미완료이므로 개선 주장 불가 |

산출물:

- [실제 adapter](../.local/training/runs/public-qa-stage1-20260922-r2/checkpoint-5/adapter_model.safetensors)
- [체크포인트 전체 명세](../.local/training/runs/public-qa-stage1-20260922-r2/checkpoint-5/checkpoint-complete.json)
- [검증 결과](public-qa-interrupted-checkpoint-20260922.json)
- [r2 실행 기록](../.local/training/public-qa-run/public-qa-stage1-20260922-r2/controller-receipt.json)

체크포인트 파일의 무결성과 실제 가중치 변경을 검증했다. 이 체크포인트에서 재개해 끝까지 수행하는 실증은 하지 않았다. 체크포인트는 당시 이미지·코드·데이터 지문에 결합돼 있어 이후 수정된 trainer로 무조건 재개하지 않는다. 재개 카운터 초기화 문제는 코드에서 수정했지만 실제 재개 검증은 별도로 필요하다.

## 중단 원인과 조치

첫 실제 실행은 모델 로딩 중 Windows commit 여유가 2.731GiB로 감소해 중단됐다. 사용자의 별도 승인을 받아 DLP 클러스터 3개를 잠시 정지한 r2에서는 실제 학습이 진행됐으나 GPU 온도가 80°C에 도달해 종료됐다. 종료 과정에서 5 step 체크포인트가 저장됐다. 실행 로그는 종료 요청 전 4 step까지 수집됐으며, 5 step은 저장된 trainer 및 256개 optimizer 상태로 확인했다.

온도 기반 휴지를 추가한 r3에서는 실제 NVML 온도 조회를 확인했으나, 모델 로드 중 Windows commit 여유가 2.497GiB로 내려가 가중치 갱신 전에 종료됐다. 온도 기반 휴지를 포함한 장시간 학습은 아직 검증하지 못했다.

독립 조회에서 GetPerformanceInfo·GlobalMemoryStatusEx·WMI 지표가 일치했다. 그 시점 commit limit은 38.863GiB, 여유는 약 10.53GiB, 자동 관리 pagefile은 7GiB였다. r3 로딩 구간에서 여유 commit이 약 8.448GiB 감소했다. Linux의 `MemAvailable`을 Windows 여유 메모리에 더할 수 없다. [독립 지표 비교](../.local/training/gpu-node/native-commit-comparison.json)

이미지의 C 컴파일러와 WSL GPU 드라이버 연결 문제를 해결했다. 모델 샤드는 직접 읽기로 해시 검증하며, 해당 학습 컨테이너의 `memory.high=2Gi`로 회수를 유도한다. 이는 엄격한 2Gi 상한이 아니며 12Gi hard limit과 호스트 감시를 유지한다. 학습하지 않는 임베딩·출력 계층은 FP16으로 유지하고 정규화 계층만 FP32로 처리한다. 기본 모델을 동결한 상태에서 LoRA만 갱신한다.

새 온도 제어는 연산 전에 GPU를 동기화하고 최소 1초 쉰다. 70°C 이상이면 65°C 이하까지 기다리고, 조회 오류·180초 초과 시 중단한다. 외부 80°C 중단 기준은 유지했다. 최종 후보 검증기는 실제 20회 optimizer 갱신과 adapter·원본·실행 코드 해시를 요구하므로 이번 중단 결과를 완료 후보로 통과시키지 않는다.

## 이 컴퓨터에서의 다음 실행 조건

1. Windows commit 여유 **14GiB 이상을 세 번 연속 확인한 뒤** 시작하도록 기준을 강화했다. 로드 실측 약 8.45GiB, 추가 학습·동시 사용 및 중단 여유를 고려한 운영 시작 기준이며 성공 보장은 아니다.
2. 사용자가 이후 pagefile 초기 16GiB·최대 24GiB 설정을 승인했고, 17:11 KST에 설정값을 저장·확인했다. 현재 할당량은 7GiB, commit limit은 38.863GiB로 그대로여서 확대 적용을 위한 Windows 재부팅이 남아 있다. 자동 재부팅은 수행하지 않았다.
3. 새 온도 제어로 20 step을 완료하고, adapter 및 학습 후 동일 베이스 평가를 확인한다. 현재 데이터의 인용 정확도·판단 보류·한국어 의미 평가와 금융 감사 도메인 데이터 검토는 별도로 남아 있다.

## 복구 및 검증

임시 정지했던 DLP 컨테이너 6개를 동일 ID와 원래 재시작 정책으로 복구했고, 세 클러스터의 노드가 모두 Ready임을 확인했다. 기본 kube context는 `k3d-dlp` 그대로다. 학습 Job은 남지 않았고 전용 학습 노드는 정지했다. 모델·데이터·체크포인트 볼륨은 보존했다. [복구 기록](../.local/training/public-qa-run/dlp-restoration.json)

집중 검증: 자원 정책 8개, 최종 후보 검증기 10개, 공개 QA 입력 6개, thermal helper 6개, artifact/checkpoint 6개, hash helper 3개, kbit helper 실제 이미지 CPU 테스트 3개 통과. 이는 학습 실행 경로의 검증이며 모델 품질 검증이나 20 step 완료를 의미하지 않는다.

## 재개 준비 및 페이지 파일 변경: 17:15 KST 후속 결과

사용자 승인 후 관리자 권한으로 pagefile 설정을 초기 16,384MiB·최대 24,576MiB로 저장하고 자동 관리를 해제했다. 첫 설정 시도는 자동 관리 해제 시 생성되는 기존 개체와 충돌해 원복됐고, 기존 개체를 갱신하도록 수정한 다음 적용했다. 실제 사용 중인 pagefile은 여전히 7,168MiB다. [설정 결과](../.local/training/pagefile/result.json)

이후 승인된 DLP 임시 정지와 전용 학습 노드 시작을 수행하고, 새 재개 컨트롤러로 세 번 측정했다. Windows commit 여유는 12.794 / 12.956 / 12.958GiB로 시작 기준 14GiB를 충족하지 못했다. `blocked_resources`로 종료했고 **새 학습 Job이나 optimizer 갱신은 발생하지 않았다.** 현재 학습 결과는 여전히 기존 checkpoint-5이다. [재개 시도](../.local/training/public-qa-run/public-qa-stage1-resume-20260922/controller-receipt.json)

체크포인트 5의 전체 파일 해시를 다시 검증했다. 이전·현재 trainer와 artifact helper의 정확한 해시 쌍만 허용하는 provenance 파일을 만들었고, 모델·데이터·학습 설정은 동일하게 유지한다. 재개 시 optimizer·scheduler의 step 5 및 RNG 복원을 확인하고, 실제 step 6~20의 15회 추가 갱신이 있어야 총 20회로 인정한다. 원본 체크포인트를 수정하지 않으며 새 출력 경로에 저장한다. [재개 명세](../.local/training/resume/public-qa-r2-step5.json), [무결성 재검증](../.local/training/resume/provenance-verification.json)

최종 추가 검증: 산출물 검증기 17개와 자원 정책 8개, Python 재개·공개 QA 테스트 16개, 총 41개 통과. 실제 GPU에서 재개한 결과를 의미하지 않는다. 전용 학습 노드를 정지하고 DLP 컨테이너 6개를 같은 ID·재시작 정책으로 복구했다. [복구 결과](../.local/training/resume/dlp-restored.json)

다음 실행은 Windows 재부팅 후 실제 pagefile 할당량과 commit 한도를 확인하는 것부터 시작한다. 기본 모델이나 데이터는 재다운로드할 필요가 없다. 동일 provenance와 새 run ID로 기존 checkpoint-5에서 이어가며, 자원 검사를 통과한 경우에만 Job을 생성한다.
