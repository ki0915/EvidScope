# 공개 한국어 QA 학습 재개 결과 — 2026-09-28

**Foundation-Sec-8B-Reasoning은 기존 5 step에서 실제 20 optimizer step까지 진행했고, 동일 베이스와 후보의 64개 검증 손실 평가를 끝냈다. 다만 종료 직후 컨트롤러의 상태 관측 경쟁 때문에 전체 실행 검증은 실패 상태로 보존했다. 운영 배포와 품질 승인은 허용하지 않는다.**

## 실제 가중치와 평가

실행은 `public-qa-resume-20260928-r1`이다. 기존 모델 revision `63c930c82d7646226d33502bec5870019738400e`, 고정 이미지, KLUE MRC 학습 320개·검증 64개, NF4 QLoRA rank 8, 길이 1024, batch 1, 누적 16을 유지했다. 원본 checkpoint-5와 재개 provenance를 변경하지 않았다.

- 기존 5회 + 이번 15회 = 실제 optimizer 갱신 20회. skipped update 0회다. 로그에서 6~20의 연속 갱신을 확인했다.
- 재개 시 optimizer 상태 256개와 scheduler step 5, RNG 복원을 확인했다. 종료 후 별도 CPU 컨테이너에서 Adam 상태 256개 모두 실제 step 20임을 확인했다.
- 최종 adapter는 27,297,032 bytes, SHA256 `77a10c126058028f635e686143188d8f66100890cc9652698ca45454b17b8993`이다. 텐서 256개가 모두 유한값이고 LoRA B 행렬 128개가 모두 0이 아닌 값을 포함한다.
- checkpoint-10의 9개 파일, checkpoint-20의 9개 파일, candidate의 7개 파일 해시가 각 완료 명세와 일치했다.
- 동일 베이스의 검증 손실은 **1.2852251529693604**, adapter 후보의 검증 손실은 **0.13406628370285034**다. 같은 64개 검증 행을 순차 평가했다. 이는 한국어 QA 학습 진단이며 인용 정확도·한국어 의미·한국법 적용·금융 감사 품질의 통과 결과가 아니다.

[산출물](../.local/training/runs/public-qa-resume-20260928-r1/), [부분 검증](public-qa-artifact-partial-verification-20260928.json), [CPU 실제 상태 검증](public-qa-cpu-artifact-verification-20260928.json).

## 종료 관측 오류와 보존된 한계

학습 프로세스는 20회 갱신과 후보 평가 후 candidate 완료 명세를 저장했다. 컨트롤러가 Running 상태를 읽은 뒤 자원 측정을 위해 컨테이너에 진입하는 사이 컨테이너가 종료되어 `container not found ("training")`가 발생했다. 컨트롤러는 오류 경로로 Job을 삭제하고 Pod 회수를 확인했다. 원본 컨트롤러 기록은 `state:error`, `terminationConfirmed:true`, terminal exit code 미관측 상태다.

containerd 로그에는 동일 Pod UID → sandbox ID → container ID의 연결과 06:29:33.902 UTC의 exit event가 남아 있다. 이는 06:29:34.324 UTC의 StopContainer보다 앞선다. 그러나 저장된 이벤트 문자열은 명시적인 exit status를 표시하지 않는다. 그 값이 0이었다고 추정하여 원본 영수증을 성공으로 바꾸지 않았다.

기존 전체 검증기를 실행한 결과는 **`controller_execution_not_verified`**다. [전체 검증 실패 기록](public-qa-artifact-verification-20260928.json), [원본 실행 영수증](../.local/training/public-qa-run/public-qa-resume-20260928-r1/controller-receipt.json), [학습 로그](../.local/training/public-qa-run/public-qa-resume-20260928-r1/training.log), [containerd 종료 근거](../.local/training/public-qa-run/public-qa-resume-20260928-r1/containerd-terminal.log)를 함께 보존한다. 부분 검증의 `controllerExecutionVerified:false`, `trainingRunCompleted:false`, `qualityClaimAllowed:false`, `promotionAllowed:false`를 유지한다. 실제 가중치 학습 20회 완료와 전체 실행 검증 통과는 별개다.

## 자원 실측

재부팅 후 실제 페이지 파일은 16,384 MiB로 확대됐고 commit limit은 약 47.863 GiB다. 시작 전 3회 commit 여유는 18.630 / 18.659 / 18.492 GiB로 기존 14 GiB 기준을 통과했다. PC 동시 사용 허용을 반영했으며 자원·온도 중단 기준을 해제하지 않았다.

| 측정 항목 | 결과 |
|---|---:|
| 컨트롤러 경과 시간 | 1,462.471초 |
| 추가 15 step 학습 구간 | 1,125.357초 |
| 베이스 / 후보 검증 시간 | 113.330 / 154.879초 |
| Windows commit 여유 최소 | 6.950 GiB |
| 전체 GPU 메모리 사용 관측 최대 | 8,778 MiB |
| 전체 GPU 온도 관측 최대 | 75°C |
| 학습 컨테이너 memory.current 관측 최대 | 1.999977 GiB |
| PyTorch allocator peak allocated | 7,963,937,280 bytes |
| PyTorch allocator peak reserved | 8,204,058,624 bytes |

전체 GPU와 Windows 지표는 주기적 표본의 최대·최소이며 순간 피크 전체를 보증하지 않는다. `memory.high=2Gi`는 회수 유도이고 hard limit은 12Gi다. GPU 비율 0.65는 장치 전체에 대한 강제 분할이 아니다. Windows·WSL·컨테이너 메모리를 합산하지 않았다.

## Docker 복구와 원상 복구

이번 Docker 시작 오류는 기존 임시 소켓과 동일한 경로에서 재현된 상태였다. Docker 프로세스가 없음을 확인하고 `docker-secrets-engine`의 단일 0-byte `engine.sock` 및 `Docker/run`의 알려진 0-byte 소켓 3개만 있는 폴더를 날짜가 붙은 백업 이름으로 보존했다. 삭제·공장 초기화·설정 변경 없이 Desktop을 숨김 시작했으며 Engine 29.6.1 응답을 확인했다. [복구 기록](../.local/training/docker-recovery-20260928.json).

학습 Job과 Pod를 회수하고 실행 lease가 없음을 확인했다. 전용 학습 노드는 정지했다. 이후 GPU 사용량은 1,343 MiB, 온도 44°C로 관측됐다. CPU 검증 컨테이너도 종료·제거됐다. 모델 추론이나 운영 배포를 활성화하지 않았다. Docker Engine은 후속 앱 이미지 검증을 위해 실행 상태로 유지했다.

9월 22일 중단된 이전 r4 준비 과정에서 일시 정지된 DLP 컨테이너 6개는 당시 ID·이름·중단 시각·재시작 정책을 현재 상태와 대조했다. 오늘 시작 당시 정지 상태라는 이유로 복구 의무를 생략하지 않았다. 동일 6개를 원래 `unless-stopped` 정책 그대로 시작했고, `dlp`, `dlp-proof`, `dlp-empirical-20260712` 세 클러스터의 노드 Ready를 확인했다. 기존 kube context와 클러스터 설정은 변경하지 않았다. [복구 대조](../.local/training/dlp-reconciliation-20260928.json), [복구 결과](../.local/training/dlp-restored-20260928.json), [Ready 확인](../.local/training/dlp-ready-20260928.json).

컨트롤러 종료 경쟁은 이후 수정했다. 측정 실패 시 같은 Pod UID·Job·컨테이너의 실제 종료 코드를 다시 조회하며, 실행 중이거나 다른 컨테이너이면 실패를 유지한다. 관련 회귀·자원 정책 23/23을 통과했다. 이 수정으로 과거 실행 영수증을 변경하지 않았다. 남은 작업은 인용·안전·한국어 의미 평가, 금융 감사 도메인의 검토 데이터 확보와 동일 베이스 비교다. 이번 공개 QA 손실만으로 금융 감사 모델이나 한국법 준수 도구의 품질을 인정하지 않는다.
