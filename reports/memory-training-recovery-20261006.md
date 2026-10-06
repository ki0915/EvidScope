# 메모리 조정과 실제 학습 검증 — 2026-10-06

페이지 파일 30GiB를 실제 할당·지속 설정으로 확인하고, DLP 임시 정지와 검사·학습 순차 실행을 적용한 후 추가 20 optimizer step을 완료했다. 물리 RAM 증설은 수행하지 않았다.

| 실제 실행 결과 | 값 |
|---|---:|
| 새 optimizer 업데이트 / adapter 이력 | 20 / 80 |
| 실제 역전파 소비 | 320건, 가능 220 / 불가능 100 |
| 체크포인트 / 유한 adapter 텐서 | 10·20단계 / 256개 |
| 최소 Windows 예약 여유 / 물리 RAM 여유 | 6.055 / 3.405 GiB |
| 최대 GPU 전체 점유 / 온도 | 9211 MiB / 73 °C |
| 컨테이너 OOM / 이번 재시도 가드 중단 | 0 / 0 |
| 최종 소스 회귀 | 836/836 통과, 제외 0 |

CPU 2·RAM 상한 12GiB·memory.high 회수 기준 2GiB·NF4·batch 1·누적 16을 유지했다. memory.high와 GPU 할당 비율은 전체 PC의 강제 메모리 격리나 2GiB RAM 상한을 뜻하지 않는다. Windows·게스트·컨테이너·GPU 수치를 합산하지 않았다.

첫 r1은 예약 사용률 가드로 중단됐고, r2는 CPU 부하로 GPU 시작 전에 차단됐다. 모두 원래 기록을 보존했다. r3은 실제 20단계와 후보 저장을 완료했지만 종료 직후 자원 조회가 겹쳐 원래 controller는 error다. 같은 Pod UID·container ID·이미지 digest의 실제 CRI CONTAINER_EXITED / exit 0을 별도로 대조해 완료를 검증했다. 원본 receipt를 성공으로 덮어쓰지 않았다. 지연 종료 재확인과 대조 검증에 신원·실패 종료·변조 거부 회귀를 추가했다.

PVC 내보내기 31파일의 로컬 해시가 모두 일치한다. adapter SHA256: 3de58b12eb5d6b46d4ad7a4ea53c008e5f070adcfe53a73826c0002e7495374e. 기존 adapter와 다르며 checkpoint 20과 후보의 adapter는 일치한다. GPU Job·Pod는 없고 학습 노드는 정지했으며, DLP의 원래 5개 running·1개 stopped 상태와 7개 컨테이너 설정을 복구했다. 사용자 앱은 종료하지 않았다.

주요 증적: [실행 검증](public-qa-grounding-continuation-verification-20261006.json), [전체 회귀](source-full-continuation-r3-final-20261006.log), [종료 경합 독립 검토](public-qa-terminal-independent-review-20261006.md), [구조화된 메모리·복구 기록](memory-training-recovery-20261006.json).

이번 결과는 메모리 조정 후 실제 가중치 학습 완료의 증거다. 공개 QA 학습을 한국법·금융 감사 설명 품질로 인정하지 않는다. 미관측 128건의 동일 베이스 순차 생성 비교와 사람의 한국어 의미 검토는 다음 단계이며 qualityClaimAllowed=false / promotionAllowed=false를 유지한다. 현재 새 소스 수정은 기존 불변 v0.1.1 출시 아카이브에 포함되지 않는다.
