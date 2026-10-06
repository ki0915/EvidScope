# 공개 한국어 QA 1차 학습

선택한 `fdtn-ai/Foundation-Sec-8B-Reasoning`의 고정 revision `63c930c82d7646226d33502bec5870019738400e`를 사용한다. 데이터는 KLUE MRC 원본의 사람이 작성한 질문·정답 위치이며 CC BY-SA 4.0 출처와 원본 해시를 보관한다. 합성 금융 감사 데이터의 사람 검토를 대신한 것으로 기록하지 않는다.

320개 학습 행과 64개 검증 행을 사용한다. 공식 heldout은 학습하지 않으며 동일 문서가 분할을 넘지 않도록 준비 단계에서 검사한다. 1024 토큰에 맞춘 문서 창 안에 원본 정답이 그대로 남는지 실제 토크나이저로 검사한다. 원본 정답을 JSON 인용 형식으로 옮기며 생성된 추론 정답을 추가하지 않는다.

## 실행

모델 및 데이터 PVC, 전용 GPU 노드, CNI 허용→차단→허용 실측이 먼저 필요하다. `scripts/public-qa-workload.mjs`의 고정 이미지와 immutable ConfigMap을 사용한다. Windows에서 Docker·Kubernetes에 접근 가능한 PowerShell로 실행한다.

```powershell
node scripts/run-public-qa-job.mjs --execute-resource-pilot public-qa-resource-pilot-N --allow-interactive-use
node scripts/run-public-qa-job.mjs --execute-explicit-request public-qa-stage1-RUN --allow-interactive-use
```

`--allow-interactive-use`는 이번 실행에 대한 사용자의 명시적 PC 동시 사용 허용을 반영한다. 자동 학습 정책을 바꾸지 않으며 메모리·온도·시간 제한을 해제하지 않는다. `--check-only`는 학습하지 않는다. 파일럿은 학습률 0으로 자원만 측정하며 학습 완료로 기록하지 않는다.

실제 학습은 NF4 QLoRA, rank 8, 길이 1024, batch 1, 누적 16, CPU 2, RAM 12Gi, 20 optimizer step이다. 10 step마다 optimizer·scheduler·RNG를 포함한 체크포인트를 보관한다. GPU 메모리 비율 0.65는 장치 전체의 강제 격리가 아니므로 호스트 GPU를 따로 측정한다.

2026-09-29부터 길이1024는 최대 길이로 유지하고, 실제 배치는 필요한 길이까지만 오른쪽 패딩한다. 기존384행을 실제 고정 토크나이저로 비교해 문맥 선택·정답·마스크·EOS와 인코딩 기록이 모두 동일함을 확인했다. 입력 텐서 합계는9,437,184→5,892,456바이트(37.56% 감소)다. 이는 전체 모델 GPU/RAM 절감률이 아니며 다음 실제 역전파 실행에서 최대 점유를 따로 측정한다. 변경된 trainer 해시를 새 실행에 결합하며 과거 resume provenance를 재사용·덮어쓰기하지 않는다. 작은 CPU 모델의 손실·기울기 동등성 및 실제 Transformers collator 검증은 `reports/public-qa-padding-runtime-20260929.log`에 있다.

컨트롤러는 시작 전 세 차례 자원을 측정하고 실행 중 Windows·WSL·컨테이너를 별도로 관찰한다. 메모리 영역을 합산하지 않는다. 해당 Job 종료와 Pod 삭제가 확인된 경우에만 실행 lease를 해제한다. 다른 작업은 종료하지 않는다.

2026-09-22 실행에서는 사용자가 별도로 승인한 DLP 클러스터 3개를 학습 동안 일시 정지한다. `.local/training/public-qa-run/dlp-temporary-stop.json`의 원래 컨테이너 ID와 실행 상태를 기준으로 반드시 복구하며, 클러스터 설정이나 재시작 정책은 변경하지 않는다.

RTX 3080 12GB/호스트 RAM 32GB 실측에 맞춰 다음을 적용했다. 모델 해시는 Linux 정렬 직접 읽기로 검증해 대용량 캐시 누적을 줄인다. 실제 학습 컨테이너의 `memory.high`를 2Gi로 설정해 회수를 유도하되, 이는 엄격한 상한이 아니며 `memory.max=12Gi`와 호스트 감시를 유지한다. 고정 임베딩·출력 계층은 FP16을 유지하고 정규화 계층만 FP32로 처리한다. GPU allocator의 미사용 예약 메모리 회수와 학습 microbatch 사이 1초 휴지를 적용한다. PC 전체 메모리 여유가 부족하면 해당 Job이 종료된다.

## 완료 검증

학습 종료 후 전용 PVC의 `/checkpoints/runs/<runId>`를 `.local/training/runs/<runId>`로 내보낸다. Job 성공만으로 완료를 인정하지 않는다.

```powershell
node scripts/verify-public-qa-artifact.mjs .local/training/runs/<runId> .local/training/public-qa-run/<runId>/controller-receipt.json reports/public-qa-artifact-verification-20260922.json
```

검증기는 실제 adapter inventory, SHA256, 20 step, 성공 종료·Pod 회수, 원본 모델·데이터·이미지·실행 코드 결합을 대조한다. 기록 자체를 신뢰할 수 없는 주체가 위조한 경우까지 증명하는 attestation은 아니다.

학습 전 adapter를 비활성화한 동일 베이스와 학습 후 후보를 같은 64개 검증 행으로 순차 평가한다. 손실 변화는 학습 진단이며 인용 정확도·안전성·한국어 의미 검토를 대신하지 않는다. 이 단계는 한국어 근거 추출 기반 학습으로, 한국법 적용성·금융 감사 품질 인증이나 운영 배포를 허용하지 않는다.

## 2차 재개 학습

1차의 `checkpoint-20`을 재개 출처로 쓸 때는 완료 명세와 파일 해시, optimizer·scheduler·RNG 상태를 확인하고, 출처와 대상 실행 코드 차이를 적은 별도 provenance JSON을 생성한다. 대상 실행은 `public-qa-stage2-*` 이름, 같은 베이스 revision·데이터·이미지, 최대 40 optimizer step으로 제한한다. 첫 단계 후보의 품질 승인으로 재개 권한을 대신하지 않는다.

```powershell
node scripts/run-public-qa-job.mjs --execute-explicit-request public-qa-stage2-RUN --allow-interactive-use --resume-provenance .local/training/resume/STAGE2.json
node scripts/verify-public-qa-artifact.mjs .local/training/runs/public-qa-stage2-RUN .local/training/public-qa-run/public-qa-stage2-RUN/controller-receipt.json reports/public-qa-stage2-verification.json
```

검증 전에 전용 PVC의 `/checkpoints/runs/public-qa-stage2-RUN` 전체를 `.local/training/runs/public-qa-stage2-RUN`으로 내보낸다. 2차 검증기는 21∼40회의 실제 optimizer 갱신, 재개 상태, 30·40 step 체크포인트, 후보 파일 해시, 컨트롤러의 성공 종료와 Pod 회수를 모두 요구한다. 실패·중단된 실행의 체크포인트는 보존하되 완료된 후보로 표시하지 않는다. 일시 정지한 DLP 컨테이너는 실행 결과와 관계없이 시작 전 기록한 동일 ID만 복구한다.

## 2차 후보의 실제 응답 진단

검증된 2차 후보만 별도의 고정 64건 한국어 QA 데이터에 연결한다. 같은 NF4 베이스에서 adapter OFF와 ON을 순차 실행하고, 128토큰 출력·1024토큰 문맥·greedy 생성·동일 프롬프트를 유지한다. 진단용 Job은 학습하지 않고 후보 승격도 하지 않는다.

```powershell
node scripts/run-public-qa-job.mjs --execute-diagnostic-stage2 public-qa-diag-stage2-RUN --allow-interactive-use
node scripts/verify-public-qa-diagnostic.mjs .local/training/diagnostics/public-qa-diag-stage2-RUN .local/training/public-qa-run/public-qa-diag-stage2-RUN/controller-receipt.json reports/public-qa-stage2-diagnostic-verification.json
node scripts/score-public-qa-diagnostic.mjs .local/public-training/diagnostic/20260928/data.jsonl .local/public-training/diagnostic/20260928/manifest.json .local/training/diagnostics/public-qa-diag-stage2-RUN/responses.json reports/public-qa-stage2-diagnostic-score.json
```

검증 전에 전용 PVC의 `/checkpoints/diagnostics/public-qa-diag-stage2-RUN`을 동일 이름의 로컬 디렉터리로 회수한다. 실제 종료·Pod 회수·응답 128개·원본 해시·실행 설정 검증 보고서와 채점 결과를 함께 보아야 한다. 채점만으로 모델 실행이나 한국법·금융 도메인 품질을 인정하지 않는다.

## 원문 보존과 무답 구별 추가 실험

`prepare-public-qa-grounding.mjs`는 기존 학습·진단에 노출된 문서군을 제외한 공개 사람 주석에서 답이 있는/없는 사례를 같은 수로 선택한다. 학습 640건과 새 검증 64건의 전체 본문을 실제 토크나이저로 확인하며, 길이 초과를 답 위치에 따라 잘라서 숨기지 않는다. 기존 검증된 40단계 adapter를 읽기 전용으로 가져오고 새 optimizer/scheduler로 20회 갱신한다. 기존 40회와 새 20회는 별도로 기록한다. 이 실행은 640건 전체의 한 epoch 완료를 뜻하지 않는다.

```powershell
node scripts/run-public-qa-job.mjs --execute-grounding public-qa-grounding-RUN --allow-interactive-use
node scripts/verify-public-qa-grounding.mjs .local/training/runs/public-qa-grounding-RUN .local/training/public-qa-run/public-qa-grounding-RUN/controller-receipt.json reports/public-qa-grounding-verification-NEW.json
```

실행 전에 `publicQaGroundingInputs({runId})`로 생성한 실행별 디렉터리를 data PVC의 `grounding/<runId>`에 보존한 채 올린다. CPU token-check Job으로 전체 원문 인코딩을 먼저 확인한다. 출력은 checkpoint PVC의 `grounding-runs/<runId>`에 저장된다. 해당 디렉터리 전체를 새 로컬 실행 디렉터리로 회수한 뒤 검증한다. 이전 실패 실행, 후보, provenance를 덮어쓰지 않는다.

추가 생성 진단은 관찰한 기존 64개 질문에서의 퇴보와 개선을 비교한다. 이전 40단계 후보의 실제 응답을 고정된 비교 기준으로 재사용하고 새 후보만 64회 생성한다. 이를 새 미관찰 시험이나 새 베이스 실행으로 기록하지 않는다. 공개 QA 결과만으로 금융 감사·법률 판단 품질을 승인하지 않는다.

추가 실험은 RTX 3080에서 네이티브 BF16 연산을 확인한 뒤 BF16 계층·NF4 계산과 FP32 LoRA를 사용한다. 앞의 FP16 재개 경로는 보존한다. 완료 검증은 actual optimizer 갱신 20회와 누락 0회, checkpoint-10/20의 재개 상태 및 256개 adapter 텐서 유한값도 요구한다. Windows `EFAULT` 상태 조회만 제한 재시도하며, 실패가 지속되면 저장된 노드 UID와 대조한 노드 내부에서 새 읽기를 수행한다. 자원 관측 실패를 정상으로 간주하지 않는다.

## 추가 20단계와 미관측 128건 비교

2026-10-06에 `public-qa-grounding-20261006-r3`의 새 optimizer 업데이트 20회와 실제 역전파 320건을 검증했다. adapter 학습 이력은 60→80이며 optimizer/scheduler는 새로 시작했다. 기존 controller의 종료 관측 오류 원본을 보존하고 동일 컨테이너의 실제 CRI 종료 코드 0을 별도 대조했다. [메모리·실행 근거](../reports/memory-training-recovery-20261006.md)를 따른다.

새 128건은 추가 학습 시작 전에 동결한 공개 인간 주석이며, 기록된 기존 학습·검증·진단 문서군과 겹치지 않는다. 사전학습 말뭉치와의 중복까지 확인한 것은 아니다. `public-qa-fresh-workload.mjs`는 source80 실행 증거와 실제 파일, 고정 runtime을 다시 검증한다. CPU token-check는 별도 runId로 실행하여 실제 생성의 새 출력 경로를 먼저 사용하지 않는다. 공급 데이터는 `fresh-evaluation`, binding은 `fresh-evaluation-bindings/<runId>`에 반입하고 바이트 해시를 비교한다.

```powershell
node scripts/run-public-qa-job.mjs --execute-fresh-evaluation public-qa-fresh-NEW --allow-interactive-use
node scripts/verify-public-qa-fresh.mjs .local/training/fresh-evaluations/public-qa-fresh-NEW .local/training/public-qa-run/public-qa-fresh-NEW/controller-receipt.json reports/public-qa-fresh-verification-NEW.json
node scripts/compare-public-qa-fresh.mjs .local/training/fresh-evaluations/public-qa-fresh-NEW .local/training/public-qa-run/public-qa-fresh-NEW/controller-receipt.json reports/public-qa-fresh-comparison-NEW.json
```

검증·비교 전에 PVC의 `fresh-evaluations/<runId>` 전체를 새로운 로컬 경로로 회수하고 260개 파일의 해시를 대조한다. 같은 Reasoning 베이스를 한 번 로드한 뒤 adapter OFF 128회→ON 128회를 실행한다. 전체 128건 토큰 사전 승인, 실제 입력 tensor 해시, adapter 상태, 호출 순서, NF4/BF16·1024 문맥·128 출력·seed42·greedy 생성, Pod·Job 신원·종료와 자원 관측을 검증한다. 시간 초과·출력 한도·잘못된 정답·원문 인용 부족·부적절한 기권은 채점 실패로 남긴다. 실행 검증과 채점은 서로 다르며 공개 QA 점수로 금융 감사·한국법 판단 품질이나 운영 승격을 인정하지 않는다.
## 메모리 압박 방지를 위한 검증 순서

전체 회귀는 `npm test`, 10회 출시는 `node scripts/release-verify.mjs --output reports/NEW_DIRECTORY`를 사용한다. 두 경로는 `.local/training/manual-public-qa-active.json`이 남아 있으면 CPU 검증을 시작하지 않는다. GPU 작업의 종료·정리 확인 없이 이 파일을 삭제하지 않는다. 중단된 작업의 lease도 정리 여부를 확인할 때까지 차단 상태로 유지한다.

이 검사는 OS의 원자적 잠금이 아니며 직접 `node --test`와 별도 `test:*` 경로까지 통제하지 않는다. 무거운 검증·이미지 빌드와 GPU 작업은 순차 실행한다. 물리 RAM·Windows 예약 여유·게스트·컨테이너·GPU 수치는 각각 확인하며 합산하지 않는다. 페이지 파일은 GPU VRAM을 늘리지 않는다. 현재 실제 측정과 적용 상태는 `reports/memory-stability-20261006.md`에 기록했다.
