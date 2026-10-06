# 로컬 감사 모델 학습 경로와 남은 실측

대상은 기존 `k3d-dlp` 환경과 RTX 3080 12GiB, RAM 32GiB다. 이번 변경은 학습 준비와 검증 경로를 구현한다. 2026-09-22 확인 시 Docker daemon에 연결할 수 없었고 사람 검토 데이터는 0건이다. 이미지 build, 모델 다운로드, Pod 실행, 실제 가중치 학습 및 품질 향상은 수행하지 않았다.

호스트의 `nvidia-smi` 프로세스 목록은 Windows WDDM에서 그래픽 또는 분류되지 않은 작업을 포함할 수 있다. `computeProcessCount`를 실제 실행 중인 ML 학습 작업 수로 해석하지 않는다. 불확실한 GPU 점유가 있는 경우 기존의 보수적 시작 제한은 유지한다.

## 고정 실행 조건

Foundation-Sec-8B-Reasoning revision `63c930c82d7646226d33502bec5870019738400e`, NF4, LoRA rank 8, sequence 1024, batch 1, gradient accumulation 16, CPU 2, RAM 12GiB, GPU PyTorch allocation fraction 0.65. 다른 추론 모델인 Foundation-Sec-1.1-8B-Instruct GGUF에 이 adapter를 적용하지 않는다. 학습·파일럿은 기존 공유 Lease와 사용자 유휴 자원 조건을 충족한 명시적 작업으로 운영한다.

`deploy/training/requirements.txt` 버전들은 선언된 호환 후보이며 이 PC에서 GPU 검증된 조합이라는 뜻은 아니다. base image digest는 승인된 CUDA/Python 이미지에서 받아야 한다. `node scripts/training-image.mjs --check-only`는 daemon과 GPU를 읽기만 한다. 환경 준비 후 `--build <approved-base@sha256:digest> <new-receipt.json>`을 명시하면 필요한 여섯 파일만 별도 임시 build context로 복사하여 build하고 이미지 ID/RepoDigests와 recipe/requirements hash를 기록한다. 사용자 파일이나 전체 저장소를 build context로 보내지 않는다. 로컬 image ID는 registry manifest digest와 다르므로 둘을 바꿔 쓰지 않는다. repo digest가 없으면 승인된 로컬 registry 배포 후 manifest digest를 확인하고 해당 이미지가 대상 k3d 노드에 적재되었는지 확인해야 한다.

## 준비, 실측, 정식 학습

1. `training-prepare.mjs render <config.json> <new-plan.json>`은 suspended Job, namespace/deny-all policy와 데이터 1GiB·베이스 20GiB·checkpoint 12GiB PVC 명세를 만든다. 실제 provisioning은 하지 않는다. 디스크에는 약 16GB 베이스 shard 외에 이미지·중간 산출물 공간도 필요하다. 데이터/모델 PVC는 승인된 별도 offline staging으로 채우고, artifact lock은 출력의 `artifactLockBytes` 그대로 저장한다. 정식 Job에는 읽기 전용으로 mount한다.
2. 같은 도구의 `probe` 모드는 실제 허용 대조군과 거부 대상의 literal IP를 요구한다. `resource-pilot` 모드는 `gpuMemoryPilotPassed`나 사람 검토 데이터 입장을 요구하지 않는 별도 준비 Job이다. 둘 다 suspended 상태로 출력되며 정식 학습 승인 영수증을 만들지 않는다. 파일럿은 합성 token, LR 0, 16회 누적 후 2회 optimizer step으로 VRAM을 측정하고 candidate를 저장하지 않는다. 제어 측에서 기존 유휴 가드·공유 Lease 아래 수행해야 한다.
3. probe의 연결 실패만으로 격리 성공을 표시하지 않는다. 실행된 Pod spec/UID, 허용 대조군, 외부 CNI 결과, token/host mount 경계, GPU UUID와 node 대응, process 종료를 함께 확인해야 한다. 준비 script는 측정하지 않은 항목을 true로 만들어 runtime config에 넣지 않는다. 전체 실측 영수증 생산·서명과 실제 cluster 연결 검증은 아직 운영 연결이 필요한 단계다.
4. `generate-financial-evals.mjs <new-candidates.jsonl>`은 공급된 `data/requirements.json`의 version/hash/URL을 증거로 연결한 합성 금융 후보 540건을 만든다. 가족별 en/ko/mixed 변형은 같은 split에 남으며 ko/mixed의 설명 목표는 한국어다. 자동 생성 내용은 expectedOutput일 뿐 approvedOutput이 아니고 모든 humanReviewed는 false다. 현재 후보는 템플릿 기반이며 독립 실데이터 평가를 대신하지 않는다.

생성된 후보와 미승인 검토 패킷은 `data/financial-evals/evidence-organizer/v1/`에 있다. 실제 시나리오는 공급자 모델 변경, 권한 철회 뒤 실행, 차단·성공 상충, 사람 승인 없는 자동 PASS, 사후 승인, 실행 기록 누락, 문서 무결성 실패의 7종이다. KR-34-RISK/EXPLAIN/OVERSIGHT/DOCUMENT를 현재 공급된 catalog에서 확인해 연결했다. tune 300, validation 60, test 180이며 사람 검토는 모두 0건이다. 이 패킷의 `approved:false`와 `approvedOutput:null`을 자동으로 채우지 않는다.
5. 기존 `model-training-data.mjs export-review/import-review/gate`로 실제 사람이 출처·개인정보·출력을 검토한 뒤 tune 300/validation 50/test 100 gate를 통과해야 정식 `training-run.mjs --execute-isolated-training`이 가능하다. 데이터·image·manifest·host 바인딩 검증을 우회하지 않는다.

## 중단과 산출물

각 run은 `/checkpoints/runs/<runId>`를 사용한다. optimizer 10 step마다 optimizer/scheduler/RNG/adapter/trainer-state 파일 hash를 `checkpoint-complete.json`에 원자적으로 기록한다. SIGTERM을 받으면 다음 step 경계에서 저장을 시도하지만 강제 종료 때는 마지막 완전 checkpoint가 복구 기준이다. runtime config의 `resumeCheckpoint`는 이 경로 아래 `checkpoint-N`만 허용한다. 데이터·베이스·이미지·trainer/helper code·hyperparameter identity가 달라지면 재개하지 않는다. optimizer 저장의 실제 지연 및 최대 유실량은 GPU 실행으로 확인해야 한다.

베이스 revision뿐 아니라 실제 `artifact-lock.json` hash도 재개·후보 검증·동일 베이스 평가에 결합한다. controller 세션은 한 번만 실행할 수 있어 다음 Job에 이전 검증 결과를 재사용하지 않는다. Python/JavaScript의 검토·평가 hash 계약은 JSON 안전 정수 범위로 제한한다. `1.0`과 `-0.0`은 각각 `1`과 `0`으로 정규화하며 비정수 수치와 안전 범위 밖 정수는 GPU 실행 전에 거절한다. 실제 모델이 반환한 지원하지 않는 숫자 표현은 raw 응답에 보존하고 구조 검증 실패로 평가한다.

완료 adapter는 `candidate/`에 별도 저장하고 파일 hash·global step·학습 receipt를 봉인한다. controller는 학습 Job Complete만으로 완료를 반환하지 않는다. 같은 고정 이미지의 CPU 전용 read-only verifier Job으로 산출물을 재검증한 뒤, verifier와 학습 Job/Pod 부재까지 확인해야 `trainingRunCompleted:true`가 된다. verifier 생성·종료가 불명확하면 공유 Lease를 격리한다. 단위 테스트의 mock receipt는 운영 실측으로 사용하지 않는다.

## 실제 평가와 적용 경계

격리된 `training-paired-eval.py`는 동일 Reasoning NF4 베이스에 PEFT adapter를 올려 adapter 비활성/활성 상태를 순차 비교한다. 베이스·후보 bytes, device UUID, image, seed와 decoding 조건을 결과에 묶고 raw 응답도 별도 보존한다. 잘못된 JSON이나 timeout은 expectedOutput으로 대체하지 않는다. 비합성·사람 검토 held-out 100건과 영어 사례가 없으면 실행 전 거절한다. GPU 1개에서 두 모델을 동시에 올리지 않는다.

출력 `baseline.json`, `candidate.json`, `measurement-receipt.json`은 기존 `model-evaluate.mjs`에 전달한다. 영어 통과율 하락 2%p 이내, 전체 향상 5%p 이상, 필수 인용·안전 검사 통과 및 별도 한국어/의미/개인정보/인젝션 사람 검토가 필요하다. `model-promote.mjs`는 registry만 갱신하며 운영 배포는 바꾸지 않는다. 기존 운영 Instruct 모델 채택이나 GGUF 변환·병합은 이 변경의 완료 조건이 아니다.
