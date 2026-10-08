# 거버넌스 매핑 모델 실행 안내서 (Windows PC)

> 2026-10-08 개선 7라운드. 작업 정의·게이트·상태 계약은 [거버넌스 매핑 로컬 모델](governance-model.md)에 있습니다.
> 이 문서의 명령은 PC에서 사람이 실행합니다. 개발 컨테이너에서는 모델을 내려받거나 실행하지 않았습니다.

## 전제

- Windows 11, WSL2 백엔드의 Docker Desktop, NVIDIA 드라이버와 Docker GPU 지원(`docker run --gpus` 동작), RTX 3080 12 GB,
  RAM 32 GB 기준입니다. 명령은 저장소 루트의 PowerShell에서 실행하고 Node 24를 씁니다.
- 기존 학습 정책을 그대로 따릅니다. 시작 전 유휴 판정(`scripts/training-host-check.mjs`)이 통과해야 하고, PC 사용이 감지되면
  체크포인트를 남기고 멈춥니다. 한 번의 실행은 1시간을 넘지 않습니다.
- 아래 `C:\evidscope-work`는 예시 작업 폴더입니다. 경로는 모두 절대 경로로 넘깁니다.

## 학습 시작까지 최단 경로

1. Instruct 학습 기반을 받아 고정한다(1절, 16 GB).
2. 사람이 Claude 초안 행을 승인·거절한다(2절). 학습 입학에는 tune 147행 중 132행 이상, validation 15행 중 3행 이상의
   승인이 필요하다. 이 단계는 건너뛸 수 없다. 초안을 검토됨으로 표시하는 자동 경로는 없다.
3. `training-set`으로 학습 파일을 만들고, 토큰 길이 확인 후 학습한다(3절, 약 35~50분).

평가(5절)용 test 승인(57행 중 30행 이상)은 학습과 병행해도 된다.

## 이미 PC에 있는 것과 새로 필요한 것

| 항목 | 상태 | 크기(대략) |
| --- | --- | --- |
| 학습 이미지 `evidscope/public-qa-training:20260922` (`scripts/public-qa-workload.mjs`의 `QA_IMAGE` digest) | 있음, 그대로 재사용(새 빌드 없음) | 10.1 GB |
| 학습 기반 `fdtn-ai/Foundation-Sec-1.1-8B-Instruct` safetensors | **새로 받아야 함** | 16 GB |
| 런타임 GGUF `foundation-sec-1.1-8b-instruct-q4_k_m.gguf` | 평가 전에 필요 | 4.9 GB |
| llama.cpp `full-cuda` 이미지(변환·평가) | 평가 전에 필요, digest로 고정 | 5~8 GB |
| 체크포인트(최근 2개, optimizer 포함) | 학습 중 생성 | 0.5 GB |

C: 여유 약 70 GB로 충분합니다. 이전 Reasoning 기반 모델(`.local/training/base/63c930c8…`, 15 GB)은 지우지 않습니다.

**왜 이미 있는 Reasoning 기반이 아닌가.** 어댑터는 학습한 가중치 위에서만 맞습니다. 콘솔이 실제로 돌리는 모델은
`Foundation-Sec-1.1-8B-Instruct`의 Q4_K_M GGUF(해시 고정)이므로, Reasoning 위에서 학습한 어댑터는 게이트의 기본 모델 해시 검사를
통과할 수 없고 런타임에 올려도 맞지 않습니다. 그래서 학습 기반만 Instruct로 새로 받습니다(이미지·격리·학습 보조 코드는 공개 QA 학습과 같음).

**왜 k3d가 아니라 Docker 직접 실행인가.** 같은 이미지와 같은 비루트 사용자·읽기 전용 루트·capability 제거·메모리 상한을 쓰되,
컨테이너에 네트워크 인터페이스 자체가 없습니다(`--network none`). 그래서 CNI 차단 실측, PVC, immutable ConfigMap 준비가 필요 없고
멈춰 있는 `evidscope-training` 클러스터를 켤 필요도 없습니다. 격리는 시작 전에 `docker inspect`로 확인합니다.

## 1. 학습 기반 모델 고정

Hugging Face에서 `fdtn-ai/Foundation-Sec-1.1-8B-Instruct`의 커밋 해시(40자)를 확인해 `REV`로 씁니다. 개발 컨테이너에서는
조회가 막혀 revision을 고정하지 못했으므로 이 단계에서 정합니다. 파일 목록은 해당 revision의 페이지에서 확인합니다
(`config.json`, `generation_config.json`, `model-0000N-of-0000M.safetensors`, `model.safetensors.index.json`,
`special_tokens_map.json`, `tokenizer.json`, `tokenizer_config.json`).

```powershell
$REV = "<40자 커밋>"; $BASE = "C:\evidscope-work\instruct-base\$REV"; New-Item -ItemType Directory -Force $BASE | Out-Null
foreach ($f in @("config.json","generation_config.json","model.safetensors.index.json","special_tokens_map.json","tokenizer.json","tokenizer_config.json",
                 "model-00001-of-00004.safetensors","model-00002-of-00004.safetensors","model-00003-of-00004.safetensors","model-00004-of-00004.safetensors")) {
  curl.exe --fail --location --retry 3 --continue-at - --output "$BASE\$f" "https://huggingface.co/fdtn-ai/Foundation-Sec-1.1-8B-Instruct/resolve/$REV/$f"
}
node -e "const fs=require('fs'),c=require('crypto'),d=process.argv[1];const files=fs.readdirSync(d).filter(f=>f!=='artifact-lock.json').sort().map(path=>({path,sha256:c.createHash('sha256').update(fs.readFileSync(d+'/'+path)).digest('hex')}));fs.writeFileSync(d+'/artifact-lock.json',JSON.stringify({repository:'fdtn-ai/Foundation-Sec-1.1-8B-Instruct',revision:process.argv[2],files}),{flag:'wx'})" $BASE $REV
```

Hugging Face 페이지에 표시된 각 파일의 SHA-256과 `artifact-lock.json`의 값을 사람이 대조합니다. 샤드 수가 다르면 목록을 고칩니다.
학습기는 시작할 때 이 잠금 파일의 모든 파일을 다시 해시합니다.

## 2. 사람 검토와 입학

[거버넌스 매핑 로컬 모델](governance-model.md)의 "사람 검토" 절차로 `reviewed.jsonl`을 만듭니다. 219행을 한 사람이 보면
행당 30초~1분, 약 2~3시간입니다. 승격 승인자는 이 검토자와 달라도 되지만 보고서 준비자·후보 실행자와는 달라야 합니다.

```powershell
node scripts/governance-mapping.mjs admission --data C:\evidscope-work\reviewed.jsonl
node scripts/governance-mapping.mjs training-set --data C:\evidscope-work\reviewed.jsonl --out C:\evidscope-work\train.jsonl
```

`admission`이 `admitted: true`가 아니면 여기서 멈춥니다(종료 코드 2).

## 3. 학습

학습 이미지는 공개 QA 학습에 쓴 고정 이미지입니다. 먼저 PC의 이미지가 그 digest인지 확인합니다.

```powershell
docker image inspect evidscope/public-qa-training:20260922 --format "{{json .RepoDigests}}"
```

`docker.io/evidscope/public-qa-training@sha256:440dbe10ff4e…24be8`가 보이면 `--image`를 생략합니다(기본값). 보이지 않으면
`docker image inspect … --format "{{.Id}}"`의 `sha256:…`를 `--image`로 주고 그 값을 실행 기록에 남깁니다.
토큰 길이를 먼저 확인합니다(GPU 불필요, 네트워크 없음).

```powershell
$IMG = "docker.io/evidscope/public-qa-training@sha256:440dbe10ff4e651296c65ff88f132077a4cbbb19054536b33c0695fdb5224be8"; $W = "C:\evidscope-work"
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --user 10001:10001 --tmpfs /tmp `
  --mount "type=bind,source=$BASE,target=/models/base,readonly" --mount "type=bind,source=$W\train.jsonl,target=/dataset/train.jsonl,readonly" `
  --mount "type=bind,source=$PWD\scripts,target=/opt/evidscope,readonly" --entrypoint python $IMG `
  /opt/evidscope/train-governance-mapping-lora.py --data /dataset/train.jsonl --model-dir /models/base --token-check
```

`maxTokens`가 1536을 넘으면 학습기가 그 행을 거부합니다. 그때는 진행하지 말고 기록합니다(길이를 늘리면 VRAM 추정이 바뀝니다).

```powershell
New-Item -ItemType Directory -Force "$W\checkpoints","$W\work" | Out-Null
node scripts/governance-mapping-train.mjs --base-dir $BASE --base-revision $REV --data "$W\train.jsonl" `
  --checkpoints-dir "$W\checkpoints" --work-dir "$W\work" --check-only
node scripts/governance-mapping-train.mjs --base-dir $BASE --base-revision $REV --data "$W\train.jsonl" `
  --checkpoints-dir "$W\checkpoints" --work-dir "$W\work"
```

`--check-only`는 docker 인자와 유휴 판정만 보여 줍니다. 실제 실행은 컨테이너를 만든 뒤 `docker inspect`로 격리를 확인하고서야
시작합니다. 멈췄다면(`stopped_for_host_activity`, `runtime_deadline`) 마지막 체크포인트로 이어갑니다.

```powershell
node scripts/governance-mapping-train.mjs ... --resume governance-mapping/run/checkpoint-<N>
```

예상치(추정, 첫 실행에서 실측으로 바꿈):

| 항목 | 값 | 근거 |
| --- | --- | --- |
| GPU 메모리 최대 | 6.7~7.6 GiB | 같은 8B NF4·rank 8·길이 1024 실측 6.28 GiB + 길이 1536·전 선형층 LoRA 분. 상한 0.65 × 12 GB = 7.8 GiB |
| 호스트 RAM | 컨테이너 12 GiB 상한 | 시작 조건은 기존 정책(여유 18 GiB 이상) |
| 학습 시간 | 35~50분(약 350행 × 2 epoch) | 1시간 상한에 걸리면 한 번 이어서 실행 |

결과는 `$W\checkpoints\governance-mapping\run\candidate`(어댑터 safetensors와 `training-receipt.json`, `trained_candidate`)입니다.

## 4. GGUF 어댑터 변환

llama.cpp `full-cuda` 이미지를 digest로 고정해 씁니다(`docker pull ghcr.io/ggml-org/llama.cpp:full-cuda` 후
`docker image inspect --format "{{index .RepoDigests 0}}"`). 이미지 안 경로는 `docker run --rm --entrypoint ls <image> /app`로 확인합니다.

```powershell
$LCPP = "ghcr.io/ggml-org/llama.cpp@sha256:<digest>"
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --tmpfs /tmp `
  --mount "type=bind,source=$BASE,target=/models/base,readonly" --mount "type=bind,source=$W\checkpoints,target=/ckpt" `
  --entrypoint python3 $LCPP /app/convert_lora_to_gguf.py /ckpt/governance-mapping/run/candidate --base /models/base `
  --outtype f16 --outfile /ckpt/governance-mapping-lora.gguf
```

약 1~2분, 결과 약 45 MB입니다. 병합 모델은 만들지 않습니다.

## 5. 격리 평가

test 분할 요청을 변형별로 만들고, 네트워크 없는 컨테이너(인터페이스 `lo`만)에서 고정 GGUF로 실행합니다.

```powershell
New-Item -ItemType Directory -Force "$W\runs" | Out-Null
foreach ($v in @("zero_shot","retrieval","retrieval_constrained","candidate")) {
  node scripts/governance-mapping.mjs requests --data "$W\reviewed.jsonl" --variant $v --out "$W\runs\$v.requests.jsonl"
}
$GGUF = "C:\evidscope-work\gguf"   # foundation-sec-1.1-8b-instruct-q4_k_m.gguf 위치
foreach ($v in @("zero_shot","retrieval","retrieval_constrained","candidate")) {
  $lora = if ($v -eq "candidate") { @("--lora","/ckpt/governance-mapping-lora.gguf") } else { @() }
  docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --gpus device=0 --tmpfs /tmp `
    --mount "type=bind,source=$GGUF,target=/models/gguf,readonly" --mount "type=bind,source=$W\checkpoints,target=/ckpt,readonly" `
    --mount "type=bind,source=$PWD\scripts,target=/opt/evidscope,readonly" --mount "type=bind,source=$W\runs,target=/runs" `
    --entrypoint python3 $LCPP /opt/evidscope/governance_mapping_batch.py --requests /runs/$v.requests.jsonl --variant $v `
    --out /runs/$v.outputs.json --receipt /runs/$v.receipt.json --operator <실행자 ID> --server-bin /app/llama-server `
    --model /models/gguf/foundation-sec-1.1-8b-instruct-q4_k_m.gguf `
    --expected-model-sha256 5813d725b38f0da1eac34486e44b70b0f728c2e2881c96873def69e76f8421ed @lora
}
node scripts/governance-mapping.mjs report --data "$W\reviewed.jsonl" --runs "$W\runs" --prepared-by <준비자 ID> --out "$W\report.json"
node scripts/governance-mapping.mjs gate --report "$W\report.json"
```

변형마다 130행, 행당 약 2초로 변형당 5분 안팎, 모델 적재 포함 전체 25~30분입니다(추정). 영수증의 `isolation.verified`가
false이거나 실패가 1건이라도 있으면 그 변형은 측정으로 인정되지 않습니다.

## 6. 기본 모드 또는 승격

- 기본 모드(어댑터 없음): 보고서를 저장소의 `reports/governance-mapping/` 아래에 두고 `roles/governance-assistant/v1/governance-mapping.json`의
  `baselineReport`에 `{path, sha256}`를 적습니다. `retrieval_constrained`가 `rules_only`를 게이트 4번 규칙으로 이기지 못하면
  상태는 계속 꺼짐입니다.
- 승격: 승인자가 자기 키를 만듭니다(`openssl genpkey -algorithm ed25519 -out reviewer-ed25519.key`; 저장소에 넣지 않음).
  공개 키(`openssl pkey -in reviewer-ed25519.key -pubout`)를 `promotion-trust.json`의 `keys`에 `{reviewerId, publicKeyPem}`으로
  넣는 변경은 별도 검토로 들어갑니다. 승인자가 `approval.json`(보고서 해시 `reportSha256`, `approved: true`, 검토 항목 다섯 개,
  `reviewerId`, `reviewedAt`)을 쓰고 직접 서명합니다.

```powershell
node scripts/governance-mapping.mjs promote --report "$W\report.json" --approval "$W\approval.json" `
  --adapter-file models/governance-mapping-lora.gguf --key reviewer-ed25519.key --out "$W\promotion.dsse.json"
```

영수증과 보고서를 `reports/governance-mapping/` 아래에 두고 `governance-mapping.json`의 `promotion`에 `receiptPath`, `receiptSha256`,
`reportPath`, `reportSha256`을, `role.json`에는 영수증의 `roleFields` 세 값을 적습니다. 런타임 Pod에는 어댑터를
`/models/foundation-sec/governance-mapping-lora.gguf`로 두고 `EVIDSCOPE_GOVERNANCE_ADAPTER_SHA256`을 영수증의 어댑터 해시로 줍니다.
`node scripts/governance-mapping.mjs status`가 `promoted_adapter`를 보일 때만 콘솔이 어댑터를 씁니다.

되돌리기는 `promotion`을 null로, `role.json`을 `adapter: "none"`, `modelVersion: "unassigned_runtime"`, `evalStatus: "UNREVIEWED"`로
돌리고 런타임 환경 변수를 빼는 것입니다. 상태는 즉시 꺼짐 또는 기본 모드로 돌아갑니다.
