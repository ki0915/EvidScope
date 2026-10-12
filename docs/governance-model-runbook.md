# 거버넌스 매핑 모델 실행 안내서 (Windows PC)

> 2026-10-08 개선 7라운드. 작업 정의·게이트·상태 계약은 [거버넌스 매핑 로컬 모델](governance-model.md)에 있습니다.
> 이 문서의 명령은 PC에서 사람이 실행합니다. 개발 컨테이너에서는 모델을 내려받거나 실행하지 않았습니다.

## 전제

- Windows 11, WSL2 백엔드의 Docker Desktop, NVIDIA 드라이버와 Docker GPU 지원(`docker run --gpus` 동작), RTX 3080 12 GB,
  RAM 32 GB 기준입니다. 명령은 저장소 루트의 PowerShell에서 실행하고 Node 24를 씁니다.
- 2026-10-10 소유자 결정으로 PC를 쓰는 중에도 학습합니다(`TRAINING_ACTIVE_USE_POLICY`). 시작 조건은 GPU 여유 메모리 8,448 MiB 이상과
  GPU 온도 75°C 이하뿐이고, 실행 중에는 호스트 여유 메모리 2 GiB 미만, GPU 여유 256 MiB 미만, 75°C 초과일 때만 체크포인트를 남기고 멈춥니다. GPU에 무리가 가지 않도록 학습은 단계마다, 평가는 요청마다 걸린 시간의 절반만큼 쉽니다(`--pause-ratio`, 기본 0.5).
  과열이나 1시간 제한으로 멈추면 GPU가 65°C 이하로 식을 때까지 기다렸다가 마지막 봉인 체크포인트에서 스스로 이어갑니다(최대 6회, 회당 30분 대기).
  2026-10-12부터 학습기는 컨테이너 안에서도 온도를 봅니다. 단계마다 쉰 뒤 GPU가 70°C 이상이면 65°C 이하가 될 때까지(단계당 최대 300초) 그 자리에서
  쉬므로, 외부 75°C 정지와 그에 따른 모델 재적재(회당 약 3분)가 줄어듭니다(`--thermal-trigger-c`, `--thermal-target-c`, `--thermal-max-wait-seconds`;
  40 ≤ target < trigger ≤ 74, 0초는 끔; 학습기 자체 옵션이라 PC 실행기 `scripts/governance-mapping-train.mjs`는 넘기지 않으므로 PC에서는 기본값이 쓰이고, 바꾸려면 실행기를 고쳐야 합니다). 온도 센서를 못 읽으면 경고 한 줄만 남기고 쉬지 않고 계속하며, 최대 대기를 넘겨도 학습을 멈추지 않습니다.
  외부 75°C 정지·65°C 재개 감시는 그대로이고 안전 한계는 그쪽입니다. 쉰 횟수·시간·최고 온도는 영수증 `timing.thermalPacing`(마지막 컨테이너 기준)과
  멈춘 컨테이너마다의 로그에 남습니다. 학습 내용(레시피·데이터 순서)은 바뀌지 않지만 체크포인트 식별자에 온도 도우미 해시가 들어가므로, 이 변경 전에
  시작한 실행은 새 코드로 이어 돌릴 수 없습니다.
  예전처럼 유휴일 때만 돌리려면 `--idle-only`를 붙입니다(이때는 자동으로 이어가지 않습니다).
- 아래 `C:\evidscope-work`는 예시 작업 폴더입니다. 경로는 모두 절대 경로로 넘깁니다.

## 학습 시작까지 최단 경로

1. Instruct 학습 기반을 받아 고정한다(1절, 16 GB).
2. (선택, 검토와 병행) 셰이크다운으로 이 PC의 VRAM·시간을 잰다(2-1절). 승격할 수 없고 품질 결과가 아니다.
3. 사람이 콘솔의 `학습 데이터 검토` 화면에서 Claude 초안 행을 승인·거절한다(2절). 학습 입학에는 tune 147행 중 132행 이상,
   validation 15행 중 3행 이상의 승인이 필요하다. 이 단계는 건너뛸 수 없다. 초안을 검토됨으로 표시하는 자동 경로는 없다.
4. `export-reviewed`와 `training-set`으로 학습 파일을 만들고, 토큰 길이 확인 후 학습한다(3절, 약 35~50분).
5. 학습·평가·승격마다 팩트시트를 기록한다(7절).

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
node --input-type=module -e "import fs from 'node:fs';import c from 'node:crypto';const [d,rev]=process.argv.slice(1);const hash=p=>new Promise((ok,no)=>{const h=c.createHash('sha256');fs.createReadStream(p).on('data',x=>h.update(x)).on('end',()=>ok(h.digest('hex'))).on('error',no)});const files=[];for(const path of fs.readdirSync(d).filter(f=>f!=='artifact-lock.json').sort())files.push({path,sha256:await hash(d+'/'+path)});fs.writeFileSync(d+'/artifact-lock.json',JSON.stringify({repository:'fdtn-ai/Foundation-Sec-1.1-8B-Instruct',revision:rev,files}),{flag:'wx'})" $BASE $REV
```

샤드가 2GiB를 넘으므로 파일을 스트림으로 해시합니다. Hugging Face 페이지(또는 `https://huggingface.co/api/models/fdtn-ai/Foundation-Sec-1.1-8B-Instruct/tree/$REV`의 `lfs.oid`)에 표시된 각 파일의 SHA-256과 `artifact-lock.json`의 값을 대조합니다. 샤드 수가 다르면 목록을 고칩니다.
학습기는 시작할 때 이 잠금 파일의 모든 파일을 다시 해시합니다.

## 2. 사람 검토와 입학

콘솔에 `reviewer` 또는 `admin` 계정으로 들어가 AI 검토실 > `학습 데이터 검토`를 엽니다. 두 확인란(개인정보 없음, 출처·사용 동의)을 체크하고,
행마다 `A`(승인) 또는 `R`(거절)을 누릅니다. 답이 틀리면 거절합니다(수정 기능 없음). 분할 버튼으로 `학습(tune)`부터 보면 학습 입학이 가장 빨리
채워집니다. 진행 표의 "추가 승인 필요"가 모두 "충족"이 되면 학습할 수 있습니다. 219행을 한 사람이 보면 행당 30초~1분, 약 2~3시간입니다.
승격 승인자는 이 검토자와 달라도 되지만 보고서 준비자·후보 실행자와는 달라야 합니다.

검토가 끝나면 상단의 `감사 내보내기`로 내보내기 파일을 받고, 볼트 공개 키(`.local/trust-anchor.pem`)로 학습용 데이터를 만듭니다.

```powershell
node scripts/governance-mapping.mjs export-reviewed --data data/governance-mapping/v1/dataset.jsonl --bundle C:\evidscope-work\export.json `
  --trust-anchor .local\trust-anchor.pem --out C:\evidscope-work\reviewed.jsonl
```

결과의 `skipped`에 `row_changed_since_decision`이 있으면 그 행은 결정 뒤 내용이 바뀐 것입니다. 콘솔에서 다시 결정합니다.
콘솔을 쓸 수 없을 때는 [거버넌스 매핑 로컬 모델](governance-model.md)의 TSV 시트 절차로 같은 `reviewed.jsonl`을 만들 수 있습니다.

```powershell
node scripts/governance-mapping.mjs admission --data C:\evidscope-work\reviewed.jsonl
node scripts/governance-mapping.mjs training-set --data C:\evidscope-work\reviewed.jsonl --out C:\evidscope-work\train.jsonl
```

`training-set`에 `--abstain-weight N`(2~5)을 주면 tune 분할의 "해당 없음" 행을 N-1번 더 복사해(id `<id>#abstain-weight-k`, `weightCopy` 필드) 보류를 더 무겁게 학습한다. 검증 분할과 데이터셋은 그대로이고, 복사 수는 명령 결과의 `abstainCopies`와 factsheet에 남는 학습 파일 해시로 확인한다(8차 분석 뒤 9차부터 사용).

`admission`이 `admitted: true`가 아니면 여기서 멈춥니다(종료 코드 2).

## 2-1. 셰이크다운 (검토 전 VRAM·시간 측정)

사람 검토를 기다리는 동안, 파생 행(tune 168, validation 47)만으로 같은 레시피를 한 번 돌려 이 PC의 GPU 메모리와 시간을 잽니다.
결과 어댑터는 **승격할 수 없고 품질 결과가 아닙니다**. 변환·평가·승격하지 않고, 수치를 기록한 뒤 지웁니다.

```powershell
$W = "C:\evidscope-work"; New-Item -ItemType Directory -Force "$W\checkpoints","$W\work" | Out-Null
node scripts/governance-mapping.mjs training-set --data data/governance-mapping/v1/dataset.jsonl --shakedown --out "$W\shakedown.jsonl"
node scripts/governance-mapping-train.mjs --base-dir $BASE --base-revision $REV --data "$W\shakedown.jsonl" `
  --checkpoints-dir "$W\checkpoints" --work-dir "$W\work" --shakedown --check-only
node scripts/governance-mapping-train.mjs --base-dir $BASE --base-revision $REV --data "$W\shakedown.jsonl" `
  --checkpoints-dir "$W\checkpoints" --work-dir "$W\work" --shakedown
```

- 출력: `$W\checkpoints\governance-mapping\shakedown\shakedown-adapter`(영수증 상태 `shakedown_not_promotable`). 후보 실행과 디렉터리가 다르고,
  체크포인트 신원에 `runMode`가 들어가므로 셰이크다운 체크포인트로 후보 실행을 이어갈 수 없습니다(반대도 같음).
- 영수증의 `trainingMetrics.cudaPeakAllocatedMiB`, `timing.loadSeconds`·`trainSeconds`·`totalSeconds`가 잴 값입니다. 행 수가 후보의 약 57~61%이므로
  후보 학습 시간은 대략 `trainSeconds × 1.6~1.8`로 봅니다(후보 350~377행 기준). 최대 메모리는 길이 1536 행이 섞이면 거의 같습니다.
- 학습기 자체가 확인합니다: 셰이크다운 모드는 `runMode: "shakedown"`인 파생 행만, 후보 모드는 셰이크다운 행을 하나라도 받지 않습니다.
- 팩트시트를 남깁니다(7절, `--kind training`). 볼트가 학습 파일을 저장소에서 다시 만들어 바이트를 비교합니다.

## 2-2. 카탈로그 밖 기준이 들어간 프롬프트 (2026-10-12, 10차부터)

`retrieval`·`retrieval_constrained`·`candidate` 요청과 학습 행의 프롬프트에 카탈로그 밖 ISMS-P 인증기준 목록(`outOfScope`, 최대 3개,
`{"criterion": "ISMS-P 2.2.4", "title": …}`), 시스템 프롬프트 한 문장, 기권 예시의 출처 기준 표시가 더해졌습니다([거버넌스 매핑 로컬 모델](governance-model.md)의
"카탈로그 밖 기준"). `zero_shot` 요청, 출력 형식, 정답, 분할, 보정 코드는 그대로입니다. 같은 변경에서 제품 런타임 문맥을 3072로 올렸습니다.

- 데이터셋은 다시 만들 필요가 없습니다. 행·정답·분할이 같으므로 저장소 `dataset.jsonl`, PC에서 지역 표로 만든 데이터셋, `reviewed.jsonl`과 검토 결정이 그대로 유효합니다.
- 학습 파일은 다시 만듭니다(`training-set`, 같은 `--abstain-weight`). 프롬프트가 행당 평균 약 149토큰 길어져 추정 최대가 1,824토큰(PC 데이터셋 1,816)입니다.
  학습 전 3절의 `--token-check`로 `maxTokens`가 2048 이하인지 확인합니다.
- 평가 요청은 네 변형 모두 다시 만들고(`requests`, 후보의 `--split validation` 포함) `retrieval`·`retrieval_constrained`·`candidate`를 다시 실행합니다.
  `zero_shot` 요청은 바이트까지 같으므로, 새 `zero_shot.requests.jsonl`의 해시가 이전 영수증의 `requestsSha256`과 같으면 이전 `zero_shot` 출력·영수증을
  그대로 둡니다(다르면 다시 실행). 가장 긴 요청은 약 1,640토큰입니다. 배치 실행기의 `--ctx` 기본값이 런타임과 같은 3072가 되었고, 프롬프트와
  `max_tokens` 512를 합쳐 이를 넘는 요청은 런타임처럼 `prompt_budget_exceeded` 실패로 셉니다(지금 데이터셋에는 없음). 다른 `--ctx`를 쓰지 않습니다.
- 임베딩: `embed-texts`가 이제 카탈로그 밖 기준 문장 74개를 더 적습니다. PC 데이터셋(지역 KISA 표)이면 그 문장에 안내서의 인증기준 문장이 붙으므로
  저장소 데이터셋용 파일로는 덮이지 않습니다. 새 목록으로 임베딩 파일을 다시 만듭니다(전체 재계산, 1절 이후의 `scripts/governance_mapping_embed.py` 그대로).
  이전 파일을 계속 쓰면 카탈로그 후보·예시는 그대로 결합 검색이고 카탈로그 밖 목록만 TF-IDF로 고릅니다(`buildMappingRequest`의
  `retrieval.outOfScope`가 `tfidf`). `embed-texts --embeddings <이전 파일> ...`의 `outOfScopeMissingFromEmbeddings: 74`가 빠진 문장 수를 보여 줍니다.
  학습 파일, 요청, 보고서는 같은 임베딩 파일(또는 모두 없음)로 만듭니다.
- 런타임: `deploy/model-runtime/render.mjs`가 `--ctx-size 3072`를 씁니다(KV 캐시 약 128 MiB 증가, 7,936 MiB Pod 안). 런타임 정책이 바뀌었으므로
  테넌트의 지원 프로필은 다음 조회 때 자동으로 새 서명 버전이 되고, 이전 정책으로 준비한 매핑 패키지는 다시 준비합니다.

```powershell
node scripts/governance-mapping.mjs embed-texts --data C:\evidscope-work\reviewed.jsonl --out C:\evidscope-work\texts.jsonl
node scripts/governance-mapping.mjs retrieval-recall --data C:\evidscope-work\reviewed.jsonl --embeddings C:\evidscope-work\embeddings.json
```

`retrieval-recall`의 `outOfScope.splits`가 기권 행의 원래 인증기준이 프롬프트 목록에 든 비율(`listed`)과 가까운 k개 안에 든 비율(`recallAtK`)을
언어·행 종류별로, `splits.*.promptRecall`이 카탈로그 정답이 프롬프트 후보에 든 비율을 보여 줍니다. 제목 행(`title`)은 당연히 맞으므로 문장 행
(`sentence`)을 봅니다. GPU 없이 TF-IDF로 잰 PC 데이터셋 test 문장 행은 0.79(한국어 24/28, 영어 21/29), k=5에서 0.86입니다.
10차 보고서를 만든 뒤 `report` 출력의 `outOfScopeSiblings`(기권해야 할 행에서 목록의 기준과 같은 절의 카탈로그 항목으로 답한 수)를 함께 기록합니다.

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

`maxTokens`가 2048(`RECIPE.sequenceLength`)을 넘으면 학습기가 그 행을 거부합니다(자르지 않음). 그때는 진행하지 말고 기록합니다(길이를 늘리면 VRAM 추정이 바뀝니다).

```powershell
New-Item -ItemType Directory -Force "$W\checkpoints","$W\work" | Out-Null
node scripts/governance-mapping-train.mjs --base-dir $BASE --base-revision $REV --data "$W\train.jsonl" `
  --checkpoints-dir "$W\checkpoints" --work-dir "$W\work" --check-only
node scripts/governance-mapping-train.mjs --base-dir $BASE --base-revision $REV --data "$W\train.jsonl" `
  --checkpoints-dir "$W\checkpoints" --work-dir "$W\work"
```

`--check-only`는 docker 인자와 시작 판정만 보여 줍니다. 실제 실행은 컨테이너를 만든 뒤 `docker inspect`로 격리를 확인하고서야
시작합니다. 멈췄다면(`stopped_for_host_activity`(메모리 부족·과열), `runtime_deadline`) 마지막 체크포인트로 이어갑니다.

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
    --model /models/gguf/foundation-sec-1.1-8b-instruct-q4_k_m.gguf --ctx 3072 `
    --expected-model-sha256 5813d725b38f0da1eac34486e44b70b0f728c2e2881c96873def69e76f8421ed @lora
}
node scripts/governance-mapping.mjs report --data "$W\reviewed.jsonl" --runs "$W\runs" --prepared-by <준비자 ID> --out "$W\report.json"
node scripts/governance-mapping.mjs gate --report "$W\report.json"
```

변형마다 130행, 행당 약 2초로 변형당 5분 안팎, 모델 적재 포함 전체 25~30분입니다(추정). 영수증의 `isolation.verified`가
false이거나 실패가 1건이라도 있으면 그 변형은 측정으로 인정되지 않습니다. `--ctx 3072`는 제품 런타임의 문맥이고(기본값과 같음), 프롬프트와
응답 한도 512를 합쳐 이를 넘는 요청은 `prompt_budget_exceeded` 실패로 셉니다. 영수증의 `usage.maxPromptTokens`가 2,560을 넘는 실행은 게이트가
측정으로 인정하지 않습니다(`prompt_over_runtime_budget`).

### 5a. 보류 보정 (선택, docs/governance-model.md "보류 보정")

후보 실행에 `--logprobs /runs/candidate.logprobs.json`을 더하고, validation 분할로 후보를 한 번 더 돌린 뒤 보고서에 `--validation-runs`를 줍니다.
보고서는 검증 행에서 고른 ID 확률 기준값과 `candidate_calibrated` 변형을 담고, 게이트는 그 변형을 판정합니다.

```powershell
New-Item -ItemType Directory -Force "$W\runs\validation" | Out-Null
node scripts/governance-mapping.mjs requests --data "$W\reviewed.jsonl" --variant candidate --split validation --out "$W\runs\validation\candidate.requests.jsonl"
# 후보 test 실행(위 5절, --ctx 3072 포함)에 --logprobs /runs/candidate.logprobs.json 추가; 검증 실행은 같은 명령에서 경로만 /runs/validation/... 으로
node scripts/governance-mapping.mjs report --data "$W\reviewed.jsonl" --runs "$W\runs" --validation-runs "$W\runs\validation" --prepared-by <준비자 ID> --out "$W\report.json"
```

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

승격한 뒤에는 7절의 `promotion` 팩트시트를 기록합니다.

되돌리기는 `promotion`을 null로, `role.json`을 `adapter: "none"`, `modelVersion: "unassigned_runtime"`, `evalStatus: "UNREVIEWED"`로
돌리고 런타임 환경 변수를 빼는 것입니다. 상태는 즉시 꺼짐 또는 기본 모드로 돌아갑니다.

## 7. 팩트시트 기록

학습·평가·승격을 마칠 때마다 요청 파일을 만들고, 콘솔의 AI 검토실 > `실험 비교` > `팩트시트 기록`에서 올립니다(`reviewer`·`admin`).
볼트가 확인한 뒤 서명된 원장 기록으로 남기고, `모델 현황` 화면과 `GET /api/model-runtime`·`GET /api/model-status`의 `factsheets`에 나타납니다.

```powershell
# 학습(후보 또는 셰이크다운): 변환한 GGUF 어댑터가 있으면 그 해시도 묶습니다.
node scripts/governance-mapping.mjs factsheet --kind training --receipt "$W\checkpoints\governance-mapping\run\candidate\training-receipt.json" `
  --training-set "$W\train.jsonl" --adapter-gguf "$W\checkpoints\governance-mapping-lora.gguf" --out "$W\factsheet-training.json"
# 평가: 볼트가 보고서 전체를 다시 계산합니다. 보고서는 reports/governance-mapping/에도 두면 실험 비교 화면에 나옵니다.
node scripts/governance-mapping.mjs factsheet --kind evaluation --report "$W\report.json" --out "$W\factsheet-evaluation.json"
# 승격: promotion-trust.json의 키로 서명된 영수증만 기록됩니다.
node scripts/governance-mapping.mjs factsheet --kind promotion --receipt "$W\promotion.dsse.json" --report "$W\report.json" --out "$W\factsheet-promotion.json"
```

같은 실행을 두 번 기록하면 409입니다. 셰이크다운 어댑터 해시로는 후보 학습·승격 팩트시트를 기록할 수 없습니다.
