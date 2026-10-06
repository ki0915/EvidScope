# Cowork를 유지하는 로컬 학습 메모리 계획

2026-10-06 실제 PC 조회 기준. 메모리 부족이 완전히 해소됐다는 보고가 아니다. Cowork를 유지하라는 사용자 선택을 적용했다.

**최신 상태(2026-10-06, 학습과 별도 생성 평가 완료):** 새로운 immutable run `public-qa-balanced-20261006-r2`가 실제 GPU 가중치 업데이트20/20회를 완료하고 파일·실행 검증까지 통과했다. 건너뛴 업데이트0회, 완료 microbatch320개(답변 가능160·판단 보류160), 유효한 adapter 텐서256개, 재개 파일이 포함된10/20 step 체크포인트를 확인했다. 기존 adapter의80회 이력과 합쳐 가중치 업데이트 이력100회이며 optimizer·scheduler는 이번 실행에서 새로 초기화했다.

GPU 최대 할당6.281GiB·예약6.393GiB, 관측된 컨테이너 RAM 최대2.000GiB, Windows 예약 여유 최소8.156GiB·물리 여유 최소5.161GiB, GPU 관측 최고73°C, OOM0이었다. 호스트 예약량과 컨테이너 RAM은 다른 지표이며 합산하지 않았다. Cowork의 원래 VM PID·생성 시각을 종료 후에도 확인했다. 임시 정지한 DLP를 원래 상태·설정으로 복구하고7개 컨테이너를 대조했으며 학습 노드는 정지했다. 기존 로컬 제품0.1.3도 원래 설정·서명키를 유지해 복구하고4개 readiness HTTP200을 확인했다.

31개 파일209,379,203bytes를 읽기 전용으로 추출하고 전후 해시·목록을 대조했다. 최종 adapter SHA256은 `dd74533db5232de4d0961139a4de3c68bfa632e494a9976d821358b5df4baba3`다. 검증 보고서는 `reports/public-qa-balanced-r2-verification-20261006.json`, 학습 완료 근거는 `reports/public-qa-balanced-r2-completion-20261006.json`이다.

별도 실행 `public-qa-fresh-balanced-r2-20261006`에서 학습·이전 평가와 분리해 고정한 공개 한국어 QA128건을 평가했다. 같은 Reasoning 베이스를 한 번 로드하고 adapter를 끈 baseline128회와 켠 candidate128회를 순차 생성했다. 실제 입력 토큰·문맥·prompt 해시, adapter 상태,256개 행별 실행과260개 결과 파일의 전후 해시를 검증했다. 전체 통과는 baseline0/128, candidate60/128이며 candidate의 답변 가능 사례27/64·답변 불가능 사례33/64가 통과했다. candidate의 JSON 형식은128/128 유효했다. baseline은128건 모두 고정128토큰 출력 제한에 걸렸으므로 이 수치를 일반 능력 향상이나 다른 출력 길이의 성능으로 확대하지 않는다.

평가 중 관측된 컨테이너 RAM 최대2.000GiB, Windows 예약 여유 최소9.159GiB·물리 여유 최소5.551GiB, OOM0, GPU 최고73°C였다. DLP 원래7개 상태·설정 복구, 전용 노드 정지, 기존 서비스4개 HTTP200과 설정·서명키 보존, Cowork 원래 VM 유지도 확인했다. 종료 후 GPU 사용량은1627MiB·사용률0%였다. 평가 완료 근거는 `reports/public-qa-fresh-balanced-r2-completion-20261006.json`, 실제 실행 검증은 `reports/public-qa-fresh-balanced-r2-verification-recheck-20261006.json`, 비교는 `reports/public-qa-fresh-balanced-r2-comparison-20261006.json`이다.

첫 평가 검증의 필드명 불일치 실패 보고서는 `reports/public-qa-fresh-balanced-r2-verification-20261006.json`에 그대로 보존했다. 실제 Python 결과의 `baseArtifactLockSha256`를 계약용 필드로 연결하도록 수정하고, 누락·변조·충돌 거부를 포함한36개 CPU 회귀와 실제 결과 재검증을 통과했다. 모델·입력·출력·고정 런타임을 수정하거나 생성 평가를 다시 실행하지 않았다. 공개 사람 주석은 로컬 법률·금융 품질 검토를 대체하지 않으며 품질 인정·운영 배포는 허용하지 않는다.

이전 r1은 모델 로드 중 Windows 예약 사용률92.078%로 종료됐으며 실패 기록과 기존 source80 adapter를 보존했다. 상세 근거는 `reports/memory-cowork-preserved-runtime-r2-20261006.md`다. 새 r2는 캐시 회수와 예약17GiB 운영 목표의 실제 안정 표본을 확인하고 시작했다. 이전14GiB 시작 여유 통과만으로 해결됐다고 판단하지 않는다.

## 지금 적용하고 확인한 조치

- 페이지 파일은 이미 30GiB로 할당·설정되어 있고 실제 Windows 예약 한도는 61.863GiB다. 이번 단계에서 더 늘리지 않았다. C드라이브 여유는 마지막 조회에서 9.239GiB이고 다른 고정 디스크는 없었다.
- 승인된 DLP 3클러스터의 실행 중인 컨테이너 5개만 잠시 정지했다. 원래 정지된 1개는 그대로 유지했다. 전용 학습 노드를 시작해 준비 파일 18개의 목록·크기·해시와 PVC, source80 adapter, base lock을 검증했다. 준비 Pod 종료와 namespace의 Pod/Job 0개를 확인했다. GPU 학습은 생성하지 않았다.
- DLP 임시 정지 중 실제 시작 검사 3개 표본의 물리 여유는 6.150/6.081/6.092GiB, 예약 여유는 12.575/12.454/12.427GiB였다. 기존 시작 기준인 예약 14GiB를 충족하지 못했다. 이후 전용 노드 정지와 DLP 원래 상태·설정 7개 비교까지 완료했다.
- `scripts/set-training-browser-memory.ps1`로 현재 사용자 Chrome 성능 정책 `HighEfficiencyModeEnabled=1`, `MemorySaverModeSavings=2`를 적용했다. Chrome 154.0.8037.97과 기존 정책 없음, 두 DWORD의 실제 읽기 결과를 확인했다. 보안·계정 정책은 변경하지 않았다. 비활성 탭이 다시 열릴 때 재로딩될 수 있으며 Chrome에 관리 정책 표시가 생길 수 있다. [Google 기능 설명](https://support.google.com/chrome/answer/12929150?hl=ko), [Chromium 절약 수준 정의](https://chromium.googlesource.com/chromium/src/+/HEAD/components/policy/resources/templates/policy_definitions/Miscellaneous/MemorySaverModeSavings.yaml).
- 현재 브라우저 자동화에는 Chrome이 연결돼 있지 않아 Chrome UI의 정책 채택은 검증하지 못했다. 실제 메모리 감소도 확인하지 못했다. 설정의 읽기 성공을 절감 성공으로 집계하지 않는다.
- 모델 shard 1개에 내용 해시를 보존한 NTFS 압축 시험을 했지만 유효한 공간 절감이 없었다. 원래 압축 해제 상태로 되돌렸으며 다른 shard에는 적용하지 않았다.

08:13:33 UTC 하드웨어 조회 당시에는 물리 여유 3.203GiB, 예약 여유 8.326GiB, Chrome private 메모리 합계 7.461GiB였다. private 메모리는 실제 상주 RAM과 다르며 GPU·VM·프로세스 수치를 합산하지 않는다. Cowork의 별도 VM `cowork-vm-f70e4dd4`는 유지했다. 활성 학습 lease는 없다.

## Cowork 유지 후 추가 캐시 회수 실측

전체 회귀 프로세스 종료 뒤 승인된 DLP만 잠시 정지하고 `scripts/recover-training-memory.ps1 -SuspendDlp`를 실제 실행했다. Docker Desktop WSL의 dirty data를 먼저 sync한 뒤 재생성 가능한 file/dentry/inode cache만 회수했다. 다른 사용자 앱과 Cowork VM 설정은 변경하지 않았다. 종료 0, 원복 오류 0이었다.

| 시점 | 물리 여유 GiB | 예약 여유 GiB |
|---|---:|---:|
| 회수 전 08:24:52 UTC | 2.437 | 7.343 |
| DLP 정지 중 마지막 표본 08:27:32 UTC | 6.147 | 11.154 |
| DLP 복구 후 08:27:36 UTC | 5.400 | 10.360 |

복구 후에도 물리 여유는 2.963GiB, 예약 여유는 3.017GiB 증가했다. 이는 관측 구간의 전후 차이이며 전체 증가분을 특정 원인 하나의 인과 효과로 보장하지 않는다. DLP 6개 중 원래 실행 중인 5개만 정지·복구하고 원래 정지된 1개는 유지했으며, 6개 모두 ID·이름·실행 상태·메모리 한도·CPU 설정·재시작 정책을 대조했다. 9개 표본 중 마지막 3개도 예약 14GiB를 충족하지 못했다. 메모리 회수 효과를 확인했지만 새 GPU 학습 시작 문제를 완전히 해결했다고 표시하지 않는다.

실행 근거는 `.local/training/memory-recovery/20261006-082450-044/receipt.json`과 `reports/memory-cowork-preserved-cache-recovery-20261006.log`다. 조회된 Windows Python 프로세스와 학습 컨테이너·lease에서 회수할 우리 소유 대형 학습 프로세스는 발견하지 못했다. 이름만 같은 `server.mjs` 프로세스를 임의 종료하지 않았다.

08:34:52 UTC 후속 표본은 물리 여유 3.513GiB·예약 여유 8.315GiB였다. 다른 작업을 계속 사용하는 동안 여유가 다시 줄었으므로 앞선 회수값을 지속 가능한 학습 여유로 보장하지 않는다. Cowork의 기존 `vmwp` 42112 / `vmmem` 35172와 같은 생성 시각을 확인했고 활성 학습 lease는 없었다(`reports/memory-cowork-post-recovery-20261006.json`).

## 학습 설정에서 더 줄일 수 있는 범위

현재 동결 런타임은 NF4 이중 양자화, BF16, batch 1, 누적 16, rank 8, SDPA, gradient checkpointing, completion 위치의 logits만 계산, worker 0, pin memory 해제를 사용한다. 컨테이너 CPU 2개·RAM hard 12GiB와 `memory.high=2GiB`가 적용된다. high는 reclaim 기준이며 Windows 전체의 강제 상한은 아니다.

새 데이터 704건은 실제 토크나이저에서 최대 643토큰이며 원문·정답이 보존됐다. 콜레이터는 실제 길이로 패딩하므로 상한을 1024에서 768로 바꿔도 같은 입력의 텐서 크기는 줄지 않는다. 640 이하는 일부 원문 보존 검증에 실패한다. 이전 source80 실제 PyTorch 최대 할당은 6.258GiB, 예약은 6.393GiB였다. GPU 비율 0.50은 이 실제 필요량보다 작다. 비율만 낮춰 텐서가 작아진다고 주장하지 않는다.

기존 시작 검사(물리 4GiB·예약 14GiB)와 실행 중 메모리·OOM·열 중단 기준을 유지한다. 이전 로드 구간의 예약 여유 감소를 고려한 준비 운영 목표는 예약 17GiB다. 여유가 부족할 때 같은 Job을 반복 생성하지 않는다. 학습과 CPU 전체 검증은 동시에 실행하지 않는다.

별도 개선 후보는 검증한 NF4 base를 새 artifact로 저장해 매번 14.96GiB BF16 원본을 매핑·양자화하는 로드 과정을 줄이는 것이다. 동일 베이스·양자화 상태·adapter 호환성·원본 대비 로드 최고 메모리를 검증해야 한다. 절감량을 아직 측정하지 않았으므로 현재 동결 base를 교체하거나 시작 기준을 낮추지 않는다.

## 실제 PC에 맞춘 증설안

메인보드는 MSI MAG B660M MORTAR WIFI DDR4 (MS-7D42)다. 현재 DIMMA1/A2/B1/B2 네 슬롯에 각 8GB, Crucial CT8G4DFRA32A와 Samsung M378A1K43EB2-CWE가 두 개씩 장착돼 있으며 실제 속도는 3200MT/s다.

Cowork·브라우저·개발 환경과 8B 학습을 함께 유지하려는 목표에는 **같은 키트의 DDR4-3200 non-ECC unbuffered DIMM 32GB×2, 총 64GB**로 교체하는 방안을 권장한다. 기존 네 모듈에 추가할 빈 슬롯은 없다. 특정 SKU 구매 전 MSI 호환 목록과 해당 제품의 모듈 사양을 확인한다. 보드 공식 사양은 DDR4 4슬롯·최대 128GB·non-ECC unbuffered를 명시한다. 이번 Windows SMBIOS 조회는 최대 64GB를 보고하므로 차이를 보존한다. 목표 64GB는 양쪽 자료의 범위 안에 있지만 특정 키트의 실물 동작 검증을 대신하지 않는다. [MSI 공식 사양 및 지원 메모리 링크](https://www.msi.com/Motherboard/MAG-B660M-MORTAR-WIFI-DDR4/Specification).

하드웨어를 구매·장착하거나 자동 재부팅하지 않았다. 교체 후에는 실제 64GB 인식과 메모리 진단, 동일한 앱을 켠 상태의 시작 표본 3개, 짧은 자원 측정, 실제 GPU 학습·checkpoint·adapter 해시·step 검증을 순서대로 수행해야 한다. RAM 용량을 늘려도 RTX 3080 12GB의 VRAM은 늘지 않으므로 현재 QLoRA 설정을 유지한다.

## 원복 및 증거

Chrome 원복은 관리자 PowerShell에서 다음을 실행한다. 스크립트는 원래 없었던 자신의 두 값만 삭제하며 외부에서 값이 바뀌면 보류한다. 다른 정책 키나 사용자 탭을 삭제하지 않는다.

```powershell
.\scripts\set-training-browser-memory.ps1 -Restore -ReceiptPath '.local\training\browser-memory\20261006-080830-778-a4dd5cdee75d4a3b9ac770b2b1701761.json'
```

성공 적용 영수증과 단계별 이전 영수증을 보존했다. 초기 PowerShell 5 영수증 교체 오류는 수정했으며, 첫 일반 권한 적용의 레지스트리 접근 거부는 쓰기 전 발생했다. 두 실패는 성공으로 집계하지 않는다.

- `reports/memory-browser-policy-check-20261006.log`
- `reports/memory-browser-policy-apply-20261006.log` (권한 거부)
- `reports/memory-browser-policy-elevated-20261006.log` (읽기 검증 성공)
- `reports/public-qa-balanced-memory-start-check-20261006.json`
- `reports/memory-cowork-preserved-hardware-20261006.json`
- `reports/memory-vm-inventory-r2-20261006.json`
- `.local/training/public-qa-run/balanced-preparation-20261006-r1/custody-restored.json`
- `.local/training/public-qa-run/balanced-preparation-20261006-r1/pvc-attempt-4b63721d-f825-4b9f-b27a-e7ac7e5f1933/preparation-receipt.json`

위 초기 준비 단계에서는 새 GPU 학습을 시작하지 않았다. 이후 실제 Job의 결과는 문서 첫머리의 최신 상태를 따른다. 기존 source80 성공 학습, 자원 가드로 중단된 balanced r1, 실제 완료·검증된 balanced r2를 구분한다.

## 텐서별 지연 로딩 후보의 실제 CPU 검증

`scripts/public_qa_streaming_load.py`를 별도 실험 후보로 추가했다. 고정 Transformers4.51.3 소스 해시와 bitsandbytes0.45.5·safetensors0.5.3·Accelerate1.6.0을 확인하고, 원본 BF16/Llama/단일 CUDA NF4 경로만 지원한다. 기존 봉인된 학습 런타임과 배포 제품에는 연결하지 않았다. 설치 라이브러리 파일이나 원본 모델을 수정하지 않는다.

원본 CPU shard 사전을 실제 텐서 대신 메타데이터 객체로 유지하고, 기존 Transformers가 해당 파라미터를 요청할 때만 읽는다. 소유 스레드와 유효 범위 검사, 파일 변경 감지, 예외 후 hook 원복을 포함한다. 파일 stat 검사는 artifact-lock의 내용 해시 검증과 읽기 전용 마운트를 대체하지 않는다.

고정 이미지에서 CPU 회귀12개가 통과했다. 실제 private loader 호출과 stub 양자화 분기의 인자 호환성, 원본 값 동일성, 범위·버전·잘못된 모델 거부와 원복을 검사했다. stub 검사를 실제 bnb 양자화 등가성으로 기록하지 않는다. 별도 reviewer의 읽기 전용 검토와 수정 후 재검토를 수행했다.

최종32MiB 합성 BF16 파일을 독립 프로세스에서3회 비교했다. 기존/지연 로더의 프로세스 RSS 증가량은 각각32.465/8.516, 32.461/8.512, 32.461/8.516MiB였다. 모든 텐서 내용 해시가 같았다. 이는 이 합성 CPU 파일 매핑의 수명·상주 페이지 비교이며 실제8B 학습의 RAM·Windows 예약량·GPU 절감으로 환산하지 않는다. 실제 원본 모델291텐서의 헤더가 BF16·PyTorch 형식임도 확인했지만 payload나 전체 내용 해시를 다시 검사한 것은 아니다.

근거: `reports/memory-streaming-loader-cpu-r2-20261006.log`, `reports/memory-streaming-loader-cpu-benchmark-final-20261006.json`, `reports/memory-streaming-base-metadata-20261006.json`, `reports/memory-streaming-loader-validation-20261006.json`. CPU2·RAM1GiB(소스 검사512MiB)·네트워크/GPU 없는 임시 컨테이너5개는 모두 exit0/OOMfalse 후 정확한 ID로 정리했다. Cowork 원래 두 PID·생성 시각과 기존 서비스4개 readiness HTTP200을 확인했다.

다음 연결 조건은 작은 GPU NF4 packed bytes·nested 통계·forward·adapter gradient 등가 검증, 동일 조건의 실제 로드 최고 메모리 비교다. 여유가 부족한 상태에서 전체8B 로드를 반복하거나, 기존 가드를 낮추거나, 미검증 후보를 기존 학습에 적용하지 않는다.

CPU 검증 종료 뒤10:25∼10:26 UTC에는 DLP를 정지하지 않고 재생성 가능한 WSL 캐시만 회수했다. 회수 직전 물리0.906/예약4.952GiB에서 최종3.147/8.283GiB로 여유가 증가했지만 시작 하한에는 미달했다. DLP6개 원래 ID·상태·설정 일치와 원복 오류0을 확인했다. 근거는 `.local/training/memory-recovery/20261006-102526-314/receipt.json`이다. 동시 작업이 포함된 전후 차이를 캐시 회수 단독 효과로 보장하지 않는다.
