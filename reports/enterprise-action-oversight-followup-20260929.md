# 행동 상태 무결성·사람 감독 증거·저메모리 학습 후속

2026-09-29. 이번 단계는 **progress**이며 법적 준수, 운영 배포 또는 모델 품질 승격 완료를 뜻하지 않는다.

후속으로 signed 이벤트 본문은 그대로 둔 채 SQL `events.action_id`만 바꾸면 행동 상세·분석완료 지표·조사 상관관계가 변하지만 integrity가 통과하던 공격을 재현하고 차단했다. 새 공통 검사기는 보존 중인 인증 이벤트와 SQL body 및 `tenant/source/id/fingerprint/action_id/trace_id/kind/received` 전 열을 identity 기반 exact compare한다. 온라인 조회, worker claim, 파기 전 검증, backup에 연결했으며 `/api/integrity`에서 `event_indexes`를 검사 범위로 올렸다. 관리자의 signed-ledger rebuild는 손상된 색인을 복구할 수 있다.

## 구현 결과

- `KR-34-OVERSIGHT`는 임의 참조나 건별 승인만으로 기술 증거가 충분해지지 않는다. 같은 시스템의 복구 가능한 감독 계획 문서와 현재 시스템·모델·정책 버전에 결합된 `human_oversight_review` 권한 출처 기록을 모두 요구한다.
- 감독 수행 기록의 서버 검증 snapshot과 hash를 assessment에 고정한다. 문서 개정, 이벤트 변경, 모델·정책·시스템 불일치가 생기면 기존 사람 판단을 덮어쓰지 않고 재검토 상태와 보완 과제를 유지한다.
- 사람 감독 수행과 건별 사전 승인을 분리했다. `human_oversight_review`는 `human_approval`을 대체하지 않으며 반대 방향의 대체도 허용하지 않는다.
- unsigned SQL `actions.version/analyzed`를 signed ledger에서 재구성해 정확히 대조한다. 이벤트, 자산, 활성 정책, 승인·만료 예외, 평가, 보존 파기 순서를 replay하며 불일치는 읽기·분석 claim·금융 보고서·감사 보고서·보존 실행·vault backup/restore를 409로 차단한다.
- `/api/integrity`는 `action_projections`를 검사 범위에 포함하고 테넌트별 결과를 반환한다. 다른 테넌트의 정상 상태는 손상된 테넌트 때문에 오염되지 않는다.

## 공격 재현과 검증

- signed 상태가 `version=3, analyzed=2`인 pending 행동을 SQL에서 `version=2, analyzed=2`로 바꿔 완료·준수처럼 보이게 하던 공격을 재현했다. 수정 후 overview, action, metrics, agents, workbench report, worker claim, integrity가 모두 거부한다.
- 검증과 사용 사이에 별도 SQLite writer가 상태를 바꾸는 시도는 같은 transaction snapshot의 쓰기 잠금으로 차단된다.
- 집중 테스트: 사람 감독·모델·거버넌스 21/21, 행동 무결성·공격·agent·평가 23/23, 금융·worker·vault·거버넌스 47/47, object integrity 32/32.
- 전체 Windows batch는 480개 중 462개가 통과했고 18개가 실패했다. 1개는 새 무결성 규칙에 맞지 않은 테스트 fixture였으며 수정 뒤 해당 파일 32/32가 통과했다. 나머지 17개는 서버 시작의 Windows `listen EFAULT`였다.
- `EFAULT` 파일 중 governance-documents, oidc-http, tls, visibility는 host 분리 실행에서 통과했다. 나머지 7개 파일은 Linux 제한 컨테이너에서 53/53 통과해 제품 assertion 회귀와 호스트 소켓 오류를 분리했다.
- 이벤트 색인·행동·파기·backup 집중 테스트 46/46, worker·평가·객체 회귀 69/69 통과.
- 최신 전체 Windows batch는 522개 중 515개 통과, 실패 7개는 모두 서버 시작의 `listen EFAULT`였다. 최신 제한 Linux 이미지에서 해당 파일과 새 공격 회귀는 42개 중 41개 통과했고 1개는 제품 assertion 이전에 테스트용 `openssl` 실행 파일이 없어 실패했다. 그 OIDC TLS 파일은 host 단독 실행 1/1 통과했다.
- 검증 이미지 `evidscope:enterprise-20260929-r5`: UID `1000:1000`, Linux amd64, image/repo digest `sha256:ff593026fd86e03cb75f3a7701f35e5103c37a1f4d82f5b36002bc325c423f35`. 재검증은 network none, read-only root, CPU 2, RAM 1GiB, 모든 capability drop 조건에서 수행했다.

## 저메모리 정식 학습 상태

- 학습 조건은 Foundation-Sec-8B-Reasoning 고정 revision, NF4 QLoRA rank 8, 최대 길이 1024, batch 1, 누적 16, 공개 사람 작성 KLUE QA 384행, step-20 checkpoint에서 stage-2 step 21–40으로 유지한다.
- 동적 패딩과 supervised completion 위치의 선택적 logits/FP32 CE만 계산하는 trainer는 이미 고정돼 있다. 동일 입력·loss·LoRA gradient 및 0-LR parameter 불변 검증을 통과했다.
- 19:23 측정은 물리 여유 7.43GiB, Windows commit 여유 4.47GiB, GPU 2.96/12GiB였다. 승인된 DLP 5개 정지 뒤 commit 6.34GiB·GPU 1.96GiB, WSL 파일 캐시 sync/drop 뒤 commit 7.92GiB·물리 11.23GiB까지 확보했다.
- 이전 실제 역전파에서 Windows commit이 약 10.4GiB 추가 감소했기 때문에 14GiB 시작 기준은 유지했다. 이 시도에서는 Job, Pod, candidate, active lease를 만들지 않았다.
- 페이지 파일은 자동 관리 off, 현재 16GiB 할당, 최대 24GiB 설정이다. 사용자 게임·브라우저·IDE·SQL Server·보안 서비스는 종료하지 않았다.
- verified safetensors를 GPU에 배치한 뒤 Linux file cache에 `POSIX_FADV_DONTNEED`를 적용하는 후보는 학습 의미를 유지할 수 있으나 예상 절감이 약 0.5–0.7GiB여서 현재 6GiB 이상 부족분을 해결하지 못한다. 14GiB 사전 조건을 만족한 0-LR 파일럿에서 실제 peak를 확인하기 전 formal trainer와 provenance에는 넣지 않는다.
- 임시 정지한 DLP 5개는 같은 ID로 복구했다. `k3d-dlp-serverlb`는 이번 시도 전부터 AhnLab Safe Transaction Service의 port 58670 점유 때문에 종료 상태였고 변경하지 않았다.

## 다음 실행 조건

정식 stage-2는 Windows commit 여유 14GiB를 3회 만족하면 기존 provenance `10f1f76497603dbfaf5e4ab35eb21392ffbfee944fed0a92ab16f4119cc99223`과 checkpoint marker `8aa6594ec8a86f13ad1593304de88b246d000b797e525d8bc9a8eed887fff81c`로 시작한다. 완료 판정은 step 40, adapter 파일과 hash, process exit, GPU 회수, DLP 복구를 모두 확인한다. 한국어 인용·보류·안전 사람 검토 전에는 quality와 promotion을 계속 false로 둔다.
