# 참조 문서 무결성 완결과 정식 학습 자원 재검사

2026-09-29. 이번 결과는 **progress**다. 로컬 vault의 서명 이력이 참조하는 문서 파일까지 무결성 검사를 연결했지만 외부 불변 보관, KMS, 실제 장기 보존, 법적 준수나 모델 품질 승격을 뜻하지 않는다.

## 감사 증적 무결성

- `/api/integrity`는 서명 원장, 보존 이벤트 본문·색인, development run, 객체·평가·행동 상태에 더해 `governance_documents` 사본과 모든 과거 공급사·거버넌스 문서 revision의 로컬 암호문을 검사한다.
- 문서는 tenant별 경로와 AES-256-GCM AAD에 결합하고, 복호화 뒤 SHA-256과 서명된 평문 길이를 대조한다. 다른 tenant의 동일 평문 암호문 교환, 최신본은 정상이지만 과거 revision이 손상된 경우, 거버넌스 문서 SQL 사본 변조를 거부한다.
- 파일은 단일 descriptor에서 최대 envelope 크기+1만 읽는다. 경로 확인 뒤 파일이 커지는 경우도 메모리 한도를 우회하지 못한다.
- 미참조 orphan 파일은 증거가 아니어서 검사하지 않는다. 각 파일의 읽기 시점 검증이며 원자적 파일시스템 snapshot, remote immutability, 보관 기간 경과를 주장하지 않는다.
- vault backup/restore도 같은 공통 검사기로 원본과 복사본을 재검증한다.

검증 결과는 최종 host 전체 `540/540`, 문서·backup 집중 `39/39`, 최종 제한 Linux 컨테이너 `106/106`이다. 최종 이미지는 `evidscope:enterprise-20260929-r8`, UID `1000:1000`, Linux amd64, digest `sha256:1a21b0a9f8c537d3c9c814afd9e28d7992da2c164110c5444e35e525f7136789`다. 컨테이너 검증은 network none, read-only root, CPU 2, RAM 1GiB, capability 전체 drop, no-new-privileges에서 수행했고 테스트 작업 경로만 tmpfs로 제공했다.

## 저메모리 정식 학습 사전검사

- 기존 step-20 checkpoint, Foundation-Sec-8B-Reasoning revision `63c930c82d7646226d33502bec5870019738400e`, NF4, rank 8, 길이 1024, batch 1, 누적 16과 저메모리 trainer를 유지했다.
- 새 출력 경로만 사용하는 stage-2 provenance는 `.local/training/resume/public-qa-stage2-lowmem-20260929-r3.json`, SHA-256 `ad8e43a9f8dd7e174ccca31a3aa4e6c8bb6556c4119b083866e6a8f5887d791d`다.
- 승인된 DLP 컨테이너 5개를 같은 ID로 임시 정지하고 WSL cache를 반환한 뒤 3회 측정했다. Windows commit 여유는 `5.804 / 5.582 / 7.556 GiB`, 물리 여유는 `8.350 / 8.369 / 9.102 GiB`, guest 여유는 `14.122 / 14.160 / 14.166 GiB`, GPU 사용은 `2287 / 2148 / 2188 MiB`였다.
- GPU와 guest RAM은 충분했지만 Windows commit 14GiB 시작 기준을 충족하지 못했다. 결과는 `blocked_resources`; Job, Pod, candidate, active lease는 생성되지 않았다.
- DLP 5개는 `bb79729aa65d`, `6111dd506c26`, `4e9d06beacf4`, `31b0ad7cd72a`, `2c999a6a96dc` 동일 ID로 복구했다. 기존 `82b18eeb2dc2`는 AhnLab의 port 58670 점유로 원래부터 종료 상태이며 변경하지 않았다.

현재 큰 private commit은 WSL 약 6.08GiB, Minecraft Java 약 2.90GiB, League/Riot 합계 약 3GiB, 두 로컬 Python 프로세스 합계 약 1.54GiB, Chrome 약 0.76GiB, SQL Server 약 0.72GiB 순서다. Docker/DLP와 cache는 승인 범위에서 이미 줄였으며, Minecraft·League·IDE·브라우저처럼 사용자 세션을 임의 종료하지 않았다. 학습을 시작하려면 이 사용자 작업이 끝난 시점에 같은 3회 검사를 다시 통과하거나, 별도 승인과 재부팅으로 pagefile의 실제 commit limit을 더 확보해야 한다.

