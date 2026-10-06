# 재시작 신뢰경계와 정식 학습 자원 상태

2026-09-29. 이번 결과는 **progress**다. 로컬 서명 이력과 조회 사본 사이의 재시작 승격 공격을 막았지만 저장소 HA, 외부 KMS/WORM, 실제 조직 IdP·공급사 연동, 법적 준수 인증 또는 모델 품질 승격을 뜻하지 않는다.

## 재현한 공격

정상 schema v3 시스템을 등록한 뒤 서명키와 원장은 건드리지 않고 SQL `objects` 사본만 `schemaVersion: 2`, 공격자 owner/purpose로 바꿨다. 이전 코드는 재시작 시 이 사본을 legacy 시스템으로 보고 정규화한 뒤 새 서명 원장에 기록했다. 그 결과 재시작 전 `/api/integrity` 실패가 재시작 후 성공으로 바뀌고, 새 금융 보고서에도 공격자 값이 고정될 수 있었다.

## 수정

- 시작 시 모든 설정 tenant의 `catalog`, `system`, `assessment` 최신 값을 최종 서명 checkpoint까지 검증한 원장과 SQL ID·본문·개수로 대조한다.
- 모든 tenant의 검증이 끝나기 전에는 카탈로그 갱신이나 시스템 이관을 시작하지 않는다.
- 검증과 후속 서명은 하나의 `BEGIN IMMEDIATE` transaction 안에서 수행해 다른 SQLite writer가 검증 직후 값을 바꿀 수 없게 한다.
- 한 tenant라도 불일치하면 전체 transaction을 rollback하고 DB를 닫은 뒤 서비스 시작을 거부한다.
- 카탈로그는 서명 payload에 별도 id가 없으므로 projection 계약과 같은 고정 키 `current`로 대조한다.

회귀 범위는 schema 강등과 owner/purpose 변조, unsigned 시스템 삽입, 시스템 삭제, SQL ID 변경, catalog 본문 변조, assessment 본문 변조, 손상 tenant 때문에 다른 tenant의 정상 legacy 이관이 일부 남는 경우, 정상 legacy 1회 이관을 포함한다.

일반 조회 경로도 같은 원칙으로 보강했다. `/api/assets`, `/api/cases`, `/api/rules`, `/api/exceptions`, `/api/governance`, overview 사건 수는 검증된 객체 사본만 반환한다. AI 가시성은 검증된 자산 등록만 목적지 정책과 미등록 판단에 사용하며, 변조된 자산으로 경보를 숨길 수 없다. `/api/agents`는 독립 검토에서 발견된 unsigned `case_decision` 삽입 공격을 차단하고 검증된 판단만 reviewed/stale 집계에 사용한다. 자산과 시스템의 일반 갱신도 변조된 이전 사본을 새 정상 기록으로 덮어 서명하지 않는다.

## 검증

- 수정 집중 host: `test/finance-evidence.test.mjs` 19/19 통과.
- 독립 읽기 전용 검토: 첫 검토에서 catalog 직접 변조 시험 공백을 보강했고, 후속 검토가 발견한 unsigned `case_decision` 집계 경로를 수정했다. 최종 재검토 45/45에서 추가 결함이 없었다.
- 첫 전체 Windows 실행: 544/546. 실패는 TLS 자식 프로세스의 `listen EFAULT` 하나가 중첩 집계된 것이며 분리 실행 8/8 통과.
- 두 번째 전체 Windows 실행: 545/547. 실패 두 건 모두 retention 자식 프로세스의 `listen EFAULT`이며 분리 실행 6/6 통과.
- 최종 전체 Windows 실행: 557/557 통과, 실패 0, 건너뜀 0.
- 추가 조회·agent 집계 host 집중: 66/66 통과.
- r11 제한 Linux: 시작·일반 조회·AI/agent 집계·정책 무결성 85/85 통과. `--network none`, read-only rootfs, CPU 2, RAM 1GiB, capability 전체 drop, no-new-privileges, UID `1000:1000`.
- 이미지: `evidscope:enterprise-20260929-r11`, Linux amd64, digest `sha256:4b87445afcba6779aee736543631431f4710f8e88f4bfefc13f11caaf47f9cca`.

앞선 두 Windows 전체 실행의 실패 기록은 환경 진단 근거로 보존한다. 최신 전체 실행과 제품 변경 관련 집중·제한 Linux 시험은 모두 통과했다.

## 학습 자원

GPU/RAM 사용량을 줄이라는 사용자 지시에 따라 이미 적용한 동적 padding, completion 위치만 계산하는 logits, FP32 completion CE, NF4 QLoRA, rank 8, batch 1, CPU 2, 비고정 worker/pinned-memory 비활성화를 유지한다. sequence length 1024와 누적 16은 step-20 checkpoint 계보에 고정되어 있어 측정 없이 바꾸거나 안전 시작 기준만 낮추지 않았다.

재부팅 뒤 승인 범위 내 DLP 5개 정지와 WSL cache 반환을 다시 적용한 정식 gate에서도 Windows commit 여유가 7.885/8.080/8.077GiB로, 실제 이전 model-load 실패를 바탕으로 둔 14GiB 시작 기준에 못 미쳤다. `public-qa-stage2-lowmem-20260929-r3`는 `blocked_resources`로 끝났고 Job, Pod, candidate, lease는 생성하지 않았다. 사용자 앱 강제 종료와 자동 재부팅은 수행하지 않았으며 DLP 5개는 같은 container ID로 복구했다. `k3d-dlp-serverlb`의 기존 AhnLab port 58670 충돌 상태는 건드리지 않았다.

다음 정식 학습 시도는 사용자 앱이 종료되어 3회 시작 검사를 통과한 뒤 기존 provenance `ad8e43a9f8dd7e174ccca31a3aa4e6c8bb6556c4119b083866e6a8f5887d791d`로 실행한다. 실제 peak가 낮아졌다는 역전파 측정 전에는 14GiB 기준을 낮추지 않는다.
