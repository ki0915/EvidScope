# 접수 영수증 무결성과 처리량 후속

2026-09-29. 이번 결과는 **progress**다. 접수 증적의 위조·보존 전환 결함은 수정했지만 현재 단일 SQLite vault는 목표 20 EPS 지속 부하를 충족하지 못했다. 이 보고서는 법적 준수 인증, 실제 금융 고객 운영, HA 또는 모델 품질 승격을 주장하지 않는다.

## 재현하고 수정한 결함

SQL `receipts`에 source/id와 맞는 fingerprint만 삽입하면 HMAC가 유효한 첫 이벤트도 `duplicate:true`, `durability:sqlite_full_commit`로 응답했지만 signed event는 0건이었다. 원장·키를 바꾸지 않는 공격이었다.

새 접수는 암호화 event를 쓴 뒤 source/id/fingerprint와 event seq/hash를 묶은 `event_receipt`를 같은 `BEGIN IMMEDIATE` transaction에서 서명한다. SQL 영수증의 삽입·변경·삭제·추가를 signed history와 대조하고, `/api/rebuild`는 signed truth만 복구한다. source 접수 영수증은 `basis:source_ingest`와 source principal을 결합한다.

독립 검토에서 두 번째 P1이 재현됐다. 영수증 도입 전 암호화 이벤트는 보존 중에는 검증됐지만, 정상 두 사람 승인으로 키를 파기한 뒤에는 원본과 영수증이 모두 없어 integrity와 rebuild가 실패했다. 수정 후 파기 transaction은 원본을 복호화·검증할 수 있을 때 `basis:verified_before_retention` 영수증을 관리자 principal로 먼저 서명한 뒤 키와 검색 사본을 지우고 disposition을 기록한다. receipt는 event 뒤·disposition 앞에 있어야 한다. 이미 근거 없이 파기된 legacy는 자동 승격하지 않는다.

## 검증

- receipt·retention·rebuild·backup 관련 집중: 71/71 통과.
- 독립 리뷰: 기존 파기 결함 재현 후 수정 재검토 32/32와 별도 경계 8/8 통과, 추가 결함 없음.
- 전체 host 첫 실행: 564/565. 실패 1건은 `/api/integrity`의 공개 검사명 배열에 `receipt_projections`를 추가한 뒤 테스트 예상 목록이 갱신되지 않은 계약 테스트였다. 예상 목록 수정 후 관련 71/71, 전체 재실행 565/565 통과.
- 제한 Linux r12: 관련 71/71 통과. `--network none`, read-only root, CPU 2, RAM 1GiB, capability 전체 drop, no-new-privileges, UID `1000:1000`. 이미지 `evidscope:enterprise-20260929-r12`, Linux amd64, digest `sha256:df99c03fe52ca976b03f9ad31a52f4bd3c32114ba9b34a07b43a47bbe91adeca`.

## 실제 로컬 처리량

`npm run bench`는 Node 로컬 HTTP, 단일 SQLite WAL/FULL writer, worker 2개, source 3개, 약 1.06 KiB 이벤트 조건으로 실행했다. 실패 중에도 결과를 잃지 않도록 benchmark가 단계·측정값·오류를 `reports/benchmark-latest.json`에 기록하게 수정했다.

| 구간 | 결과 | p95 | 판정 |
|---|---:|---:|---|
| normal 200건, 요청 20 EPS | 200 접수 | 1122.14 ms | 실패: p95 1초 초과 |
| burst 200건, 동시성 20 | 200 접수 | 2511.12 ms | 해당 구간의 완전 접수 기준 통과 |
| sustained 600건, 요청 20 EPS | 60 접수, 503 540건 | 6006.46 ms | 실패 |

마지막 signed export도 gateway 6초 timeout으로 HTTP 503이어서 최종 원본·분석 수 대조는 수행되지 않았다. 원인은 현재 접수 전 `verifiedActions`가 retained event 복호화, signed ledger, receipt, action projection을 전체 재검증해 원장 증가에 따라 비용이 커지는 경로와 일치한다. 이는 코드 경로와 지연 곡선에 기반한 원인 후보이며 profiler로 분리 측정하기 전 단독 원인으로 확정하지 않는다. 무결성을 약화시키지 않는 증분 인증 상태와 수집 경로의 최소 중복 검증을 설계·시험해야 한다.

## 학습 자원 상태

step-20 checkpoint의 stage-2 계보는 rank 8, sequence 1024, batch 1, 누적 16, 동일 데이터·베이스·이미지에 고정돼 있다. 동적 padding, completion 위치 logits, FP32 completion CE, NF4, worker 0, pinned memory off는 이미 적용했다. 시퀀스나 rank를 바꾸면 같은 resume가 아니므로 자원 절감처럼 기록하지 않는다.

재부팅과 승인된 DLP 5개 임시 정지·WSL cache 반환 후 3회 commit 여유는 7.885/8.080/8.077 GiB로 14 GiB 안전 시작 기준에 미달했다. Job, Pod, candidate, lease는 만들지 않았고 DLP 컨테이너를 같은 ID로 복구했다. GPU는 당시 약 2.5 GiB/12 GiB 사용이어서 시작 차단의 직접 조건은 Windows commit이었다. 기존 20-step 계보를 유지하는 추가 메모리 절감은 모델 적재 peak를 새 역전파 파일럿으로 입증해야 하며, 사용자 앱 강제 종료나 안전 기준 하향으로 대체하지 않는다.
