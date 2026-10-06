# 독립 금융 업무 실증 구현·10회 검증

2026-10-06. 승인·AI 실행·업무 처리의 세 독립 프로세스가 자체 상태에서 기록을 생성하고 HTTP로 직접 수집하는 경로를 구현했다. **최종10회에서 기본6개·부정4개, 총100개 사례가 통과했고 고정된 서명 보고서100개를 별도 검증했다.** 전체 기업 운영·한국법 준수 인증이나 새 LLM 학습 완료를 주장하지 않는다.

## 바뀐 부분

- `scripts/finance-workflow-pilot.mjs`: 새 임시 설정·문서·서비스 환경, 사례 요청 조정, 당시 정책·공급사 근거와 운영 기록 대조, 고정 보고서·종료 영수증 생성.
- `scripts/finance-workflow-producer.mjs`: 승인 상태·철회·합성 차단, 결정적인 AI 점수 계산, 별도 업무 상태 적용. AI의 `workflow-ai`와 업무의 `workflow-business`는 다른 HMAC 자격으로 직접 HTTP에 제출한다. 부모는 완성 이벤트를 전달하지 않는다.
- [실행 안내](../docs/finance-workflow-validation.md): 새 영수증 경로와 고정 입력 hash를 사용하는 재현 방법.

기존 승인 엔진을 새로 만들지 않았다. 제품 수집·분석·문서 보관·금융 보고서 API와 로컬 lifecycle을 사용했다. 실행 전후 제품96개 파일의 해시를 봉인된0.1.3 manifest와 대조했고 모두 일치했다. 기존 ZIP/TAR·설치본·실서비스 데이터는 수정하지 않았다. 새 fixture는 개발 작업 트리에 추가된 검증 도구이며 봉인된0.1.3 안에 포함됐다고 표시하지 않는다.

## 최종 실제 사례

| 사례 | 확인한 결과 |
| --- | --- |
| 공급사 모델 v1 / 현재 배포 v2 | `MODEL_VERSION_MISMATCH`, 공급사 적용 범위 재검토 |
| 권한 철회 뒤 실행 | `AUTHORITY_MISMATCH`, 철회·실행 원본 참조 |
| 차단 / 별도 업무 프로세스 처리 성공 | `BLOCK_SUCCESS_CONFLICT`, safety와 business 원본 참조 |
| 건별 승인 없는 자동 처리 | 승인 누락·승인 필요 여부 미확인 경보 없음 |
| 과거 발급 / 실행 증거 뒤 수신한 승인 | `LATE_EVIDENCE`, 사후 승인 불일치 경보 없음; 발생·수신 순서 분리 |
| 실행 없음 / 공급사 문서 복구 불가 | `execution_evidence_missing`, `DOCUMENT_EVIDENCE_MISSING` 유지 |
| 잘못된 HMAC | HTTP401, 해당 실행 증거 미수집 |
| 다른 시도의 승인 | `APPROVAL_MISMATCH`, 다른 실행 승인 차용 없음 |
| 다른 모델의 승인·증빙 | 승인 불일치와 `MODEL_ID_MISMATCH` |
| 같은 행동 식별자의 다른 테넌트 결과 | beta 수집 HTTP202, alpha 보고서와 분리·타 테넌트 조회404 |

고정 fixture SHA-256은 `1eb3301de40065cba61dbbe73efc2fffb2f672937da3825b514c9a5ad12d63cf`, 최종10회 정규화 결과 SHA-256은 모두 `e2c9593e21b68ca0d1dd4e71b950cb1e4a4dc23c76f5d7a01c76d1b0d40abe0f`다. 시각·보고서 ID·신뢰키처럼 실행마다 다른 값은 관계 검증에 사용하고 재현성 digest에서는 구별했다.

## 검증 근거

- [최종10회 영수증](finance-workflow-final-20261006/verification.json): 매회6+4, source 변경0, 각 프로듀서 정상 exit0·종료 확인, 네 서버 종료 확인.
- [별도 수용 검증](finance-workflow-independent-verification-20261006.json): 저장된100개 서명 보고서를 초기화 때 따로 얻은 공개키로 검증. 원본 참조·권한/시도/모델·AI 상태·업무 상태 hash·테넌트 경계를 대조하고 보고서 변조와 잘못된 고정 digest 거부를 확인. 별도 의미 관계 digest도10회 동일하다.
- [장애 주입 검증](finance-workflow-late-crash-verification-20261006.json): 최종 API 검사 뒤 자체 임시 worker만 실제 비정상 종료. 성공 판정 차단, 실패 영수증, 모든 임시 프로세스 종료를 확인했다.
- [실행 후 복구](finance-workflow-runtime-recovered-20261006.json): 총70개 프로세스 인스턴스에 해당하는69개 고유 PID와 임시 수신 포트 잔여0. 기존 서비스 네 readiness HTTP200, Cowork PID·생성 시각 유지, GPU lease 없음.
- [제품 소스 사전](finance-workflow-product-source-match-20261006.json)·[사후](finance-workflow-product-source-match-after-20261006.json): 관련96개 파일이 봉인0.1.3과 일치.

첫 두 실행은 수정 전 정상 경로에서도 통과했으며 원본 영수증을 보존했다. 별도 reviewer가 마지막 API 검사 뒤 서버 장애가 성공으로 기록될 수 있는 P1을 발견했다. `runtime.stop()` 이후 `runtime.failure`를 실패 영수증·최종 판정에 반영하도록 수정했고 실제 장애 주입으로 회귀를 검증했다. **최종10회는 이 수정 뒤의 동일 소스로 실행했다.** 기존 전체 제품 회귀951개를 이번 fixture 추가 뒤 다시 실행했다고 주장하지 않는다. 제품 파일은 동일하며 이번 변경 경로를 실제 HTTP·서명·장애·재현성 검사로 검증했다.

별도 reviewer `balanced_runtime`가 최종 수정·장애 영수증·10회/100사례·서명/상태 hash/재현성 영수증과 합성 범위 표시를 다시 읽기 전용으로 대조했고 추가 수정 사항을 발견하지 않았다. reviewer 자체가 테스트를 실행한 것은 아니다.

## 아직 완료하지 않은 범위

같은 사용자 계정의 합성 프로세스이며 실제 금융사·별도 호스트·AGT 운영 연동은 아니다. AI는 합성 함수이고 사람 검토는 수행하지 않았다. 합성 차단 보고의 실제 강제 차단 효력, 외부 감사자의 근거 탐색 시간, 경쟁 제품 동일 입력 비교, 장기간 문서 보관 운영은 검증하지 않았다. 출처 서명·보고서 서명은 진실성과 법률 충분성을 보증하지 않는다. 한국 법률 출처의 미확인 사항과 사람 판단 상태도 유지한다.

추가 balanced LLM 학습은 [별도 실제 실행](memory-cowork-preserved-runtime-r2-20261006.md)에서 메모리 guard로 중단됐고 미완료다. 무백업 Docker VHD 압축·조건부 페이지 파일 확장은 자동 승인 검토 거부 후 사용자 승인 대기다. 이번 CPU 실증을 학습 완료나 전체 목표 달성으로 확대하지 않는다.
