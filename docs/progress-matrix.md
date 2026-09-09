# 목표 대비 근거와 남은 작업

이 표는 전체 목표 완료 선언이 아니다. 구현 파일의 존재와 실제 시험을 분리한다.

| 제품 결과 | 현재 실행 근거 | 남은 검증/구현 |
|---|---|---|
| 인증 이벤트→저장→검색→타임라인→탐지→사건 | src/서비스 + HTTP 통합 + 브라우저 사례 | source별 세부 수집 quota·큰 데이터 검색 비용 |
| 출처·tenant·업무AI write-only | 실제 게이트웨이와 vault 401/403, HMAC/replay/collision/tenant tests | 운영 source 자격 회전·SSO·실제 조직 경계 |
| 과거 권한·정책·승인·위임·외부 결과 | model4 + HTTP late/revoke/approval/stop 구분 | 실제 공급자 adapter는 미연동 |
| 원본·사본 분리 및 독립 export | 서명 checkpoint, 별도 trust key, 변조/누락/순서/rollback tests | 외부 KMS/WORM·키 회전/backup 실제 연결 |
| 동시성·지속성·재전송·프로세스 복구 | 다중 writer/worker HTTP, SIGKILL/restart, 실제 SQLite write-lock 503 | OS 정전·매체/backup 복구; 단일 PVC의 Pod 복구 실측은 아래 Kubernetes 행 참조 |
| 안전한 룰·두 사람 승인·예외·이력 | DSL 제한, 시험/승인/만료 재평가 + browser403 | 큰 룰/동일 action bounded workload 재평가 |
| 규정 출처→시스템→통제→증거→사람→과제 | 한국14/NIST4/EU2, 사례2, 인간 API·UI·stale/hash tests | 최종 한국 고시 일부, ISO 본문 미확보; 실제 법률 검토 |
| 최소수집·보존·정당한 파기 | source allowlist; v2 이벤트 암호화; 기간/hold/2인승인/재전송/파기4 HTTP tests | backup/export/물리매체 파기, legacy평문 migration, 인간문서 별도 보존 |
| 분산 분석·부하·backpressure | 실제 worker claim/lease/commit, bounded streaming, 1,000건 실측 모두 분석 | HPA 증감 관측 완료; 확장 중 처리량 개선·vault 순회/쓰기 병목 검증 필요 |
| TLS·Kubernetes 보안·실확장 | 전용3노드 배포·Service각60/60·HPA2→3→2·새Pod처리·수집/vault Pod재생성·515접수보존 | 부하8timeout·故장3실패, CNI packet귀속 미입증, 외부 LB·vault HA 미구현 |
| 한국어 인간 UI | 실제 브라우저 행동검색·출처/참조 대조·근거3개 선택·판단저장·보고서JSON/Markdown 다운로드·새증거 재검토 확인 | 보존 탭 전 과정의 최신 브라우저 검증, 접근성/소형 화면·다중 사용자 사용성 검증 |
| 감사자 판단과 사건 보고서 | HTTP5개·별도CLI·4종사본변조·기한/파기/늦은증거재검토; 실제 다운로드 서명·Markdown snapshot일치 | 운영SSO·사건별권한·검토예약/정족수·외부봉인·큰사건분할 운영기준 |

최신 사용자 우선순위(완제품 참고·사람이 판단할 행동/참고자료 가시성)를 반영해 `docs/product-reference.md`에 공식 제품5개를 비교하고, 행동 상세의 단계별 근거·참고자료 v1/v2·불확실성 및 자기보고/서비스 출처를 연결했다. 이는 실연동 완료가 아닌 합성 중립 계약과 실제 backend/UI 구현이다.

사전 성능 기준은 docs/validation-plan.md에 보존한다. 고도화 검증은 validation-2026-09-08T07-13-01-908Z.json의50PASS와 benchmark-2026-09-08T07-02-18-863Z.json에 기록했다. 조사함500ms간격조회 중1,000건 수집·분석, 조사함p95 315.53ms, 전체원장대조 단일사건보고서5회p95 137.29ms. Kubernetes 미검증을 로컬 테스트로 대체하지 않는다.

로드밸런싱 보강 후 선행 Windows 검증은 `reports/validation-2026-09-08T07-34-53-979Z.json`의67 PASS다. 이후 실제 배포로 발견한 준비 단계와 ConfigMap 진입점 결함을 수정했다. 최신 Windows 검사08:01 UTC는 listen EFAULT에 따른56 PASS/10 FAIL이며 별도 Linux 결과와 구분한다. [실제 배포 결과](../reports/kubernetes-runtime-20260908.md)와 [Kubernetes 검증 문서](kubernetes-load-balancing.md)에 관측·실패·한계를 기록했다.

Linux 최종 전체 회귀는 `reports/linux-validation/validation-2026-09-08T08-06-28-225Z.json`의70/70 PASS다. Node24.20.0·2CPU/1GiB·host mount/port 없는 독립 컨테이너이며 Windows24.15.0 실패 원자료도 유지한다.
