# 검증 현황 · 2026-10-06

[제품 소개](product-overview.md) · [GitHub 홈](../README.md)

## 버전과 시험을 분리해서 읽기

현재 소스의 `package.json`은 **0.1.2**다. 검증이 끝난 이전 **0.1.1 로컬 설치본**과 같은 상태로 취급하지 않는다. 아래는 저장된 실행 기록을 검토한 결과이며 이번 GitHub 문서 게시가 모든 실행·법령·모델을 다시 검증했다는 뜻은 아니다.

| 대상 | 결과 | 원본 근거 |
|---|---|---|
| v0.1.1 설치본 전체 회귀 | 758/758 통과 | [실제 설치 로그](../reports/security-release-install-regression-r2-retry-ipv6-20261006.log) |
| v0.1.1 반복 실행 | 10회·각 39개 통과 | [반복 검증 JSON](../reports/security-release-20261006-r2-retry/verification.json) |
| v0.1.1 Linux 이미지 | 39/39 통과 | [컨테이너 로그](../reports/security-release-container-r2-20261006.log) |
| 최근 소스 전체 회귀 기록 | 836/836, 실패 0 | [소스 로그](../reports/source-full-continuation-r3-final-20261006.log) |
| v0.1.2 반복 실행 | 10회 요청·9회 실행·8회 통과, `passed:false` | [원본 JSON](../reports/release-012-20261006/verification.json) |
| v0.1.2 9회차 | 117/119, 2개 실패 | [실패 로그](../reports/release-012-20261006/round-09.log), [조사와 집중 2/2 재검증](../reports/release-012-round09-diagnosis-20261006.md) |

KR33 실패는 합성 fixture의 관측 시간이 수신 시각보다 3ms 미래였던 문제로, fixture를 수정했고 제품의 시간 검증을 완화하지 않았다. 권한 시험의 `fetch failed`는 원인이 확정되지 않았으며 진단을 보강했다. 집중 재검증 통과를 전체 10회 반복 완료로 계산하지 않는다.

## 이번 공개 준비에서 다시 확인한 범위

2026-10-06 게시 준비 중 Node.js 24.15.0·Windows·IPv6 loopback에서 README의 핵심 7개 테스트 파일을 실행해 **53/53 통과**, 실패·취소·skip 0을 확인했다. 원장/영수증 무결성, 거버넌스 변경 권한, 잘못된 금융 참조, 한국법 HTTP, 문서 보관, 백업·복구 경로다. [실제 호스트 로그](../reports/publication-core-tests-host-20261006.log).

첫 sandbox 실행은 임시 경로의 파일 rename `EPERM` 등 실행 오류로 실패했다. 제품 코드를 바꾸지 않고 같은 검사를 실제 호스트에서 재실행했다. [최초 실패 로그](../reports/publication-core-tests-sandbox-20261006.log)를 보존하며 OS 차원의 근본 원인을 확정한 것으로 보지 않는다.

주요 5개 Markdown의 로컬 파일 링크 128개가 존재함을 확인했고, SVG 2개를 실제 PNG로 렌더링해 배치를 검토했다. 별도 검토자가 기능·결과 표현을 확인했으며, 전용 구현 근거가 부족한 OpenInference 지원 표현과 `unknown` 상태 설명을 수정했다. Claude가 README 초안을 작성하고 Codex가 코드·실행 근거로 교정·확장했다.

이 집중 검사는 전체 소스 회귀, v0.1.2의 10회 반복, 모델 생성 평가 또는 실제 기관 연동을 대신하지 않는다.

## 성능

[2026-10-05 원본 벤치마크](../reports/benchmark-2026-10-05T06-29-04-501Z.json)는 i7-12700F·RAM 32GiB·Windows·로컬 SQLite WAL·1 writer·2 workers에서 합성 이벤트를 처리한 결과다.

| 구간 | 접수 / 생성 | 관측 처리량 | 요청 p95 |
|---|---:|---:|---:|
| Normal | 200 / 200 | 20.08 EPS | 15.07 ms |
| Burst | 200 / 200 | 158.34 EPS | 156.15 ms |
| Sustained | 600 / 600 | 19.86 EPS | 206.81 ms |

최종 backlog 0, peak backlog 181, Vault RSS 약 139MiB. 조사함 검색 p95 362.52ms, 단일 사건 서명 보고서 p95 239.46ms. 독립 호스트·원격 저장소·실제 금융 고객 트래픽·운영 SLA의 증거는 아니다. [개선 구현과 이전 실패](../reports/enterprise-incremental-integrity-performance-20261005.md)를 함께 확인한다.

## 모델 학습과 품질

- [후속 학습 검증](../reports/public-qa-grounding-continuation-verification-20261006.json): 공개 인간 주석 QA, 이번 optimizer 20회, adapter 계보 누적 80회. 실행·산출물 검증과 `qualityClaimAllowed:false`, `promotionAllowed:false`를 함께 보존한다.
- [앞선 64문항 비교](../reports/public-qa-grounding-comparison-20261006-r4.json): 엄격 통과 16→25/64, 답변 가능 문항 12→9/32, 답변 불가능 문항 4→16/32. 같은 관측 세트의 진단이며 최신 80회 후보 결과가 아니다.
- [회귀 분석](../reports/public-qa-grounding-continuation-analysis-20261006.md): 과도한 기권과 입력 길이 분포를 분석했지만 원인 가설의 인과를 확정하지 않았다.
- [새 평가 준비](../reports/public-qa-fresh-evaluation-preparation-20261006.json): 준비·데이터 분리·runner 구현은 생성 평가 완료와 다르다. 공개 근거에서 새 평가의 완료를 확인하지 못했다.

합성 금융 fixture는 사람 검토가 완료된 학습 데이터로 취급하지 않는다. 모델 가중치, 원본 학습 캐시, 자격, 키, DB는 공개 저장소에서 제외한다.

## 공개 범위와 재현

소스·합성 fixture·문서·검증 보고서·시험 로그를 공개한다. 과거 로그에는 개발 PC 경로, 로컬 실험 식별자와 실패 기록이 포함될 수 있다. `.local/`, `.test-runs/`, `.planning/`, `releases/`, 모델 가중치와 자격 파일은 포함하지 않는다. 따라서 과거 문서의 로컬 경로는 공개 다운로드 링크가 아니다.

이 저장소의 공개는 소스 공개를 뜻하며 npm 배포나 모델 가중치 재배포를 뜻하지 않는다. `private:true`와 `UNLICENSED`는 그대로 유지한다. 별도 오픈소스 라이선스가 부여되었다고 해석하지 않는다.

```powershell
npm ci --ignore-scripts --no-audit --no-fund
# Windows IPv4 loopback 문제가 있는 환경에서만 선택
$env:EVIDSCOPE_TEST_HOST='::1'
npm test
```

전체 연구 테스트 중 일부는 공개하지 않는 로컬 모델 잠금·과거 학습 영수증에 의존한다. 새 clone의 기본 전체 테스트와 과거 동결 설치본 테스트는 범위가 다를 수 있다. 실제 테스트 오류는 숨기지 않으며, 첫 확인에는 [README의 핵심 경로 검사](../README.md#검증)를 사용할 수 있다.
