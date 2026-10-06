# EvidScope 1차 구현 검증 보고서

검증일: 2026-09-12  
검증 환경: Windows 로컬 개발 환경, Node.js 테스트 및 정적 Kubernetes 구성 검사

## 판정

수집·가시성·거버넌스·조사·AI 검토실·격리 실행 경로·학습 자료 게이트·호스트 자원 보호까지 1차 코드와 합성 시험을 구현했다. 실제 Foundation-Sec 계열 모델 추론, CipherGuard 추론, Kubernetes Pod 실행, GPU QLoRA 학습은 수행하지 않았다. 모델은 기본 OFF이며 호스트 유휴 조건을 만족하기 전에는 학습 Job을 만들지 않는다.

## 자동 검증 결과

| 검증 | 결과 | 범위 |
|---|---:|---|
| 전체 회귀 시험 | 174/174 통과 | 로컬 HTTP/TLS/SQLite, 수집·감사·가시성·거버넌스·UI·격리 정책·학습 게이트 |
| 1차 기능 묶음 | 61/61 통과 | 신규 다국어·가시성·거버넌스·모델 런타임·학습 보호 기능 |
| UI 구문 검사 | 통과 | 기존 UI와 `team-support.js`, `console.js` |
| Kubernetes 정적 검사 | 통과 | 매니페스트 구조와 필수 보안 설정 |

전체 시험은 합성 서버와 주입한 실행기를 사용한다. 실제 모델 가중치, Docker, Kubernetes 클러스터 또는 외부 네트워크를 시작하지 않는다.

기계 판독 가능한 전체 실행 결과는 [`validation-2026-09-12T08-54-48-348Z.json`](validation-2026-09-12T08-54-48-348Z.json)에 보존했다. 실행 종료 뒤 프로젝트 포트 8080~8083·9080~9083·11434에서 listener가 없었고 Python·Ollama·llama-server·Docker·kubectl 프로세스도 없었다. 당시 GPU 값은 877/12,288MiB, 사용률 34%, 44°C였다. 해당 점검에서 EvidScope 모델은 발견되지 않았지만 다른 GPU 사용 주체나 Discord 종료 원인을 판정한 것은 아니다.

## 다른 컴퓨터 작업을 방해하지 않는 학습 보호

학습 시작 전 호스트 검사 기준은 다음과 같다.

- 마지막 사용자 입력 이후 900초 이상 유휴
- CPU 사용률 20% 이하
- 여유 메모리 18GiB 이상
- AC 전원 연결
- GPU 메모리 사용 1,024MiB 이하, GPU 사용률 10% 이하, 온도 80°C 이하
- 다른 Python·Ollama 계열 연산 프로세스 없음

학습 중에는 2초마다 다시 검사한다. 사용자 입력이 감지되거나, 여유 메모리가 8GiB 아래로 내려가거나, 전원·온도 조건이 깨지면 해당 실행이 만든 Job만 중단한다. 중단 후 최대 40회 확인해 작업이 사라지지 않으면 `TRAINING_STOP_UNCONFIRMED`로 실패 처리한다.

Kubernetes 학습 Job은 처음부터 `suspend: true`이고 낮은 우선순위와 `preemptionPolicy: Never`를 사용한다. CPU는 최대 2개, 메모리는 최대 12GiB, GPU 메모리 분율은 프로세스 수준에서 최대 0.65로 제한한다. CPU 스레드는 2개, 데이터 로더 worker는 0개이며 실행 기한은 1시간이다.

2026-09-12 실제 호스트 사전 검사에서는 다음 이유로 시작이 차단됐다.

```text
idleSeconds: 339
cpuPercent: 8.45
freeMemoryGiB: 18.813
onAcPower: true
gpuMemory: 657 / 12288 MiB
gpuUtilization: 36%
gpuTemperature: 55 C
computeProcessCount: 0
allowed: false
reasons: interactive_session_not_idle, gpu_busy
```

이 결과에서 학습 Job, 모델 서버, Pod는 생성되지 않았다. 같은 GPU를 공유하는 한 사용자 프로그램에 대한 지연을 수학적으로 0으로 보장할 수는 없다. 검사 대기 간격 2초 외에도 probe·Kubernetes 요청·Pod 종료 시간이 필요하므로 2초 안의 종료는 보장하지 않는다. 절대적인 비간섭이 필요하면 별도 PC 또는 전용 GPU 노드에서만 학습해야 한다.

2026-09-19 정정: 이 보고서 작성 당시 자원 보호 로직은 독립 모듈과 주입한 실행기의 시험 범위였으며 실제 Kubernetes 학습 CLI에는 연결되지 않았다. 실제 연결 및 현재 실행 가능 여부는 2026-09-19 학습 준비 결과에서 별도로 기록한다.

## 구현된 기능

- 로컬 SDK, HTTP, OTLP, Zeek 및 AI 연동 메타데이터를 정규화하고 원문을 중앙에 저장하지 않는다.
- 연동된 수집 지점에서만 프롬프트·응답을 일시 검사하며 언어 비율, 민감정보 범주, 검사 범위와 완료 상태만 전송한다.
- 등록되지 않은 AI, 권한 위반, 민감자료 외부 전송 의심, 인젝션 의심, 자료 버전 불일치, 비정상 호출량, 수집 중단, 중단 요청 이후 실행을 조사 신호로 제공한다.
- 한국 AI 기본법, EU AI Act, NIST AI RMF, ISO/IEC 42001 요구사항 후보와 증거를 연결하고 최종 적용 판단은 사람에게 남긴다.
- UI를 현황, AI 자산·수집, 탐색·조사, 거버넌스, AI 검토실, 운영·설정의 여섯 메뉴로 구성한다.
- Foundation-Sec 분석 모델과 CipherGuard 보조 분류기를 별도 Pod로 격리하며 비루트, 읽기 전용 루트 파일시스템, 권한 상승 금지, 서비스 계정 토큰 미탑재, 외부 연결 차단 정책을 둔다.
- 합성 다국어 평가 후보 540건과 CipherGuard 후보 180건을 만들었지만 모두 사람 미검토 상태로 표시해 학습에 사용할 수 없게 했다.

## 아직 검증되지 않은 항목

- Foundation-Sec-1.1-8B-Instruct와 Foundation-Sec-8B-Reasoning의 동일 자원 직접 비교
- CipherGuard V5의 한국어·영어·혼합 입력 실제 민감정보 분류 성능
- 모델 이미지 digest, SBOM, 취약점 검토와 CipherGuard revision 고정
- 실제 CNI egress 차단, 읽기 전용 파일시스템, 서비스 계정 토큰 미탑재의 클러스터 관측
- 검토된 학습 300건, 검증 50건, 시험 100건 확보와 QLoRA 실행
- 기본 모델 대비 목표 과제 5%p 이상 개선 및 영문 성능 저하 2%p 이하 확인

이 항목을 완료하기 전에는 학습 어댑터를 채택하거나 운영 모델로 승격하지 않는다.
