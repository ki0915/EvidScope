# 학습 시작 요청 후 실제 처리

사용자는 합성 데이터의 자동 검증만으로 실험 학습을 진행하는 대신, 사람이 주석한 공개 데이터를 먼저 확보하도록 선택했다. 기존 사람 검토 기준을 우회하거나 미검토 금융 정답을 검토 완료로 표시하지 않는다.

## 실행 환경 복구와 실측

Docker Desktop 4.80.0의 기동을 실제로 시도했다. backend 로그에서 `dockerInference`, 이어서 Secrets Engine `engine.sock`의 오래된 실행 소켓 접근 실패를 확인했다. 첫 소켓을 재생성한 뒤 두 번째 오류까지 진행된 사실로 두 오류를 구별했다. 개별 소켓 이름 변경도 실패해 Docker 프로세스가 종료된 상태에서 0바이트 소켓만 있는 실행 폴더를 백업 이름으로 보존했다. 삭제·factory reset·prune·디스크 초기화는 수행하지 않았다.

보존 위치는 `%LOCALAPPDATA%` 아래 다음과 같다.

- `Docker/run.evidscope-backup-20260922-141320`
- `docker-secrets-engine.evidscope-backup-20260922-141424`
- `Docker/run.evidscope-backup-20260922-141646`

복구 후 Docker Linux 엔진 29.6.1과 기존 `k3d-dlp` 노드의 Ready 상태를 확인했다. 기존 컨테이너·볼륨·Kubernetes 설정은 수정하지 않았다. Docker 시작 시 기존 restart 정책에 따라 다른 k3d 컨테이너도 시작되었으며, 진단 종료 후 Docker를 정상 종료해 초기 정지 상태로 복원했다. 남은 `docker-desktop` WSL 인스턴스도 종료했다. Ubuntu 등 다른 배포판에는 종료 명령을 보내지 않았다.

이미 설치된 Ollama 이미지에서 읽기 전용·네트워크 없음·호스트 마운트 없음·CPU 1개·RAM 256MiB 제한으로 `nvidia-smi`만 실행했다. RTX 3080 12288MiB를 확인했고, 모델을 적재하지 않았으며 컨테이너는 자동 제거됐다.

그러나 기존 Kubernetes 노드의 `nvidia.com/gpu` 할당 가능 수는 0이다. NVIDIA 장치 플러그인 DaemonSet도 없고 노드 컨테이너는 GPU DeviceRequests 없이 runc를 사용한다. Docker의 GPU 조회 성공은 Pod의 GPU 접근·격리 증거가 아니다. [k3d의 CUDA 문서](https://k3d.io/stable/usage/advanced/cuda/)도 노드 이미지와 NVIDIA 런타임, 장치 플러그인 구성을 요구한다. 오래된 문서의 WSL 제한을 현재 불가능성으로 단정하지 않는다.

Docker 실행 중 관측한 가용 RAM은 5.586GiB로 기존 시작 기준 18GiB보다 낮았다. GPU 메모리와 사용자 유휴 조건도 통과하지 않았다. 기존 작업을 중단하거나 호스트 시작 기준을 낮춰 학습을 강행하지 않았다. WDDM 프로세스 목록 수는 활성 ML 작업 수를 뜻하지 않는다.

재현 가능한 측정값은 [실행 시도 보고서](training-start-attempt-20260922.json)에 저장했다. 같은 종류의 소켓 장애는 [Docker 이슈 #448](https://github.com/docker/desktop-feedback/issues/448)과 [#625](https://github.com/docker/desktop-feedback/issues/625)에도 보고돼 있지만, 이 PC의 디스크 손상이나 한글 경로를 원인으로 확정한 것은 아니다.

## 데이터 작업

금융 합성 후보 중 156건의 의미 오류를 수정했다. 자동 처리에는 당시의 `approvalRequired:false` 정책을 넣고 승인 누락 경보를 요구하지 않는다. 지연 수신은 실행 전 승인 발급과 실행 후 수신을 구분한다. 540건·180가족을 유지하며 승인 상태를 변경하지 않았다. 관련 생성기·회귀 테스트 6개가 통과했다.

[공개 데이터 조사](training-data-sources-20260922.md)의 우선 대상은 KLUE-MRC v1.1이다. 한국어 질문·정답 위치와 답변 불가 주석을 보존해 근거 읽기 보조 학습에 사용한다. 원문 주석을 법률 적용 판단이나 금융 운영 충돌의 정답으로 재명명하지 않는다. 수집 산출물은 원본·고정 commit·해시·라이선스와 함께 `.local/public-training/`에 저장한다. 실제 확보 수와 검증 결과는 수집 manifest가 기준이다.

실제로 commit `3efd98708a40ff49251fddde35453f8fbb11f536`에서 원본 train 17,554건과 dev 5,841건을 확보했다. 공식 dev와 문서·지문 가족이 겹치는 train 4,149건을 제외했고, 나머지는 학습 12,060건·검증 1,345건으로 나눴다. 공식 dev 5,841건은 원문 정답을 유지한 평가 전용 자료다. Unicode 문자 기준 정답 위치, 답변 불가 표시, 중복 ID와 분할 누출을 검사했다. 질문·지문·정답을 새로 생성하거나 의역하지 않았다. 관련 공개 수집·금융 생성·학습 준비 테스트 총 10개가 통과했다.

원본과 정규화 JSONL, 변경 내역, 출처·CC BY-SA 4.0 표시는 `.local/public-training/klue-mrc/3efd98708a40ff49251fddde35453f8fbb11f536/manifest.json`에서 확인할 수 있다. 이는 한국어 근거 읽기 학습 후보 확보 결과이며, 개인정보 검토나 금융 감사 과제의 자유 서술 정답 검토를 완료했다는 뜻은 아니다.

## 아직 실행하지 않은 것

학습 이미지 빌드, 베이스 가중치 다운로드, GPU Pod 실행, optimizer step, adapter 생성은 수행하지 않았다. 공개 QA의 학습 형식 연결, GPU가 노출되는 Kubernetes 노드, 실제 격리·자원 파일럿, 현재 자원 조건을 충족해야 한다. 확보한 공개 사람 주석과 EvidScope 감사 과제의 검토·품질 승인은 별개다.
