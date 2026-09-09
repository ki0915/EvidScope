# Docker 시작 오류: 검토 가능한 복구 범위

**실행 완료:** 사용자 승인 후2026-09-08 run 소켓 폴더와 추가로 관측된0바이트 engine.sock만 있는 임시 폴더를 백업 이름으로 보관했다. 마지막 시작에서 Docker Desktop4.80.0 / Engine29.6.1이 정상 응답했다. 삭제나 공장 초기화는 없었다. [실행·백업 위치 기록](../reports/docker-recovery-20260908.json), [이어진 Kubernetes 결과](../reports/kubernetes-runtime-20260908.md). 아래는 실행 이전의 검토 계획이다.

2026-09-08 관측: 정식 권한 검토 후 설치된 Docker Desktop4.80.0을 실행했지만 inference manager가 `%LOCALAPPDATA%\Docker\run\dockerInference`를 열거나 제거하지 못해 종료했다. 해당 run 디렉터리는 2026-07-16에 남은 0-byte ReparsePoint 세 개(dockerInference, dockerEthernetVfkit, userAnalyticsOtlpHttp.sock)만 표시했다. Docker 프로세스와 WSL Ubuntu/docker-desktop은 실행 중이 아니었다. 기존 kube context `k3d-dlp`는 EvidScope 소유가 아니므로 사용·변경하지 않았다.

동일 증상이 Docker 공식 GitHub 저장소의 사용자 이슈에 보고돼 있다. 이것은 이 컴퓨터의 원인이 확정됐다는 뜻이나 Docker가 모든 복구법을 보장한다는 뜻은 아니다. [시작 단계의 AF_UNIX endpoint 제거 실패 보고](https://github.com/docker/desktop-feedback/issues/531), [런타임 endpoint 오류 보고](https://github.com/docker/desktop-feedback/issues/625)

사용자 확인을 요청한 범위는 **공용 로컬 Docker 런타임 복구**다. 권한이 확인되기 전에는 설정 변경·socket 삭제·directory rename을 실행하지 않는다. 기본값이 읽기 전용인 `scripts/docker-runtime-recovery.ps1`을 준비했다. 적용 모드는 기존 runtime 폴더를 같은 Docker 부모 폴더 안의 timestamp backup으로 이름 변경하고 Docker Desktop을 다시 시작하는 구체적 한 단계다. 파일 삭제·factory reset·VM/disk/volume 삭제·기존 kube context 변경은 하지 않는다. 기본 runtime dir 외부 경로를 받지 않는다.

검증 순서: 실행 중인 Docker 프로세스가 없고 source가 예상된 일반 디렉터리이며 모든 자식이 관측한 0-byte socket인지 다시 확인 → 원래 폴더와 backup 경로가 같은 명시된 Docker 부모 아래인지 확인 → 중복 없는 이름 변경 → Hidden 시작 → 독립 `docker version` 확인. 결과를 본 뒤에만 EvidScope 전용 새 cluster 여부를 판단한다. 이전 폴더는 유지하며 임의 재귀 삭제를 수행하지 않는다.

PowerShell 실행 정책이 스크립트를 거부한 환경에서는 이를 우회하지 않는다. 이 문서는 아직 실행하지 않은 복구 계획이며 실제 성공이나 Kubernetes 검증 근거가 아니다.
