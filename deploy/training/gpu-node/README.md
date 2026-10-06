# 별도 WSL GPU 학습 노드

`k3d-dlp`를 수정하지 않고 `evidscope-training` 단일 서버 클러스터를 만든다. `create.ps1`은 기본 kubeconfig를 병합하거나 현재 컨텍스트를 전환하지 않는다. 실행 후 `.test-runs/evidscope-training/kubeconfig.yaml`을 모든 kubectl 호출에 명시한다. 이 파일은 로컬 관리자 자격 증명이라 저장소나 보고서에 포함하지 않는다.

노드에는 NVIDIA Container Toolkit만 설치한다. WSL에서 Linux NVIDIA 커널 드라이버를 설치하지 않는다. CUDA 이미지, K3s 이미지, device plugin의 레지스트리 digest를 확인해서 고정한다. 노드 이미지의 Docker ID와 빌드 로그도 보존한다. 단일 노드 메모리 상한 14GiB는 12GiB 학습 컨테이너와 제어 평면 여유를 위한 상한이며, 실제 메모리 예약이나 학습 시작 허가가 아니다.

```powershell
docker build --build-arg K3S_IMAGE=rancher/k3s@sha256:2074403abe1bded11ef3dde09d457e13be8e0b64c218b1c4f8269b4565cfbc65 --build-arg CUDA_IMAGE=nvidia/cuda@sha256:8767a245ed2c481eb245d8f6c625accc3788e1fb8612403d6b4cd4645a4f09c7 -t evidscope/k3s-gpu:20260922 deploy/training/gpu-node
& deploy/training/gpu-node/create.ps1 -K3dPath (Get-Command k3d -ErrorAction Stop).Source -NodeImage evidscope/k3s-gpu:20260922 -DevicePluginImage nvcr.io/nvidia/k8s-device-plugin@sha256:8bb7d27a144e0e7e4b2ca598400d32714d12f701ce53accf5c596e0e186c6ae5
```

실제 GPU Pod에는 `runtimeClassName: nvidia`와 `nvidia.com/gpu: 1` 요청/상한이 모두 필요하다. node allocatable=1은 CUDA 연산·네트워크 격리·메모리 적합성 증거를 대신하지 않는다. GPU는 WSL 호스트와 공유하므로 물리적 독점 사용도 아니다. 정식 학습의 별도 데이터·아티팩트·리소스·격리 검증을 유지한다.

현재 컴퓨터에서 legacy 런타임은 노드의 `nvidia-smi`가 성공해도 Pod에 `libdxcore.so`를 전달하지 않아 NVML 초기화가 실패했다. `configure-wsl-cdi.ps1`이 새 학습 노드에만 CDI 모드를 설정하고 이 라이브러리의 읽기전용 마운트를 보완한다. WSL이 생성한 `all` 장치에 실제 조회한 단일 GPU UUID와 index 0 별칭을 붙인다. GPU가 여러 개이면 실행을 거부한다. 수정 후 GPU 자원 1개 등록과 비루트·읽기전용 Pod에서 요청 GPU 1개의 `nvidia-smi` 성공을 확인했다. 이는 실제 CUDA 학습 및 네트워크 차단 시험과 별도이다. [동일한 NVIDIA 공개 이슈](https://github.com/NVIDIA/OpenShell/issues/404).

근거: [k3d CUDA 노드 구성](https://k3d.io/v5.8.3/usage/advanced/cuda/), [K3s 런타임 자동 탐지](https://docs.k3s.io/advanced#nvidia-container-runtime), [NVIDIA Toolkit 설치](https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/install-guide.html), [공식 device plugin v0.17.1 WSL 구현](https://github.com/NVIDIA/k8s-device-plugin/blob/v0.17.1/internal/rm/wsl_devices.go), [WSL CUDA 제약](https://docs.nvidia.com/cuda/wsl-user-guide/). WSL은 일부 NVML 조회와 pinned/unified memory에 제약이 있으므로 Windows 작업 목록을 실행 중인 CUDA 작업으로 단정하지 않는다.
