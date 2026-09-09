# Kubernetes 실제 실행 결과 — 2026-09-08

사용자 승인 후 Docker 임시 소켓 폴더를 이름 변경해 보관하고 Docker Desktop 4.80.0 / Engine 29.6.1을 복구했다. 기존 프로젝트의 컨테이너·볼륨·kubeconfig를 삭제하거나 바꾸지 않았다. 백업 위치와 환경은 [복구 기록](docker-recovery-20260908.json)에 있다.

전용 `evidscope-lab-20260908` 클러스터: k3d 5.9.0, Kubernetes 1.35.5+k3s1, 서버1·에이전트2, 노드별 메모리 상한2GiB, API는127.0.0.1:9645. 같은 Windows PC/WSL2의 컨테이너 노드이므로 물리 장애영역3개를 의미하지 않는다. core23개 리소스의 서버 dry-run, 이미지 빌드·로드, 실제 TLS 배포를 실행했다. 실험 자격과 kubeconfig는 `.local/k8s-lab-20260908`에 분리했다.

## 분산과 장애 관측

| 시험 | 실제 관측 | 판정 범위 |
|---|---|---|
| 준비 이후 수집 | 60/60 성공, Pod별27/33 | Service 경유 두 Pod 처리 확인 |
| 준비 이후 감사 | 60/60 성공, Pod별33/27 | 별도 감사 Service 경유 두 Pod 처리 확인 |
| 수집 Pod 종료 중300건 | 297성공, 503 1건·연결 거부2건, 남은 Pod247건 처리 | 무오류 시험 실패; 남은 Pod 처리와 성공접수 보존 확인 |
| 교체 이후 수집 | 60/60 성공, 기존 Pod28·새 Pod32 | 새 Pod가 실제 수집 처리 |
| vault Pod 종료·재생성 | 성공접수515건 모두 보존, 이전 signed checkpoint6453의 head가 새 원장에 그대로 포함 | 같은 PVC/노드의 Pod 복구 확인; 정전·노드 분실·스토리지 HA 시험 아님 |

원자료: [수집 정상](k8s-distribution-collector-prepared.json), [감사 정상](k8s-distribution-auditor-prepared.json), [장애 중](k8s-distribution-collector-fault.json), [교체 후](k8s-distribution-collector-recovered.json), [최종 독립 대조](k8s-reconciliation-after-vault-fault.json). 각 처리 Pod는 [시작 상태](k8s-cluster-before.json), [장애 상태](k8s-cluster-during-ingress-fault.json), [교체 상태](k8s-cluster-after-ingress-fault.json)의 UID·IP·노드·EndpointSlice와 대조했다. 독립 export의 port-forward는 서명·접수 대조용이며 분산 근거로 사용하지 않았다.

최초 Job 두 회차는 시작 직후 연결 거부가 발생했다. 수집50/60·48/60, 감사48/60·48/60으로 **실패**이며 [첫 수집](k8s-distribution-collector.json), [두 번째 수집](k8s-distribution-collector-stable.json) 등 원자료를 보존했다. 신규 client Pod의 네트워크 정책 반영 지연을 의심하지만 단일 원인으로 확정하지 않았다. 선택적30초 readiness 사전 확인을 추가하고 실패 시각·오류를 별도로 저장했다. 준비 완료 뒤 본측정은 재시도하지 않았다. 본측정 실패를 사전 확인으로 재분류하지 않는다.

성공접수515건은 모든 수집 회차에서202가 확인된 unique tenant/source/id 집합이다. 실패한25건은 성공으로 계산하지 않았으며, 원 요청 본문을 보관하지 않은 이 드라이버로 해당25건의 동일 본문 재전송은 수행하지 않았다. 수집 SDK의 durable outbox와 정확한 재전송 운영 검증은 남는다.

## 실제 HPA와 처리 용량

감사 읽기 트래픽을120초, 최대80회/초·동시성20으로 실행했다. 실제 dispatch는43.36회/초, 5,203건 시도, 5,195건 성공·3초 timeout8건, 전체 p95 778.57ms였다. 동시성 상한에 따른 대기 때문에 목표80회/초를 달성하지 못했고 `trafficCompletedWithoutErrors=false`다. [전체 부하 원자료](k8s-hpa-traffic.json).

동일 HPA UID에서 actual replica2→3, CPU74%/목표60%, lastScaleTime08:00:29Z를 확인했다. [부하 전](k8s-cluster-before-hpa.json), [확장 관측](k8s-cluster-hpa-sample1.json). replica나 CPU 임계값을 수동 변경하지 않았다. 새 Pod는 부하 중 아직 Ready가 아니어서 본 부하 응답은 기존 두 Pod에서만 관측됐다. 부하 종료 후 Ready가 된 세 번째 Pod를 포함해 **60/60 성공·3개 Pod 18/23/19건**을 확인했다. [Ready 상태](k8s-cluster-hpa-ready.json), [새 Pod 처리](k8s-distribution-auditor-scaled.json). 이후2개로 축소된 상태와08:03:44Z scale time도 [최종 상태](k8s-cluster-after-vault-fault.json)에 남았다.

따라서 자동 증감과 새 Pod 서비스 참여는 관측했지만, 확장 중 무오류·처리량 개선을 입증한 것은 아니다. 단일 vault의 쓰기·서명·조회 비용과 gateway 준비 지연을 별도 개선해야 한다.

## 네트워크 격리의 관측 한계

기본 거부와 수집자/감사자별 경로를 실제 시험했다. ConfigMap symlink 때문에 코드가 실행되지 않은 첫 회차는 빈 로그로 보존하고 통과로 계산하지 않았다. 수정 후 즉시 시작한 두 번째 회차도 초기 연결 거부로 실패했다.

준비5초 뒤 세 번째 회차에서는 collector→ingress와 auditor→audit가 각각3/3 TLS 검증200, 나머지7개 경로가 각각3회 연결 거부였다. Pod IP와 kube-router의 REJECT 정책 규칙 및 허용 대조군을 함께 기록했다. 다만 관측 중 패킷 counter 증가를 포착하지 못했으므로 개별 실패를 해당 규칙에 인과적으로 귀속하는 검증은 미완료다. 단순 ECONNREFUSED를 자동으로 격리 성공 처리하지 않으며 raw probe의 엄격한 pass=false를 유지한다. [수집자](k8s-network-collector-run3.json), [감사자](k8s-network-auditor-run3.json), [무라벨](k8s-network-unlabeled-run3.json).

## 남은 작업

외부 LoadBalancer/controller/DNS·조직 접근 경로, 저장소 HA·키관리, 노드·매체 장애, 운영 SSO와 공급자 실연동은 완료하지 않았다. 현재 서비스는 ClusterIP 내부 분산이다. cluster의 k3d serverlb는 Kubernetes API용이며 제품 외부 로드밸런서로 주장하지 않는다. 실험 클러스터와 합성 데이터는 보존했으며 자동 삭제하지 않는다.

Windows 최종 회귀는 [08:01 UTC 보고서](validation-2026-09-08T08-01-38-754Z.json)에서56 PASS/10 FAIL이다. 실패들은 `listen EFAULT`에 따른 서버 시작 실패이며 TLS 하위 시험 일부도 실행되지 않았다. 이전67 PASS를 최신 통과처럼 표시하지 않는다.

Linux 전용 컨테이너의 [08:06 UTC 전체 회귀](linux-validation/validation-2026-09-08T08-06-28-225Z.json)는 **70/70 PASS·0 FAIL·0 SKIP**, 35.82초, Kubernetes 정적 검사23리소스+2분산Job 및 UI 구문 통과다. [실행 환경](linux-validation/environment.json)은 host mount/port 없이 network none,2CPU/1GiB, 합성 테스트만 포함한다. Linux Node24.20.0과 Windows Node24.15.0의 버전 차이도 있어 EFAULT 원인을 OS만으로 확정하지 않는다.

검증용 port-forward는 종료했다. 전용 cluster는 보존됐고 최종 audit2/2·ingress2/2·worker2/2·vault1/1 Ready, 기존 기본 kube context는 k3d-dlp 그대로다.
