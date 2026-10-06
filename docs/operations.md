# EvidScope 실행·배포·복구

2026-10-06 v0.1.0의 출시 계약은 [1차 파일럿 안내](first-release-20261006.md)를 따른다. 로컬 배포본과 실행 절차를 제공하며, 아래 Kubernetes 기록은 별도 과거 실험이다. 새 파일럿에는 기존 `.local` 자격·개인키·DB를 복사하지 않고 고유한 자격과 키를 생성한다. 기존 데이터의 업그레이드·복구는 원본 경로를 보존하고 독립 백업을 검증한 뒤 진행한다. 모델·GPU·학습 워커는 기본 OFF이며 로컬 실행 명령으로 켜지지 않는다.

검증 상태: 사용자 승인 후 Docker를 복구하고 별도 evidscope-lab-20260908 클러스터에 이미지 빌드·배포, Service 분산, HPA 자동 증감, Pod 복구 시험을 실행했다. 기존 kube context k3d-dlp는 사용하거나 바꾸지 않았다. [실행 원자료와 실패·한계](../reports/kubernetes-runtime-20260908.md)를 확인한다. CNI 규칙과 거부 응답은 관측했지만 개별 패킷 귀속 검증은 미완료다. `Static` 성공은 실배포 성공을 뜻하지 않는다.

현재 로드밸런싱 패키지는 `/readyz` 의존성 검사, 두 노드 이상 topology spread, 무중단 갱신 목표, 실제 처리 Pod별 분산 probe를 포함한다. [로드밸런싱 검증 절차](kubernetes-load-balancing.md)를 함께 따른다. ClusterIP 내부 분산과 외부 LoadBalancer 제공자, 단일 vault 저장소의 고가용성은 별도 범위다.

2026-09-08 실제 실행: 기본 manifest 오프라인 검사 exit 0, 부하 드라이버 구문 검사 exit 0. 부하 드라이버를 독립적인 loopback vault/ingress/audit 프로세스에 연결한 smoke에서 source 3개·6건 접수 성공, 오류 0, 감사 조회 1회 성공, 접수 p95 53.04 ms를 관측했다(exit 0). 이는 6건의 기능 smoke이며 용량·Kubernetes·TLS 측정이 아니다. 최초 시험 harness는 Node fork의 `--input-type` 상속 때문에 exit 1이었으며 상속 옵션을 제거한 뒤 실행했다.

## 실행 구조와 보안 경계

Node.js 24의 SQLite를 사용한다. `vault` 1개만 원본 DB, 인증 설정, 서명 개인키를 갖는다. `ingress`는 수집 전용 HTTP 경로만 전달하고 `audit`는 인간 감사 경로를 전달한다. 양쪽은 요청자의 인증을 vault에서 다시 확인한다. `worker`는 분석 권한만 가진 별도 토큰으로 vault에 작업을 요청한다. 서비스별 파일시스템·자격증명·HTTP 경로를 분리한다.

| 컴포넌트 | replica | 연결·소유 상태 |
|---|---:|---|
| vault | 1, Recreate | SQLite RWO PVC, 인증 설정, 서명키, 자체 TLS 키 |
| ingress | 2~6 HPA | 수집자 → ingress → vault, 자체 TLS 키·vault 신뢰 CA |
| audit | 2~6 HPA | 감사자 → audit → vault, 자체 TLS 키·vault 신뢰 CA |
| worker | 2~6 HPA | worker → vault, 작업자 토큰·자체 TLS 키·vault 신뢰 CA |

TLS는 애플리케이션에서 종료한다. Node의 CA/호스트명 검증을 유지하며 `NODE_TLS_REJECT_UNAUTHORIZED=0`을 사용하지 않는다. Kubernetes의 HTTPS health probe는 애플리케이션의 실제 클라이언트 인증서 검증 시험을 대신하지 않는다. 모든 컨테이너는 UID/GID 1000, 읽기 전용 root filesystem, 모든 capability 제거, privilege escalation 금지, RuntimeDefault seccomp로 실행하고 service account token을 자동 마운트하지 않는다.

NetworkPolicy는 ingress/egress 기본 거부에서 시작하여 gateway/worker의 vault 연결 및 DNS만 연다. 동일 namespace의 `evidscope.io/client=collector` Pod는 ingress, `evidscope.io/client=auditor` Pod는 audit에 접근할 수 있다. 이 라벨은 네트워크 경계일 뿐 서비스 인증을 대체하지 않는다. workload 생성·라벨 수정 권한은 신뢰하는 운영자에게만 둬야 한다. 일반 외부 Ingress/LoadBalancer는 생성하지 않는다. 실제 조직의 승인된 ingress controller/접근 프록시에 대해서는 해당 namespace+Pod selector만 추가한다.

기본 DNS 허용은 `kube-system`, `k8s-app=kube-dns`를 가정한다. NodeLocal DNS나 다른 CNI/DNS 구성이면 실제 목적지에 한정하여 조정하고 차단 시험을 다시 수행한다. NetworkPolicy를 집행하는 CNI가 없으면 정책 파일이 있어도 경계가 성립하지 않는다. [Kubernetes NetworkPolicy](https://kubernetes.io/docs/concepts/services-networking/network-policies/) 문서 확인일: 2026-09-08.

## 로컬 실행

v0.1.0 배포 ZIP에는 고정한 node_modules가 포함된다. ZIP 설치는 바로 `npm start`를 사용하며, 아래 `npm ci`는 소스에서 의존성을 새로 설치할 때만 실행한다. 로컬 실행기는 HTTP 전용이며 TLS 환경 변수가 설정되어 있으면 별도 TLS 배포 경로를 안내하고 시작을 거부한다.

프로젝트 root에서 Node.js 24.15 이상 25 미만을 사용한다. `openid-client` 6.8.8과 전이 의존성은 `package-lock.json`에 고정되어 있으므로 먼저 설치한다. 폐쇄망에서는 승인한 동일 잠금 파일의 의존성 묶음과 Node 런타임을 제공하고 설치·검증한다.

```powershell
npm ci --ignore-scripts --no-audit --no-fund
npm run init
npm start
# 별도 터미널
npm run demo
npm test
npm run bench
node scripts/k8s-static.mjs
```

이 PC에서 IPv4 loopback 오류가 발생하면 시작 전 `$env:EVIDSCOPE_LOCAL_HOST='::1'`을 설정한다. 감사 URL은 `http://[::1]:8082`다. `EVIDSCOPE_LOCAL_DIR`로 별도 파일럿의 자격·키·데이터 경로를, `EVIDSCOPE_LOCAL_PORT_BASE`로 기본 8080부터 시작하는 네 포트를 선택한다. 기본 데이터 경로는 `.local`이며 기존 경로의 데이터를 덮어쓰거나 초기화하지 않는다. 포트 기준 `0`은 시험용 자동 할당으로 일반 사용 안내에 고정 URL을 재사용하지 않는다. 종료는 실행 터미널의 `Ctrl+C`를 사용하고 네 자식 프로세스가 종료된 뒤 재시작한다.

개발용 loopback HTTP와 합성 자격증명은 통제된 파일럿용이다. 외부 네트워크에 노출할 때는 검증된 TLS 인증서와 조직별 인증·접근 통제가 필요하다. Docker 빌드 컨텍스트는 명시한 소스·정적 화면·catalog·역할 자료·잠금 파일과 제한된 배포 보조 스크립트만 허용하며 로컬 DB·키를 제외한다. `.local` 데이터나 인증 정보를 이미지에 포함하지 않는다. Docker 이미지는 구성요소 서버 실행용이며 초기화·검증·백업 CLI는 함께 제공한 소스 배포본에서 실행한다. 이미지 하나로 네 구성요소와 자격 초기화가 자동으로 준비되었다고 간주하지 않는다.

## 개인 실험 클러스터 준비

요구 환경: Linux worker node, PVC를 provision하는 기본 StorageClass, NetworkPolicy 집행 CNI, CPU metrics API를 제공하는 metrics-server, Node24 이미지를 실행할 수 있는 런타임. HPA는 실제 CPU utilization을 CPU request와 비교하므로 request가 있어야 하며, API가 없거나 수집이 실패하면 확장 결과를 확인할 수 없다. [Kubernetes HPA](https://kubernetes.io/docs/concepts/workloads/autoscaling/horizontal-pod-autoscale/) 확인일: 2026-09-08.

`deploy/kubernetes.json`은 `v1/List` 형식으로 `kubectl apply -f`가 읽는다. 기본 namespace는 `evidscope`다. `node deploy/render-manifests.mjs`로 같은 구성을 재생성한다. 운영 이미지는 테스트한 digest로 고정하고 취약점/공급망 검토 후 배포한다. Dockerfile은 Node24.15.0-bookworm-slim 공식 index digest를 고정하고 잠금 npm 의존성을 설치한다. 배포의 `evidscope:local` 태그는 여전히 실험 프로파일이며 완성 이미지 검증·운영 승격을 대신하지 않는다. [OIDC 전송·네트워크 정책 요구](oidc-authentication.md)를 함께 적용한다.

예시는 이미 별도 승인된 개인 클러스터를 전제로 한다. 아래 context 값을 실제 실험 context로 바꾸고 사전에 소유권과 비용을 확인한다. 이 문서와 스크립트는 클러스터나 metrics-server를 설치하지 않는다.

```powershell
$labContext = 'YOUR-EXPLICIT-LOCAL-LAB-CONTEXT'
docker build -t evidscope:local .
# kind 사용자는 본인의 실험 클러스터 이름에 맞춰 이미지를 로드한다.
# kind load docker-image evidscope:local --name YOUR-LAB
kubectl --context $labContext create namespace evidscope
```

다음 민감 파일을 보호된 로컬 디렉터리에 준비한다. 저장소에 커밋하지 않는다. 초기화 산출물을 사용할 경우 실험용 tenant/source/human/worker의 역할을 먼저 확인한다. 운영 키와 고객 데이터는 실험에 넣지 않는다.

* `config.json`: vault가 읽는 검증된 principal 설정. source 제출 권한, tenant, source 유형, 인간 역할, worker identity를 구분한다.
* `signing-private.pem`: vault의 Ed25519 개인키. 대응 공개키와 trusted checkpoint는 export와 독립된 감사자 저장소에 전달한다.
* `worker-token.txt`: config에 등록된 worker의 원시 토큰만 담은 파일. 줄바꿈을 추가하지 않는다.
* `ca.crt`: TLS 발급 CA 공개 인증서.
* `vault.crt`/`vault.key`, `ingress.crt`/`ingress.key`, `audit.crt`/`audit.key`, `worker.crt`/`worker.key`: 서로 다른 TLS 키. vault 인증서 SAN에 `vault.evidscope.svc`를 포함한다. 감사·수집 service DNS와 port-forward 시험의 `localhost`를 각 해당 인증서 SAN에 포함한다. 조직 PKI 또는 개인 실험 PKI를 사용한다. CA 개인키는 Pod에 마운트하지 않는다.

```powershell
$secretRoot = 'C:\YOUR-PROTECTED-LAB-SECRETS'
kubectl --context $labContext -n evidscope create secret generic vault-config --from-file="config.json=$secretRoot\config.json"
kubectl --context $labContext -n evidscope create secret generic vault-signing --from-file="signing-private.pem=$secretRoot\signing-private.pem"
kubectl --context $labContext -n evidscope create secret generic worker-identity --from-file="token=$secretRoot\worker-token.txt"
kubectl --context $labContext -n evidscope create secret generic vault-ca --from-file="ca.crt=$secretRoot\ca.crt"
foreach ($component in @('vault','ingress','audit','worker')) {
    kubectl --context $labContext -n evidscope create secret tls "$component-tls" --cert="$secretRoot\$component.crt" --key="$secretRoot\$component.key"
    if ($LASTEXITCODE -ne 0) { throw "TLS secret creation failed: $component" }
}
powershell -NoProfile -File scripts/k8s-validate.ps1 -Action ServerValidate -Context $labContext
powershell -NoProfile -File scripts/k8s-validate.ps1 -Action Deploy -Context $labContext -LocalLab
kubectl --context $labContext -n evidscope get pods,pvc,svc,hpa,pdb,networkpolicy
```

이미 존재하는 Secret에는 `create`가 실패한다. 기존 값을 덮어쓰지 말고 소유자와 rotation 절차를 확인한다. `ServerValidate`는 API server에 dry-run을 전송하지만 실제 Pod 실행을 시험하지 않는다. `Deploy`는 namespace와 workload를 변경한다. 각 모드에서 명령 실패는 비정상 exit code로 보고된다.

감사 UI와 수집 API를 로컬에서 시험할 때 각각 터미널을 사용한다. port-forward는 CNI 네트워크 정책 시험이 아니며, Kubernetes 권한을 가진 운영자만 사용할 수 있어야 한다.

```powershell
kubectl --context $labContext -n evidscope port-forward service/audit 8082:8080
kubectl --context $labContext -n evidscope port-forward service/ingress 8081:8080
# 인증서를 검증하는 클라이언트에서 https://localhost:8082 로 접속한다.
# Node 부하 클라이언트에는 필요시 NODE_EXTRA_CA_CERTS=$secretRoot\ca.crt 를 설정한다.
```

## 부하·자동 확장·복구 검증

`scripts/k8s-load.mjs`는 서버를 시작하지 않는 원격 HTTPS 부하 드라이버다. collector 설정에는 `role=source`인 principal만, audit observer 설정에는 인간 principal만 포함해야 한다. 이 검증은 코드에서 강제하며 `vault-config`를 재사용하지 않는다. API 인증 토큰/HMAC secret은 결과 JSON에 출력하지 않는다. 기본 collector는 3개 source·20 EPS·30초이며 전체 원본/분석 수는 별도 audit observer 및 export와 대조한다. 응답이 끊기면 저장 성공 여부가 불명확할 수 있어 해당 outcome을 `ambiguousReceipt`로 보존한다. 자동 retry는 없으며 Pod 장애 시험에서의 timeout을 성공 접수로 계산하지 않는다.

개인 실험 cluster에 구성요소 배포가 끝난 뒤, 각각 `principals` 배열만 가진 collector와 auditor 전용 설정을 만든다. 전자는 source 3개, 후자는 인간 auditor 1개면 된다. 서버 vault 설정에 등록한 동일 identity를 사용하되 최소 권한만 복사한다.

```powershell
kubectl --context $labContext -n evidscope create secret generic load-collector-config --from-file="config.json=$secretRoot\collector-config.json"
kubectl --context $labContext -n evidscope create secret generic load-auditor-config --from-file="config.json=$secretRoot\auditor-config.json"
kubectl --context $labContext apply --dry-run=server -f deploy/load-jobs.json
kubectl --context $labContext apply -f deploy/load-jobs.json
kubectl --context $labContext -n evidscope wait --for=condition=complete job/load-collector job/load-auditor --timeout=180s
New-Item -ItemType Directory -Force -Path deploy/reports | Out-Null
kubectl --context $labContext -n evidscope logs job/load-collector | Set-Content -Encoding UTF8 deploy/reports/collector.json
kubectl --context $labContext -n evidscope logs job/load-auditor | Set-Content -Encoding UTF8 deploy/reports/auditor.json
```

각 Job의 부하는 `deploy/load-jobs.json`의 EPS/TOTAL/DURATION_SECONDS/CONCURRENCY 환경 값으로 바꾼다. 급증은 `TOTAL=200`, `EPS=10000`, `CONCURRENCY=20`으로 설정한다. 정상은 20 EPS·10초, 지속은 20 EPS·30초로 구분한다. Job 이름은 매 회차 별도로 바꿔 결과와 혼동하지 않으며 실행 중 Job을 덮어쓰지 않는다. 원격 프로세스가 있는 별도 환경에서는 동일 env로 `node scripts/k8s-load.mjs`를 직접 실행하고 `REPORT_FILE=deploy/reports/run.json`에 저장할 수도 있다. 결과 파일은 git에서 제외한다. Job 실패의 stderr/exit code는 `kubectl logs`와 Pod termination 상태에서 확인한다. 이 드라이버의 준비·구문 검사는 실제 TLS·CNI·자동 확장 합격을 의미하지 않는다.

사전 합격 기준은 `docs/validation-plan.md`에 있다. 로컬 벤치마크 결과를 Kubernetes 결과로 재사용하지 않는다. 실제 클러스터용 부하 실행은 수집자 라벨을 가진 Pod에서 HTTPS ingress service를 통해 수행해야 CNI·Service·다중 replica를 함께 검증할 수 있다. 브라우저와 독립된 감사자 클라이언트도 audit 경로로 조회한다. exporter가 생성/시도/성공/오류·source sequence를 외부 파일에 기록하고 감사 측에서 원본/검색/분석 수와 대조해야 한다. 서버 성공 응답은 source 측 중복 ID와 함께 보존한다.

먼저 정상 20 EPS 10초, 동시성 20의 200건 급증, 20 EPS 30초 지속 부하를 동일한 합성 source 3개 및 약 1 KiB 이벤트로 실행한다. 측정은 생성/시도/접수 unique/중복/오류, p50/p95/p99, 원본 수, 분석 수, 최종 backlog, CPU/RSS/PVC 지표를 함께 기록한다. 보장 범위는 실제 이벤트 크기·룰 수·tenant/source 수·조회 동시성·노드·스토리지 유형과 함께 보고한다.

```powershell
# 부하를 주는 별도 터미널과 동시에 실행한다. metrics API 미제공 시 실패한다.
powershell -NoProfile -File scripts/k8s-validate.ps1 -Action Observe -Context $labContext -Samples 36 -IntervalSeconds 10
kubectl --context $labContext -n evidscope describe hpa
kubectl --context $labContext -n evidscope top pods
kubectl --context $labContext -n evidscope get events --sort-by=.metadata.creationTimestamp
```

HPA 확인은 정상 부하 뒤 rate/concurrency를 단계적으로 증가시켜 충분한 CPU 관측 기간을 둔다. 예: 20→100→200 EPS를 각 3분, 총량과 비용 상한은 실행 전에 정한다. 최소 한 stateless 구성요소의 actual replica가 2에서 3 이상으로 증가하고 새 Pod가 Ready 상태로 트래픽을 처리해야 확장을 확인한 것이다. CPU가 기준에 미달하면 HPA 미발동을 기록한다. 낮은 부하에서 복제 수가 유지된 사실을 확장 검증으로 보고하지 않는다. vault에 응답 지연/CPU/I/O가 집중되면 frontend replica를 늘려도 처리량이 개선되지 않을 수 있다. worker의 실행은 vault DB에 집중되므로 worker CPU HPA가 분석 backlog에 민감하다고 보장하지 않는다.

승인된 실험에서 부하를 유지한 채 한 번에 장애 하나를 주입한다.

```powershell
powershell -NoProfile -File scripts/k8s-validate.ps1 -Action KillIngress -Context $labContext -LocalLab -AllowFailureDrill
powershell -NoProfile -File scripts/k8s-validate.ps1 -Action KillVault -Context $labContext -LocalLab -AllowFailureDrill
# 별도 회차: vault 서비스 전체를 일시 중지하고 source의 실패/재전송 수를 기록한다.
powershell -NoProfile -File scripts/k8s-validate.ps1 -Action HaltVault -Context $labContext -LocalLab -AllowFailureDrill
powershell -NoProfile -File scripts/k8s-validate.ps1 -Action ResumeVault -Context $labContext -LocalLab -AllowFailureDrill
```

Pod 종료는 1초 grace period를 사용한다. `HaltVault`는 서비스 중단 시험이며, 실제 저장장치 I/O 실패나 power loss 시험이 아니다. 디스크 오류 주입은 스토리지/CSI마다 별도 승인된 disposable volume 실험이 필요하며 아직 제공·실행하지 않았다. 각 회차 뒤 성공 접수한 모든 unique ID가 남는지, retry가 중복 원본을 만들지 않는지, 분석 backlog가 회복되는지, 이전 export/checkpoint 검증이 유효한지, tenant·producer의 접근 거부가 유지되는지 확인한다. Pod Ready만으로 데이터 복구 합격을 선언하지 않는다.

네트워크 시험은 동일 namespace에서 승인된 collector/auditor Pod와 무라벨 Pod를 각각 실행하여 ingress/audit/vault 직접 접근의 예상 허용/거부 행렬을 측정한다. collector→ingress만 허용, collector→audit/vault 거부, auditor→audit만 허용, 무라벨→모든 서비스 거부가 기준이다. 각 Pod는 서로의 token/key를 갖지 않아야 한다. 실패 연결 timeout과 HTTP 401/403은 각각 네트워크 차단과 애플리케이션 인증 거부로 구분한다. node-origin traffic 및 관리자 port-forward/exec는 이 일반 NetworkPolicy 보장 범위 밖이다.

## 백업·보존·운영 한계

SQLite vault는 단일 쓰기·저장 병목이자 단일 장애 지점이다. RWO는 클러스터 관리자나 동일 노드 침해에 대한 불변 저장 보장이 아니다. `Recreate` 갱신·노드 장애·PVC 재연결 동안 수집과 감사가 중단될 수 있다. PDB `minAvailable: 1`은 자발적 eviction을 제한하지만 단일 vault 고가용성이나 직접 Pod 삭제 방지를 제공하지 않는다. 유지보수 drain은 이 PDB에 막힐 수 있으므로 계획된 중단과 복구를 사전 승인해야 한다. [PDB 문서](https://kubernetes.io/docs/tasks/run-application/configure-pdb/) 확인일: 2026-09-08.

로컬 SQLite backup API를 사용하는 [증적 백업·복구 도구](vault-recovery.md)를 제공한다. 실행 중인 DB의 일관된 snapshot과 과거 공급사 문서를 암호화 백업하고, 별도 공개키·anchor와 대조해 새 디렉터리에 복원한다. 실제 HTTP 복구와 테넌트 접근 검증을 수행했다. 운영 복원은 별도 namespace/volume에서 먼저 실증해야 한다. 실행 중인 DB 파일 하나만 복사한 것을 일관된 백업이라고 간주하지 않는다. 자동 CSI snapshot/원격 backup/KMS/WORM/외부 checkpoint 보관 연동은 미구현이다. 원본 DB, 개인키, trusted checkpoint를 함께 침해한 관리자는 이 로컬 보장을 넘어선다.

Secret은 Kubernetes API에 저장된다. etcd encryption at rest, Secret RBAC, node 접근 통제, 키 rotation, 원격 불변 archive는 운영자가 별도 구성·검증해야 한다. 제한된 securityContext의 근거는 [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)이며, 2026-09-08 확인했다. namespace 분리나 해시 체인만으로 완전 격리·법적 증거능력·운영 인증을 주장하지 않는다.

자동 삭제/보존기간 종료 작업은 배포 명령에 포함하지 않는다. PVC 삭제, 서명키 교체, 데이터 파기, 공유 클러스터 변경은 소유자·보존 정책·허가를 확인한 별도 작업이다.
