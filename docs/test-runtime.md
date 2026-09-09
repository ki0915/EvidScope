# 시험 전용 runtime은 기본 중지

EvidScope의 로컬 모델과 Kubernetes 실험 자원은 시험하지 않을 때 중지한다. 2026-09-09 현재 전용 Ollama container `evidscope-ollama-assistance-20260909`, k3d cluster `evidscope-lab-20260908`의 server load balancer, server, agent 2개, 합성 UI fixture가 모두 명시적으로 중지돼 있다. 포트 9080–9083과 11434도 listen하지 않는다. 다른 프로젝트의 Ollama, container, `k3d-dlp` cluster는 변경하지 않았다.

일반 `npm start`, demo 데이터 열람, 문서·UI 열람은 추론 runtime을 자동 시작하지 않는다. 아래 명령만 전용 자원을 시작한다. 원격 모델 API fallback은 없다.

```powershell
# 변경 없는 상태 확인
node scripts/test-runtime.mjs status

# 가장 안전한 시험: 필요한 자원만 명시하고 실제 시험 command를 넣는다.
# command 종료/실패/Ctrl+C 뒤 자신이 시작한 자원을 finally에서 중지한다.
node scripts/test-runtime.mjs with --resources ollama -- node <model-test-script.mjs>
node scripts/test-runtime.mjs with --resources k3d -- node <cluster-test-script.mjs>

# 합성 UI fixture는 기존 foreground 명령으로 시작하고 Ctrl+C로 종료
node scripts/ui-fixture.mjs
```

`--resources ollama|k3d|all`을 반드시 지정한다. Model 시험은 Ollama만, cluster 시험은 k3d만 시작해 사용하지 않는 자원을 켜지 않는다. 선택한 자원이 이미 실행 중이면 다른 사용자나 시험의 자원일 수 있으므로 소유권을 추정하지 않고 거부한다. k3d를 선택하면 정확한 kubeconfig/context도 확인한다. Windows child process는 숨김 창으로 실행한다. 시작 도중 일부 단계가 실패해도 시작을 시도한 전용 자원만 역순으로 중지한다. container/cluster/volume/data 삭제 명령은 사용하지 않는다.

기존 `scripts/local-ai-test.mjs`는 과거 Qwen 0.6B 시험 및 9080–9083 합성 service fixture를 전제로 하므로 위 Ollama-only 예시에 그대로 넣지 않는다. 새 assistance model 시험기는 자신의 model 이름과 endpoint를 명시하고, service fixture가 필요하면 다른 terminal에서 `node scripts/ui-fixture.mjs`를 foreground로 실행한 뒤 `Ctrl+C`로 종료해야 한다.

긴 수동 시험에서만 명시적 lease를 사용한다.

```powershell
node scripts/test-runtime.mjs start --resources ollama --owner manual-test --idle-ms 1800000
# 출력된 leaseId를 보관하고 시험 수행
node scripts/test-runtime.mjs stop --lease <leaseId>
```

Manual start는 반드시 명시적 `stop`이 필요한 예외 경로다. `idle-ms`는 shutdown timer가 아니며 자동 중지를 약속하지 않는다. deadline을 넘으면 소유권 재확인이 필요하다는 표시만 남긴다. Manual lease가 idle deadline을 넘거나 wrapper owner PID가 죽으면 `status`가 `reconciliationRequired:true`를 표시한다. 만료만으로 자동 중지하거나 새 소유자에게 넘기지 않는다. 실제 시험 프로세스가 끝났는지 확인한 뒤 다음처럼 정확한 lease를 명시한다.

```powershell
node scripts/test-runtime.mjs reconcile --lease <leaseId>
```

관리 범위는 코드 상수로 고정돼 있다.

| 자원 | 고정 범위 |
|---|---|
| Ollama container | `evidscope-ollama-assistance-20260909` |
| k3d cluster | `evidscope-lab-20260908` |
| Kubernetes context | `k3d-evidscope-lab-20260908` |
| kubeconfig | `.local/k8s-lab-20260908/kubeconfig.yaml` |

Status는 Docker inspect, k3d JSON 목록, 지정 kubeconfig의 current-context만 읽는다. kubeconfig 내용, container 환경변수, model output, token은 출력하지 않는다. UI fixture는 기존 foreground 프로세스의 `Ctrl+C` handler로 자신이 만든 자식만 종료하며 다른 Node 프로세스나 포트를 이름만 보고 종료하지 않는다.

정상 종료, 일반 child 오류, `SIGINT`/`SIGTERM`은 model/cluster wrapper의 `finally` cleanup 범위다. 운영체제 강제 종료, 전원 손실, `kill -9`, Docker/k3d 자체 정지는 `finally` 실행을 보장하지 않는다. 이 경우 lease를 자동 인수하지 않고 dead-owner 상태와 실제 전용 자원 상태를 확인한 다음 `reconcile`한다. 현재 UI fixture는 foreground 프로세스가 받은 정상 `Ctrl+C` 범위에서만 cleanup을 보장하며, 프로세스 자체가 강제 종료된 경우 포트와 자식 PID를 사람이 확인해야 한다.
