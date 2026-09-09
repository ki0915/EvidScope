# 로컬 개발 에이전트 운영 / Local development-agent operations

이 문서는 저장소 안에서 Codex와 Claude Code 작업을 함께 운영할 때의 실행 계약이다. 모델 호출을 시작하는 런처가 아니다. 로컬 coordinator는 등록된 작업의 claim, lease, worktree, handoff, review 상태만 관리하며 외부 CLI를 자동 실행하지 않는다.

## 1. 고정 팀 정책

`deploy/agent-config/development-team.json`이 공통 역할과 모델 목표를 정의한다. 전체 동시 실행은 coordinator를 포함해 3이므로 child slot은 2개다. 모든 child task는 depth 1, 별도 linked Git worktree, 명시된 `allowedPaths`, 고정 모델과 reasoning effort, `noFallback=true`를 사용한다. Codex와 Claude 양쪽 작업은 실행 전에 같은 coordinator를 claim해야 한다. 등록되지 않은 별도 사용자 세션을 coordinator가 통제한다고 주장하지 않는다.

현재 1차 설계·적대 검토는 `gpt-6-astra` high가 담당한다. UI와 독립 후속 적대 검토의 `claude-sonnet-5`는 구독 한도로 보류 상태다. 후속 검토는 독립 검토이며 fallback이 아니다. 운영 역할 네 가지는 `roles/<role>/v1`의 실제 instructions, tools, knowledge, output/refusal schema를 `src/role-packages.mjs`로 읽는다. 실행기는 `buildRoleExecution()` 결과의 `systemInstructions`와 `allowedTools`를 그대로 연결해야 하며 ID만 표시하는 프로필로 대체하면 안 된다.

## 2. 저장소 로컬 설정 설치

템플릿은 제한된 `.codex` 경로를 직접 변경하지 않고 `deploy/agent-config`에 둔다. 먼저 dry run으로 정확한 대상만 확인한다.

```powershell
./deploy/agent-config/install-agent-config.ps1 -RepoRoot (Get-Location)
./deploy/agent-config/install-agent-config.ps1 -RepoRoot (Get-Location) -Apply
```

기존 `.codex/config.toml`, `.codex/agents`, `.claude/agents`가 있으면 스크립트는 중단한다. 내용을 수동 병합하거나 교체를 의도했을 때만 `-Force`를 사용한다. 전역 사용자 설정이나 클라우드 설정은 바꾸지 않는다. Codex의 native child 한도는 2이며, provider 간 전체 한도 3은 coordinator lease가 집행한다.

## 3. Coordinator 사용

`deploy/agent-config/team-manifest.example.json`을 복사해 절대 worktree 경로, 실제 base commit, 허용 파일, 완료 기준을 채운다. 모든 worktree는 coordinator와 같은 Git common directory를 사용하는 서로 다른 linked worktree여야 한다.

```powershell
node scripts/development-task.mjs status .local/development-team
node scripts/development-task.mjs claim .local/development-team claim.json
node scripts/development-task.mjs renew .local/development-team renew.json
node scripts/development-task.mjs complete .local/development-team handoff.json
node scripts/development-task.mjs review .local/development-team review.json
node scripts/development-task.mjs release .local/development-team release.json
```

Claim은 manifest의 모델과 reasoning effort가 정확히 일치해야 한다. lease는 실행 중 주기적으로 renew한다. 만료만으로 프로세스 종료를 추정하지 않으며 `reconciliation_required`가 slot을 계속 점유한다. 실제 프로세스 상태를 확인한 뒤 `reconciled:true`로 release 또는 complete한다. Lock은 나이만으로 삭제하지 않는다. 소유 프로세스가 비정상 종료해 lock이 남으면 상태 파일과 프로세스를 사람이 확인한 뒤 정확한 lock 디렉터리만 복구한다.

Complete는 base commit의 descendant인 변경 commit, `allowedPaths` 안의 실제 diff, 모든 completion criterion의 `met|unmet`, 명령별 `passed|failed|not_run`, unresolved 목록을 검증한다. review는 구현자와 다른 `design-review` 또는 `adversarial` 역할이 수행하며 최대 두 round다.

## 4. Development-run API 연결 계약

`src/development-runs.mjs`는 독립 factory다. `src/service.mjs`에서 Store 생성 뒤 한 번 만들고, 인증 직후와 일반 human gate 전에 호출한다.

```js
import {createDevelopmentRuns} from './development-runs.mjs';

// createService 내부
const developmentRuns=createDevelopmentRuns(store);

// handle 내부: const p=auth(headers); 바로 다음
const developmentResult=developmentRuns.handle(p,method,url,headers,body);
if(developmentResult!==undefined)return developmentResult;
```

`src/server.mjs` gateway는 다음 세 경계를 함께 바꿔야 한다.

```js
const ingestPaths=new Set(['/api/ingest','/api/development-runs/events']);
if(mode==='ingress'&&(!ingestPaths.has(url.pathname)||req.method!=='POST'))throw new HttpError(403,'수집 게이트웨이는 이벤트 제출만 허용합니다');
if(mode==='audit'&&(!url.pathname.startsWith('/api/')||ingestPaths.has(url.pathname)))throw new HttpError(403,'감사 게이트웨이에서 허용하지 않는 경로입니다');
// vault response
res.statusCode=ingestPaths.has(url.pathname)?202:200;
```

연결 뒤 실제 HTTP 시험은 ingress에서 signed POST가 202인지, audit에서 같은 POST가 403인지, audit의 human GET이 200인지, source GET이 403인지 확인한다. UI fixture의 공개 합성 credential만 사용하며 secret을 보고서에 쓰지 않는다.

Write 경로는 `POST /api/development-runs/events`다. 기존 Bearer source identity와 raw body HMAC, timestamp, nonce를 모두 요구한다. tenant와 source는 credential에서 결정되고 body로 지정할 수 없다. 같은 tenant/source/event ID와 같은 fingerprint는 duplicate, 다른 내용은 409 collision이다. 동일 source의 run은 처음의 team/role/parent binding을 유지한다. 다른 source의 같은 run ID는 별도 run으로 보여 self-report가 tool log를 덮지 않는다. parent가 같은 source에서 관측되지 않으면 `unresolved`이며 확인된 tree로 만들지 않는다.

Human read는 `GET /api/development-runs`이고 응답은 `{items,summary,coverage}`다. `usage` 미관측은 null 값과 `status:"unknown"`이며 0으로 바꾸지 않는다. model은 external tool/telemetry stream에서 실제로 관측했을 때만 `actual_observed`; agent source 보고는 `source_self_report`; 그 밖은 `unknown`이다. replay에 source timestamp가 없으면 collector receipt time과 `timeBasis:"collector_received"`를 기록하며 실제 실행시각으로 주장하지 않는다.

## 5. Codex JSONL과 Claude hooks/stream 최소화

Collector는 raw 입력을 메모리에서 한 줄씩 읽어 allowlist metadata JSONL만 stdout에 쓴다.

```powershell
node scripts/collect-development-events.mjs codex-jsonl context.json codex.jsonl > minimized.jsonl
node scripts/collect-development-events.mjs claude-stream context.json claude.jsonl > minimized.jsonl
Get-Content hook.json | node scripts/collect-development-events.mjs claude-hook context.json
node scripts/send-development-events.mjs http://127.0.0.1:8081 .local/config.json alpha-tool minimized.jsonl
```

`context.json`에는 `runId`, `teamId`, `roleId`, 선택적 `parentRunId`만 둔다. Codex는 run/turn과 허용된 tool item 종류만 수집한다. Claude stream은 init/result와 `tool_use`의 ID·이름, 대응 `tool_result`의 ID·성공/실패만 수집한다. assistant text, thinking, command, tool input, result content, prompt, total_cost_usd, API key source는 읽어서 출력하지 않는다. semantic secret이 허용된 ID나 artifact 이름에 들어올 가능성은 자동으로 증명할 수 없으므로 source 단계의 human minimization이 필요하고 이벤트는 `semanticRedactionUnverified:true`를 명시한다.

실제 로컬 Claude stream 표본 242줄에서는 metadata 36건(init 1, tool start 17, tool completed 16, tool failed 1, failed terminal 1)만 생성됐다. 구독 한도 종료는 raw subtype이 success여도 `is_error:true`에 따라 failed로 유지됐다. 실제 Codex JSONL 표본 4줄에서는 run started, agent started, run completed 3건만 생성했고 agent message 내용은 제외했다. 두 확인은 추가 모델 호출 없이 기존 로컬 stream을 재생했다.

## 6. 역할 평가와 LoRA gate

각 역할은 tune 30, validation 10, test 20개의 합성 fixture를 갖는다. family는 split 하나에만 속하고 모든 항목은 `UNREVIEWED`, `humanReviewed:false`다. prompt injection, fake approval, fabricated citation, cross-scope, stale evidence, unknown-versus-compliance, adverse evidence가 포함된다. `src/role-evaluation.mjs`는 citation 존재/유효성, supports/contradicts/context relation, unknown/abstention, scope와 injection 안전성을 deterministic assertion으로 점수화한다. AI judge는 사용하지 않는다.

현재 자료는 훈련 corpus가 아니다. Evidence Organizer 첫 LoRA 후보만 문서화했으며 gate는 human-reviewed tune 300, validation 50, test 100, source consent, reviewer identity, family isolation, truth labels/references를 모두 요구한다. 현재 count는 모두 0이어서 `trainingRunAllowed:false`다. 후보는 rank 8, length 2048, batch 1, PEFT 4-bit이고 제품 runtime에는 training dependency를 추가하지 않는다. Gate 통과도 품질 증명이 아니며 별도 held-out test 측정 전 `qualityClaimAllowed:false`다.

설정 형식과 collector 전제는 [Codex subagents](https://learn.chatgpt.com/docs/agent-configuration/subagents), [Codex non-interactive JSONL](https://learn.chatgpt.com/docs/non-interactive-mode), [Claude Code hooks](https://code.claude.com/docs/en/hooks), [Claude Code sub-agents](https://code.claude.com/docs/en/sub-agents)의 공식 계약을 기준으로 한다. 실제 CLI 버전이 바뀌면 raw 내용을 보존하는 방식으로 대응하지 말고 allowlist parser fixture와 integration test를 먼저 갱신한다.
