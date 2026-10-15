# AI 코딩 에이전트 행동 감시 (Claude Code, Codex CLI)

> 2026-10-15 추가. 이 PC에서 실제로 쓰는 AI 도구의 행동을 EvidScope로 받고, 위험 행동을 규칙으로 표시합니다.

## 무엇을 하는가

Claude Code가 도구를 쓸 때마다(명령 실행, 파일 읽기·쓰기, 검색, 웹 접속, MCP 호출) `PreToolUse`·`PostToolUse` hook이
`scripts/claude-code-hook.mjs`를 실행합니다. Codex CLI는 같은 형식의 hook(`~/.codex/hooks.json`)으로 `scripts/codex-hook.mjs`를
실행합니다. 두 hook 모두 `src/agent-hook-runner.mjs`가 그 호출을 서명된 수집 요청(`POST /api/ingest`, [수집 계약](contract.md))으로
EvidScope에 보냅니다.

| hook | 기록 | 담는 것 |
|---|---|---|
| PreToolUse | `intent` | 행위자(`claude-code@<컴퓨터>` 또는 `codex@<컴퓨터>`), 도구(`claude-code`·`codex`), 행동 분류(`shell_exec`, `file_read`, `file_write`, `file_search`, `web_fetch`, `web_search`, `mcp_call`, `subagent`), 대상(`resource`: 파일 경로·명령·URL), 목적지(URL 호스트), 원문 메모(`note`) |
| PostToolUse | `self_report` | 같은 `actionId`의 결과(`success`/`failure`). 대상은 다시 싣지 않아 규칙이 호출당 한 번만 걸립니다. |

- Codex의 셸 도구는 `Bash`(명령이 인자 목록이면 공백으로 이어 붙임), 파일 수정은 `apply_patch`입니다. `apply_patch`는 패치에
  적힌 파일 경로(`*** Add File:`·`Update File:`·`Delete File:`·`Move to:`)만 대상으로 싣고, 패치 내용은 기록하지 않습니다.
- 대상(`resource`)은 소문자·`/` 구분자로 정규화해 256자까지, 메모(`note`, `[도구] 명령 또는 경로`)는 원래 대소문자 그대로 1024자까지
  싣습니다. 위험 규칙(팩 버전 2)은 메모를 `words` 연산자로 읽습니다.
- 명령 속 비밀번호·토큰·`Authorization` 헤더·URL 사용자 정보·잘 알려진 키 형식(`sk-`, `ghp_`, `AKIA` 등)은 `<redacted>`로 가립니다.
  최선 노력이며, 기록은 이 PC의 EvidScope에만 저장됩니다.
- hook은 도구 호출을 막거나 바꾸지 않습니다. 아무것도 출력하지 않고 항상 0으로 끝납니다. EvidScope가 꺼져 있으면 기록을
  `~/.evidscope/<에이전트>-spool.jsonl`(최대 5 MiB)에 두었다가 다음 호출 때 보냅니다.
- 이 기록은 `agent` 출처의 자기 보고입니다. hook은 AI 도구 안에서 돌기 때문에 독립 실행 기록(`tool` 출처)이 아닙니다. 그래서 권한
  증거·승인 규칙(도구 출처 실행 기록용)은 걸리지 않고, 등록 자산·목적지 정책·사용자 규칙이 적용됩니다.

## 위험 규칙

`data/risk-rules/ai-agent-baseline.json`의 60개 규칙을 테넌트 규칙으로 올립니다. 모두 `note words <패턴>` 형식(평가 엔진 v6,
`src/rule-words.mjs`)이며 일치는 검토 신호이지 판정이 아닙니다.

- 패턴은 공백으로 나눈 단어를 **순서대로** 찾습니다. 사이에 다른 단어가 있어도 됩니다(`curl -d`는 `curl -s -X POST -d @f`에도 걸림).
- `*`는 아무 글자, `|`는 대안, `"…"`는 글자 그대로(`rm -rf "/*"`), `!`로 시작하는 단어는 명령 어디에도 없어야 합니다. 그래서 이 PC
  자신(`localhost`, `127.*`)으로 보내는 `curl -d`는 외부 전송으로 보지 않습니다.
- 대문자가 든 단어만 대소문자를 구분합니다(`curl -F` 업로드와 `curl -f` 실패 옵션을 가름). 역슬래시는 `/`로 읽습니다.
- 정규식을 만들지 않고 단어를 한 번 훑으므로 규칙이 분석을 멈추게 할 수 없습니다.
- 실행 후 기록(`self_report`)은 실행 전 기록과 메모가 같으므로 `words` 규칙은 호출당 한 번, 실행 전 기록에만 겁니다. 실행 전 기록이
  없을 때(PreToolUse hook이 꺼진 경우)는 실행 후 기록을 읽습니다.
- 팩 버전 1(`resource contains`)은 플래그 순서가 바뀐 명령(`curl -X POST -d`, `rm -r -f /`, `git push origin main --force`),
  256자를 넘는 명령의 뒷부분을 놓쳤고, `.env.example`, 공개 인증서 `.pem`, `--force-with-lease`, 이 PC로 보내는 `curl -d`를 잘못
  걸었습니다. 버전 2는 이를 고쳤고 Firefox 저장 비밀번호, `Set-NetFirewallProfile -Enabled False`, `Clear-History`,
  순서가 바뀐 `Remove-Item -Force -Recurse`를 더했습니다.

| 묶음 | 예 |
|---|---|
| 자격증명 파일 | `/etc/shadow`, `/etc/sudoers`, `.ssh/id_`, `.aws/credentials`, `.kube/config`, `.git-credentials`, `.env`, Windows SAM, 브라우저 저장 비밀번호 |
| 자격 탈취 | `lsass`, `mimikatz` |
| 파괴적 명령 | `rm -rf /`, `rm -rf ~`, `Remove-Item -Recurse -Force`, `del /s`, `mkfs`, `format c:`, 디스크 `dd`, `git push --force`, `git reset --hard`, `DROP TABLE` |
| 외부 전송 | `curl -d`, `--data`, `--upload-file`, `curl -T`, `--form`, `wget --post-file`, `-Method Post`, `-InFile`, `scp`, `nc`, `pastebin` |
| 보안 설정 변경 | Defender·방화벽·iptables·SELinux 변경, 이벤트 로그 삭제, `history -c`, `chmod 777` |
| 감시 우회 | `~/.evidscope/` 수집 설정, `~/.claude/settings`·`~/.codex/hooks.json`·`~/.codex/config.toml` hook 설정 접근 |

규칙 하나를 바꾸거나 더하려면 파일을 고치고 설치 스크립트를 다시 실행합니다. 필드·연산자·값·등급·제목이 같은 활성 규칙은 그대로
두고, 달라진 규칙만 새 버전(검토자 작성·시험, 관리자 승인)으로 올립니다.

평가 엔진 v6은 테넌트 규칙에 `words` 규칙이 있을 때만 평가에 적힙니다. 그 밖의 평가는 v1~v5와 결과가 같고, v6을 모르는 검증기는
v6 평가를 `contains`로 잘못 읽지 않고 `engine_unavailable`로 밝힙니다.

평가 엔진 v7은 AI 코딩 도구가 실행한 명령에 든 HTML·스크립트 표기(`grep "<script" index.html`, `onerror=`)를 "로그 주입 의심"으로
보지 않습니다. 코드를 쓰는 일이기 때문입니다. 감사자에게 지시하는 문장(`ignore ... instructions`, 감사 룰 변경 요구)은 그대로
잡고, 코딩 도구가 아닌 기록의 표기도 그대로 잡습니다. 그런 명령이 있는 행동의 평가에만 v7이 적히고(입력 `agentCommands`), 재생은
v7 평가에만 이 입력을 다시 만듭니다. 원장에 v7 평가가 생긴 뒤에 같은 종류의 행동을 이전 엔진으로 적은 평가는 `mismatch`입니다.

## 여러 행동을 엮은 이상 징후 (평가 엔진 v5)

> 2026-10-15 추가(`src/sequence-rules.mjs`).

위험 규칙은 도구 호출 하나만 봅니다. 평가 엔진 v5는 같은 AI(행위자)의 다른 도구 호출 가운데 위험 규칙에 걸린 것(위험 단계)을
함께 읽어, 하나씩은 신호일 뿐인 행동이 이어서 만드는 패턴을 표시합니다.

| 코드 | 등급 | 조건 |
|---|---|---|
| `SEQ_SENSITIVE_THEN_OUTBOUND` | high | 자격증명·비밀 파일 접근(`risk.cred.*`) 뒤 30분 안에 외부 전송(`risk.out.*`) |
| `SEQ_DEFENSE_OFF_THEN_ACTION` | high | 백신·방화벽·iptables·SELinux 해제 뒤 30분 안에 자격증명 접근·외부 전송·파괴 명령 |
| `SEQ_RISK_THEN_TAMPER` | high | 위험 행동(자격증명·외부 전송·파괴·보안 해제·`chmod 777`) 뒤 30분 안에 로그·명령 기록 삭제나 감시 설정 접근(`risk.audit.*`) |
| `SEQ_BULK_SENSITIVE` | medium | 앞뒤 10분 안에 서로 다른 자격증명·비밀 대상 5곳 이상 |
| `SEQ_REPEATED_DESTRUCTIVE` | medium | 앞뒤 10분 안에 파괴적 명령이 든 도구 호출 3번 이상 |

- 발견사항은 패턴에 속한 도구 호출의 평가에 붙습니다. 메시지는 이 호출의 역할(앞 단계, 뒤 단계, 한 명령 안에 둘 다, 중간)과
  엮인 다른 행동 수를 알려 줍니다. 증거는 이 호출의 기록만 인용합니다. 다른 행동의 기록은 그 행동의 평가에 있습니다.
- 같은 행위자끼리만 엮고, 시각은 각 기록의 발생 시각(`occurredAt`)입니다. 늦게 도착한 기록도 창 안이면 엮입니다. 뒤 단계가
  먼저 평가됐다면, 앞 단계가 평가될 때 같은 패턴이 앞 단계 쪽에서 표시됩니다.
- 이 컴퓨터로 보내는 전송(목적지 `localhost`, `127.x.x.x`, `::1`, `0.0.0.0`)은 외부 전송으로 세지 않습니다. 로컬 API 시험이 유출
  패턴으로 보이지 않게 하기 위해서입니다.
- 평가 입력(스냅샷)에는 같은 행위자의 위험 단계 요약이 `relatedSteps`로 들어갑니다(창 안 최근 50개, 원장 순서; seq·id·행동·시각·
  대상·목적지·일치한 규칙과 버전). 이 행동에 위험 단계가 없으면 넣지 않으므로 그 평가는 이전 엔진의 결과와 같습니다.
- 오프라인 재계산(`scripts/replay-findings.mjs`, `scripts/verify.mjs --replay`)은 v5라고 적힌 평가에만 이 입력을 다시 만듭니다.
  v5 이전에 쌓인 평가는 예전처럼 재계산됩니다. 원장에 v5 평가가 한 번 나온 뒤에 위험 단계가 있는 행동을 이전 엔진으로 평가한
  기록은 불일치(엔진 되돌림, `diff.engine`)로 보고합니다. v5를 모르는 검증기는 v5 평가를 `engine_unavailable`로 밝힙니다.
- 정상 개발 작업에서도 걸릴 수 있습니다. 예를 들어 `.env`를 읽은 뒤 `~/.claude/settings.json`을 고치면 `SEQ_RISK_THEN_TAMPER`가
  표시됩니다. 판정이 아니라 검토 신호입니다.

## 관련 기준(감사 증적과의 연결)

위험 규칙의 발견사항은 증거 묶음 대응표 버전 3부터, 여러 행동 이상 징후(`SEQ_*`)는 버전 4부터
([감사인용 증거 묶음](evidence-pack.md#대응표-버전)) 아래 항목의 증거로 셉니다. "이 항목을 검토할 때 볼 기록"이라는 뜻이며
준수·위반 판정이 아닙니다. 대응표는 사람 검토 전 초안입니다.

| 기준 | 항목 | 세는 발견사항 |
|---|---|---|
| ISMS-P | 2.11.3 이상행위 분석 및 모니터링(①) | 모든 위험 규칙, 모든 이상 징후 |
| ISMS-P | 2.6.7 인터넷 접속 통제(②) | 외부 전송(`risk.out.*`), `SEQ_SENSITIVE_THEN_OUTBOUND` |
| ISMS-P | 2.10.1 보안시스템 운영(③) | Defender·방화벽·iptables·SELinux 변경, `SEQ_DEFENSE_OFF_THEN_ACTION` |
| ISMS-P | 2.9.4 로그 및 접속기록 관리(②) | 이벤트 로그·명령 기록 삭제, 감시 설정 접근(`risk.audit.*`), `SEQ_RISK_THEN_TAMPER` |
| AI 기본법 | KR-32-MONITOR 안전사고 모니터링·대응 체계, KR-34-RISK 고영향 위험관리 | 모든 위험 규칙, 모든 이상 징후 |
| EU AI Act | 12(2)(a) 위험 상황 식별 이벤트, 14(4)(a) 감독자의 이상 탐지 | 모든 위험 규칙, 모든 이상 징후 |

에이전트의 행동 기록 자체(`intent`)는 버전 2부터 ISMS-P 2.5.2·2.9.4와 EU AI Act 12(2)(c)의 증거입니다. 콘솔의 탐지 경보와 행동
조사 화면은 경보마다 이 관련 기준을 보여 주고(`GET /api/home/finding-requirements`), 홈의 항목별 증거와 증거 묶음도 같은 대응표로 셉니다.

## 설치

EvidScope를 켠 상태에서(로컬 실행기 `node scripts/local.mjs`) 실행합니다.

```powershell
node scripts/install-agent-monitoring.mjs --local-dir <EVIDSCOPE_LOCAL_DIR> --port-base 8090 --hook-dir C:/evidscope-work/hook --claude-settings
```

Codex CLI는 `--agent codex --codex-hooks`로 설치합니다(`~/.codex/hooks.json`, `CODEX_HOME`이 있으면 그 폴더).

```powershell
node scripts/install-agent-monitoring.mjs --agent codex --local-dir <EVIDSCOPE_LOCAL_DIR> --port-base 8090 --hook-dir C:/evidscope-work/hook --codex-hooks
```

1. 에이전트를 자산으로 등록합니다(행위자 `<에이전트>@<컴퓨터>`, 도구 `claude-code`·`codex`, 정책 버전 `<에이전트>-monitoring-v1`).
2. 위험 규칙을 검토자가 작성·시험하고 관리자가 승인합니다(규칙 API의 4-eyes).
3. `~/.evidscope/<에이전트>-hook.json`에 수집 주소(`port-base + 1`)와 테넌트 `agent` 출처 자격을 씁니다.
4. `--hook-dir`이 있으면 hook과 모듈 둘(`src/agent-hook-runner.mjs`, `src/agent-hook-events.mjs`)을 그 폴더로 복사합니다. 한글·공백이
   든 경로를 hook 명령줄에 넣지 않기 위해서입니다.
5. `--claude-settings`(Claude Code)는 `~/.claude/settings.json`, `--codex-hooks`(Codex)는 `~/.codex/hooks.json`의 `hooks`에
   `PreToolUse`·`PostToolUse`를 더합니다. 다른 hook은 그대로 두고, 원래 파일은 `<파일>.before-evidscope-<시각>`으로 남깁니다.
   없으면 넣을 내용을 출력만 합니다.

설치 뒤 새로 시작한 세션부터 기록됩니다. Codex는 직접 넣지 않은 hook을 사용자가 한 번 신뢰해야 실행합니다: Codex CLI에서
`/hooks`를 열어 EvidScope hook을 신뢰합니다(hook 파일이 바뀌면 다시 신뢰). 신뢰한 뒤에도 두 항목이 모두 켜져 있는지 확인합니다.
`PreToolUse`가 꺼져 있으면(`config.toml`의 해당 `hooks.state` 항목에 `enabled = false`) 결과 기록(`self_report`)만 오고 대상이 없어
위험 규칙이 걸리지 않습니다(2026-10-15 실제로 확인). 되돌리려면 설정 파일에서 두 hook 항목을 지우거나 백업 파일로 바꿉니다.

## 한계

- 감시는 에이전트 hook이 보는 도구 호출까지입니다. AI가 만든 스크립트가 나중에 따로 실행되면 그 안의 행동은 보이지 않습니다.
- 규칙은 문자열 포함 검사입니다. 변수·인코딩으로 감춘 명령은 놓칠 수 있습니다.
- 여러 행동 이상 징후는 위험 규칙에 걸린 단계만 엮습니다. 규칙에 없는 단계(예: 압축)는 보지 않으므로 "읽기 → 압축 → 전송"은
  읽기와 전송으로 엮이고, 규칙에 걸리지 않는 방식의 전송은 놓칩니다. 서로 다른 AI 도구 사이(Claude Code가 읽고 Codex가 보냄)는
  엮지 않습니다.
- hook이 없는 AI 도구(예: Claude 데스크톱 채팅 앱)는 기록하지 않습니다. Codex 데스크톱 앱과 VS Code 확장이 같은
  `hooks.json`을 읽는지는 아직 확인하지 않았습니다.
