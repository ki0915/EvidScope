# AI 코딩 에이전트 행동 감시 (Claude Code)

> 2026-10-15 추가. 이 PC에서 실제로 쓰는 AI 도구의 행동을 EvidScope로 받고, 위험 행동을 규칙으로 표시합니다.

## 무엇을 하는가

Claude Code가 도구를 쓸 때마다(명령 실행, 파일 읽기·쓰기, 검색, 웹 접속, MCP 호출) `PreToolUse`·`PostToolUse` hook이
`scripts/claude-code-hook.mjs`를 실행합니다. hook은 그 호출을 서명된 수집 요청(`POST /api/ingest`, [수집 계약](contract.md))으로
EvidScope에 보냅니다.

| hook | 기록 | 담는 것 |
|---|---|---|
| PreToolUse | `intent` | 행위자(`claude-code@<컴퓨터>`), 도구(`claude-code`), 행동 분류(`shell_exec`, `file_read`, `file_write`, `file_search`, `web_fetch`, `web_search`, `mcp_call`, `subagent`), 대상(`resource`: 파일 경로·명령·URL), 목적지(URL 호스트), 원문 메모(`note`) |
| PostToolUse | `self_report` | 같은 `actionId`의 결과(`success`/`failure`). 대상은 다시 싣지 않아 규칙이 호출당 한 번만 걸립니다. |

- 대상은 소문자·`/` 구분자로 정규화합니다. 규칙 DSL(`src/model.mjs` `matches()`)이 대소문자를 구분하는 `contains`이기 때문입니다.
- 명령 속 비밀번호·토큰·`Authorization` 헤더·URL 사용자 정보·잘 알려진 키 형식(`sk-`, `ghp_`, `AKIA` 등)은 `<redacted>`로 가립니다.
  최선 노력이며, 기록은 이 PC의 EvidScope에만 저장됩니다.
- hook은 도구 호출을 막거나 바꾸지 않습니다. 아무것도 출력하지 않고 항상 0으로 끝납니다. EvidScope가 꺼져 있으면 기록을
  `~/.evidscope/claude-code-spool.jsonl`(최대 5 MiB)에 두었다가 다음 호출 때 보냅니다.
- 이 기록은 `agent` 출처의 자기 보고입니다. hook은 AI 도구 안에서 돌기 때문에 독립 실행 기록(`tool` 출처)이 아닙니다. 그래서 권한
  증거·승인 규칙(도구 출처 실행 기록용)은 걸리지 않고, 등록 자산·목적지 정책·사용자 규칙이 적용됩니다.

## 위험 규칙

`data/risk-rules/ai-agent-baseline.json`의 50개 규칙을 테넌트 규칙으로 올립니다. 모두 `resource contains <값>` 형식이며 일치는
검토 신호이지 판정이 아닙니다.

| 묶음 | 예 |
|---|---|
| 자격증명 파일 | `/etc/shadow`, `/etc/sudoers`, `.ssh/id_`, `.aws/credentials`, `.kube/config`, `.git-credentials`, `.env`, Windows SAM, 브라우저 저장 비밀번호 |
| 자격 탈취 | `lsass`, `mimikatz` |
| 파괴적 명령 | `rm -rf /`, `rm -rf ~`, `Remove-Item -Recurse -Force`, `del /s`, `mkfs`, `format c:`, 디스크 `dd`, `git push --force`, `git reset --hard`, `DROP TABLE` |
| 외부 전송 | `curl -d`, `--data`, `--upload-file`, `-Method Post`, `scp`, `nc`, `pastebin` |
| 보안 설정 변경 | Defender·방화벽·iptables·SELinux 변경, 이벤트 로그 삭제, `history -c`, `chmod 777` |
| 감시 우회 | `~/.evidscope/` 수집 설정, `~/.claude/settings` hook 설정 접근 |

규칙 하나를 바꾸거나 더하려면 파일을 고치고 설치 스크립트를 다시 실행합니다. 같은 값·등급의 활성 규칙은 그대로 두고, 달라진
규칙만 새 버전(검토자 작성·시험, 관리자 승인)으로 올립니다.

## 설치

EvidScope를 켠 상태에서(로컬 실행기 `node scripts/local.mjs`) 실행합니다.

```powershell
node scripts/install-agent-monitoring.mjs --local-dir <EVIDSCOPE_LOCAL_DIR> --port-base 8090 --hook-dir C:/evidscope-work/hook --claude-settings
```

1. 에이전트를 자산으로 등록합니다(행위자 `claude-code@<컴퓨터>`, 도구 `claude-code`, 정책 버전 `claude-code-monitoring-v1`).
2. 위험 규칙을 검토자가 작성·시험하고 관리자가 승인합니다(규칙 API의 4-eyes).
3. `~/.evidscope/claude-code-hook.json`에 수집 주소(`port-base + 1`)와 테넌트 `agent` 출처 자격을 씁니다.
4. `--hook-dir`이 있으면 hook과 모듈 하나를 그 폴더로 복사합니다. 한글·공백이 든 경로를 hook 명령줄에 넣지 않기 위해서입니다.
5. `--claude-settings`가 있으면 `~/.claude/settings.json`의 `hooks`에 `PreToolUse`·`PostToolUse`를 더합니다. 원래 파일은
   `settings.json.before-evidscope-<시각>`으로 남깁니다. 없으면 넣을 내용을 출력만 합니다.

설치 뒤 새로 시작한 Claude Code 세션부터 기록됩니다. 되돌리려면 `settings.json`에서 두 hook 항목을 지우거나 백업 파일로 바꿉니다.

## 한계

- 감시는 Claude Code hook이 보는 도구 호출까지입니다. AI가 만든 스크립트가 나중에 따로 실행되면 그 안의 행동은 보이지 않습니다.
- 규칙은 문자열 포함 검사입니다. 변수·인코딩으로 감춘 명령은 놓칠 수 있습니다.
- 여러 행동을 엮은 이상 징후(민감 파일 읽기 → 압축 → 외부 전송)는 아직 판정하지 않습니다.
- Codex CLI는 아직 연결하지 않았습니다.
