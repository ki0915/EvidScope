# 로컬 모델 기록 프록시

Ollama, vLLM, LM Studio, llama.cpp 서버처럼 PC나 사내 서버에서 직접 돌리는 모델을 부르는 활동을 EvidScope의 서명 기록에 남깁니다.
Claude Code·Codex는 hook으로 기록하지만([agent-monitoring.md](agent-monitoring.md)), Open WebUI, Continue, Aider, 직접 짠 스크립트처럼
로컬 모델을 부르는 도구에는 hook이 없습니다. 이 도구들은 모두 모델 서버의 HTTP API(OpenAI 호환 API 또는 Ollama API)를 부르므로,
그 앞에 기록 프록시를 두면 어떤 도구가 부르든 같은 방식으로 기록됩니다.

```
도구(Open WebUI, Continue, Aider, 스크립트) ──▶ 기록 프록시 127.0.0.1:11435 ──▶ 모델 서버(Ollama 127.0.0.1:11434 등)
                                                  │
                                                  └──▶ EvidScope 수집 게이트웨이(서명 요청, 순번 사슬)
```

## 무엇을 기록하는가

모델 호출 하나마다 기록 2~4건을 남깁니다. 모두 `agent` 출처 기록이고 도구 이름은 `local-model-proxy`입니다.

| 기록 | 시점 | 내용 |
|---|---|---|
| 요청(intent) | 요청이 들어올 때 | 엔드포인트, 모델 이름, 메시지 수, 모델에 건넨 도구 이름, 요청 크기와 SHA-256, 부른 프로그램(User-Agent) |
| 내용 검사(prompt) | 요청이 들어올 때 | 이번 호출에서 새로 들어간 사용자 메시지의 보안 신호(라벨·개수·해시) |
| 내용 검사(tool_result) | 요청이 들어올 때 | 모델에게 돌려준 도구 결과의 보안 신호(라벨·개수·해시) |
| 응답(self_report) | 응답이 끝날 때 | HTTP 상태, 종료 이유, 모델이 부르려 한 도구 이름, 토큰 수, 응답 크기와 SHA-256, 걸린 시간, AI 사용 관측(`aiObservation`) |

- **본문(프롬프트·응답 글)은 기록에 넣지 않습니다.** 크기와 SHA-256만 남깁니다. 비밀번호·API 키 같은 `Authorization` 헤더도
  모델 서버에는 그대로 전달하지만 기록하지 않습니다.
- 대화형 API는 호출할 때마다 대화 전체를 다시 보냅니다. 그래서 "모델의 마지막 답 뒤에 새로 붙은 메시지"만 검사합니다.
  같은 글이 호출마다 반복해서 경보가 되지 않게 하기 위해서입니다.
- 내용 검사는 hook과 같은 검사기(`src/agent-content-signals.mjs`)를 씁니다. 그래서 평가 엔진 v9의 LLM 보안 발견
  (`LLM_SECRET_IN_PROMPT`, `LLM_INDIRECT_INJECTION`, 개인정보 포함 등)이 로컬 모델 호출에도 그대로 나옵니다. 예: 사용자가 로컬 모델에
  클라우드 접근 키를 붙여 넣으면 높음 경보 `LLM_SECRET_IN_PROMPT`가 됩니다.
- 응답 기록의 `aiObservation`은 콘솔의 AI 사용 현황(`/api/ai-visibility`)에 모델·토큰 수와 함께 나옵니다.
- 모델 목록 조회(`GET /v1/models`, `/api/tags`)처럼 모델을 돌리지 않는 요청은 기록 없이 전달만 합니다. 모델 내려받기·삭제
  (`/api/pull`, `/api/delete` 등)는 `model_admin`으로 기록합니다.

기록하는 엔드포인트: `/v1/chat/completions`, `/v1/completions`, `/v1/responses`, `/v1/embeddings`(OpenAI 호환: vLLM, LM Studio,
llama.cpp 서버, Ollama의 `/v1`), `/api/chat`, `/api/generate`, `/api/embed`, `/api/embeddings`, `/api/pull`, `/api/push`, `/api/create`,
`/api/delete`, `/api/copy`(Ollama).

## 무결성: 빠짐과 변경을 드러내는 방식

- 모든 기록은 hook과 같은 순번 사슬(`chain: {stream, seq, prev}`, [agent-monitoring.md "수집 연속성"](agent-monitoring.md#수집-연속성))을
  가집니다. 상태 파일은 `~/.evidscope/local-model-proxy-chain.json`입니다. 금고의 `GET /api/collection/chains`가 빠진 순번·연결
  불일치·번호 중복을 보여 주고, 확정된 문제는 `COLLECTION_GAP`(높음) 경보가 됩니다.
- 프록시는 상주 프로세스라서 시작할 때와 10분마다(`heartbeatMs`) 순번이 붙은 **심장박동 기록**을 보냅니다. hook만으로는 "보내기 전에
  끝부분 기록이 지워지면 드러나지 않는" 한계가 있었는데, 프록시 기록은 다음 심장박동이 더 큰 순번을 가지고 도착하므로 그 사이에
  지워진 순번이 빈 곳으로 드러납니다.
- EvidScope에 닿지 않으면 기록은 `~/.evidscope/local-model-proxy-spool.jsonl`에 순서대로 쌓였다가 다음 전송 때 함께 갑니다. 모델 호출
  자체는 기록 실패와 상관없이 그대로 진행됩니다(기록 때문에 사용이 막히지 않음).
- 응답은 받은 바이트 그대로, 받는 즉시 흘려보냅니다(스트리밍 유지). 기록은 옆에서 읽기만 합니다.

## 본문 보관(선택, 기본 꺼짐)

설정 `recordText: true`(또는 `--record-text`)를 켜면 요청·응답 본문을 PC의 `~/.evidscope/local-model-text/<날짜>.jsonl`에 한 호출당 한
줄로 보관합니다. 본문은 서명 원장에 들어가지 않지만, 보관된 본문의 SHA-256이 서명된 요청·응답 기록의 해시와 같으므로 나중에 보관
본문이 바뀌지 않았는지 원장과 대조할 수 있습니다. 개인정보·영업 비밀이 그대로 남으므로 보관 기간과 접근 권한을 먼저 정한 뒤 켜세요.

## 설치와 실행

PC나 서버에 서비스·자동 시작·시스템 프록시 설정을 등록하지 않습니다. 직접 실행할 때만 동작합니다.

```
# 1) 설정 파일 만들기: 이미 설치된 Claude Code(또는 Codex) hook 설정의 수집 자격 증명을 그대로 씁니다.
#    --local-dir를 주면 로컬 EvidScope에 프록시를 자산으로 등록해 "미등록 AI" 경보가 나지 않습니다.
node scripts/local-model-proxy.mjs init --upstream http://127.0.0.1:11434 --provider ollama --local-dir <EVIDSCOPE_LOCAL_DIR>

# 2) 실행(Ctrl+C로 종료)
node scripts/local-model-proxy.mjs run
```

그다음 도구의 모델 서버 주소를 프록시로 바꿉니다.

| 도구 | 바꿀 곳 |
|---|---|
| Open WebUI | 설정의 Ollama API 주소를 `http://127.0.0.1:11435`로 |
| Continue, Aider 등 OpenAI 호환 클라이언트 | API base를 `http://127.0.0.1:11435/v1`로 |
| `ollama` 명령줄 | `OLLAMA_HOST=127.0.0.1:11435` |
| vLLM·LM Studio 앞에 둘 때 | `init --upstream http://127.0.0.1:8000 --provider vllm`(LM Studio는 `:1234`, `--provider local`) |

요청 헤더 `X-EvidScope-Client`(프로그램 이름)와 `X-EvidScope-Session`(대화 묶음 id)을 주면 기록에 그대로 쓰고, 모델 서버로는
보내지 않습니다. 없으면 User-Agent의 첫 이름과 날짜로 묶습니다.

설정 파일(`~/.evidscope/local-model-proxy.json`, `EVIDSCOPE_PROXY_CONFIG`로 바꿀 수 있음):

| 키 | 기본값 | 뜻 |
|---|---|---|
| `url`, `token`, `hmacSecret` | hook 설정에서 복사 | EvidScope 수집 게이트웨이와 `agent` 출처 자격 증명 |
| `upstream` | `http://127.0.0.1:11434` | 실제 모델 서버 |
| `listen` | `127.0.0.1:11435` | 프록시 주소. 다른 PC에서 쓰게 하려면 바꾸되, 프록시에는 인증이 없으므로 사내망 방화벽 안에서만 |
| `provider` | `ollama` | `ollama`, `vllm`, `llama.cpp`, `local`, `other` |
| `screenContent` | `true` | 새 메시지·도구 결과의 보안 신호 검사 |
| `recordText` | `false` | 본문 보관(위 참고) |
| `heartbeatMs` | `600000` | 심장박동 간격(0이면 끔) |
| `actor`, `assetRef` | `local-model-proxy@<PC 이름>`, `asset.local-model-proxy.<PC 이름>` | 기록의 행위자와 AI 사용 현황의 자산 id |

## 한계

- 도구가 프록시를 거치지 않고 모델 서버를 직접 부르면 기록되지 않습니다. 사내망에서는 모델 서버를 프록시만 부를 수 있게(모델
  서버를 127.0.0.1에만 열고 프록시만 밖에 열기, 또는 방화벽) 막아야 "모든 호출"이 됩니다. 이 강제는 아직 설치 도구가 해 주지 않습니다.
- 모델이 부르려 한 도구는 이름만 기록합니다. 그 인자(실행할 명령 등)와 도구를 실제로 실행했는지는 프록시가 볼 수 없습니다. 실행은
  도구 쪽 기록(예: hook)과 대조해야 합니다.
- 모델의 응답 글은 해시만 남기고 보안 신호 검사는 하지 않습니다(검사하는 것은 모델에게 들어가는 글).
- 프록시가 있는 PC의 관리자는 프록시 설정·자격 증명을 읽어 앞뒤가 맞는 가짜 기록을 만들 수 있습니다. 사슬은 전송 중 유실·변경을
  보여 줄 뿐 기록 내용이 참이라는 증명이 아닙니다.
- 프록시가 꺼져 있는 동안 도구가 모델 서버를 직접 부르면 그 시간은 비어 보입니다. 심장박동이 끊긴 시간대로만 짐작할 수 있습니다.
- HTTPS 모델 서버 앞(upstream `https://…`)에도 둘 수 있지만, 프록시 자신은 HTTP로만 받습니다.
