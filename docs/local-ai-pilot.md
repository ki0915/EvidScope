# 실제 로컬 AI 1차 시험

2026-09-08 실제 Qwen3 0.6B 모델을 CPU 2개·메모리 2GB 제한의 전용 Ollama Docker 컨테이너에서 실행했다. 자료와 업무 도구는 합성 예제이며 모델 응답은 사전 작성한 mock이 아니다. 모델은 권한·감사 토큰이나 임의 파일/명령 실행 기능을 받지 않는다.

공식 [Ollama Docker](https://docs.ollama.com/docker), [tool calling](https://docs.ollama.com/capabilities/tool-calling), [Qwen3 0.6B 모델](https://ollama.com/library/qwen3:0.6b)을 확인했다. 받은 이미지 digest는 `sha256:32931b46719f673c05fdbaa81ccb26da18ea4a1c57590a754874ab28ba269eb2`, 모델 digest는 `7df6b6e09427a769808717c0a93cadc4ae99ed4eb8bf5ca557c90846becea435`다. 컨테이너 `evidscope-ollama-lab-20260908`, 볼륨 `evidscope-ollama-models-20260908`, 루프백 포트 11434만 사용한다.

`node scripts/local-ai-test.mjs`로 두 번의 실제 추론과 고정 자료 조회를 실행한다. `node scripts/verify-local-ai-test.mjs`는 별도 인간 감사자 권한으로 결과를 조회·검증한다. 모델 실행 도중 수집 응답을 기다려 업무를 차단하지 않고, 완료 후 수신 결과를 확인한다.

첫 두 실행은 모델이 도구 호출 없이 JSON 텍스트를 반환해 실패로 기록됐다. 자료 조회 요청과 답변 형식을 분리한 실행 `local-ai-1788871723465`에서 실제 함수 호출 → 버전 2 파일 읽기 → 모델의 버전 2 인용을 확인했다. 첫 추론 3.563초, 최종 응답 9.301초, 최종 출력 76토큰이다. 요청·실행·결과·모델 보고 4개 기록 모두 수집됐고, 같은 테넌트 서명 원장의 공개 이벤트 4개와 일치했다. `reports/local-ai-audit-verification.json`에 검증 결과를 저장했다. 서명 검증은 성공했지만 이전 독립 checkpoint를 주지 않았으므로 rollback 검증은 하지 않았다.

초기 실패 두 건의 파일도 보존한다. 이번 성공은 통계적 신뢰도·모델 안전성·범용 공급자 연동 완료를 뜻하지 않는다. 자료 조회 도구와 AI 관측은 서로 다른 source 키를 사용하지만 하나의 신뢰된 파일럿 프로세스이며 독립 호스트 격리를 입증한 것은 아니다. 권한/승인 이벤트를 만들어내지 않아 미등록 자산·권한 증거 누락 경보가 그대로 보인다. 실제 내부 사고 과정이나 자료의 인과적 사용을 입증하지 않는다.

다시 시험하지 않을 때는 `docker stop evidscope-ollama-lab-20260908`로 이 컨테이너만 중지할 수 있다. 다른 프로젝트나 클러스터를 중단하지 않는다. 모델 파일은 재실험을 위해 이름 있는 볼륨에 남아 있다.
