# 제33조 선택적 확인 요청의 감사 화면 표시

2026-10-06. 독립 검토에서 확인한 화면 누락을 수정했다. 소유 범위는 `public/app.js`의 `governanceTechnicalEvidence` 렌더러, `test/governance-ui.test.mjs` 및 보고서다. 평가 함수·서비스·학습·작업·검증기·출시 아카이브는 이번 표시 수정에서 변경하지 않았다.

## 증상과 수정

API는 필수 사전 검토 지원과 선택적 요청 상태를 분리했지만 화면은 `optionalWorkflows`를 읽지 않았다. 필수 검토가 지원 상태일 때 선택적 요청의 미접수·실패·잘못된 출처 사유와 연결 증거가 일반 감사 화면에서 보이지 않았다. 원시 JSON 상세 보기에는 데이터가 있었지만 업무 상태로 표시하지 않았다.

`public/app.js:715–725`에서 기존 `message`, `muted`, `table`, `limits`를 사용해 **선택적 확인 요청** 영역을 별도로 표시한다.

- 요청하지 않음, 요청 여부 미확인, 접수 근거 없음, 요청 근거 부족·충돌, 접수 보고 근거 연결을 구별한다.
- 추가 확인 사유·누락은 기존 한국어 조치·사유 설명을 이용한다. 연결된 요청 근거의 종류·원본 기록 참조·문서 해시와 workflow 한계를 함께 표시한다.
- 필수 사전 검토와 별도로 추적하며, 접수 보고 근거가 정부 회신·고영향 해당성 결정·법적 준수 완료를 뜻하지 않는다고 표시한다.
- 미지의 상태는 숨기지 않는다. 상태가 접수 지원이어도 `supportsRequestReceipt`가 true가 아니면 미확인으로 표시한다. 과거 보고서에 optionalWorkflows가 없으면 기존 표시를 유지한다.

DOM 요소의 textContent 경로를 사용하며 외부 사유·참조를 HTML로 삽입하지 않는다.

## 검증

새 검사 `test/governance-ui.test.mjs:87,107`는 수정 전에 **12개 중 10 통과·2 실패**했다. 선택적 요청 영역 부재와 실패 사유 부재를 직접 검출했으며 로그는 `reports/kr-governance-33-ui-before-20261006.log`에 보존했다.

수정 후 governance UI, finance UI, UI language/state의 관련 3파일은 **30/30**, 실패·취소·건너뜀 0, exit 0, 439.7727ms다. 로그: `reports/kr-governance-33-ui-after-20261006.log`.

```powershell
node --test --test-concurrency=1 test/governance-ui.test.mjs test/finance-ui.test.mjs test/ui-language-state.test.mjs
```

검사는 VM-DOM에서 실제 앱 렌더러와 governanceReport 경로를 실행했다. 필수 검토의 지원 메시지를 유지하면서 다섯 선택적 상태, 미접수·잘못된 출처·실패 사유, 원본 참조·문서 해시, 미지 상태, 접수 지원 여부가 불일치하는 입력, 과거 응답을 검사했다. 공격용 태그 문자열은 문자로 남고 IMG/SCRIPT 요소가 생성되지 않았다. 브라우저 시각 QA나 실제 기관 연동 결과로 확대하지 않는다. 이전 수정의 실제 HTTP 증거는 `reports/kr-governance-33-fix-20261006.md`에 별도로 기록되어 있다.

검증한 파일 SHA-256:

- `public/app.js`: `66d185c4aadf5ba2217438df199813bfa9665ca70f5ed528383736f40f6aaaa0`
- `test/governance-ui.test.mjs`: `d1aef9b9bd8b5142d231b46ab8bcfac211410d640920e2baf464a94470bcc012`

검사 프로세스는 종료했으며 추가 수정 예정이 없다. 전체 제품 회귀와 후속 패키징은 root의 동결 후 검증 범위다.
