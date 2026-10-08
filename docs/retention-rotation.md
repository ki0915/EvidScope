# 정기 로테이션: 일상 기록의 주기적 파기와 운영 로그 관리

> 2026-10-08 개선 7라운드에서 추가한 기능입니다. 기존 보존 정책·보존 보류(hold)·두 사람 파기 계획은 그대로이며,
> 이 문서는 그 위에 얹은 **사전 승인된 정기 파기**와 접근 기록·프로세스 로그의 크기 관리를 설명합니다.

## 무엇을 하는가

"중요 정보가 아니면 로그는 주기적으로 로테이션해야 한다"는 요구에 맞춰, 일상적인 이벤트 분류는 기간이 지나면 사람이 매번
계획을 세우지 않아도 정해진 주기로 파기할 수 있게 했습니다. 다만 파기는 되돌릴 수 없으므로 다음 원칙을 코드와 오프라인 검증기에서
함께 강제합니다.

- **기본값은 꺼짐입니다.** 배포 설정 `RETENTION_ROTATION_INTERVAL_MS`가 없으면 스케줄러가 돌지 않고, 설정해도 tenant마다
  두 사람이 활성화한 로테이션 정책이 없으면 아무것도 파기하지 않습니다.
- **두 사람이 미리 승인합니다.** 검토자(reviewer 또는 admin)가 정책을 제안하고, **제안자가 아닌 관리자(admin)**가 활성화해야
  효력이 생깁니다. 한 사람은 정책을 켤 수 없고, 즉시 **끌 수만** 있습니다(중지는 안전한 방향이므로 검토자 한 명으로 충분).
  다시 켜려면 새 제안과 다른 관리자의 승인이 필요합니다.
- **보존 보류와 미종결 사건이 항상 우선합니다.** 해당 행동(`actionId`)에 활성 hold가 있거나, 테넌트 전체 hold가 있거나,
  닫히지 않은 사건이 있으면 그 이벤트는 건너뜁니다. 이벤트 봉투의 `retainUntil`(접수 당시 보존 정책)도 지나야 합니다.
- **중요 기록 분류는 지정할 수 없습니다.** 아래 표의 분류만 "일상"으로 지정할 수 있고, 나머지는 제안 단계에서 400으로 거부되며
  누군가 서명 키로 원장에 억지로 넣어도 검증기가 거부합니다.
- **원장은 잘리지 않습니다.** 여기서 "로테이션"은 이벤트 내용의 암호키와 검색 사본을 파기하는 것이며, 서명 원장 레코드·해시
  체인·접수 영수증·파기 기록은 그대로 남습니다. 파일을 잘라 내거나 오래된 원장 구간을 지우는 기능이 아닙니다.

## 로테이션할 수 있는 분류와 할 수 없는 분류

분류는 `출처 종류(sourceKind) / 이벤트 종류(kind) / 데이터 민감도(sensitivity)`입니다. 민감도는 이벤트의 `dataCategories`로
정합니다. 비어 있으면 `none`, 레지스트리 위험 규칙의 민감 범주(personal, health, financial, credential, 주민등록번호 등)가 하나라도
있으면 `sensitive`, 그 밖은 `standard`입니다. 정책에서는 `kind:"*"`(그 출처의 일상 종류 전체)와 `sensitivity:"any"`를 쓸 수 있습니다.

| 출처 종류 | 로테이션 가능(일상) | 로테이션 불가(중요) |
|---|---|---|
| agent | intent, self_report, delegation | — |
| tool | execution, result | — |
| telemetry | heartbeat, notice | gap(수집 공백), governance_check(조항별 검증) |
| otlp | notice, self_report | — |
| authority | — | grant, revoke, human_approval, automated_review, human_oversight_review, governance_check 전부 |
| safety | — | stop_requested, block_registered, stop_confirmed, safety_alert 전부 |
| enforcement | — | policy_decision, guardrail_decision, bundle_activation 전부 |

정책 결정·승인·중지 명령·레지스트리·사건·평가·보존 정책·hold는 이벤트가 아니라 서명 객체 레코드이므로 처음부터 파기할 키가
없습니다. 분석 결과(finding)의 입력 이벤트는 그 행동에 미종결 사건이나 hold가 있는 동안 보호됩니다.
여러 정책 분류가 한 이벤트에 맞으면 **가장 긴 기간**을 적용합니다.

## 두 사람 사전 승인의 흐름

```text
POST /api/retention/rotation                 검토자 A: 제안(status proposed, 7일 안에 승인 필요)
POST /api/retention/rotation/{id}/approve    관리자 B(≠A): 활성화(status active, validUntil = 승인 시각 + validDays)
POST /api/retention/rotation/{id}/reject     검토자: 제안 반려
POST /api/retention/rotation/{id}/suspend    검토자 한 명: 즉시 중지
POST /api/retention/rotation/run             관리자: 지금 한 번 실행(스케줄러와 같은 함수)
GET  /api/retention/rotation                 감사자 포함 모든 사람 역할: 상태 조회
```

제안 본문 예시입니다. 기간은 초 단위이며 1초~10년, 정책 유효기간 `validDays`는 1~1095일(기본 365일),
1회 실행 최대 파기 건수 `maxPerRun`은 1~1000(기본 1000)입니다.

```json
{
  "classes": [
    {"sourceKind": "telemetry", "kind": "heartbeat", "sensitivity": "any", "retentionSeconds": 2592000},
    {"sourceKind": "agent", "kind": "intent", "sensitivity": "none", "retentionSeconds": 7776000}
  ],
  "accessLogRetentionSeconds": 63072000,
  "validDays": 365,
  "purpose": "일상 heartbeat·intent 최소 보관",
  "reason": "개인정보 없는 운영 신호; 법무 검토 2026-10-08"
}
```

정책은 `retention_rotation` 서명 객체로 저장됩니다. 상태가 바뀌어도 `terms`(분류·기간·접근 기록 기간·유효 일수·목적·근거)는
제안 그대로여야 하며, 검증기는 제안 레코드의 서명 주체가 제안자이고 활성화 레코드의 서명 주체가 제안자와 다른 승인자인지
확인합니다. 새 정책을 활성화하면 이전 활성 정책은 `superseded`가 됩니다. 정책 유효기간이 지나면 실행은 `policy_expired`로
멈추며 다시 두 사람 승인이 필요합니다.

## 정기 실행이 남기는 것

`RETENTION_ROTATION_INTERVAL_MS`(최소 1000ms, 예: 3600000)를 설정하면 vault가 그 주기로 각 tenant를 실행합니다. 한 번의 실행은
하나의 쓰기 트랜잭션에서 다음을 합니다.

1. 서명 원장·객체·행동 사본을 검증하고, 정책 이력 전체를 오프라인 검증기와 같은 함수로 확인합니다. 이력이 맞지 않으면 실행을 거부합니다.
2. 기간이 지났고(원장 기록 시각 기준), `retainUntil`이 지났고, hold·사건이 없는 일상 분류 이벤트를 최대 `maxPerRun`건 고릅니다.
3. 수동 파기와 같은 방법으로 키와 검색 사본을 지우고, 정책 레코드 해시·버전과 이벤트별 분류를 담은 `retention_disposition`과
   실행된 `retention_plan`(작성자·승인자는 정책을 승인한 두 사람)을 `retention-rotation` 주체로 서명합니다.
4. 방금 쓴 원장을 다시 검증기에 넣어 보고, 통과하지 못하면 트랜잭션 전체를 되돌립니다.

파기된 이벤트를 입력으로 쓴 평가는 지금과 같이 `--replay`에서 `not_replayable`(`erased_input`)로 표시되고, 나머지 평가는 그대로
재현됩니다. 복구 프런티어(`vault-recovery`)도 정기 파기 계획을 받아들여 오래된 백업에서 복원할 때 같은 이벤트를 다시 파기합니다.
기존 export·백업·외부 사본과 디스크 잔존물은 이 기능으로 파기되지 않으므로 기존과 같이 별도 절차가 필요합니다.

## 감사인이 확인하는 방법

```bash
node scripts/verify.mjs export.json trust-anchor.pem --replay
```

export에 로테이션 정책이나 정기 파기 기록이 있으면 결과에 `retentionRotation`이 붙고, 하나라도 어긋나면 종료 코드 1입니다.
검증기는 다음을 원장 레코드만으로 확인합니다.

- 모든 정책 레코드에 중요 분류가 없고, 제안·활성화가 서로 다른 두 서명 주체이며, 활성화가 제안 유효기간 안에 있었는지
- 정기 파기가 당시 **활성** 정책 레코드(해시 일치)를 가리키고, 그 유효기간 안에 `retention-rotation` 주체로 실행됐는지
- 파기된 각 이벤트의 분류가 일상 분류이고 정책이 이름 붙인 분류이며, 원장 기록 시각부터 정책 기간과 `retainUntil`이 지났는지
- 그 시점에 해당 행동의 활성 hold·테넌트 전체 hold·미종결 사건이 없었는지

화면의 **보존 · 파기 검토 → 정기 로테이션** 카드는 활성 정책과 분류, 스케줄러 상태(주기·마지막 실행·다음 실행), 서명된 정기
파기 횟수와 분류별 파기 건수, 접근 기록 정리 경계를 보여 줍니다. 감사자는 읽기만 하고, 제안·승인·중지는 서버가 역할을 확인합니다.

**한계:** 파기된 이벤트의 분류는 파기 시점에 vault가 복호화해 서명한 주장입니다. 내용이 사라진 뒤에는 검증기가 암호문에서 분류를
다시 계산할 수 없으므로, 분류를 독립적으로 대조하려면 파기 전에 받은 export(공개 내용 포함)와 비교해야 합니다. 행동 ID가 봉투에
평문으로 없는 초기 v1 봉투는 hold·사건을 오프라인으로 확인할 수 없으므로 정기 로테이션 대상에서 제외합니다. 한 번의 실행은 tenant
원장 전체를 복호화해 고르므로 큰 tenant에서는 쓰기 잠금 시간이 길어질 수 있습니다(수동 파기 계획과 같은 비용).

## 접근 기록(access-log.db) 정리

조회 기록은 `access-log.db`에 해시 체인으로 쌓이고, 일정 단위로 원장의 `audit_access_batch` 레코드(건수·체인 머리·Merkle 루트·
첫/마지막 시각)에 봉인됩니다. 정책에 `accessLogRetentionSeconds`를 넣으면 정기 실행이 **봉인이 끝났고 마지막 기록이 그 기간보다
오래된 배치**까지를 정리합니다.

- 하한은 1년입니다. 개인정보처리시스템 접속기록은 1년 이상(대규모·민감 처리 시 2년 이상) 보관해야 하므로
  (개인정보의 안전성 확보조치 기준 제8조) 더 짧게 지정할 수 없습니다. 실제 기간은 조직의 법무 검토로 정하세요.
- 먼저 `audit_access_prune` 레코드(정리 경계 = 어떤 배치의 끝 순번과 체인 머리, 정책 레코드 해시)를 원장에 서명하고, 그 커밋이
  끝난 뒤에만 경계 이하의 행을 지웁니다. 중간에 멈추면 행이 남을 뿐이며 다음 실행이 마저 지웁니다.
- `access-log.db`의 삭제 트리거는 tenant별 정리 경계(`access_log_floor`) 위의 행 삭제를 계속 막고, 경계는 줄어들 수 없습니다.
  기존 파일은 처음 열 때 한 번 이 트리거로 바뀝니다.
- 테넌트 전체 hold가 있으면 접근 기록도 정리하지 않습니다.
- 정리 후에도 배치 레코드가 남으므로 배치 사이의 체인 연결과 이후 모든 기록, 아직 남은 기록의 변조·누락은 그대로 검증됩니다
  (`/api/integrity`, 백업 검증, `verifyAccessBatches`). 정리된 기록 자체와 그 포함 증명은 더 이상 제공되지 않습니다(404).
  검증기는 서명된 경계 아래의 행만 없어도 되는 것으로 인정합니다.

## 프로세스 로그(stdout·stderr)

EvidScope는 로그 파일을 직접 쓰지 않습니다. 서버는 시작 정보와 오류를 stdout·stderr에 대부분 한 줄 JSON으로 쓰며, 증거 검증은 이 출력에
의존하지 않습니다. 크기 관리는 실행 환경에 맡깁니다.

- **컨테이너:** Docker는 `json-file` 드라이버에 `--log-opt max-size=10m --log-opt max-file=5`처럼 상한을 두고, Kubernetes는
  kubelet의 `containerLogMaxSize`·`containerLogMaxFiles`(기본 10Mi·5개)로 회전합니다. 중앙 수집기로 보내는 경우 그쪽 보존기간을 정하세요.
- **systemd:** journald의 `SystemMaxUse=`·`MaxRetentionSec=`로 상한을 둡니다.
- **파일로 리디렉션한 경우:** logrotate에서 `copytruncate`를 쓰거나 서비스를 재시작하는 `postrotate`를 두세요. 예:

```text
/var/log/evidscope/*.log {
  daily
  rotate 14
  maxsize 50M
  compress
  missingok
  notifempty
  copytruncate
}
```

`evidence.db`, `evidence.db-wal`, `access-log.db`, 키 파일, 투명성 상태 파일은 로그가 아닙니다. logrotate나 정리 스크립트의 대상에
넣지 마세요. 이 파일을 지우거나 자르면 검증이 실패하고 복구가 필요합니다.
