# 공개 한국어 근거 QA 추가 학습과 백업 검증 수정

## 완료된 제품 수정

백업의 테넌트 목록에서 `actions` 테이블이 빠져, 서명 이력이 없는 다른 테넌트의 위조 행동 행을 보존하면서 복구 성공으로 기록하는 문제를 재현했다. 이제 해당 테넌트도 서명 원장과 대조하므로 새 백업과 과거 형식의 정상 서명된 백업 복구에서 모두 거부한다.

- 호스트 관련 검사: 34/34 통과. `grounding-controller-recovery-tests-20261005.log`.
- 수정된 로컬 이미지: `evidscope:enterprise-20261005-r15`, ID `sha256:fc8394717ae08b489a5853804fa189788f98a098956790e4f270b8e7b5e1947c`.
- 비루트, 읽기 전용 파일시스템, 네트워크 없음, CPU 2개, RAM 1GiB 컨테이너에서 실제 복구 검사 17/17 통과. `enterprise-recovery-container-r15-20261005-retry.log`.
- 첫 컨테이너 검사는 테스트 전용 `scripts/init.mjs`가 없어서 실행되지 않았다. 테스트 지원 스크립트를 읽기 전용으로 연결한 재검증에서 통과했다. 첫 실패 로그도 보존했다.

## 추가 학습의 근거와 범위

기존 40단계 후보는 진단의 무답 32건 중 4건만 모든 조건을 충족했다. 기존 학습 320건에는 이미 무답 97건이 있었다. 단순한 무답 데이터 누락이 원인은 아니다. 실패 27건 중 25건이 문서의 실제 구절을 복사했으며, 10건은 원본 사람 주석의 유인 답변과 정확히 같았다. 조건·관계·부정 표현의 구별이 부족하다는 가설을 다음 실험에서 점검한다.

원본 공개 사람 주석 KLUE-MRC에서 새 학습 640건(답 있음/없음 각각 320)과 새 검증 64건(각각 32)을 결정적으로 선정했다. 기존 학습·검증 및 관찰한 진단의 ID, 문서군, 본문 중복은 제외했다. 전체 문서를 보존하고 답 위치에 따른 자르기를 하지 않는다. 실제 베이스 토크나이저 검사에서 704건 모두 통과했으며 최대 579토큰이었다.

검증된 Foundation-Sec-8B-Reasoning의 기존 40단계 adapter만 초기 가중치로 가져온다. 새 optimizer/scheduler를 사용한 20회 갱신을 별도 실험으로 기록한다. 이는 optimizer 상태를 60단계로 이어 받은 실행이 아니다. Batch 1, 누적 16으로 새 학습 640건 전체의 한 epoch를 끝내는 실행도 아니다. 사람 작성 공개 주석을 사용하지만 로컬 사람 검토·금융 감사 품질 승인으로 표시하지 않는다.

NF4, rank 8, 최대 길이 1024, CPU 2개, RAM 12GiB, GPU 할당 비율 0.65와 실측 메모리·온도 중단 조건을 유지한다. GPU 비율은 PC 전체의 강제 격리로 표현하지 않는다.

## 실행 상태

첫 추가 실행 `public-qa-grounding-20261005-r1`은 Kubernetes가 삽입한 ConfigMap 기본값을 볼륨 검사에서 처리하지 못해 가중치 갱신 전에 중단됐다. `live_grounding_mount_scope_invalid`, Pod 회수 확인, 실패 영수증 보존. 수정 후 별도 실행과 실제 결과를 아래에 기록한다.

두 번째 실행 `public-qa-grounding-20261005-r2`은 FP16의 8번째 optimizer 시도에서 수치 오버플로로 실제 갱신 1회가 누락됐다. 성공으로 처리하지 않고 해당 Job의 UID를 확인한 뒤 중단했다. 전체 학습 로그와 마지막 checkpoint-10 기준 종료 코드 75, 실제 갱신 9회/시도 10회, 후보 없음. 컨트롤러는 외부에서 삭제한 Job을 찾지 못해 `terminationConfirmed:false`를 기록했다. 이 실패 기록을 수정하지 않고, 이후 별도 종료 대조에서 컨트롤러 종료·해당 namespace Job/Pod 0개·GPU 회수를 확인한 뒤 자신의 lease만 해제했다.

RTX 3080의 네이티브 BF16 지원과 실제 BF16 행렬 연산 유한값을 별도 GPU Pod로 실측했다. 세 번째 실행 `public-qa-grounding-20261005-r3`는 로그에서 실제 4회 갱신·누락 0회를 관찰했으나 Windows의 API 조회 소켓 `invalid pointer address` 오류로 중단됐다. 종료 때 checkpoint-5가 저장됐고 완료된 후보는 없다. 컨트롤러 종료·Pod 삭제·GPU 회수가 확인됐으며 실패 출력은 별도 디렉터리에 보존했다. 읽기 조회에만 최대 3회 재시도하고 같은 노드 UID를 확인한 내부 조회로 한 번 전환하도록 수정했다. 변경 작업은 재시도하지 않는다. 컨트롤러 6개 검사와 별도 검토자가 수행한 읽기 전용 검토를 통과했다.

기존 FP16 재개 경로를 보존하기 위해 공유 kbit 준비 파일은 원래 해시로 복구하고 BF16 준비 코드를 별도 helper로 분리했다. r3의 ConfigMap `public-qa-grounding-5c0e85cfedf347cc`와 provenance `25ace99fdafb68d16c33ea2e5b94e16006e3abc2e24ca880d0546ab372db731c`는 수정하지 않았다. 새 r4 실행은 별도 입력·출력 디렉터리와 ConfigMap `public-qa-grounding-b2c3ff71ba1db0fb`를 사용한다. 기본 실행 ID와 실제 평가 대상 ID를 혼동하지 않도록 생성 진단은 검증 보고서의 실제 `runId`를 사용한다. GPU allocator 비율·NF4·rank·길이·CPU/RAM 한도는 동일하다. 마지막 후보는 GPU에서 유한값을 검사하고, 별도 검증기가 candidate와 checkpoint-10/20의 256개 LoRA F32 텐서를 CPU에서 독립적으로 검사한다.

전체 호스트 회귀 검사 628개 중 626개 통과. 두 실패는 모두 Windows `listen EFAULT`이며 해당 복구·보존 23개를 분리 재실행해 23/23 통과했다. 전체 실행을 모두 통과한 것으로 표시하지 않는다. 실패와 재검증 로그를 모두 보존했다.

## r4 실제 완료와 재부팅 뒤 확인 (2026-10-06)

`public-qa-grounding-20261005-r4`는 2026-10-05T08:03:20Z에 추가 optimizer 갱신 20회, 누락 0회로 완료됐다. 기존 40회 adapter의 초기 가중치를 사용한 별도 optimizer 실행으로 adapter 계보상 합계는 60회이며 optimizer 60단계 재개가 아니다. 새 학습 데이터의 0.5 epoch를 소비했다. 런타임은 965.2027초, 검증 loss는 같은 베이스 1.2803634405에서 adapter 적용 0.0775439441이다. 이것을 생성 답변·무답 보류·금융 감사 품질 개선으로 해석하지 않는다.

재부팅 뒤 PVC 원본과 로컬 전체 내보내기의 주요 파일 6개 해시를 대조했다. 후보와 checkpoint-10/20을 독립 CPU 검증기에 넣어 실제 step, 재개 상태, 256개 F32 adapter 텐서 6,815,744개 요소의 유한값을 확인했다. adapter SHA-256은 `c3b836df159917cd9ababd61ed9f574ac5b77252b8ec058a66269b045c78d9f6`이다. 최종 [실행 검증 JSON](public-qa-grounding-verification-20261005.json)의 `actualTrainingExecutionVerified`, `trainingRunCompleted`, `terminationConfirmed`는 true, `qualityClaimAllowed`, `promotionAllowed`는 false다.

2026-10-06 Docker가 중단 상태에서 또 소켓 초기화에 실패했다. Docker 프로세스가 없는지와 대상 경로·파일 속성을 확인하고 중단된 두 소켓 디렉터리만 같은 부모 아래로 보존한 후 엔진을 복구했다. 이미지·볼륨·사용자 설정은 삭제하지 않았다. 학습 namespace의 Job/Pod 0개, 학습 전 실행 중이던 DLP 컨테이너 5개 모두 원래 전체 ID로 복구, 전용 GPU 노드 정지, lease 해제를 별도 영수증에서 확인했다.

새 후보의 64건 생성 비교는 아직 실행하지 않았다. 확인 시 물리 여유 7.501GiB, Windows commit 여유 5.196GiB가 14GiB 시작 기준에 못 미쳤다. 현재 완료한 가중치 학습과 미완료 답변 평가를 구분하며 자원 부족 상태에서 GPU 작업을 중복 시작하지 않았다.
