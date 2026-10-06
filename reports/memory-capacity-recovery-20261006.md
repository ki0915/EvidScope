# Windows 커밋 메모리 확장과 학습 평가 입장 검증

2026-10-06. 사용자의 메모리를 줄이거나 늘려 실제로 해결하라는 요청에 따라 PC의 페이지 파일을 **실할당 16GiB에서 30GiB로 확대**했다. 재부팅이나 사용자 앱 종료 없이 현재 커밋 한도가 **47.863→61.863GiB**로 증가했다. 초기 진단 커밋 여유는 2.581GiB였고 영구 설정 확인 시 17.646GiB였다. 물리 RAM은 기존 32GB 그대로다.

## 조치와 검증

- 실제 Win32_PageFileUsage는 AllocatedBaseSize 16384→30720MiB로 변했다. initial/max 설정도 30720/30720MiB를 WMI로 다시 읽어 확인했다.
- 디스크 여유에서 추가 할당분을 뺀 뒤 최소 10GiB를 남기는 사전 조건을 강제했다. 영구 설정 확인 시 C드라이브 여유 13.011GiB였다.
- 먼저 Docker WSL의 쓰기를 동기화하고 재생성 가능한 파일 캐시만 반환했다. 당시 커밋 여유는 2.753GiB로 여전히 부족하여 캐시 반환만으로 해결됐다고 기록하지 않았다.
- 관리자 승인으로 내부 `NtCreatePagingFile` 확장을 수행했고 status 0, 실할당과 커밋 한도 증가를 따로 확인했다. 기존 파일만 확장했으며 추가 페이지 파일, 메모리 압박을 유도하는 강제 할당, 자동 재부팅을 사용하지 않았다.
- live 확장 이후 CIM 영구 설정 변경은 범위 오류로 실패했다. 원인은 미확인이다. 이 부분 실패 영수증을 보존하고, 별도 관리자 작업에서 검증된 기존 `PagingFiles` 한 항목을 typed REG_MULTI_SZ로 변경했다. 레지스트리·WMI·실할당을 함께 확인했고 ExistingPageFiles나 자동관리값을 변경하지 않았다.

원본 증거: `.test-runs/memory-diagnosis-20261006.json`, `.local/training/pagefile-resize-20261006-r1/before.json`, `result.json`(처음 부분 실패), `persistent-before.json`, `persistent-result.json`(영속·실제 적용 성공). 앞선 실패 기록을 성공으로 덮어쓰지 않았다.

## 기존 학습 기준으로 재검증

최신 검증된 `public-qa-grounding-20261005-r4` 후보의 파일·계보를 다시 검증했다. 메모리 확대 전 검사 `public-qa-gdiag-20261006-r2`는 커밋 여유 1.656/2.449/2.296GiB로 차단됐다.

확대 후 `public-qa-gdiag-20261006-r3`의 안정성 검사 3회는 다음과 같다.

| 표본 | 물리 메모리 여유 GiB | 커밋 여유 GiB | 커밋 사용 % | GPU 사용 MiB |
|---|---:|---:|---:|---:|
| 1 | 6.863 | 17.658 | 71.456 | 1994 |
| 2 | 6.920 | 17.646 | 71.475 | 1987 |
| 3 | 6.914 | 17.703 | 71.383 | 1986 |

기존 시작 기준 **커밋 여유 14GiB**·물리 여유 4GiB·GPU 여유 9216MiB를 낮추지 않았고, `admission.allowed=true`, `reasons=[]`, `state=ready_check_only`를 확인했다. 이는 현재 자원 입장 조건의 통과이며, 새 GPU Job·역전파·생성 평가를 수행했다는 증거는 아니다(이번 검사 modelCalls 0). 해당 컨트롤러들은 종료됐고 GPU 노드는 정지 상태다. 실제 실행 시 다시 자원·GPU·네트워크·PVC와 Job identity를 검사한다.

## 제품 진행 상태

거버넌스 변경 권한 누락을 수정해 작업 파일럿을 v0.1.1로 재시작했다. 기존 데이터와 키를 유지했으며 실제 시스템 2개 조회, 감사자 변경 403, 네 서비스 readyz 200을 확인했다. 실행 영수증 `releases/evidscope-0.1.1-working-runtime.json`은 설치 아카이브의 최종 승인 영수증과 구별한다.

보안 패치 설치 반복은 첫 3회 39/39, 4회차는 원인 미확인 fetch failed 1건으로 실패했다. 전체 설치는 756/757였으며 한 실패는 긴 Windows 경로의 Git 오류로 별도 재현했다. Windows Git 호출에만 core.longpaths=true를 적용했고 원래 기능과 새 긴 경로 회귀가 독립 2/2를 통과했다. 다음 전체 설치의 일시적인 lease rename EPERM은 분리 실행 5/5에서 재현되지 않았다. IPv4 재실행의 listen EFAULT도 보존했다. IPv6 루프백을 명시한 새 설치 전체는 **758/758**를 통과했다(`security-release-install-regression-r2-retry-ipv6-20261006.log`). 10회 반복은 별도 새 디렉터리 `security-release-20261006-r2-retry`에서 순차 실행한다. 이전 실패를 통과로 집계하지 않는다.

## 메모리 복구 후 실제 GPU 실행 완료

`public-qa-gdiag-20261006-r4`는 최신 학습 후보의 답변 **64건을 실제 생성**했다. 컨트롤러는 `process_completed`, exit 0, `terminationConfirmed=true`를 기록했다. PVC 출력 68개 파일을 내보내 원본과 해시를 대조했고, 별도 실행 검증기도 `evaluationExecutionVerified=true`를 확인했다. 실제 Job·Pod와 내보내기 Pod를 제거한 뒤 전용 GPU 노드를 정지했다. 기존 DLP 컨테이너의 ID·실행 상태·자원 및 재시작 설정은 보존했다. 위의 r3 입장 검사와 별도의 실행이다.

실측 자원 최솟값·최댓값과 OOM 여부는 [실행 자원 영수증](public-qa-grounding-memory-execution-20261006.json)에 기록했다. 메모리 정책을 낮추지 않았고, 메모리 부족 종료나 자원 중단은 없었다. 페이지 파일 증설과 함께 NF4 모델, CPU 2·컨테이너 상한 12GiB, 실제 `memory.high=2GiB`로 파일 캐시 압력을 제한했다. GPU 할당 비율은 강제적인 전체 GPU 격리로 표현하지 않는다.

이번 실행은 **추가 역전파 학습이 아니라, 이미 학습한 후보의 생성 진단**이다. 이전 40-update 후보와 최신 60-update 이력 후보를 같은 과거 관측 64행에서 대조한 자동 채점은 16→25건 통과였다. 답변 가능한 32행은 12→9건으로 감소했고, 답변 불가능한 32행의 올바른 판단 보류는 4→16건으로 증가했다. 과도한 판단 보류와 회귀가 남아 있으므로 새 품질 승인·운영 승격을 허용하지 않았다. 이전 후보의 출력은 고정된 과거 실행을 재사용했으며 이번에 다시 생성하지 않았다.

근거: [실행 검증](public-qa-grounding-diagnostic-verification-20261006-r4.json), [문항별 비교](public-qa-grounding-comparison-20261006-r4.json). 물리 RAM은 32GB 그대로이며, 페이지 파일이 물리 메모리의 처리 속도를 늘린다는 의미는 아니다.

## 설정 근거

[Microsoft 페이지 파일 설명](https://learn.microsoft.com/en-us/troubleshoot/windows-client/performance/introduction-to-the-page-file)은 커밋 한도와 페이지 파일의 관계를 설명한다. [Win32_PageFileSetting](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-pagefilesetting)의 부팅 설정과 현재 실할당을 구분했다. [Microsoft Windows Support 팀의 설정 방법](https://jpwinsup.github.io/blog/2023/02/08/Performance/Hang_BSOD/HowToChangePagingFileSetting/)에 따라 REG_MULTI_SZ의 초기·최대 크기를 읽기 확인했다. 내부 확장 API를 모든 Windows 버전에서 지원되는 공개 API로 표시하지 않는다.
