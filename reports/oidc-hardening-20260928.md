# OIDC 통합·검증 기록 — 2026-09-28

**최종 코드 전체 회귀: 367/367 통과, 실패·skip 0, 72.1초.** [최종 로그](enterprise-tests-final-20260928.log). 아래 315건·47건 등은 구현 중간 검증이며 최종 실행은 객체 무결성 검사까지 포함한다.

조직 로그인, 테넌트·역할 결합, 세션 만료·회수, 서명 접근 상태, 감사 UI를 기존 vault와 audit gateway에 연결했다. 기본 로컬 실행 설정은 유지하며 실제 조직 IdP를 활성화하지 않았다. 설치·배포 절차는 [운영 문서](../docs/oidc-authentication.md)에 기록했다.

- 코드 교환: RS256 서명, issuer·audience·state·nonce·PKCE·auth_time·선택 ACR 검증. 브라우저별 flow cookie, 재사용 거부, 고정 callback.
- 권한: 서버 소유 issuer/subject 매핑. IdP 임의 role·tenant 속성 무시. OIDC에서 인간 Bearer 자격 거부, 수집기 HMAC·worker 유지.
- 세션: opaque HttpOnly cookie, 운영 HTTPS의 Secure·__Host- 속성, 고정 Origin·CSRF, 유휴·절대 만료, 즉시 회수·접근 중지, 재시작·복구 시 기존 세션 무효.
- 보존: ID/access/refresh token, PKCE·flow state, cookie·CSRF는 증적 DB에 저장하지 않음. 접근 변경과 사유만 서명 원장에 저장. 백업 검증의 객체 유형에 `identity_access` 추가.
- 성능: 별도 검토자가 인증마다 전체 원장을 다시 검증하는 비용을 지적했다. 최초 전체 체인과 이후 새 기록·캐시 기준점을 검증하는 상태 캐시를 연결했다. unsigned 객체 사본을 권한으로 신뢰하지 않는다. 과거 전체 바이트의 매 요청 무결성 검사를 뜻하지 않는다.

## 실행한 검증

| 범위 | 결과·근거 |
|---|---|
| 서명 상태 캐시·HTTP·HTTPS·UI 집중 회귀 | 35/35 통과 |
| 전체 기존 회귀 | 315/315, 실패·skip 0, 약 70.3초. [원본 로그](enterprise-tests-20260928.log) |
| 실제 브라우저 | Codex in-app browser → 합성 IdP → 독립 audit/vault. 로그인, 관리자 계정 조회, 자기 세션 회수, 재로그인, 로그아웃 확인 |
| 브라우저 변경의 원장 검증 | session_authorized 2회, revoke_sessions 1회, session_logout 1회. 서명 체인 9행 검증. [기록](oidc-browser-20260928.json) |
| 브라우저에서 발견한 표시 오류 | 익명 상태 확정 후 ‘접속 방식 확인 중’이 남는 오류 수정. 이후 관련 UI 27/27 통과, 실제 브라우저에서 ‘인증 필요’ 표시 확인 |
| 독립 최종 코드 검토 | 별도 검토자가 현재 호출 경로의 인증 우회·오래된 권한 적용 결함을 찾지 못함. 운영 적합성 인증을 의미하지 않음 |

최종 367건 회귀는 익명 인증 상태 표시 수정과 후속 정책·객체 무결성 변경을 포함한다. 실제 브라우저의 합성 서버·탭은 종료했다. 검증 캡처: [세션 회수 완료](oidc-session-revoked-20260928.png).

추가 측정: 합성 원장 20,001행·25,658,052 bytes에서 기존 전체 재검증 조회 p50 312.62ms, 증분 캐시 조회 p50 0.177ms, 최초 검증 326.67ms, 새 2행 반영 0.216ms였다. GPU 학습과 같은 PC에서 실행한 단일 프로세스 직접 SQLite 측정이며 HTTP SLO가 아니다. [원자료](identity-cache-benchmark-20260928.json), 재현: `node scripts/benchmark-identity.mjs 20000 <report.json>`.

`npm audit --omit=dev`의 이번 조회에서 공개 advisory 0건을 반환했다. [결과](npm-audit-20260928.json). 취약점 부재 인증이나 컨테이너 전체 취약점 검사를 의미하지 않는다. Dockerfile의 고정 npm 설치와 `.dockerignore`의 두 package 파일 허용을 함께 반영했다.

실제 이미지 실행에서 필수 `roles/` 파일 누락으로 서버 시작이 실패하여 Dockerfile과 빌드 허용 목록에 추가했다. 수정 이미지 `evidscope:enterprise-20260928`에서 인증·객체/정책 무결성·백업 복구·학습 컨트롤러 종료 회귀 **95/95 통과**(2.6초). 외부 네트워크 차단, 읽기 전용 rootfs, UID1000, CPU2, RAM1GiB, 임시 파일시스템으로 실행했으며 시험 fixture와 CLI scripts만 읽기 전용 mount했다. 실제 배포는 하지 않았다. [빌드](container-build-20260928.log), [실행 로그](container-tests-20260928.log), [이미지 식별](container-image-20260928.json). 이미지 manifest list digest는 `sha256:d63c1880b212daaa666affe0409ca8754a5cad98194f821040aff6899467a92e`다. 컨테이너 전체 OS 취약점 검사는 아직 수행하지 않았다.

npm 의존성 [CycloneDX SBOM](npm-sbom-20260928.json)을 생성했다. openid-client6.8.8·oauth4webapi3.8.8·jose6.2.12, 모두 기록된 MIT 라이선스다. OS 패키지 SBOM은 포함하지 않는다. 공식 Docker registry에서 Node24.15.0-bookworm-slim index digest `sha256:4e6b70dd6cbfc88c8157ba19aa3d9f9cce6ba4703576d55459e45efcbc9c5f5d`를 확인해 Dockerfile에 고정했다. image tag만으로 최신성·보안성을 추정하지 않는다.

후속 정책 감사에서 룰·예외·거버넌스 작업의 조회 사본 재서명 경로를 수정했다. 전체 회귀 315건은 이 후속 변경 전 결과이며, 후속 변경에는 [별도 HTTP·회귀 47/47](policy-integrity-tests-20260928.log)을 실행했다. 정책 원본/SQL ID·본문·누락·추가 행 대조를 같은 트랜잭션에 두고, 룰 시험은 서명된 원본 이벤트를 사용한다. 처음 19개 공격 회귀는 수정 전 실패했고 수정 후 통과했다. 2MiB 초과 정책 객체는 413으로 중단하되, 무관한 큰 원장 기록은 청크 해시 검증 후 계속 처리한다. 모든 API의 무결성 감사를 끝냈다는 의미는 아니다.

추가로 `/api/integrity`의 객체 사본 미검증 문제를 수정했다. 백업의 전체 객체 비교 함수를 `src/object-integrity.mjs`로 공유하고, 이미 검증한 원장 기록을 재사용한다. 신규 공격 회귀 32개가 수정 전 실패·수정 후 통과했으며, 기존 백업·HTTP/CLI 복구 15개도 통과했다. API는 `objectProjection`과 `verificationScope`를 반환한다. 화면에도 평가·개발 실행 사본, 이벤트 색인, 문서 파일이 이 검사 범위에 포함되지 않는다고 표시했다. 이 항목들은 백업 복구 검사에서 별도로 검증한다.

## 남은 범위

실제 조직 IdP와 계정 회수 정책, SCIM·back-channel logout, 여러 vault 간 세션 공유, 비밀 회전·외부 KMS, 운영 부하/SLO·고가용성 검증은 미완료다. 브라우저 검증은 loopback 합성 IdP이며, HTTPS cookie 속성 검증은 별도 실제 TLS 자동 시험이다. 합성 성공을 조직 SSO 운영 완료로 해석하지 않는다.

캐시는 SAVEPOINT 해제 후 검증 상태를 공개한다. 현재 접근 변경은 상태 읽기 후 한 번 쓰므로 미커밋 상태를 캐시에 넣지 않는다. 향후 외부 트랜잭션에서 ‘쓰기 → 캐시 조회 → rollback’ 호출을 추가한다면 캐시 공개를 커밋 이후로 옮겨야 한다. 프로세스 재시작 후 정상 서명된 과거 DB 전체 교체 탐지는 독립 anchor 보관에 의존한다.
