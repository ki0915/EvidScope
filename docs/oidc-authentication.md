# 조직 OIDC 로그인과 접근 회수

OIDC를 활성화하면 조직 인증 공급자에 로그인하고, 서버에 설정된 issuer·subject의 테넌트·역할을 사용한다. ID token의 email·role·tenant 속성을 권한으로 사용하지 않는다. 기존 수집기 HMAC·worker 자격은 유지하고 사람의 고정 Bearer token은 거부한다. `profile: "enterprise"`는 OIDC 설정 없이는 시작하지 않는다. 기본 로컬 프로필을 자동 전환하지 않는다.

설정 파일은 vault만 읽는다. 아래 주소·subject·비밀은 실제 조직에서 발급한 값으로 교체하고 저장소에 커밋하지 않는다. `principals`에는 기존 source·worker 설정을 넣는다.

```json
{
  "profile": "enterprise",
  "principals": [],
  "oidc": {
    "enabled": true,
    "issuer": "https://id.example.org/realms/finance",
    "publicOrigin": "https://audit.example.org",
    "clientId": "evidscope",
    "clientSecret": "REPLACE_WITH_ORGANIZATION_CLIENT_SECRET",
    "sessionTtlSeconds": 900,
    "idleTtlSeconds": 300,
    "maxAuthenticationAgeSeconds": 300,
    "requiredAcrValues": [],
    "bindings": [
      {"id": "audit-admin-01", "subject": "REPLACE_WITH_STABLE_SUBJECT", "tenant": "finance", "role": "admin"}
    ]
  }
}
```

바인딩 ID는 기존 자격 ID와 중복할 수 없다. 지원 역할은 auditor·reviewer·admin이며 한 subject를 하나의 테넌트·역할에 연결한다. 변경은 서버 설정 수정 후 vault 재시작으로 적용한다. 여러 테넌트 전환이나 IdP group 자동 매핑은 아직 없다.

IdP callback은 정확히 **`publicOrigin + /auth/callback`**이다. issuer는 discovery 문서 주소가 아닌 발급자의 issuer 값이며 마지막 `/`까지 일치해야 한다. RS256 ID token, authorization code, S256 PKCE, confidential client의 `client_secret_post`를 지원한다. `requiredAcrValues`에는 실제 IdP의 요구 인증 수준을 지정한다. 비어 있으면 MFA 완료를 주장하지 않는다. `max_age`와 `auth_time`을 검증한다.

authorization·token·JWKS endpoint는 기본적으로 issuer와 동일한 origin이어야 한다. 별도 도메인이 필요하면 검토한 origin만 `allowedEndpointOrigins` 배열에 추가한다. endpoint 리다이렉트는 거부하며 응답은 각 1MiB, 요청은 각 4초로 제한한다. 성공 후 `/`, 실패 후 `/?auth=failed`로 이동하며 사용자 입력 return URL은 받지 않는다.

## 전송과 세션

운영 IdP와 publicOrigin은 HTTPS만 허용한다. audit·vault 인증서와 신뢰 CA는 `TLS_CERT_FILE`, `TLS_KEY_FILE`, `NODE_EXTRA_CA_CERTS`로 배치한다. 프록시는 원래 public Host를 유지하고 audit까지 HTTPS로 전달해야 한다. `X-Forwarded-*`로 출처·프로토콜을 추정하지 않는다. HTTP 종료 프록시 뒤에서 public HTTPS를 구성하는 방식은 지원하지 않는다.

기존 `deploy/kubernetes.json`의 vault는 outbound deny-all이다. OIDC 설정만 추가해도 이 정책을 통과하지 못한다. 실제 배포에는 조직에서 확정한 IdP endpoint와 DNS로만 나가는 별도 egress 정책, 사설 IdP라면 vault용 신뢰 CA mount가 필요하다. 기본 네트워크 격리를 자동 해제하지 않았으며 해당 운영 overlay와 CNI 실증은 미완료다.

세션은 무작위 opaque cookie이며 `__Host-`, Secure, HttpOnly, SameSite=Lax, Path=/를 사용하고 Domain은 발급하지 않는다. vault는 cookie의 SHA-256 및 세션 정보를 메모리에 보관한다. ID/access/refresh token, PKCE verifier, flow state, cookie·CSRF는 증적 DB·백업에 저장하지 않는다. 로그인 흐름은 5분간 메모리에 보관하며 동시 흐름 1,000개·세션 10,000개로 제한한다.

state·nonce·PKCE와 별도 flow cookie를 결합해 검증한다. `openid-client`의 `enableNonRepudiationChecks`를 명시 적용해 ID token 서명을 검증한다. HTTPS만으로 서명 확인을 대체하지 않는다. 모든 cookie 인증 POST에는 고정 publicOrigin과 세션별 `X-Evid-CSRF`가 필요하다. Bearer 자격 혼용은 거부한다.

기본 절대 수명 15분·유휴 수명 5분이다. 재시작·복구 후 기존 cookie는 모두 무효다. 브라우저는 token·cookie·CSRF를 localStorage나 sessionStorage에 저장하지 않는다. `syntheticLocalIdp: true`는 `synthetic-local` 프로필의 숫자 loopback HTTP에서만 사용하며 enterprise에서는 시작을 거부한다.

## 접근 관리와 서명 상태

OIDC 관리자는 수집·증적 건강 화면에서 동일 테넌트 계정의 접근을 변경하며 사유를 남긴다.

| 작업 | 결과 |
|---|---|
| 세션 회수 | 현재 세션 무효. 새 조직 로그인 가능 |
| 접근 중지 | 현재 세션 무효 및 이후 로그인 거부 |
| 접근 복원 | 새 로그인 허용. 이전 cookie는 계속 무효 |
| 로그아웃 | EvidScope 세션만 종료. 조직 IdP 로그인은 유지 |

`GET /api/access`, `POST /api/access/subjects/:id`를 사용하며 action은 `revoke_sessions`, `disable`, `enable`이다. 자기 계정 접근 중지는 거부하고 자기 세션 회수는 허용한다. 상태·사유는 서명 원장에 저장하며 unsigned 사본으로 접근을 복원하지 않는다.

접근 상태는 최초 전체 체인을 검증한 후 메모리에 보관한다. 이후 조회는 캐시 기준점과 새 기록을 서명된 체크포인트까지 검증한다. 변경되지 않은 과거 모든 바이트를 매 요청 재검증하는 무결성 보고서는 아니다. 재시작 시 전체를 다시 검증하며, 실행 중 과거 체크포인트로의 rollback은 거부한다. 프로세스 종료 후 원장 전체를 정상 서명된 과거 백업으로 교체하는 rollback 탐지는 기존 독립 anchor 보관 절차가 필요하다.

IdP의 외부 계정 삭제·그룹 변경을 실시간 수신하는 SCIM·back-channel logout은 아직 없다. 조직 계정 차단 시 EvidScope 접근 중지도 함께 실행해야 한다. 운영 배포 전에 실제 IdP의 ACR·계정 회수 절차를 검증한다.

## 검증

```powershell
npm ci --ignore-scripts --no-audit --no-fund
node --test --test-concurrency=1 test/identity-state.test.mjs test/oidc-http.test.mjs test/oidc-tls.test.mjs test/oidc-ui.test.mjs
```

독립 합성 IdP와 audit·vault 프로세스에서 서명·코드 교환·권한·회수·만료·재시작·복구를 검증한다. HTTPS 시험은 임시 CA와 정상 hostname 검증을 사용하고 TLS 검증을 해제하지 않는다. UI 자동 시험은 VM DOM이다. 실제 조직 IdP, 다중 vault 세션 공유, 비밀 관리·회전, 고가용성·운영 부하 기준은 별도 검증이 필요하다.
