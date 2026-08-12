# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **§20 UMA 2.0 — Protection API and ticket grant (contract 1.10).** New `OidcOperations`
  methods on `AxiamClient`: `umaRegisterResource` / `umaReadResource` / `umaUpdateResource` /
  `umaDeleteResource` / `umaListResources`, `umaRequestTicket`, `umaExchangeTicket`, plus the
  `ResourceSet` / `RequestedPermission` / `RptPermission` / `RequestingPartyToken` records and
  `UmaChallenge` with its static `parse` / `header` helpers.

  Two behaviours are load-bearing rather than incidental, and both are asserted by counting
  requests. **`umaExchangeTicket` never retries** — the one documented exception to the §16
  retry policy, because a ticket is consumed before the request is evaluated, so a retry
  cannot succeed and under concurrency is exactly the second redemption that
  ilpanich/axiam#302's measured residual describes. And **`UmaChallenge.parse` does not
  exchange the ticket it parsed**: the `as_uri` names an authorization server the caller has
  not chosen to trust.

  The PAT is an explicit first argument on every Protection API call rather than being taken
  from the client's session, because that session is usually a *user* session and a ticket
  binds to a `client_id`.

  `access_denied` on the ticket grant arrives as **403** (UMA 2.0 §3.3.6), unlike RFC 8628's,
  which is a 400. It is mapped to `OAuthProtocolError` by a mapper local to this grant rather
  than by widening `ErrorMapper`'s 400/401 rows — an ordinary REST 403 still maps to
  `AuthzError`, unchanged.

- **§20.3 challenge emission from the §11 interceptor.** `AxiamAuthorizationInterceptor`
  gains a second constructor taking a `UmaChallenger` (realm, `as_uri`, PAT, client); with
  one, an `@AxiamRequireAccess` denial mints a permission ticket for the action that was
  refused and returns it as `WWW-Authenticate: UMA` alongside the unchanged 403 body.

  It is **opt-in** because emitting a challenge means minting a credential: an interceptor
  that did it by default would turn every unauthorized request into a Protection API call,
  which is a denial-of-service amplifier pointed at your own authorization server. And a
  **minting failure is not an escalation** — an expired PAT or an unreachable Protection API
  still yields the plain 403, never a 500 and never an allow. The requested scope is the
  AXIAM *action*, so the ticket asks for exactly the authority just refused and the engine's
  deny rules keep applying to whatever RPT comes back.

  Paired with `examples/uma-resource-server` and `examples/uma-client`, which demonstrate
  both halves: emitting the challenge, and consuming it — including the trust decision §20.3
  keeps in the caller's hands rather than auto-exchanging against whatever host a 403 named.

- **§18 `AxiamClient.close()` semantics** — idempotent via `compareAndSet` (a concurrent
  double-close does the work once), clears the memo, and use-after-close throws `NetworkError`
  rather than silently reconnecting. It does **not** log out and never reaches the network:
  the server-side session outlives the client object, and a `close()` that logged out would
  end every user's session on each deploy.
- **§19 telemetry hooks** — `Builder.telemetryHook(...)`, the **sealed** `TelemetryEvent`
  hierarchy (`RequestStart`, `RequestEnd`, `Retry`, `Refresh`) and `examples/telemetry-hook`.
  A throwing hook cannot fail the operation that fired it, and no event payload can carry a
  token. One request pair per *attempt*.
- **§17 decision memo — opt-in, off by default** — `Builder.decisionMemoTtl(...)`, clamped to
  `DecisionMemo.MAX_TTL` (5 s), thread-safe. Allows and denies memoized identically, failures
  never memoized, cleared on any credential change.
  **Reads-your-own-writes is not guaranteed.**
- `Builder.retryDisabled()` (§16.6). No builder method for the attempt cap, base or delay
  cap: §16.1 forbids raising them.
- `Retry.withRetry` gains an attempt-aware overload that passes the 1-based attempt to the
  operation and emits the §16.5 retry event.

### Changed

- Re-vendored `CONTRACT.md` at **1.8.2**. `openapi.json` unchanged — docs-only contract revs.
- `login`, `verifyMfa`, `refresh` and `logout` clear the decision memo (§17.1 rule 9) and
  reject after close (§18.1 rule 4).

### Notes

- §16's arithmetic is **unchanged**: this SDK's policy was already conformant, and of the
  five SDKs that had invented one it was the only one that got both full jitter and
  `Retry-After`-as-a-floor right. The contract adopted its parameters.

## [1.0.0-alpha24] - 2026-08-04

### Added

- Apply the full CONTRACT §10.1 local-verification set
- Add HMAC-SHA256 webhook signature verifier (CONTRACT.md §13)

### Changed

- Device (mTLS) tokens now carry aud=axiam:m2m (#36)
- Service accounts can use login_client_credentials (#35)
- Bump the minor-patch group with 5 updates
- Bump actions/setup-java from 5.6.0 to 5.7.0
- Bump coverallsapp/github-action from 2.3.7 to 2.3.8

### Fixed

- Clear the SecurityContext when a caller's token is rejected (#37)
- Lower the clock-skew ceiling 300s -> 60s (§13.4 observation 5) (#34)

## [Unreleased]

### Changed — BREAKING (configuration)

- **`JwksVerifier.MAX_CLOCK_SKEW_SECONDS` lowered 300 → 60 (§13.4 observation 5).**
  The old ceiling satisfied CONTRACT.md §10.1 rule 7 — it was named and bounded —
  but it was 5× the RECOMMENDED leeway and 5× what every sibling SDK fixes its
  value at, so an operator could widen the acceptance window on an expired token
  to five minutes and still be "conformant". The ceiling now equals the
  recommendation.

  A `LocalVerificationPolicy` constructed with a leeway above 60 now throws
  `IllegalArgumentException` instead of being accepted. The default (60) is
  unchanged, so this affects only deployments that explicitly widened it.

### Changed — BREAKING

- **Local token verification now applies the complete CONTRACT.md §10.1
  minimum local-verification set.** `AxiamAuthenticationFilter` — the §10
  Spring Boot guard, and the only place this SDK turns a token into an
  identity without asking the server — routes through a single new entry
  point, `JwksVerifier.verifyAccessToken(token, configuredTenantId)`. This
  **tightens acceptance**; tokens the AXIAM server mints are unaffected (they
  always carry `exp` and never a future `nbf`), but a guard fed tokens from
  another signer sharing the organization-wide JWKS may start rejecting what
  it previously accepted. That is the intent.

  What changed in behaviour:

  - **`exp` is now REQUIRED (§10.1 rule 2).** The filter previously ran
    `if (expiration != null && expiration.before(new Date()))`, so a
    signature-valid token carrying **no** `exp` — a permanent credential — was
    accepted. This is the SEC-080 defect and nimbus-jose-jwt does not close
    it: `JWTClaimsSet` accessors are pure getters, so `getExpirationTime()`
    simply returns `null` for an absent claim and nothing in the library
    objects. (nimbus *does* reject a wrong-typed `exp` — a string, a boolean —
    at `getJWTClaimsSet()` parse time; that path is now covered by tests.)
  - **`nbf` is now honoured (§10.1 rule 3).** It was not checked at all
    before: a token that had not yet become valid was accepted.
  - **A null or blank configured tenant now fails closed (§10.1 rule 4)**
    instead of being compared against and quietly mismatching.
  - **`iss` and `aud` are checked when configured (§10.1 rules 5-6).** Both
    are new, **optional, and unset by default** — no issuer or audience is
    ever assumed or hardcoded, so a deployment that configures neither sees
    no change from these two rules. Configure them via the new
    `JwksVerifier.LocalVerificationPolicy` record or the new optional
    `axiam.expected-issuer` / `axiam.expected-audience` Spring properties.
    `JwksVerifier.RECOMMENDED_RESOURCE_SERVER_AUDIENCE` (`"axiam:user"`) is
    exposed for guards fronting a user-facing resource server.
  - **Clock skew is now a named, bounded constant (§10.1 rule 7).** Rules 2
    and 3 allow `JwksVerifier.DEFAULT_CLOCK_SKEW_SECONDS` (60 s, the
    RECOMMENDED value) of leeway, overridable via the policy record or the
    new `axiam.clock-skew-seconds` property but hard-bounded by
    `MAX_CLOCK_SKEW_SECONDS` (300 s) — an out-of-range value throws
    `IllegalArgumentException` at construction rather than silently widening
    acceptance. Previously there was no leeway at all, so a token within 60 s
    of expiry that used to be rejected on a skewed clock is now accepted.
  - **The `alg` pin is now explicit rather than incidental.**
    `verifySignatureOnlyUnchecked` reads `alg` off the raw JOSE header before
    any JWS parsing, so `alg: none` is rejected by the EdDSA allowlist itself
    instead of relying on nimbus's parser refusing the header shape. The
    parsed-header check is retained as a second assertion.

- **`JwksVerifier.verify(String)` has been renamed to
  `JwksVerifier.verifySignatureOnlyUnchecked(String)`** (source-breaking for
  anyone who called it directly). Its behaviour is unchanged: it verifies the
  EdDSA signature and *nothing else*. §10.1 permits such a raw primitive but
  requires its name to make the omission obvious at the call site and forbids
  it being the documented guard entry point — `verifyAccessToken` is now that
  entry point.

- `AxiamAutoConfiguration.axiamAuthenticationFilter(...)` gained three
  parameters (`axiam.expected-issuer`, `axiam.expected-audience`,
  `axiam.clock-skew-seconds`). All three properties are optional with
  defaults, so no `application.properties` change is required; only direct
  Java callers of the bean factory method are affected.

### Added

- Add `io.axiam.sdk.webhook.AxiamWebhooks.verify` — HMAC-SHA256
  webhook-signature verification with a two-sided freshness window
  (CONTRACT.md §13, T-145)
- `JwksVerifierLocalVerificationSetTest` and two new
  `AxiamAuthenticationFilterTest` cases cover the complete §10.1 required
  negative set (expired, no `exp`, non-numeric `exp`, future `nbf`, different
  tenant, no `tenant_id`, `alg: none`, HS-signed token bearing an EdDSA kid)
  plus issuer/audience mismatch cases, each with a non-vacuity positive. One
  test pins nimbus's null-expiry-for-absent-`exp` behaviour so a future
  library change surfaces loudly instead of leaving dead defensive code.

## [1.0.0-alpha23] - 2026-08-02

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha21.

## [1.0.0-alpha21] - 2026-07-30

### Added

- Implement OIDC/SSO relying-party helpers (CONTRACT §12)

### Changed

- Re-sync vendored CONTRACT.md to contract 1.6
- Re-sync vendored CONTRACT.md to contract 1.5
- Bump the minor-patch group with 5 updates
- Bump actions/checkout from 7.0.0 to 7.0.1

### Fixed

- Stop runExclusive treating a settled refresh as busy
- Widen Sensitive.expose() to public (F-02, CONTRACT §7 rule 3)

## [1.0.0-alpha18] - 2026-07-24

### Changed

- Bump org.junit.jupiter:junit-jupiter (#21)
- Bump actions/setup-java from 5.5.0 to 5.6.0 (#20)
- Ratchet jacoco LINE floor 0.92->0.93 (#23)

## [1.0.0-alpha16] - 2026-07-22

### Added

- Implement getUserInfo/getUserInfoAsync (CONTRACT §1.1)

### Changed

- Vendor userinfo.proto + CONTRACT 1.3 (§1.1 gRPC userinfo)

## [1.0.0-alpha15] - 2026-07-21

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha12.

## [1.0.0-alpha12] - 2026-07-19

### Fixed

- Supply organization context for login/refresh (CONTRACT §5.1) (#19)

## [1.0.0-alpha11] - 2026-07-18

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha10.

## [1.0.0-alpha10] - 2026-07-18

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha9.

## [Unreleased]

### Added

- OIDC / SSO relying-party helpers (CONTRACT.md §12, adopting contract version
  1.4): the nine canonical operations — `oidcDiscover`, `oidcBegin`,
  `oidcExchange`, `oidcRefresh`, `loginClientCredentials`, `introspect`,
  `revoke`, `ssoStart`, `ssoComplete` — exposed directly on `AxiamClient`
  (new `io.axiam.sdk.oidc` package for the supporting types), each with a
  `*Async` `CompletableFuture` companion. Built entirely on existing SDK
  machinery: the §4 cookie jar, §6 TLS configuration, §7 `Sensitive` wrapper,
  §9 single-flight refresh guard (extended with `RefreshGuard.runExclusive`
  so `oidcRefresh` can never interleave with a cookie-session `refresh()`),
  and the §10 JWKS verifier (extended with `JwksVerifier.forJwksUri`/
  `verifyForOidc` to read `jwks_uri` from the discovery document and to raise
  a stable §12.3 reason code per failed rule). `oidcBegin` is pure local PKCE
  (`SecureRandom` + `MessageDigest`, S256-only) with no network I/O; every ID
  token is validated in full (algorithm, signature, issuer, audience, time,
  nonce — §12.4) before `oidcExchange`/`oidcRefresh` return, discarding the
  whole token set on any failure. New `OAuthProtocolError`, a sub-type of the
  now-non-`final` `AuthError` (existing `catch (AuthError e)` code keeps
  working), surfaces an `OAuth2ErrorResponse` body from `/oauth2/*`; a 401
  from `/oauth2/token`/`/oauth2/introspect`/`/oauth2/revoke` never enters the
  §9 refresh guard. `OidcStateStore` + the in-memory `MemoryOidcStateStore`
  (10-minute TTL, single-use `consume`) are optional, opt-in state storage for
  framework glue. New Spring MVC `AxiamOidcLoginRoutes` (a
  `RouterFunction<ServerResponse>` login-redirect + callback pair),
  auto-registered by `AxiamAutoConfiguration` only when the consuming
  application sets `axiam.oidc.enabled=true`. This SDK now conforms to
  CONTRACT.md §1–§12 (was §1–§11). No new runtime dependency.

- gRPC-only `getUserInfo` operation (CONTRACT.md §1.1, adopting contract version
  1.3): `GrpcAuthzClient.getUserInfo()` and its `CompletableFuture`-returning
  `getUserInfoAsync()` twin invoke `axiam.v1.UserInfoService/GetUserInfo` on the
  client's existing gRPC channel — the low-latency counterpart of the server's
  REST `GET /oauth2/userinfo`. The request is empty; identity is derived
  server-side from the bearer token. Returns a typed
  `GrpcAuthzClient.UserInfo { sub, tenantId, orgId, Optional<String> email,
  Optional<String> preferredUsername }` — `sub`/`tenantId`/`orgId` are always
  present, while `email` (`"email"` scope) and `preferredUsername` (`"profile"`
  scope) are populated only when the access token carries the gating scope.
  Calling it with no token raises `AuthError` client-side without a wire call;
  a gRPC `UNAUTHENTICATED` participates in the §9 single-flight refresh guard and
  retries the RPC once, reusing the same auth + `x-tenant-id` metadata and
  refresh-retry machinery as `checkAccess`. The vendored `proto/` and
  `CONTRACT.md` were re-synced to contract 1.3 (new
  `proto/axiam/v1/userinfo.proto`).

- Client-certificate / mutual-TLS (mTLS) support (CONTRACT.md §6.1):
  `AxiamClient.builder(...).clientCertificate(byte[] certPem, byte[] keyPem)`
  configures a client-side X.509 identity (PEM certificate chain + PKCS#8
  private key) that is applied to **both** the REST (OkHttp `KeyManager`) and
  gRPC (`GrpcSslContexts.keyManager`) transports. A new
  `GrpcAuthzClient(target, refreshGuard, session, customCaPem, clientCertPem, clientKeyPem)`
  constructor carries the same identity onto the gRPC channel. Presenting a
  client certificate never relaxes strict server verification; both cert and key
  are required together (else `IllegalArgumentException` at `build()`), a
  malformed PEM fails at construction time, and the private key is held as
  secret material (never exposed via a getter, `toString()`, or logs).

### Fixed

- `Sensitive.expose()` widened from package-private to `public` (CONTRACT.md
  §7 rule 3, contract 1.5): CONTRACT.md §12 hands `accessToken`/
  `refreshToken`/`idToken` on `OidcTokenSet` to the calling application in the
  `/oauth2/token` response body, not via a `Set-Cookie` the SDK captures on
  the caller's behalf, so a §12 caller had no way to read the tokens it was
  handed — `expose()` was reachable only from within `io.axiam.sdk` itself.
  Additive and non-breaking: redaction (`toString()`, Jackson serialization)
  is unaffected, and there is still exactly one accessor and no implicit
  reachability path.
- REST HTTPS hostname verification: the OkHttp client no longer overrides the
  hostname verifier with `HttpsURLConnection.getDefaultHostnameVerifier()` (an
  always-reject verifier that failed verification for every host); it now uses
  OkHttp's built-in strict `OkHostnameVerifier` (full RFC 2818 SAN/CN matching).

## [1.0.0-alpha2] - 2026-07-16

### Added

- Declarative authorization helpers (CONTRACT.md §11): the framework-free
  `@AxiamRequireAuth`, `@AxiamRequireAccess`, and `@AxiamRequireRole`
  annotations (`io.axiam.sdk.annotations`) plus the Spring MVC
  `AxiamAuthorizationInterceptor` that enforces them, auto-registered by
  `AxiamAutoConfiguration` via a `WebMvcConfigurer`. Enforcement runs after the
  §10 authentication guard, issues the check for the authenticated end user
  (`subject_id`), resolves the resource UUID from a path variable or a static
  literal, and maps outcomes to 401/403/400/503 (fail closed on transport
  failure). The example Spring Boot app gains an annotated
  `GET /documents/{id}` controller.
- Subject-aware `AxiamClient.checkAccess(subjectId, action, resourceId, scope)`
  overload (and its `checkAccessAsync` twin) carrying `subject_id` in the
  request body; the existing overloads are unchanged.

### Changed

- This SDK now conforms to CONTRACT.md §1–§11 (was §1–§10).

## [1.0.0-alpha] - 2026-07-15

First alpha release of the official Java client SDK for AXIAM. This is an early,
pre-production preview published to Maven Central for evaluation and feedback —
the public API may still change before the beta and stable releases.

### Added

- REST client (OkHttp) covering the AXIAM API surface (authentication,
  authorization checks, tenant/user/role/resource management).
- gRPC client for low-latency authorization checks.
- Spring Boot integration for guarding application endpoints.
- `io.github.ilpanich:axiam-bom` Bill of Materials to keep SDK artifact
  versions aligned in consumer projects.
- Strict TLS by default with no certificate-verification bypass surface.
- Fully documented public API (Javadoc, published to javadoc.io).
- Spring Boot example application.

[1.0.0-alpha]: https://github.com/ilpanich/axiam-java-sdk/releases/tag/v1.0.0-alpha
