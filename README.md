# axiam-sdk (Java)

[![CI](https://github.com/ilpanich/axiam-java-sdk/actions/workflows/sdk-ci-java.yml/badge.svg?branch=main)](https://github.com/ilpanich/axiam-java-sdk/actions/workflows/sdk-ci-java.yml)
[![Coverage Status](https://coveralls.io/repos/github/ilpanich/axiam-java-sdk/badge.svg?branch=main)](https://coveralls.io/github/ilpanich/axiam-java-sdk?branch=main)
[![Maven Central](https://img.shields.io/maven-central/v/io.github.ilpanich/axiam-sdk.svg)](https://central.sonatype.com/artifact/io.github.ilpanich/axiam-sdk)
[![javadoc](https://javadoc.io/badge2/io.github.ilpanich/axiam-sdk/javadoc.svg)](https://javadoc.io/doc/io.github.ilpanich/axiam-sdk)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Official Java client SDK for [AXIAM](https://github.com/ilpanich/axiam) — Access eXtended Identity and Authorization Management.

**Platform documentation:** <https://ilpanich.github.io/axiam/> — getting started, the authorization model, the OAuth2/OIDC surface, and the operations guides. This README covers the SDK; the site covers the server it talks to.

Source: [ilpanich/axiam-java-sdk](https://github.com/ilpanich/axiam-java-sdk)

## Package identity

- **Maven coordinates:** `io.github.ilpanich:axiam-sdk` (BOM: `io.github.ilpanich:axiam-bom`)
- **GroupId:** `io.github.ilpanich`
- **ArtifactId:** `axiam-sdk`
- **Registry:** Maven Central _(reserved, not yet published)_
- **API docs:** [javadoc.io](https://javadoc.io/doc/io.github.ilpanich/axiam-sdk) — served automatically from the `-javadoc.jar` on Maven Central
- **License:** Apache-2.0

## Contract conformance

This SDK conforms to CONTRACT.md §1–§13 and §12.7, §14, §15, §17, §19, §20, §22,
§23, §24, §25, §26 — including §6.1 mTLS (client-certificate authentication), the
§1.1 gRPC-only `getUserInfo` operation, the §10.1 minimum local-verification set,
the §12 OIDC/SSO relying-party helpers, the §13 webhook-signature verifier, the
§20 UMA 2.0 Protection API and ticket grant, the §22 reactor runtime, the §23
OPAQUE (RFC 9807) login path, the §24 WebAuthn relying-party layer with its
§24.6a JSON bridge, the §25 account-lifecycle and MFA-enrolment operations, and
§26 Pushed Authorization Requests (RFC 9126).

§12.7, §14, §15, §20, §22, §23, §24, §25 and §26 are named rather than folded into
the range because they landed after this SDK already claimed §1–§13: widening the
range silently would turn a statement that was true when written into a different
claim without anyone editing it.

§24.6b — the linked-API ceremony helper — is **deliberately absent**. The JVM has
no authenticator, and §24.6b rule 2 forbids emulating one in software: a
"credential" held in process memory is not a second factor. See
[WebAuthn / passkeys](#webauthn--passkeys-iaxiamsdkwebauthn-24) for what an
Android app does instead.

See [`CONTRACT.md`](CONTRACT.md) for the full cross-language behavioral contract.

## Local token verification (§10.1)

`AxiamAuthenticationFilter` verifies the access token **locally**, so it applies
the complete CONTRACT.md §10.1 minimum local-verification set through the single
`JwksVerifier.verifyAccessToken(token, configuredTenantId)` entry point:

| # | Claim | What this SDK does |
|---|-------|--------------------|
| 1 | signature | `alg` pinned to `EdDSA`, read off the raw JOSE header **before** any JWS parsing or JWKS lookup, so `alg: none` and HS-family confusion are rejected without ever consulting a key |
| 2 | `exp` | **Required.** A token with no `exp` is a permanent credential and is rejected; a wrong-typed `exp` fails at claims-parse time |
| 3 | `nbf` | Honoured when present; absent is valid |
| 4 | `tenant_id` | **Required** and asserted against the configured tenant; a null/blank configured tenant fails closed |
| 5 | `iss` | Checked **only** when an expected issuer is configured (optional, unset by default — no issuer is ever assumed) |
| 6 | `aud` | Checked **only** when an expected audience is configured; a user-facing resource server should use `JwksVerifier.RECOMMENDED_RESOURCE_SERVER_AUDIENCE` (`"axiam:user"`) |
| 7 | clock skew | `JwksVerifier.DEFAULT_CLOCK_SKEW_SECONDS` (60 s), bounded by `MAX_CLOCK_SKEW_SECONDS` (300 s) — an out-of-range value is refused, never silently applied |

Rules 5–7 are configured through `JwksVerifier.LocalVerificationPolicy`, or via
three **optional** Spring properties read by the auto-configuration:

```properties
axiam.base-url=https://axiam.example.com
axiam.tenant-id=acme-tenant
# Optional §10.1 rule 5-7 settings; blank/absent means the claim is not checked.
axiam.expected-issuer=https://axiam.example.com
axiam.expected-audience=axiam:user
axiam.clock-skew-seconds=60
```

```java
JwksVerifier verifier = new JwksVerifier(
        baseUrl,
        new JwksVerifier.LocalVerificationPolicy(
                "https://axiam.example.com",                        // or null: no iss check
                JwksVerifier.RECOMMENDED_RESOURCE_SERVER_AUDIENCE,  // or null: no aud check
                JwksVerifier.DEFAULT_CLOCK_SKEW_SECONDS));
```

`JwksVerifier.verifySignatureOnlyUnchecked(...)` is the raw signature-only
primitive §10.1 permits for integrators implementing their own policy. Its name
states the omission: it checks **no** claims at all, and the SDK's own guards
never call it.

## Getting started

### Maven

```xml
<dependency>
  <groupId>io.github.ilpanich</groupId>
  <artifactId>axiam-sdk</artifactId>
  <version>1.0.0-alpha39</version>
</dependency>
```

Consumers depending on multiple AXIAM artifacts (e.g. `axiam-sdk` alongside a
future companion module) should import the BOM instead of pinning individual
versions:

```xml
<dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>io.github.ilpanich</groupId>
      <artifactId>axiam-bom</artifactId>
      <version>1.0.0-alpha39</version>
      <type>pom</type>
      <scope>import</scope>
    </dependency>
  </dependencies>
</dependencyManagement>
```

### Gradle (Kotlin DSL)

```kotlin
dependencies {
    implementation("io.github.ilpanich:axiam-sdk:1.0.0-alpha39")
}
```

Or via the BOM:

```kotlin
dependencies {
    implementation(platform("io.github.ilpanich:axiam-bom:1.0.0-alpha39"))
    implementation("io.github.ilpanich:axiam-sdk")
}
```

### Quick start

`tenantId` is a **required, positional** argument to `AxiamClient.builder(...)`
— AXIAM is multi-tenant and there is no default tenant (CONTRACT.md §5); a
blank value throws `AuthError` at construction time. Because a tenant slug is
only unique *within* an organization, `login`/`refresh` additionally require
**organization context** (CONTRACT.md §5.1): supply it with `.orgSlug("acme")`
(or `.orgId(UUID)`) — omitting it makes `login` fail at runtime with
`400 "must provide org_id or org_slug"`. `AxiamClient` is `AutoCloseable`, so
always construct it with try-with-resources to release its underlying OkHttp
connection pool/dispatcher:

```java
try (AxiamClient client = AxiamClient.builder("https://axiam.example.com", "acme-tenant")
        .orgSlug("acme")
        .build()) {
    LoginResult result = client.login("user@example.com", "password");
    if (result.mfaRequired()) {
        result = client.verifyMfa(result.challengeToken(), "123456");
    }
    boolean allowed = client.can("read", "documents/123");
}
```

See [`examples/`](examples/) for runnable per-capability examples covering
login+MFA, REST authorization, gRPC `CheckAccess`, the AMQP consumer, passkeys,
account lifecycle, pushed authorization requests, and a complete Spring Boot 3.x
application wiring `AxiamAuthenticationFilter` explicitly in a
`SecurityFilterChain` bean.

### mTLS / client certificates

For IoT devices and service accounts that authenticate by **mutual TLS**
(CONTRACT.md §6.1), configure a client-side X.509 identity — a PEM certificate
chain plus its PKCS#8 private key — via `clientCertificate(...)`. The same
identity is applied to **both** the REST and gRPC transports of the client, and
strict server verification is never relaxed (a client certificate is purely
additive; the system trust store, plus any `customCa(...)`, still validates the
server):

```java
byte[] certPem = Files.readAllBytes(Path.of("client-cert.pem")); // chain, leaf first
byte[] keyPem  = Files.readAllBytes(Path.of("client-key.pem"));  // PKCS#8 (-----BEGIN PRIVATE KEY-----)

try (AxiamClient client = AxiamClient.builder("https://axiam.example.com", "acme-tenant")
        .customCa(serverCaPem)                    // optional: extra trusted server CA
        .clientCertificate(certPem, keyPem)       // client identity for mTLS
        .build()) {
    boolean allowed = client.can("read", "devices/123");
}

// The same identity applies to the gRPC transport:
try (GrpcAuthzClient grpc = new GrpcAuthzClient(
        "dns:///axiam.example.com:9443",
        client.refreshGuard(), client.session(),
        serverCaPem, certPem, keyPem)) {
    // ...
}
```

Both the certificate and the private key are required together — supplying only
one throws `IllegalArgumentException` at `build()`, and a malformed PEM surfaces
as a clear error at construction time. The private key is treated as secret
material (CONTRACT.md §7): it is consumed into an in-memory key store and never
exposed via a getter, `toString()`, or logs. mTLS is opt-in; omitting
`clientCertificate(...)` leaves the default bearer/cookie behavior unchanged.

## gRPC transport (`GrpcAuthzClient`)

For low-latency service-mesh authorization the SDK ships a gRPC transport,
`io.axiam.sdk.grpc.GrpcAuthzClient`, built from the same `AxiamClient`'s shared
refresh guard and session (one guard, never a second — CONTRACT.md §9). It wraps
a single long-lived, strict-TLS channel and injects the `authorization` bearer
token and `x-tenant-id` metadata on every call (§5). Each operation exposes a
blocking method plus a `CompletableFuture`-returning `*Async` twin (§1 Java async
convention). On gRPC `UNAUTHENTICATED` it drives the shared single-flight refresh
once and retries the RPC once (§9); errors map through the §2 taxonomy
(`PERMISSION_DENIED` → `AuthzError`, `UNAVAILABLE`/`DEADLINE_EXCEEDED`/… →
`NetworkError`).

```java
try (GrpcAuthzClient grpc = new GrpcAuthzClient(
        "dns:///axiam.example.com:9443",
        client.refreshGuard(), client.session(), null)) {

    // Single / batch access checks (CONTRACT.md §1)
    GrpcAuthzClient.AccessResult r = grpc.checkAccess("read", "documents/123");
    boolean allowed = r.allowed();

    // userinfo — gRPC-only (CONTRACT.md §1.1), the low-latency counterpart of
    // the server's REST GET /oauth2/userinfo. Empty request; identity comes from
    // the bearer token. Requires a prior login() — calling it with no token
    // raises AuthError client-side (no wire call).
    GrpcAuthzClient.UserInfo info = grpc.getUserInfo();
    String sub = info.sub();               // always present
    String tenantId = info.tenantId();     // always present
    String orgId = info.orgId();           // always present
    Optional<String> email = info.email();                       // only with the "email" scope
    Optional<String> username = info.preferredUsername();        // only with the "profile" scope

    // async twin
    CompletableFuture<GrpcAuthzClient.UserInfo> future = grpc.getUserInfoAsync();
}
```

## Declarative authorization helpers

On top of the §10 authentication guard (`AxiamAuthenticationFilter`), the SDK
provides the CONTRACT.md §11 declarative, per-endpoint authorization
annotations. Place them directly on a `@Controller` method (or type) to require
a specific AXIAM permission without writing `checkAccess(...)` in the handler
body:

```java
@RestController
public class DocumentController {

    // Requires the authenticated caller to pass a "read" access check on the
    // resource whose UUID is the {id} path variable.
    @AxiamRequireAccess(action = "read", resourceParam = "id")
    @GetMapping("/documents/{id}")
    public String read(@PathVariable("id") String id) {
        return "document " + id;
    }
}
```

Three annotations live in the framework-free `io.axiam.sdk.annotations`
package:

| Annotation | Effect |
|------------|--------|
| `@AxiamRequireAuth` | Requires an authenticated identity (401 otherwise). |
| `@AxiamRequireAccess(action, resourceParam / resourceId, scope)` | Requires the authenticated caller to pass an AXIAM authorization check for `action` on the resolved resource. |
| `@AxiamRequireRole({"admin", ...})` | Local check that the caller holds at least one of the named roles (no server round-trip). Coarser than `@AxiamRequireAccess`; not a substitute for it. |

Enforcement is by `io.axiam.sdk.spring.AxiamAuthorizationInterceptor`, a Spring
MVC `HandlerInterceptor` auto-registered by `AxiamAutoConfiguration` (via a
`WebMvcConfigurer`) whenever an `AxiamClient` bean and Spring MVC are present.
It runs strictly **after** authentication, reads the authenticated principal
from `SecurityContextHolder`, and issues the check for that end user (passing
`subject_id = <authenticated user id>`, not the application's own service-account
session). Method-level annotations override type-level ones.

Error mapping (standard `{ "error", "message" }` JSON body): unauthenticated →
**401** `authentication_failed`; denied → **403** `authorization_denied`;
missing/non-UUID resource → **400** `invalid_request`; authz transport failure →
**503** `authz_unavailable` (**fail closed** — a transport failure denies,
never allows). Decisions are never cached. `AxiamClient` also exposes a
subject-aware `checkAccess(subjectId, action, resourceId, scope)` overload that
the interceptor uses; the existing overloads are unchanged.

The annotated controller is demonstrated in
[`examples/spring-boot-app`](examples/spring-boot-app).

## OIDC / SSO relying-party helpers (`io.axiam.sdk.oidc`)

CONTRACT.md §12 adds nine operations for offering "Login with AXIAM"
(authorization-code + PKCE against AXIAM's own OIDC provider), service-account
`client_credentials` login, token introspection/revocation, and driving the
server's upstream-IdP federation endpoints. They are exposed directly on the
existing `AxiamClient` — there is no separate OIDC client type — and are built
entirely on the SDK's existing machinery (the §4 cookie jar, §6/§6.1 TLS
configuration, §7 `Sensitive` wrapper, §9 single-flight refresh guard, and the
JWKS verifier the §10 middleware uses).

| Operation | Wire call |
|-----------|-----------|
| `oidcDiscover()` | `GET /.well-known/openid-configuration`, cached per origin (&ge;5 min TTL), single-flight |
| `oidcBegin(configuration, redirectUri, scope, extraParams)` | none — pure local PKCE/state/nonce computation |
| `oidcExchange(configuration, code, codeVerifier, redirectUri, nonce, tenantId)` | `POST /oauth2/token` (`grant_type=authorization_code`) |
| `oidcRefresh(refreshToken, scope, tenantId, configuration)` | `POST /oauth2/token` (`grant_type=refresh_token`) |
| `loginClientCredentials(scope, tenantId, configuration)` | `POST /oauth2/token` (`grant_type=client_credentials`) |
| `introspect(token, tokenTypeHint, tenantId, configuration)` | `POST /oauth2/introspect` (confidential clients only) |
| `revoke(token, tokenTypeHint, tenantId, configuration)` | `POST /oauth2/revoke` (confidential clients only; idempotent) |
| `ssoStart(federationConfigId, redirectUri, tenantId, tenantSlug, orgId, orgSlug)` | `POST /api/v1/auth/federation/oidc/start` |
| `ssoComplete(state, code)` | `POST /api/v1/auth/federation/oidc/callback` (session via `Set-Cookie`) |

Each also has a `*Async` `CompletableFuture` companion (`oidcExchangeAsync`, …)
per CONTRACT.md §12.2's Java note, and a bare-`String` convenience overload
wherever the canonical signature takes a `Sensitive` secret.

```java
AxiamClient client = AxiamClient.builder(baseUrl, tenantId)
        .oidcClientId("my-app")
        .oidcClientSecret(clientSecret) // omit for a public client
        .build();

OidcConfiguration config = client.oidcDiscover();
AuthorizationRequest request = client.oidcBegin(config, redirectUri, "openid profile", null);
// redirect the browser to request.url(), persisting state/nonce/codeVerifier yourself

// ...on the callback, after checking the returned state matches...
OidcTokenSet tokens = client.oidcExchange(
        config, code, request.codeVerifier(), redirectUri, request.nonce());
System.out.println(tokens.idClaims().sub()); // validated ID-token subject
```

**The caller owns the login state.** `oidcBegin` and `oidcExchange` are
stateless by contract (CONTRACT.md §12.3 rule 1): the SDK never stores
`state`, `nonce`, or `code_verifier` anywhere. Persist the three values
returned by `oidcBegin` in your own HTTP session and pass `nonce`/
`codeVerifier` back into `oidcExchange` yourself. For a two-request
redirect flow, `io.axiam.sdk.oidc.OidcStateStore` (with the in-memory
`MemoryOidcStateStore` reference implementation — 10-minute TTL, single-use
`consume`) bridges the login and callback requests; a multi-instance
deployment should implement `OidcStateStore` against shared storage (Redis,
a database) instead.

Every ID token is validated in full (issuer, audience, expiry, signature,
nonce — CONTRACT.md §12.4) before `oidcExchange`/`oidcRefresh` ever return an
`OidcTokenSet`; any failure raises `AuthError` with a stable reason code
(`invalid_alg`, `unknown_kid`, `invalid_signature`, `invalid_issuer`,
`invalid_audience`, `token_expired`, `nonce_mismatch`) and discards the whole
token set — there is no partial success and no way to disable validation.
`access_token`, `refresh_token`, `id_token`, `client_secret`, and
`code_verifier` are always `Sensitive`-wrapped; `state` and `nonce` are plain
strings (not secrets). An `OAuth2ErrorResponse` body from `/oauth2/*` surfaces
as `OAuthProtocolError`, a sub-type of `AuthError` — existing
`catch (AuthError e)` code keeps working unchanged.

### Spring MVC login routes (`io.axiam.sdk.spring.AxiamOidcLoginRoutes`)

A ready-made login-redirect + callback `RouterFunction<ServerResponse>` pair
for Spring MVC:

```java
RouterFunction<ServerResponse> oidcRoutes = AxiamOidcLoginRoutes.routes(
        client, new MemoryOidcStateStore(),
        new AxiamOidcLoginRoutes.Options("/oidc/login", "/oidc/callback", redirectUri));
```

Auto-registered by `AxiamAutoConfiguration` **only when the consuming
application opts in** with `axiam.oidc.enabled=true` (unlike the §11
authorization interceptor, this is never wired up by the mere presence of a
dependency — an OIDC login route is too large a behavioral surface to add
silently). Additional properties: `axiam.oidc.client-id` (required),
`axiam.oidc.client-secret` (confidential clients only), `axiam.oidc.redirect-uri`
(required), `axiam.oidc.login-path`/`axiam.oidc.callback-path` (default
`/oidc/login`/`/oidc/callback`), `axiam.oidc.scope`, `axiam.oidc.success-redirect`.

## UMA 2.0 — protecting resources whose owner isn't the caller (§20)

For a resource server holding data that belongs to *users*: instead of
answering an unauthorized request with a bare 403, tell the caller where to go
and get authority.

Registration and the ticket grant live on `AxiamClient`
(`umaRegisterResource` / `umaReadResource` / `umaUpdateResource` /
`umaDeleteResource` / `umaListResources`, `umaRequestTicket`,
`umaExchangeTicket`). Every Protection API call takes the **PAT** as an
explicit first argument — a client-credentials token carrying `uma_protection`
(§20.2 rule 1) rather than the client's ambient session, because that session is
usually a *user* session and a minted ticket binds to a `client_id`.

The registered id **is** the AXIAM resource id, so UMA scopes are AXIAM
actions: the same grants — deny rules included — govern an RPT-carrying request
and an ordinary one.

**Emitting the challenge.** Hand a `UmaChallenger` to the §11 interceptor and a
denial carries the ticket with it:

```java
UmaChallenger challenger = new UmaChallenger(
        "invoices", client.oidcDiscover().issuer(), pat, client);
registry.addInterceptor(new AxiamAuthorizationInterceptor(client, challenger));
// A denied @AxiamRequireAccess handler now answers 403 with
//   WWW-Authenticate: UMA realm="invoices", as_uri="…", ticket="…"
```

Opt-in, deliberately: minting on every denial by default would put a Protection
API call — and a live credential — behind every unauthorized request. And a
minting failure still denies plainly, never a 500 and never an allow.

**Consuming it.** `UmaChallenge.parse(header)` parses and *stops there*. It does
not exchange the ticket, because the `as_uri` it names was chosen by the server
that just refused you; auto-redeeming would send the requesting party's token
wherever a 403 pointed. The trust decision is the caller's:

```java
UmaChallenge challenge = UmaChallenge.parse(response.header("WWW-Authenticate"));
if (challenge != null && trustworthy(challenge.asUri())) {
    RequestingPartyToken rpt =
            client.umaExchangeTicket(challenge.ticket(), userToken, null, null);
}
```

`umaExchangeTicket` sends **one** request and never retries — the documented
exception to the §16 retry policy, because a ticket is consumed before the
request is evaluated, so a retry cannot succeed and under concurrency is exactly
the double redemption to avoid. On failure, obtain a *new* ticket.

Both halves run in [`examples/uma-resource-server`](examples/uma-resource-server)
and [`examples/uma-client`](examples/uma-client).

## Device authorization grant (§14)

RFC 8628 — signing in a device that cannot show a browser: a TV, a CLI, a headless
commissioning tool.

```java
OidcTokenSet tokens = client.deviceLogin(null, null, null, authorization -> {
    // Called BEFORE the first poll. Display it however the device can —
    // screen, QR code, e-ink panel. The SDK never prints it for you.
    System.out.printf("visit %s and enter %s%n",
            authorization.verificationUri(), authorization.userCode());
});
```

`deviceAuthorize` and `devicePoll` are also public, for an application driving its
own loop. The polling rules are where implementations go wrong:

- **`slow_down` raises the interval permanently.** An SDK that backs off for one
  round and returns to the original interval will be told to slow down again,
  forever.
- **`access_denied` and `expired_token` stay distinct.** A human said no, versus
  nobody answered — the only information the device can act on.
- **Polling stops at `expiresIn`**, even if the server has not yet said
  `expired_token`.
- **A `5xx` mid-poll is not terminal.** A server restart must not lose a grant the
  user has already approved.

`deviceCode()` is `Sensitive`; `userCode()` deliberately is not — it exists to be
read aloud, and wrapping it would defeat the one thing it is for.
`deviceAuthorize` sends no `client_secret` and does not refuse a client built
without one. An interrupt during the inter-poll sleep restores the thread's
interrupt flag rather than swallowing it, so a shutting-down device can observe it.

Per §14.3 rule 4, `deviceLogin` **returns** the token set; this SDK does not adopt
it, matching its `loginClientCredentials` posture.

## Token exchange (§15)

RFC 8693 — a service holding a user's token exchanging it for a *narrower* one
before calling the next service.

```java
ExchangedToken exchanged = client.tokenExchange(
        Sensitive.of(userToken),
        OidcOperations.ACCESS_TOKEN_TYPE,   // required (§15.1), no default
        null, List.of("orders:read"),
        "orders-service", null, null, null);
```

Most of what this method does is refuse to be helpful:

- **No default `actorToken`.** Passing `null` asks for *impersonation*; the SDK
  will not quietly substitute the client's own session token and turn that into a
  delegation.
- **No auto-narrowing after `invalid_scope`.** The server refuses rather than
  silently narrowing precisely so the caller finds out here.
- **No refresh token, ever** — `ExchangedToken` has no such component. Re-run the
  exchange.
- **No adoption.** A MUST NOT, where `loginClientCredentials` adoption is a MAY.

### External-IdP subject tokens (§15.7)

The same method exchanges a token minted by a **trusted external IdP** — a
partner's Entra, Okta or Keycloak — for an AXIAM token scoped to what the
resolved AXIAM user may actually do. There is no separate operation, just an
overload that lets you name what kind of token you hold:

```java
ExchangedToken exchanged = client.tokenExchange(
        Sensitive.of(partnerToken),
        OidcOperations.JWT_TOKEN_TYPE,   // required; named, never guessed
        null,                            // no actor token, ever, here
        List.of("read:orders"), "https://orders.internal", null, null, null);
```

- **`subjectTokenType` is yours to state, and is required** (§15.1). The SDK
  never decodes the subject token to pick it, and never overrides what you
  named. There is no default: `null` or blank is refused client-side with no
  wire call, because a default would be the SDK choosing for you.
- **No actor token.** Delegation across a trust boundary is unsupported in v1;
  sending one is `invalid_request`, which the SDK will not work around by
  dropping it and re-sending.
- **One refusal is distinguishable.** `invalid_grant` whose `errorDescription()`
  is `the subject token's issuer is not configured for token exchange` means
  *fix the AXIAM trust configuration*. Every other `invalid_grant` means *fix
  your token*, and is deliberately generic.
- **Forward the result as-is.** It carries an `ext_exchange` claim naming the
  partner issuer; never strip it, and never read it as an authorization input.
  It also cannot be exchanged again — exchanges do not compose.

The operator guide is `docs/api/federated-token-exchange.md`.

## Logout — RP-initiated and back-channel (§12.7)

`logoutUrl` builds the redirect; `verifyLogoutToken` validates a token the OP
**pushed** to your back-channel endpoint.

```java
String url = client.logoutUrl(Sensitive.of(storedIdToken));

// …and at your registered backchannel_logout_uri:
VerifiedLogoutToken verified = client.verifyLogoutToken(logoutToken, null);
if (verified.sid() != null) {
    endSession(verified.sid());   // that session ONLY
}
```

The verifier is where the security weight sits — the input arrives unsolicited and
instructs you to terminate a session. It checks the signature (same JWKS path and
same EdDSA/`kid` discipline as §12.4), `iss`, `aud`, that `events` carries the
back-channel-logout key (**the only thing separating a logout token from an ID
token**), that `nonce` is *absent* (its presence is how an ID token gets replayed
as one), that something is named, and freshness.

It returns `sid`/`sub`/`jti` rather than a bare `boolean`: you have to know *which*
session to end. **Dedup on `jti` yourself** — delivery is at-least-once, so a valid
token legitimately arrives twice; the SDK has no durable store and an in-memory
guard would silently drop a real second logout after a restart.

## Decision reason codes (§11 rule 9)

`AccessResult.reasonCode()` — on both the REST and gRPC results — distinguishes
`no_grant` ("ask an admin for access") from `denied_by_rule` ("an admin has already
decided"). Opposite instructions to the person on the other end, which is why the
contract forbids collapsing them into a bare `false`. An unrecognised code is
surfaced verbatim and never changes `allowed()`; `null` means the server did not
send one.

## Webhook signature verification (`io.axiam.sdk.webhook`, §13)

```java
import io.axiam.sdk.Sensitive;
import io.axiam.sdk.webhook.AxiamWebhooks;
import io.axiam.sdk.webhook.WebhookEvent;
import io.axiam.sdk.webhook.WebhookVerificationException;

// request.getBody() MUST be the exact raw bytes received off the wire —
// never re-serialize a parsed JSON body, since that changes key
// order/whitespace and breaks the MAC.
byte[] body = readRawBody(request);

try {
    WebhookEvent event = AxiamWebhooks.verify(
            Sensitive.of(webhookSecret),
            request.getHeader("X-Axiam-Signature"),
            body);

    // Dedup at-least-once retries using X-Axiam-Delivery (not part of the
    // MAC — keep a short-lived seen-set keyed on it).
    String deliveryId = request.getHeader("X-Axiam-Delivery");

    switch (event.type()) {
        case "user.created" -> { /* ... */ }
        default -> { /* ignore unknown event types */ }
    }
} catch (WebhookVerificationException e) {
    // e.reason() is a stable Reason code; e.getMessage() never contains the
    // expected/received signature or the secret.
    response.setStatus(401);
}
```

`AxiamWebhooks.verify` defaults to a ±300-second freshness window
(`AxiamWebhooks.DEFAULT_TOLERANCE`, overridable via the `Duration tolerance`
overload) and throws `WebhookVerificationException` — never a bare/generic
exception — on any failure. A `Clock` overload is available for tests that
need a fixed "now".

## Reactors — AMQP extension actors (`io.axiam.sdk.reactor`, §22)

A **reactor** is your process, subscribed to named hook events on the AXIAM AMQP bus,
answering allow / deny / mutate inside a timeout the server declared. It is AXIAM's answer
to Zitadel Actions and Keycloak SPIs, and the difference is the whole design: those load
third-party code *into* the authorization server, and this keeps it outside, reachable only
through a signed reply schema the server validates before it believes a word of it.

```java
// §8b: build the broker connection through ReactorConnections and the transport
// rules hold by construction — amqps:// only, hostname verification on, and no
// argument anywhere that turns either off.
ConnectionFactory factory = ReactorConnections.connectionFactory(
    "amqps://reactor:secret@broker.internal:5671/%2f",
    Files.readAllBytes(Path.of("/etc/axiam/broker-ca.pem")));  // null for a public CA
Connection connection = factory.newConnection();
Channel channel = connection.createChannel();

ReactorServeOptions options = ReactorServeOptions
    .builder(channel, tenantId, Sensitive.of(subkeyHex))
    .reactorId(reactorId)               // the queue is the server's; we only consume it
    .handler(event -> switch (event.event()) {
        case ReactorEvents.TOKEN_PRE_ISSUE ->
            ReactorDecision.mutate(Map.of("ext.department", "engineering"));
        case ReactorEvents.LOGIN_POST_AUTH ->
            embargoed(event) ? ReactorDecision.deny("embargoed region")
                             : ReactorDecision.allow();
        default -> ReactorDecision.allow();
    })
    .build();

try (ReactorServer server = ReactorServer.reactorServe(options)) {
    Thread.currentThread().join();
}
```

### Transport security (§8b)

`ReactorServeOptions.builder(channel, …)` takes an already-open channel, so the SDK cannot
inspect how it was opened. §8b's requirements used to live only in that method's javadoc —
"its connection MUST have been opened over `amqps://` with a trusted CA" — which meant a
caller who built a `ConnectionFactory` from an `amqp://` URI got a working reactor, no
warning, and signed-but-readable token decisions on the wire.

`ReactorConnections` is the enforcing path:

| Argument | Meaning |
|---|---|
| `uri` | Must be `amqps://` (rules 1 and 5). Every other scheme is refused, and so is a URI that will not parse — a security check must fail closed on an input it cannot read. |
| `customCaPem` | CA bundle for a privately issued broker certificate (rule 2 — the common in-cluster case). Added to the system roots, never substituted for them. |
| `clientCertPem` + `clientKeyPem` | Mutual TLS (rule 3). All-or-nothing: half an identity is refused before dialling. |

Hostname verification is enabled explicitly, because the RabbitMQ Java client leaves it
**off** by default — a certificate that verifies but names a different host is precisely the
attack TLS exists to stop. There is deliberately no verification-skip argument under any
name (rule 4).

Note there is no loopback exception: §8b rules 1 and 5 carry no host carve-out, and the
AXIAM server is TLS-only with no plaintext listener for one to reach.

`ReactorServeOptions` still accepts any channel. Enforcing at construction cannot
retroactively constrain a channel someone else opened, and refusing to serve on one whose
provenance cannot be inspected would break every legitimate custom setup to catch a mistake
`ReactorConnections` already prevents.

### Binding handlers per event (§22.14)

The `switch` above is the shape every multi-event reactor grows, and its `default` arm —
`ReactorDecision.allow()` — answers on behalf of code that never ran. That is the defect
§22.10 rule 2 forbids the *runtime* from committing, relocated into your file where the
rule does not reach it: an operator who set `fail_closed` on the registration has it
defeated there.

`ReactorHandlers` is §22.14's declarative form, and it uses the same annotation mechanism
the §11 `@AxiamRequireAccess` helper already uses:

```java
public final class ClaimsReactor {

    @OnReactorEvent(ReactorEvents.TOKEN_PRE_ISSUE)
    public ReactorDecision enrich(ReactorEvent event) {
        return ReactorDecision.mutate(Map.of("ext.department", "engineering"));
    }

    @OnReactorEvent(ReactorEvents.LOGIN_POST_AUTH)
    public ReactorDecision screen(ReactorEvent event) {
        return embargoed(event) ? ReactorDecision.deny("embargoed region")
                                : ReactorDecision.allow();
    }
}

ReactorHandlers handlers = ReactorHandlers.of(new ClaimsReactor());
ReactorServeOptions options = ReactorServeOptions
    .builder(channel, tenantId, Sensitive.of(subkeyHex))
    .reactorId(reactorId)
    .handler(handlers.handler())
    .build();
```

- **A misspelled event is refused when the annotation is read** — `ReactorHandlers` accepts
  only §22.5 registry names, which is also how it refuses the three hot-path operations
  §22.7 excludes: they are in no registry row. The message names the registry, never the
  exclusions.
- **An unbound event abstains** — the composed handler throws
  `UnboundReactorEventException`, and `ReactorServer` publishes **nothing** for a handler
  that threw, so the registration's `failure_policy` decides (§22.8) exactly as it decides
  a timeout. Never a synthesized `allow`.
- Binding the same event twice throws rather than silently overwriting, and
  `handlers.events()` feeds `ReactorEvents.defaultFailurePolicyFor` so you can see what an
  unreachable reactor costs before you go live.

Lambdas work too — `new ReactorHandlers().bind(ReactorEvents.TOKEN_PRE_ISSUE, fn)` — and
both spellings are governed by the same rules. It is pure sugar: `handler()` returns exactly
the `ReactorHandler` `ReactorServer` already takes. It opens nothing, verifies nothing,
signs nothing, does not filter a patch, and a handler's own throwable reaches the runtime
unwrapped so nothing is published and the log names the real failure.

Register the reactor first — the queue it consumes is declared by the **server**, from a
`POST /api/v1/reactors` registration. See [`examples/reactor`](examples/reactor) for a
runnable one that enriches a token and screens a login.

### Both directions are signed

The server signs the event with the tenant's HKDF-derived AMQP subkey; this SDK signs the
reply with **the same** subkey. An unsigned or stale reply is not a weak reply — the server
discards it as though the reactor had never answered, and the registration's
`failure_policy` takes over.

Everything is §8 v2 verbatim (same key derivation, same constant-time HMAC-SHA256, same
±300 s window, same `key_version` floor of 2) with **one** difference, and it is the one that
costs an implementer a day if it is not stated: a reactor body is signed with
`hmac_signature` **present and set to `null`**, where §8's own two message types omit it.
`ReactorProtocol` is the only place that rule lives, and it is proven byte-for-byte against
the server-generated §22.13 vectors — including the omission rules for `reason`, `patch` and
`require_mfa` (a reply serializing `"require_mfa": false` rather than omitting it produces a
different MAC).

Before your handler runs, the runtime rejects `key_version < 2`, verifies the MAC, checks
freshness in **both** directions, and checks the nonce. A runtime that hands an unverified
payload to user code has already lost.

### Five events, and what each may change

| Event | Mutable fields (the complete allow-list) | Default failure policy |
|---|---|---|
| `token.pre_issue` | **`ext.` namespace only** | `fail_open` |
| `login.post_auth` | — (veto, or `require_mfa`) | `fail_closed` |
| `user.pre_create` | `username`, `email`, `metadata.` namespace | `fail_closed` |
| `user.pre_update` | `username`, `email`, `metadata.` namespace | `fail_closed` |
| `grant.pre_assign` | — (veto only) | `fail_closed` |

An entry ending in `.` is a namespace prefix and needs at least one character after the dot:
`ext.department` and `ext.a.b.c` are in, and `ext.`, `ext`, `extra`, `external_id` and
`evil.ext.department` are not. No standard claim is reachable from `token.pre_issue`, because
none of them begins with `ext.` — a **correctly signed** reply setting `sub` is refused
exactly as a forged one is.

A registration naming no `failure_policy` inherits the **strictest** default among its
events, in either array order (`ReactorEvents.defaultFailurePolicyFor`). A reactor registered
for both `token.pre_issue` and `login.post_auth` can veto a login, so it gets `fail_closed`.

### `authz.check` is not hookable, and never will be

`authz.check`, `authz.check_batch` and `token.introspect` are **absent** from
`ReactorEvents.REGISTRY` and from every constant this SDK exposes — asserted by a test
against the list, not documented by a comment. The reason is arithmetic, not policy: a
reactor round trip is milliseconds and the check path's budget is microseconds. Hooking it
would not produce a slower check, it would produce a different product.

This SDK also offers no interceptor, middleware hook or callback presenting itself as the
reactor equivalent for those operations. An application that needs external input on an
authorization decision writes a **deny grant**, which the engine evaluates in the hot path at
hot-path cost.

### What the runtime will not do for you

- **It will not declare topology.** No `exchangeDeclare`, `queueDeclare` or `queueBind`,
  anywhere — a reactor that can bind is a reactor that can bind itself to
  `*.token.pre_issue` and read another tenant's issuance events. `reactorId(..)` names your
  own queue and no other.
- **It will not synthesize an `allow` for a handler that threw.** Throwing publishes
  *nothing*, and the operator's `failure_policy` decides what that costs. Answering `allow`
  on your behalf would defeat a `fail_closed` setting from inside the library.
- **It will not filter your patch.** A forbidden key goes on the wire as written and the
  server refuses the whole patch. Trimming it silently would leave you believing a field was
  set when it was dropped.
- **It will not reply late.** When your handler returns after `event.timeoutMs()` has
  elapsed, the reply is abandoned — the server stopped listening, and publishing anyway only
  adds load.
- **It will not retry a reply (§16).** A correlation is single-use and a late reply is
  discarded; the recovery mechanism for an unanswered dispatch is the server-side
  `failure_policy`, not a resend. Connection recovery is the RabbitMQ client's, left on.

`close()` is §18-deterministic: it cancels the consumer so no new delivery starts, drains
what is in flight, and is idempotent. §19 telemetry emits one `RequestStart`/`RequestEnd`
pair per dispatch with the event name as the path template — a closed set of five values.

### Listeners

`mode: "listen"` is fire-and-forget observation: the server never waits and never reads a
reply. Pass `.listener(..)` instead of `.handler(..)` — it returns `void`, so a listener
*cannot* publish a reply rather than merely being told not to. Write it idempotently: a
redelivery after a broker hiccup is normal.

### Logging

The signing key is a credential and is wrapped in `Sensitive` — never logged at any level,
never in a reconnect diagnostic. The `payload`, `patch`, `reason` and `decision` are **not**
secrets and stay readable (a handler that cannot inspect the event cannot decide anything),
but they are tenant business data: this SDK never logs the payload, and neither should you at
`info` level. The `nonce`, `correlation_id` and `hmac_signature` are not secrets and may be
logged for correlation.

## OPAQUE (`io.axiam.sdk.opaque`, §23)

`loginOpaque` proves the password to the server without the password — or
anything from which it can be cheaply recovered — ever crossing the wire. The
server stores a **registration record** sealed under a tenant-wide oblivious
PRF seed, and what travels is a blinded group element and a MAC, neither
useful without both.

```java
char[] password = readPassword();
LoginResult result = client.loginOpaque("alice", password);
java.util.Arrays.fill(password, '\0');
```

It takes the same arguments as `login` and returns the same `LoginResult`, MFA
branch included, so switching a tenant to OPAQUE needs no change to how the
result is handled. A runnable end-to-end example, including the fallback and
the enrolment call, is in [`examples/opaque-login`](examples/opaque-login).

Unlike the SRP-6a it replaces, there is no separate server-proof step and
nothing has been dropped: RFC 9807's AKE authenticates the server during the
handshake, so opening `KE2` **is** the proof that it holds the record. The old
contract had to mandate an `M2` check in capitals because skipping it kept only
half the protocol; there is now nothing to skip.

### The protocol is not implemented here

CONTRACT.md §23.1 forbids an SDK from writing its own OPAQUE. SRP-6a was
arithmetic every language can express, which is why `io.axiam.sdk.srp` existed
at ~700 lines of modular exponentiation. OPAQUE is not: it needs an oblivious
PRF, `hash_to_curve`, `expand_message_xmd`, an envelope construction and a
three-message AKE, and eleven independent implementations of that is eleven
chances to be subtly and silently wrong in a way that still interoperates until
it does not.

`io.axiam.sdk.opaque` therefore contains **no cryptography**. It is a JNA
binding to `libaxiam_opaque_ffi`, the same implementation the AXIAM server
links, plus the ownership bookkeeping a binding has to get right.

### Installing

Two things are needed, and both are deliberately optional:

1. **JNA** — `net.java.dev.jna:jna`, declared `<optional>true</optional>` here
   so it does not reach your classpath transitively. A REST/gRPC/AMQP consumer
   whose tenant does not use OPAQUE should not be made to carry a native-access
   library. Add it explicitly to use OPAQUE:

   ```xml
   <dependency>
     <groupId>net.java.dev.jna</groupId>
     <artifactId>jna</artifactId>
     <version>5.19.1</version>
   </dependency>
   ```

2. **The shared library** — a Rust `cdylib` published as a per-platform asset
   on the [axiam release page](https://github.com/ilpanich/axiam/releases), not
   an artifact on Maven Central. Put it on `java.library.path`, or point at it:

   ```bash
   java -Daxiam.opaque.library=/opt/axiam/libaxiam_opaque_ffi.so ...
   # or: export AXIAM_OPAQUE_LIBRARY=/opt/axiam/libaxiam_opaque_ffi.so
   ```

This SDK targets Java 21, where the FFM API (`java.lang.foreign`) is still
preview and would oblige every consumer to build with preview enabled. Raising
the baseline to 22 to avoid one optional dependency would be the larger break.

Ask before you need it:

```java
if (client.opaqueAvailable()) {
    result = client.loginOpaque(user, password);
} else {
    result = client.login(user, new String(password));
}
```

Unlike the `srpAvailable()` it replaces — hard-coded `true` on the JVM because
`BigInteger` and BouncyCastle are always there — this can genuinely answer
`false`. It reports rather than throwing, so an application chooses the
password path up front instead of discovering the gap mid-exchange.

### What this buys, and what it does not

OPAQUE closes holes TLS 1.3 does not:

- a TLS-terminating reverse proxy, ingress controller, CDN or service mesh
  sees every plaintext password today; under OPAQUE it sees `KE1` and `KE3`;
- an accidental request-body log, a heap dump or a crash reporter can no
  longer capture a plaintext password, because the server never has one;
- **a stolen record database is not offline-crackable on its own.** This is the
  substantive gain over SRP: cracking a record also requires the tenant's OPRF
  seed, which is AES-256-GCM encrypted at rest under a key the database does
  not hold.

It does **not** protect against a compromised AXIAM server, and this SDK does
not claim it does.

### Tenant policy, and the errors that are not credential failures

`opaque_mode` is an organization baseline a tenant may tighten:

| mode | `login` | `loginOpaque` |
|---|---|---|
| `disabled` (default) | works | `NetworkError` — the endpoint answers `404` |
| `optional` | works | works |
| `required` | `AuthzError` | works |

Which exception you get is most of what this SDK owns on this path:

| condition | exception | why |
|---|---|---|
| tenant has OPAQUE disabled | `NetworkError` | a property of the tenant, not of any user — fall back to `login` |
| shared library or JNA absent | `NetworkError` | a deployment fact, raised before any request is sent |
| server named a KSF this build cannot perform | `NetworkError` | a configuration problem; substituting one would surface as a wrong password |
| `*/start` response missing `ke2` | `NetworkError` | malformed response |
| envelope did not open / `KE2` did not verify | `AuthError` | the **whole** of the credential check |
| tenant refuses password login (`login`) | `AuthzError` | the credentials were never examined |

That `AuthError` covers both halves of the mutual authentication: a wrong
password, an account that does not exist, and a server that does not hold the
record are indistinguishable by design. **Nothing is sent to `login/finish` in
that case** (§23.4 rule 7), and you must not retry over `login()` — that hands
the plaintext to an endpoint that just failed to prove it holds the record.

`required` refuses **every** principal in the tenant, not only the enrolled
ones. Splitting the response on whether an account has a record would turn
`/auth/login` into an enumeration oracle costing one junk password per name. It
also means `required` locks out anyone not yet enrolled: a record needs the
plaintext password, and a stored Argon2id hash is not invertible, so nobody can
be enrolled retroactively. Operators turn it on last, after a password-reset
campaign.

### Enrolment

The server cannot build a registration record, so any request that **sets** a
password has to carry one. `opaqueEnrollment` produces the `opaque` object for
`POST /api/v1/users`, `/auth/password/change`, `/auth/reset/confirm` and
`/admin/bootstrap`:

```java
OpaqueEnrollment enrolment = client.opaqueEnrollment(newPassword);
request.set("opaque", enrolment.toJson(mapper));
```

Note the arguments that are gone. There is no `identity`: the SRP version
required the account's canonical **username**, and an email there produced a
verifier no login could ever satisfy — and renaming a user invalidated their
verifier outright. A record binds to a credential identifier the server
chooses, so neither is true any more. There is no group or KDF either: those
come from the `register/start` response, so a caller cannot pick a cost the
server will not honour.

Unlike `srpEnrollment` this performs I/O — one `register/start` round trip. The
envelope is sealed under the server's oblivious PRF, so there is no offline
computation that produces a valid record.

### Cost

`loginOpaque` runs the tenant's key-stretching function: Argon2id at 19 MiB and
t=2 by default, which is tens to hundreds of milliseconds of CPU plus that
memory, per login attempt. That cost is the point — it is what makes a stolen
record expensive to attack even by someone holding the OPRF seed. Size thread
pools and request timeouts accordingly; it is not a cost `login` has.
`loginOpaqueAsync` moves it off the calling thread but not off the CPU.

### Cryptographic parameters

The ciphersuite is `OPAQUE-3DH` over **ristretto255** with **SHA-512**,
HKDF-SHA-512 and HMAC-SHA-512, fixed AXIAM-wide. It is not negotiated and not
read from the server: a client that accepted a suite from the endpoint it is
authenticating would be accepting a downgrade.

The key-stretching function *is* the server's to name, per exchange, and is
honoured as given rather than cached or defaulted — a credential enrolled under
one cost keeps working after a tenant raises its policy. `argon2id` and
`scrypt` are accepted; anything else is refused rather than substituted.
Costs outside the bands this SDK will act on (`memory_kib` 8 MiB–1 GiB,
`iterations` 1–10, `parallelism` 1–16, `log_n` 14–20, `r`/`p` 1–16) are refused
too: a server is trusted to name its own policy, not to name a cost that would
wedge every device an account owns.

### Zeroization

`loginOpaque` and `opaqueEnrollment` take the password as a `char[]` so the
caller can clear it, and clear every copy they make of it — including the UTF-8
bytes handed across the ABI. They cannot clear the caller's array; do that
yourself, in a `finally`. If your password arrives as a `String` (from a JSON
body, say), it is already immutable and already copied; the `char[]` signature
is honest about where this SDK's reach ends rather than implying a guarantee it
cannot keep.

The password crosses the ABI as **UTF-8**, explicitly, never through JNA's
`String` mapping — which uses the platform charset unless `jna.encoding` says
otherwise. A password that encoded differently under a different default locale
would derive a randomized password no AXIAM server agrees with, and would
surface as a wrong password on that machine only.

## WebAuthn / passkeys (`io.axiam.sdk.webauthn`, §24)

Six wire operations, two ceremonies, and one thing this SDK deliberately does
not do.

```java
// Enrolment — requires a session (§24.1), refused client-side without one.
WebauthnChallenge challenge = client.webauthnRegisterStart();
String response = /* the authenticator's JSON, verbatim */;
WebauthnCredential credential =
        client.webauthnRegisterFinish(challenge.stateToken(), "Pixel 9", response);

// Sign-in with no username at all — the authenticator picks the account.
WebauthnChallenge signIn = client.webauthnDiscoverableStart(null);
WebauthnLoginResult result =
        client.webauthnDiscoverableFinish(signIn.stateToken(), assertionJson);
```

**The server chooses every option and verifies every response; this SDK passes
both through byte-for-byte** (§24.0). `WebauthnChallenge.challenge()` is a raw
`JsonNode`, not a modelled type: no defaulting, no validation-that-rejects, no
re-encoding. A client that "helpfully" filled in a missing field would be
overriding a policy decision it cannot see, and one that re-serialized a
response would risk corrupting a signed buffer to no purpose.

### The two authentication ceremonies are different flows (§24.2)

`webauthnAuthenticateStart`/`Finish` is a **second factor** — it continues a
`login()` that answered `mfaRequired` with `"webauthn"` among its methods, and
the challenge token names the user so the server can send an `allowCredentials`
list. `webauthnDiscoverableStart`/`Finish` is a **primary factor**: nothing
precedes it, `allowCredentials` is empty, and the assertion itself identifies
the user. They are not one operation with an optional token — merging them
reproduces a bug the server already fixed.

One difference a reactor author will ask about: `discoverable/finish` fires the
`login.post_auth` hook event (§22.5) and `authenticate/finish` does not. The
latter continues a login that was already gated at its password step; the former
has no such step to have been gated at.

### Android, via the §24.6a JSON bridge

Android's Credential Manager is a string-in / string-out API, which is exactly
why this artifact stays a plain JVM library with **no AAR and no Android
dependency**:

```kotlin
// build.gradle.kts
implementation("io.github.ilpanich:axiam-sdk:<version>")
implementation("androidx.credentials:credentials:1.3.0")
implementation("androidx.credentials:credentials-play-services-auth:1.3.0")

val challenge = client.webauthnRegisterStart()

val response = CredentialManager.create(context).createCredential(
    context,
    CreatePublicKeyCredentialRequest(
        requestJson = challenge.requestJson(),   // verbatim
    ),
) as CreatePublicKeyCredentialResponse

client.webauthnRegisterFinish(
    challenge.stateToken(),
    "Pixel 9",
    response.registrationResponseJson,                    // verbatim
)
```

Sign-in mirrors it: `webauthnDiscoverableStart(null)`, then
`GetPublicKeyCredentialOption(requestJson = challenge.requestJson())`,
then `webauthnDiscoverableFinish(challenge.stateToken(),
credential.authenticationResponseJson)`.

`webauthnRegisterFinish` and both `*Finish` calls accept the platform's JSON as
a `String` for precisely this reason. Passing something that is not JSON, or is
not a JSON object, raises `AuthenticationError` client-side — the SDK will not
POST a body it knows the server cannot verify.

### Two error rows that are not the §2 defaults (§24.4)

- A **403 from `register/finish`** is the tenant's *attestation policy*
  rejecting this particular authenticator. The server's message is the only
  place that says which one would be accepted, so it is lifted into the
  `AuthorizationError`'s message rather than discarded. Show it.
- A **503 from `register/start`** means the policy needs FIDO metadata the
  server cannot reach. That is a configuration state, not a transient one, and
  it is **not retried** — the second documented exception to §16 after §20's.

Session cookies: as of contract 1.28 both `*/finish` authentication calls set
the `axiam_access` / `axiam_refresh` / `axiam_csrf` triple alongside the token
body, so a completed ceremony leaves the client signed in for every
cookie-driven call that follows (§24.3).

Worked end to end in [`examples/webauthn-passkeys`](examples/webauthn-passkeys).

## Account lifecycle and MFA enrolment (`io.axiam.sdk.account`, §25)

Nine operations covering the things a user does to their own account — none of
which is administration, and all of which were previously reachable only by
hand-rolling HTTP.

```java
LoginResult result = client.login("alice@example.com", password);

if (result.mfaSetupRequired()) {
    // The third outcome. The tenant requires MFA, this account has none, and
    // the server handed back a setup token to finish with. There is no session
    // yet — the token IS the credential.
    Sensitive setupToken = result.setupToken();
    MfaEnrollment enrollment = client.mfaSetupEnroll(setupToken);
    renderQr(enrollment.totpUri().expose());
    result = client.mfaSetupConfirm(setupToken, code);   // completes the LOGIN
}
```

`LoginResult` gained two components rather than changing shape, so every
pre-1.28 call site still compiles: the 3-argument constructor remains, and
answers `false` for the new flag. **Handle the new outcome anyway.** A tenant
that turns on required MFA will start returning it, and a client that only
branches on `mfaRequired()` will report a successful login that has no session.

`mfaSetupConfirm` adopts credentials exactly as `login()` does, because it *is*
the completion of a login (§25.2 rule 2). `mfaEnroll`/`mfaConfirm` are the
voluntary pair, from inside an existing session, and they do **not** clear the
§17 decision memo — the subject has not changed, and discarding a warm memo on
an unrelated profile action costs a round trip on every check that follows.

Both halves of an `MfaEnrollment` are `Sensitive`, and the second one matters:
the `otpauth://` URI *contains* the secret (§25.3). Wrapping the bare secret and
then logging the URI leaks the same bytes.

### Password reset, and the two things it will not tell you

```java
client.requestPasswordReset(new PasswordResetRequest("alice@example.com"));
// returns void, whether or not that address has an account

PasswordResetContext context = client.passwordResetContext(token);
if (context.opaque() != null) {
    // This tenant runs §23. Build a registration record from these parameters;
    // a plaintext password would be refused, and refused late (§25.4 rule 1).
}
client.confirmPasswordReset(new PasswordResetConfirmation(token, newPassword, tenantId));
```

`requestPasswordReset` returns nothing and throws nothing on an unknown address,
and this SDK exposes no way to tell the two cases apart. That is not an omission
to improve on: a client that surfaced a "no such user" state — even one inferred
from timing — would turn the endpoint into the account-enumeration oracle its
uniform response exists to prevent. Likewise a `404` from
`passwordResetContext` means unknown, expired **or** already-consumed, and the
SDK does not distinguish them either (§25.4 rule 3).

`verifyEmail` and `resendVerification` are unauthenticated — a user whose
address is unverified may have no session at all — and carry the tenant as a
**body** field, since §12.1 rule 2's `?tenant_id=` convention is scoped to
`/oauth2/*`.

Worked end to end in [`examples/account-lifecycle`](examples/account-lifecycle).

## Pushed Authorization Requests (§26, RFC 9126)

PAR moves the authorization request off the browser. Instead of putting `scope`,
`redirect_uri`, `state` and the PKCE challenge into a URL the user agent
carries, the client POSTs them straight to AXIAM over an authenticated back
channel and puts an opaque `request_uri` in the redirect.

```java
OidcConfiguration config = client.oidcDiscover();
if (config.pushed_authorization_request_endpoint() == null) {
    // §26 is optional; fall back to the plain oidcBegin redirect.
}

AuthorizationRequest begun = client.oidcBegin(config, redirectUri, "openid profile", null);
PushedAuthorizationRequest pushed =
        client.oidcPar(config, begun, redirectUri, "openid profile", null);

redirect(pushed.url());   // exactly ?client_id=…&request_uri=…
```

Three things worth knowing:

- **The server answers `201`,** not `200` — RFC 9126 §2.2 specifies *Created*. A
  success predicate written `== 200` treats every successful push as a failure.
- **The redirect URL carries exactly two parameters.** The server refuses a
  request that mixes a `request_uri` with inline authorization parameters rather
  than merging them; merging is where parameter confusion lives (§26.2 rule 2).
  Any query the discovered `authorization_endpoint` already carried is dropped.
- **`oidcBegin` still owns `state`, `nonce` and the PKCE pair.** There is no
  second generator (§26.2 rule 1), and `PushedAuthorizationRequest` carries all
  three straight through to the exchange.

The push is **not retried** on a 5xx or a transport failure: it is a POST that
creates server state, so it falls outside §16.2's read-only eligibility exactly
as `oidcExchange` does. The safe recovery is a fresh push, which costs one round
trip and cannot double-consume anything. The `requestUri` is `Sensitive` because
between the push and the redirect it is a bearer handle to a fully-formed
authorization request (§26.5).

A **FAPI 2.0 client has no alternative**: `profile: "fapi2"` refuses a
registration that does not set `require_par`, so such a client cannot authorize
any other way (§21.1).

Worked end to end in [`examples/par-login`](examples/par-login).

## Building from source

Requires JDK 21+ and Maven 3.9+.

```bash
mvn -B verify              # build, test, javadoc/sources jars (SDK)
mvn -B -f bom/pom.xml verify   # the BOM is an independent reactor
```

gRPC stubs are generated at build time by `protobuf-maven-plugin` from the
vendored `proto/axiam/v1/*.proto` tree into `target/generated-sources`
(gitignored, never committed). `proto/` is synced from the
[AXIAM server repo](https://github.com/ilpanich/axiam); `buf` is not used by
this SDK.

## Status

Java SDK, extracted from the AXIAM monorepo into its own repository.

## Client quality-of-life (CONTRACT.md §16–§19)

### Retry policy (§16)

Read-only authorization checks — `checkAccess` (both overloads) and `batchCheck` — retry
transient failures under the contract's normative table: **3 attempts** (1 initial + 2
retries), 200 ms base, 5 s cap, **full jitter** (uniform over `[0, backoff]`), and
`Retry-After` honored as a **floor**.

This SDK's `Retry` was already conformant — it is the implementation whose parameters the
contract adopted, and of the five SDKs that had invented a policy it was the only one that
got jitter and `Retry-After` both right. D5 adds the disable switch and the §16.5 retry
event; the arithmetic is unchanged.

```java
// Turn it off if you own your own retry layer — you know your deadline, this SDK doesn't.
AxiamClient client = AxiamClient.builder(baseUrl, "acme").retryDisabled().build();
```

There is deliberately no builder method for the attempt cap, base delay or delay cap: §16.1
forbids raising them, and eleven SDKs agreeing on one table is the point.

### Deterministic shutdown (§18)

`close()` releases the client's local resources. It is idempotent — a concurrent double-close
does the work once — and any call afterwards throws `NetworkError` naming the cause rather
than silently reconnecting.

**`close()` does not log out.** It never reaches the network. The server-side session
deliberately outlives the client object — that is what lets a process restart and resume — so
a `close()` that logged out would silently end every user's session on each deploy. Call
`logout()` first if ending the session is what you want.

### Telemetry hooks (§19)

Wire metrics without this library depending on any metrics API:

```java
AxiamClient client = AxiamClient.builder(baseUrl, "acme")
    .telemetryHook(event -> {
        if (event instanceof TelemetryEvent.RequestEnd end) {
            histogram.record(end.duration().toMillis(), /* labels */);
        } else if (event instanceof TelemetryEvent.Retry retry) {
            counter.increment(/* labels */);
        }
    })
    .build();
```

- **A hook that throws cannot fail the operation that fired it.** Telemetry is not permitted
  to fail an authorization check.
- **No event payload can carry a token.** `TelemetryEvent` is a **sealed** hierarchy of
  records with fixed component lists — no code outside the SDK can add a variant, which is
  what makes that guarantee checkable rather than aspirational.
- **Path templates, not URLs**, so a metric label cannot become a cardinality bomb.

One `RequestStart`/`RequestEnd` pair is emitted **per attempt**, so you can count real wire
calls. See [`examples/telemetry-hook`](examples/telemetry-hook).

### Decision memo (§17) — opt-in, off by default

An optional TTL-bounded cache for `checkAccess` results. **Disabled by default**, because
§11.2 rule 6's ban on caching authorization decisions is still the default behaviour.

```java
AxiamClient client = AxiamClient.builder(baseUrl, "acme")
    .decisionMemoTtl(Duration.ofSeconds(5))
    .build();
```

**What you are accepting.** The staleness bound is the TTL, in *both* directions: a grant
revoked on the server can still read as allowed for up to the TTL, and a grant just added can
still read as denied for up to the TTL.

> **Reads-your-own-writes is not guaranteed.** An admin UI that grants a role and immediately
> re-checks is the case that breaks, and it breaks silently. If that is your workload, leave
> this off.

The TTL is clamped to `DecisionMemo.MAX_TTL` (5 s) rather than rejected. Allows and denies are
memoized identically — asymmetric caching would leak which outcome occurred through latency.
Failures are never memoized: caching a transport error as a deny would turn a blip into a
TTL-long outage. The memo is cleared on `login`, `verifyMfa`, `refresh` and `logout`, since
entries are keyed by subject rather than by session. It is thread-safe.
