# axiam-sdk (Java)

[![CI](https://github.com/ilpanich/axiam-java-sdk/actions/workflows/sdk-ci-java.yml/badge.svg?branch=main)](https://github.com/ilpanich/axiam-java-sdk/actions/workflows/sdk-ci-java.yml)
[![Coverage Status](https://coveralls.io/repos/github/ilpanich/axiam-java-sdk/badge.svg?branch=main)](https://coveralls.io/github/ilpanich/axiam-java-sdk?branch=main)
[![Maven Central](https://img.shields.io/maven-central/v/io.github.ilpanich/axiam-sdk.svg)](https://central.sonatype.com/artifact/io.github.ilpanich/axiam-sdk)
[![javadoc](https://javadoc.io/badge2/io.github.ilpanich/axiam-sdk/javadoc.svg)](https://javadoc.io/doc/io.github.ilpanich/axiam-sdk)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Official Java client SDK for [AXIAM](https://github.com/ilpanich/axiam) — Access eXtended Identity and Authorization Management.

Source: [ilpanich/axiam-java-sdk](https://github.com/ilpanich/axiam-java-sdk)

## Package identity

- **Maven coordinates:** `io.github.ilpanich:axiam-sdk` (BOM: `io.github.ilpanich:axiam-bom`)
- **GroupId:** `io.github.ilpanich`
- **ArtifactId:** `axiam-sdk`
- **Registry:** Maven Central _(reserved, not yet published)_
- **API docs:** [javadoc.io](https://javadoc.io/doc/io.github.ilpanich/axiam-sdk) — served automatically from the `-javadoc.jar` on Maven Central
- **License:** Apache-2.0

## Contract conformance

This SDK conforms to CONTRACT.md §1–§13, including §6.1 mTLS (client-certificate
authentication), the §1.1 gRPC-only `getUserInfo` operation, the §10.1 minimum
local-verification set, the §12 OIDC/SSO relying-party helpers, and the §13
webhook-signature verifier.

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
  <version>1.0.0-alpha23</version>
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
      <version>1.0.0-alpha23</version>
      <type>pom</type>
      <scope>import</scope>
    </dependency>
  </dependencies>
</dependencyManagement>
```

### Gradle (Kotlin DSL)

```kotlin
dependencies {
    implementation("io.github.ilpanich:axiam-sdk:1.0.0-alpha23")
}
```

Or via the BOM:

```kotlin
dependencies {
    implementation(platform("io.github.ilpanich:axiam-bom:1.0.0-alpha23"))
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
login+MFA, REST authorization, gRPC `CheckAccess`, the AMQP consumer, and a
complete Spring Boot 3.x application wiring `AxiamAuthenticationFilter`
explicitly in a `SecurityFilterChain` bean.

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
