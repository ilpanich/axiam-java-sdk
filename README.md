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

This SDK conforms to CONTRACT.md §1–§11, including §6.1 mTLS (client-certificate
authentication).

See [`CONTRACT.md`](CONTRACT.md) for the full cross-language behavioral contract.

## Getting started

### Maven

```xml
<dependency>
  <groupId>io.github.ilpanich</groupId>
  <artifactId>axiam-sdk</artifactId>
  <version>1.0.0-alpha12</version>
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
      <version>1.0.0-alpha12</version>
      <type>pom</type>
      <scope>import</scope>
    </dependency>
  </dependencies>
</dependencyManagement>
```

### Gradle (Kotlin DSL)

```kotlin
dependencies {
    implementation("io.github.ilpanich:axiam-sdk:1.0.0-alpha12")
}
```

Or via the BOM:

```kotlin
dependencies {
    implementation(platform("io.github.ilpanich:axiam-bom:1.0.0-alpha12"))
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
