# axiam-sdk (Java)

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

This SDK conforms to CONTRACT.md §1-§11.

See [`CONTRACT.md`](CONTRACT.md) for the full cross-language behavioral contract.

## Getting started

### Maven

```xml
<dependency>
  <groupId>io.github.ilpanich</groupId>
  <artifactId>axiam-sdk</artifactId>
  <version>0.1.0</version>
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
      <version>0.1.0</version>
      <type>pom</type>
      <scope>import</scope>
    </dependency>
  </dependencies>
</dependencyManagement>
```

### Gradle (Kotlin DSL)

```kotlin
dependencies {
    implementation("io.github.ilpanich:axiam-sdk:0.1.0")
}
```

Or via the BOM:

```kotlin
dependencies {
    implementation(platform("io.github.ilpanich:axiam-bom:0.1.0"))
    implementation("io.github.ilpanich:axiam-sdk")
}
```

### Quick start

`tenantId` is a **required, positional** argument to `AxiamClient.builder(...)`
— AXIAM is multi-tenant and there is no default tenant (CONTRACT.md §5); a
blank value throws `AuthError` at construction time. `AxiamClient` is
`AutoCloseable`, so always construct it with try-with-resources to release
its underlying OkHttp connection pool/dispatcher:

```java
try (AxiamClient client = AxiamClient.builder("https://axiam.example.com", "acme-tenant").build()) {
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
