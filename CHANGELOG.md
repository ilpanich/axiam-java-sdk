# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0-alpha11] - 2026-07-18

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha10.

## [1.0.0-alpha10] - 2026-07-18

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha9.

## [Unreleased]

### Added

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
