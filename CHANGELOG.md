# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
