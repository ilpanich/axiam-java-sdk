# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **Re-vendored the AXIAM contract artifacts at contract 1.36.** `CONTRACT.md`,
  `openapi.json` and `management-registry.json` are byte-identical copies of the
  `sdks/` sources in [`ilpanich/axiam`](https://github.com/ilpanich/axiam)
  (ilpanich/axiam#396). `proto/` and `opaque-test-vectors.json` did not change
  in 1.36 and are untouched. No SDK code changes with them; the three entries
  below are why not.

- **§5.2.2 rule 4 is new, and is an errata rather than a wire change.** The
  server now scopes every *self-service* endpoint to `principal_tenant_id`
  rather than to the acting tenant — `GET`/`PUT /users/{own id}`, that user's
  `mfa-methods`, `POST /users/{own id}/reset-mfa`, `POST /auth/mfa/enroll` and
  `/confirm`, `POST /auth/webauthn/register/start` and `/finish`, `POST
  /users/me/resend-verification`, the §25 account export and erasure for the
  caller's own id, and `GET /oauth2/userinfo`. Each of those answered `404` for
  an organization-level caller that had switched to another tenant and now
  succeeds. No request or response field is added, so nothing here is a wire
  change.

  The rule also forbids the obvious workaround: an SDK MUST NOT clear or rewrite
  the acting-tenant header for those calls, because that header is what makes
  the **administrative** form of the same endpoints reach the tenant the caller
  asked for — stripping it would break reading another tenant's user in order to
  fix reading your own. This SDK was audited for such a workaround and has none:
  `X-Tenant-ID` is set in one place, `rest/AuthInterceptor.java`, whose only
  eligibility test is host-based (same origin or an OAuth2 path); no endpoint is
  special-cased.

- **Issue #395 is settled: the acting-tenant header is `X-Axiam-Tenant`**, and
  §5.2, §5.2.2 and §5.2.3 now name it. The note under 1.0.0-beta05 below
  recorded the contract and the server disagreeing on it; they no longer do, and
  the name this SDK documents was already the server's — checked against the
  vendored contract rather than assumed. §5 rule 2's *unconditional*
  `X-Tenant-ID` is deliberately **not** renamed, and the contract now carries a
  note saying why it must not be: it names the client's *constructor* tenant, so
  folding it into `X-Axiam-Tenant` would override the acting tenant on every
  request an organization-level principal made after a switch. Every existing §5
  rule 2 send is left exactly as it was.

- **`openapi.json` gains `/api/v1/auth/me`, `/api/v1/auth/password/change` and
  `/api/v1/admin/bootstrap`.** All three were always served and always normative
  in `CONTRACT.md`; they were missing from the generated document only because
  their handlers were never listed in its `paths(…)`. `management-registry.json`
  changes only in its `spec_digest` and by one new exclusion entry —
  `operation_count` stays **155**, bootstrap being excluded on the §27.0
  boundary — so §27 code generation must produce no diff. Re-ran `python3
  scripts/gen_management.py` to confirm it produces none.

## [1.0.0-beta05] - 2026-08-30

### Added

- Contract 1.35, carrying 1.34 — service-account RBAC, principal tenant, tenant scope

- **Contract 1.35, which carries contract 1.34 with it.** Nothing had been
  fanned out since 1.33, so this re-vendors `CONTRACT.md`, `openapi.json` and
  `management-registry.json` across both revisions. The registry still holds
  155 operations across 24 namespaces — 1.35 changed only its `spec_digest` —
  so the eight §27 operations below arrived with 1.34 and are new here
  regardless.

- **§27: service accounts as RBAC principals** (contract 1.34) — eight
  generated operations across `RolesApi`, `GroupsApi` and
  `ServiceAccountsApi`. `unassignFromServiceAccount` takes the same optional
  `resourceId` query parameter as the user and group unassign calls: omitting
  it removes the *global* grant specifically, not every grant of that role.

- **§5.2.2/§5.2.3: `PrincipalScope`, reached from `LoginResult.scope()`.**
  Where the signed-in principal lives (`principalTenantId`,
  `principalTenantSlug`, `orgId`) and how far its roles reach
  (`reachableTenantIds`), alongside the tenant being acted on
  (`actingTenantId`).

  Grouped into one record rather than five more `LoginResult` components: that
  record's canonical constructor already gained an arity once, and a type that
  grows a component per contract revision breaks every caller each time. The
  pre-1.34 six-argument constructor is kept as an overload.

  Absent means equal, not unknown — `PrincipalScope`'s compact constructor
  falls `principalTenantId` back to `actingTenantId`, which is exactly right
  against a server that cannot switch the acting tenant. An empty
  `reachableTenantIds` normalises to `null` for the same reason in reverse: an
  empty list would read as "reaches nothing", the opposite of what an omitted
  field means.

### Changed

- **The four completed-login paths share one response reader.** `readJson`
  consumes the body stream, so the §5.2 flag and the §5.2.2 scope cannot be
  read by two passes; `authenticatedFrom` reads it once and also caches the
  principal tenant for `opaqueEnrollmentForSelf`.

### Fixed

- **A registration record for your own password was sealed against the wrong
  tenant.** CONTRACT.md §5.2.2 rule 2: the caller's credentials live in the
  tenant the *account* lives in, not whichever tenant the client is currently
  pointed at, and a record sealed against the acting tenant is refused with
  "the OPAQUE session was issued for a different tenant".

  `opaqueEnrollment` had one behaviour for a method documented for three
  callers — user creation, change-password and reset completion — and only the
  first of those wants the acting tenant. It keeps that behaviour; the new
  `opaqueEnrollmentForSelf` seals against the principal tenant and is what a
  self-service password change must call.

  The two collapse to the same request for every ordinary principal, so this
  only bit an organization-level account that had switched tenant.

- **An empty `tenantScope` is no longer put on the wire.** The server refuses
  `[]` with `400`: an assignment reaching no tenant is a grant that does not
  exist rather than a restriction. `@JsonInclude(NON_NULL)` did not prevent it,
  because `List.of()` is the natural thing to pass for "no tenants named" and
  is not null. The generated records now normalise it to `null` in a compact
  constructor, via a one-field allowlist — elsewhere `[]` means "clear this
  list", and normalising it away would make "remove every entry" inexpressible.

### Note on `X-Tenant-ID` vs `X-Axiam-Tenant`

CONTRACT.md §5.2.2 and §5.2.3 name the acting-tenant header `X-Tenant-ID`, but
the AXIAM server reads **`X-Axiam-Tenant`** (`ACTIVE_TENANT_HEADER` in
`crates/axiam-api-rest/src/extractors/auth.rs`), as do its own tests, the admin
UI, and the `openapi.json` vendored alongside that contract. The server never
reads `X-Tenant-ID` at all.

Documentation updated here names `X-Axiam-Tenant`, because a tenant switch sent
under the other name is not refused — it is ignored, and the request quietly
acts on the principal's own tenant instead. The discrepancy has been reported
upstream; this SDK's existing `X-Tenant-ID` sends are left as they are, being
out of scope for a contract re-vendor.

## [1.0.0-beta04] - 2026-08-28

### Added

- Sigstore signature bundles on the Maven Central release path (H-1)

### Changed

- Attest the published jars, document the Maven Central posture, re-vendor contract 1.33

- **CONTRACT 1.32 — signing in an organization-level principal (§5.2.1).**
  `CONTRACT.md`, `openapi.json` and `management-registry.json` re-vendored from
  the AXIAM server, where the same bug class had made an organization-level
  administrator unable to sign in at all (ilpanich/axiam#388).

  Naming no tenant now resolves the organization's own reserved scope on
  `/auth/login`, `/auth/opaque/login/start`, `/auth/opaque/register/start` and
  `/auth/webauthn/authenticate/discoverable/start`. That reserved tenant's slug
  is `organization`, so this SDK reaches it through the ordinary factory:

  ```java
  AxiamClient.builder(baseUrl, "organization").orgSlug("globex").build()
  ```

  Prefer that over omitting the tenant: §5 rule 2 still requires one on the
  `X-Tenant-ID` header of every request after the login.

### Fixed

- Reject a blank orgSlug instead of sending it as ""

- **`Builder.orgSlug` now rejects a blank slug** (CONTRACT.md §5.1, §5.2.1
  rule 2). `builder(baseUrl, tenantId)` already refused a blank tenant;
  `orgSlug` accepted `""` and put it on the wire.

  An SDK MUST NOT send an empty-string slug. Nothing can carry one, so the
  server resolves nothing — and on `/auth/opaque/login/start` it fails on the
  workspace *before* the tenant's OPAQUE mode is read, so the `404` of §23.4
  rule 10 never arrives, this SDK has no fallback to take, and sign-in fails
  even against a tenant with OPAQUE **disabled**.

## [1.0.0-beta02] - 2026-08-28

### Added

- Contract 1.31 — list search, the truthful resend, organization scope

- **CONTRACT 1.31 — the AXIAM server PR #383 surface.** `CONTRACT.md`,
  `openapi.json` and `management-registry.json` re-vendored, and the six things
  they describe implemented.

  - **`search` on all twenty paginated management operations** (§27.4 rule 4).
    A third component on `PageRequest`, not a third argument on twenty generated
    `list` methods, reached through a new `PageRequest.matching(limit, term)`
    factory beside `of(limit)`:

    ```java
    Page<UserResponse> page = client.users().list(PageRequest.matching(50, "ada"));
    List<UserResponse> all  = client.users().listAll(PageRequest.matching(200, "ada"));
    ```

    Putting it on the page request is what makes `atOffset` — and so `listAll` —
    carry the term across the whole walk. A walk that filtered its first request
    and not the rest returns the matches followed by the unfiltered tail, which
    from the caller's side looks like a server bug.

    The server applies it **before** `offset`/`limit`, so `Page.total()` counts
    matches rather than rows. A blank or whitespace-only term is treated as
    unset and sends no `search` parameter, so a box that fires on every
    keystroke does not ask a different question once it is cleared. The server's
    length cap is deliberately **not** copied here: a client-side truncation the
    server would not have made is a silently different query.

    A two-component `PageRequest(offset, limit)` constructor is kept, so a call
    site written against contract 1.30 still compiles.

  - **`AxiamClient.resendOwnVerification()`** and its `…Async` twin (§25.1,
    §25.7) — `POST /api/v1/users/me/resend-verification`, for a caller signed in
    to the account it is asking about. It takes no address, and reports what
    happened: returns for enqueued, `AuthzError` for
    already-verified-or-ineligible, `NetworkError` for the daily limit.

    `resendVerification` still exists and still returns normally whatever
    happens, because it takes an address from an anonymous caller and a truthful
    answer there is an enumeration oracle. Use the new one whenever there is a
    session — a profile page wired to the old one reports success while doing
    nothing, which is the defect the pair exists to separate. This SDK does not
    fall back from one to the other in either direction (§25.7 rule 2).

  - **`LoginResult.organizationLevel()`** (§5.2) — whether the account holds
    grants that apply in every tenant of its organization. Check it before
    offering a tenant switch: an ordinary tenant principal changing
    `X-Tenant-ID` gets a `403`. `false` against a server older than contract
    1.31, which is the safe reading of absent. A five-component `LoginResult`
    constructor is kept alongside the six-component one, so a call site written
    against contract 1.28 still compiles.

  - **`Tenant.kind()` and `TenantKind`** (§27.11) — ordinary tenant or the
    organization's own scope. `null` on a row written before that scope existed.
    Read-only: it is not on `CreateTenantRequest` or `UpdateTenantRequest`.

  - **`MtlsTrustAnchorResponse.trustedAnchors()`** (§27.11) — how many CAs the
    live listener now trusts, when it was reloaded. `null` is **not** zero: it
    means there was no listener to ask, which is the case
    `restartRequired() == true` already reports.

  - **`Certificate.boundServiceAccountId()`** (§27.11) — the service account a
    certificate authenticates, resolved for a whole page in one query by
    `certificates().list()` and `null` on `certificates().get()`. The SDK does
    not issue a second request to fill it in there.

- **The §27 namespace handles now sit directly on the client** — `client.roles()`,
  `client.serviceAccounts().rotateSecret(id)` — which is the form §27.3's Java row
  specifies. `client.management()` still reaches the same 24 handles behind one accessor;
  §27.2 rule 4 makes that the *additional* form ("SHOULD **additionally** be reachable
  behind one accessor"), so shipping only it had the two the wrong way round: the optional
  form present and the one the naming map specifies absent.

  The javadoc on `management()` argued the opposite, citing §27.2. That reading was wrong
  and is corrected: what §27.2 argues against is spreading the 146 *operations* across the
  client — twenty namespaces have a `list` and fourteen a `get`, so flattened they would
  each need a disambiguating prefix. Twenty-four namespace accessors are not that, and
  §27.3's Java row asks for them by name.

  Each direct method forwards to `management()`, so rule 4's "where an SDK offers both, the
  two MUST return equivalent handles" holds structurally rather than by two code paths
  agreeing to stay in step. `ManagementClientAccessorsTest` invokes **all twenty-four** and
  compares the handle type each form returns — a forwarding one-liner is exactly where a
  copy-paste sends one namespace to its neighbour, which compiles and which a sampled test
  would miss — then asserts wire-level equivalence for a representative and for the
  org-scoped case.

- **CONTRACT.md §27 Management API** — `client.management()`, 146 operations
  across 24 namespaces (users, groups, roles, permissions, resources, scopes,
  service accounts, certificates, CA certificates, PGP keys, webhooks, OAuth2
  clients, federation, notification rules, e-mail config, settings, SCIM tokens,
  reactors, WebAuthn policy, audit, privacy, organizations, tenants, platform).

  The models and namespace handles are **generated** by
  `scripts/gen_management.py` from the vendored `management-registry.json` and
  `openapi.json`, and the generated output is committed. A new CI job runs the
  generator with `--check` on every pull request, so the committed surface and
  the vendored contract cannot drift apart. §27.8 requires the generated layer
  to sit on the SDK's existing request path, and it does: all 146 operations
  funnel through one `ManagementTransport`, inheriting §3 CSRF, the §4 cookie
  jar, the §5 `X-Tenant-Id` header, §6 TLS, §16 retry and §19 telemetry by
  construction rather than by 146 opportunities to forget one.

  §27 is the first surface to put a `Sensitive` inside a JSON **request** body,
  which needed a writer that serializes one in the clear. That writer overrides
  `Sensitive`'s own redacting serializer with a Jackson **mixin** rather than a
  module-registered serializer: a class-level `@JsonSerialize` wins over
  `SimpleModule.addSerializer`, so the module form would have sent every
  password and private key to the server as the literal string
  `"[SENSITIVE]"`. Everywhere else `Sensitive` still redacts.

- **The §27.6 declarative layer** — `client.management().manifest()`, with
  `plan` (reads only), `apply` (stops at the first failure, does not roll back),
  derived ordering, and back-reference checking at `build()`.

- **`AxiamClient.resolvedOrgId()` / `resolvedTenantId()`** — the organization and
  tenant UUIDs §27.4 rule 3 interpolates into implicit paths. Public because §27
  also has routes where `{org_id}` / `{tenant_id}` name the entity being
  administered rather than the calling context (`tenants`, and the signing CAs
  under `caCertificates`); those take the identifier as an ordinary argument, and
  without these a caller had no way to pass the same one the implicit routes use.
  Distinct from `tenantId()`, which is the identifier the client was built with
  and is a slug as often as a UUID.

- Three runnable examples: `examples/management-basics`,
  `examples/management-manifest`, and `examples/device-mtls-provisioning` — the
  last being a full operator/device split, minting a Device certificate from the
  tenant's signing CA and then authenticating with it over §6.1 mutual TLS.

### Changed

- Re-vendor openapi.json and management-registry.json from axiam main (#78)

- Re-vendor the contract artifacts: spec digest + §27.10 posture (#76)

- Put the §27 namespace handles directly on the client, per §27.2/§27.3

- Correct the §27.4 rule 7 error table in the docs

- Implement CONTRACT.md §27 Management API

- Re-vendor CONTRACT.md, openapi.json and the §27 registry

- **Generated management enums gained an `UNKNOWN` constant, and no longer throw
  on an unrecognised value** (§27.11 rule 1). A closed enum turns the next
  `kind` or `status` the server adds into a parse error on the *whole* response,
  taking down every record on the page over one field of one of them — including
  the records the caller was after.

  A Java enum constant cannot carry the string it was decoded from, so this one
  does not pretend to: `UNKNOWN.wire()` is the empty string, which no server
  value is. Fifteen of these enums appear in request bodies, and that is what
  makes carrying an unrecognised value back into an update a `400` from the
  server rather than a silent rewrite into a spelling it never used. The
  accessor deliberately does not throw — Jackson calls it on every constant
  while building the deserializer, and a throwing one would break decoding for
  the whole enum, which is the failure this change exists to avoid.

- **`AuthzError` and `NetworkError` are no longer `final`.** §27.4 rule 7
  classifies three statuses *inside* the existing §2 taxonomy rather than beside
  it: `NotFoundError` (404) and `ConflictError` (409) extend `AuthzError`;
  `ValidationError` (400/422) extends `NetworkError`. Each keeps the parent §2
  already gave its status. Every existing `catch` for the base types keeps
  catching the new ones — which is the property the rule is asking for — and
  code that wants the distinction can now ask for it.

- **JaCoCo bundle line-coverage floor raised from 0.93 to 0.95.** The new code
  brought the bundle to ~95.2%; the floor moves with it so the gate keeps
  meaning something.

### Fixed

- **`scripts/gen_management.py` no longer drops a projected list element.** The
  server answers `GET /api/v1/certificates` with `Certificate` plus one resolved
  graph edge, expressed as an `allOf` of the `$ref` and an anonymous object.
  Read as a whole, that composition has no name, so the registry carried a page
  with no element type and the added field reached no record. The generator now
  takes the base name through the `allOf` and folds the projection's added
  fields onto the base record as optional components. (The registry-side half of
  this is AXIAM PR #386.)

### Documentation

- **Corrected the §27.4 rule 7 error table in the README and in this file.**
  Both said `ConflictError` extends `NetworkError`. It does not, and never did:
  the code, the example and `conflictIsNotRetried` all have it under
  `AuthzError`, which is what §27.4 rule 7 specifies — §2 already maps 409 to
  `AuthzError` as "resource-level access denied", and the sub-type keeps that
  mapping rather than re-deciding it. A reader who trusted the old sentence
  would have written `catch (NetworkError e)` around a create and never caught
  the 409. A new test pins the parent of all three sub-types so the prose
  cannot drift from the hierarchy again.

## [1.0.0-alpha44] - 2026-08-25

### Changed

- Re-vendor openapi.json at alpha43 for tenant signing CAs (axiam#379)

- **Re-vendor `openapi.json` at 1.0.0-alpha43** for AXIAM server PR #379, which
  adds **tenant signing CAs**: an intermediate CA created beneath one of the
  organization's CAs and scoped to a single tenant, so a tenant's user, service
  and device certificates chain through a CA that can be revoked, rotated or
  handed to a different operator without redistributing the anchor the rest of
  the estate trusts. `CONTRACT.md` and `proto/` were untouched by that PR and are
  already current.

  This is a specification re-sync with **no SDK surface change**. CA-certificate
  administration is not part of the SDK contract — `CONTRACT.md` §1 maps no
  method onto any `/api/v1/organizations/{org_id}/...` CA route — and this SDK
  models none of the schemas below, so nothing here gains, loses, or changes a
  symbol. The spec is vendored so what this SDK is written against keeps
  describing the server it talks to.

  What moved in the spec:

  - **`POST /api/v1/organizations/{org_id}/tenants/{tenant_id}/signing-cas`**
    (`generate_intermediate`) — create a tenant signing CA under an organization
    CA, with AXIAM generating the key. Returns `GeneratedCaCertificate`; the
    private key comes back exactly once, and not at all under `vault_pki`, where
    it was born inside Vault and no API exports it.
  - **`GET .../signing-cas`** (`list_intermediates`) — a paginated list of one
    tenant's signing CAs.
  - **`POST .../signing-cas/sign-csr`** (`sign_intermediate_csr`) — the BYOK
    counterpart: sign a PKCS#10 CSR produced elsewhere, so the private key never
    reaches AXIAM at all. The response carries no `private_key_pem` because there
    is none to carry.
  - **`CaCertificate` gains two nullable fields** — `tenant_id`, the tenant a CA
    signs for, and `parent_ca_id`, the CA in the organization that signed it.
    Both are absent for an organization-level CA, which is the trust anchor and
    the only kind that existed before this change.
  - **Four new schemas**: `CreateIntermediateCa`, `CreateIntermediateCaRequest`,
    `SignIntermediateCsr` and `SignIntermediateCsrRequest`.

  The spec version moves from **1.0.0-alpha40** to **1.0.0-alpha43**; the
  intervening alpha41 and alpha42 releases changed nothing in it but that string.

## [1.0.0-alpha43] - 2026-08-24

### Added

- Run the suite on JDK 25 alongside the 21 floor (#70)

- **JDK 25 is now a CI-run runtime.** `mvn test` runs on JDK 21 **and** JDK 25.
  `maven.compiler.release` stays 21 on both legs, so the 25 leg compiles to
  Java 21 bytecode with JDK 25's compiler and then executes it on a JDK 25
  runtime — which is the situation every consumer is in when a jar built in CI
  lands on whatever JDK the production base image ships, and which a single-JDK
  build cannot exercise at all.

- **`io.axiam.sdk.SupportedVersions`** — `MIN_JAVA_RELEASE` and
  `NEWEST_TESTED_JAVA`. The bytecode level takes care of the lower bound by
  itself (an older JVM fails with `UnsupportedClassVersionError`), but nothing
  records the upper one: release-21 class files load on any later JVM whether
  or not anybody ever ran them there.

- **`VersionPolicyTest`** — a conformance test for the support policy, binding
  `maven.compiler.release`, the CI matrix and both constants together. It also
  asserts `SupportedVersions` is not instantiable, which keeps the new class at
  100% coverage rather than costing the jacoco gate two uncovered lines.

- **`examples/version-compatibility`** — a runnable preflight reporting the
  running JVM against the declared range.

- **A "Supported Java versions" section in the README.**

### Changed

- Bump the minor-patch group with 9 updates

- Bump the minor-patch group

- **The gating CI matrix is floor + newest (JDK 21, JDK 25)** rather than a
  single JDK. `maven.compiler.release` is **unchanged at 21**, so the published
  bytecode level is identical and no consumer loses a runtime they had before.
  The other CI jobs (javadoc gate, signed verify, gRPC codegen, BOM validate,
  Spring Boot example) stay on JDK 21 — they check artifacts and source, not
  runtime behaviour.

## [1.0.0-alpha41] - 2026-08-24

### Added

- Honour `mode` when KE2 fails (CONTRACT §23.4 rule 7)

### Changed

- Re-vendor openapi.json for the vault_pki CA custodian (axiam#368)
- Re-vendor CONTRACT.md at 1.29 and openapi.json at alpha40

## [1.0.0-alpha40] - 2026-08-23

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha39.

## [1.0.0-alpha39] - 2026-08-23

### Changed

- Re-vendor CONTRACT.md for the §14.1 anchor repair
- Claim §20, which this SDK has shipped since contract 1.10
- Re-vendor openapi.json at 1.0.0-alpha38

## [1.0.0-alpha38] - 2026-08-22

### Changed

- Re-vendor CONTRACT.md at 1.28
- Add WebAuthn, account lifecycle and PAR (CONTRACT §24–§26)

## [1.0.0-alpha37] - 2026-08-21

### Changed

- Bump org.bouncycastle:bcprov-jdk18on from 1.83 to 1.84

## [1.0.0-alpha34] - 2026-08-21

### Added

- Replace SRP-6a with OPAQUE (RFC 9807), CONTRACT §23

- CONTRACT.md §24 — WebAuthn / passkeys relying-party layer
  (`io.axiam.sdk.webauthn`): the six wire operations, the two distinct
  authentication ceremonies, and §24.6a's JSON bridge, which lets an Android
  app pass Credential Manager's `requestJson`/`registrationResponseJson`
  straight through without this artifact gaining an Android dependency.
  §24.6b's linked-API helper is deliberately absent — the JVM has no
  authenticator, and §24.6b rule 2 forbids emulating one in software.

- CONTRACT.md §25 — account lifecycle and MFA enrolment
  (`io.axiam.sdk.account`): voluntary and forced TOTP enrolment, email
  verification, and the password-reset triple including the `reset/context`
  call a tenant with §23 enabled requires before a new password can be built.

- CONTRACT.md §26 — Pushed Authorization Requests, RFC 9126 (`oidcPar`,
  `oidcParAsync`, `PushedAuthorizationRequest`). Required for a FAPI 2.0
  client, which cannot authorize any other way (§21.1).

- `examples/webauthn-passkeys`, `examples/account-lifecycle` and
  `examples/par-login`.

- `io.axiam.sdk.opaque.OpaqueMode` — the tenant `opaque_mode` a `login/start`
  response reports, read from a field that is optional on the wire and whose
  absence, per §23.4 rule 7, reads as `required`.

### Changed

- Link to the AXIAM platform documentation site

- Re-vendor openapi.json at alpha32 (#61)

- **Re-vendor `openapi.json`** for AXIAM server PR #368, which adds a third CA
  key custodian, `vault_pki`, having HashiCorp Vault's PKI secrets engine
  generate the CA key inside Vault and sign on AXIAM's behalf. The spec version
  is unchanged at **1.0.0-alpha40**; `CONTRACT.md` and `proto/` are untouched by
  that PR and are already current.

  This is a specification re-sync with **no SDK surface change**. CA-certificate
  administration is not part of the SDK contract — `CONTRACT.md` §1 maps no
  method onto `/api/v1/organizations/{org_id}/ca-certificates`, and this SDK
  models none of the five schemas below — so nothing here gains, loses, or
  changes a symbol. It is vendored so the spec this SDK is written against keeps
  describing the server it talks to.

  What moved in the spec:

  - `CaCertificate` gains a nullable `chain_pem`: the issuers above
    `public_cert_pem`, concatenated PEM, nearest issuer first and the root last.
    Absent for a CA that is its own root, which is every CA AXIAM generated
    before this. Present for a `vault_pki` CA, where it is the only copy of the
    root certificate anything outside Vault will ever see.
  - `CaCertificate.public_cert_pem` is now documented as the certificate that
    *signs*, which under `vault_pki` custody is the intermediate rather than the
    root beneath which it was created. The field itself is unchanged.
  - `GeneratedCaCertificate.private_key_pem` is **no longer required**. Under
    `vault_pki` custody the key is born inside Vault and no API exports it, so
    there is nothing to return. The field is omitted rather than sent as `null`,
    which keeps a client that has always read it working unchanged against every
    custodian that does produce a key.
  - `GeneratedCertificate` gains a nullable `chain_pem`, present only when the
    signer returned one — the `vault_pki` case, where the root's certificate
    exists nowhere a client could fetch it from.
  - `CreateCaCertificate` and `CreateCaCertificateRequest` gain the optional
    `issue_from_root`, `intermediate_subject` and `intermediate_validity_days`.
    All three are `vault_pki`-only and ignored by every other custodian.
    `issue_from_root` defaults to off: a root that signs only one intermediate
    can have that intermediate revoked and replaced without redistributing the
    trust anchor, and a root that signs leaves directly cannot.

- **`loginOpaque` now honours the `mode` the `login/start` response carries
  (contract 1.29, §23.4 rule 7).** A `KE2` that does not open still sends no
  `KE3` — that part is unchanged — but what follows now depends on `mode`,
  and on nothing else. Under `"optional"` the SDK retries over
  `POST /api/v1/auth/login` with the same credentials and returns that call's
  outcome; under `"required"`, and for any response carrying **no** `mode`
  field (a server older than it), the failure stays an `AuthError` and no
  plaintext retry is made. An unrecognised value reads as `required`, failing
  closed.

  This is a behaviour change for `optional` tenants, and the reason it is
  needed is that `optional` is the mid-migration state: every account has no
  registration record the moment an operator enables OPAQUE, and acquires one
  only as its password is next set, so reporting the failed exchange as final
  locked out every user of such a tenant. `mode` is **not** downgrade
  protection and this SDK does not present it as such — a hostile server
  wanting the plaintext could answer `404` and get a fallback whatever it puts
  there; what closes that is `required`, server-side. `404` handling is
  untouched: a tenant with OPAQUE disabled is still the distinguishable
  `NetworkError`, never a credential failure.

- Re-vendored `CONTRACT.md` at **contract 1.29** and `openapi.json` at
  **1.0.0-alpha40**.

- Re-vendor `CONTRACT.md`. Repairs §14.1's link to the `device_login` heading,
  which dropped a hyphen the em dash leaves behind and so rendered as a link
  that went nowhere; the same heading's other two links were already correct.
  Link target only — no normative change and no contract-version bump.

- **Conformance statement now names §20.** The UMA 2.0 Protection API and ticket
  grant — all seven §20.1 canonical operations — have been on `AxiamClient` since
  contract 1.10 and are documented in the README body; the headline statement had
  never been widened to say so.

- Re-vendor `openapi.json` at **1.0.0-alpha38**. The server registered the four
  GDPR data-subject endpoints (`POST /api/v1/account/export`,
  `GET /api/v1/account/export/{token}`, `POST /api/v1/account/delete`,
  `GET /api/v1/auth/account/delete/cancel`), taking the document to 181
  operations across 121 paths. Purely additive, and no SDK surface changes with
  it: nothing in this repo is generated from the spec, so the cross-repo
  artifact-drift gate was the only thing reporting `STALE`.

- `LoginResult` gained `mfaSetupRequired` and `setupToken` for §25.2 rule 1's
  third login outcome. Additive: the three-argument constructor still compiles
  and answers `false` for the new flag. Callers that branch only on
  `mfaRequired()` should still add the new branch — a tenant that turns on
  required MFA will start returning it, and ignoring it reports a successful
  login that has no session.

- `OidcConfiguration` gained `pushed_authorization_request_endpoint`. Positional
  construction of the record changes arity; the parsed-from-discovery path does
  not.

- Re-vendored `CONTRACT.md` and `openapi.json` at contract 1.28.

### Fixed

- Build the KSF before spending the exchange's state handle

## [1.0.0-alpha33] - 2026-08-21

### Added

- OPAQUE (RFC 9807) login and enrolment (CONTRACT §23): `loginOpaque`,
  `loginOpaqueAsync`, `opaqueEnrollment` and `opaqueAvailable` on
  `AxiamClient`, plus the new `io.axiam.sdk.opaque` package.
- `examples/opaque-login`.
- `net.java.dev.jna:jna` as an **optional** dependency. It binds
  `libaxiam_opaque_ffi`; a consumer whose tenant does not use OPAQUE does not
  receive it transitively and does not need it.

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha31.
- Re-vendor `openapi.json` at **1.0.0-alpha32**, matching the server. The
  content was already byte-identical in every path and schema; only
  `info.version` differed, which is what the cross-repo artifact-drift gate
  reports as `STALE`.
- **BREAKING** — the OPAQUE protocol is NOT implemented in this SDK. CONTRACT
  §23.1 forbids it, so the client half is a JNA binding to
  `libaxiam_opaque_ffi` — the same implementation the AXIAM server links,
  published as a per-platform asset on the axiam release page rather than on
  Maven Central. Put it on `java.library.path` or set
  `-Daxiam.opaque.library=` / `AXIAM_OPAQUE_LIBRARY`.
- **BREAKING** — `opaqueAvailable()` can genuinely return `false`, where
  `srpAvailable()` was hard-coded `true` on the JVM. Both JNA and the shared
  library are optional and independently absent-able. Code that ignored
  `srpAvailable()` must not ignore this one.
- `opaqueEnrollment` performs I/O, where `srpEnrollment` did not: OPAQUE's
  envelope is sealed under the server's oblivious PRF, so there is no offline
  computation that produces a valid record. It also drops the `identity`,
  `group` and KDF arguments — a record binds to a credential identifier the
  server chooses, and the key-stretching parameters are the server's.
- Failure taxonomy for the OPAQUE path: a tenant with OPAQUE disabled, an
  absent library, and a key-stretching function this build cannot perform are
  all `NetworkError` (a caller can fall back, or an operator can act);
  everything else is `AuthError` and must NOT be retried over `login()`
  (§23.4 rule 7).

### Removed

- **BREAKING** — SRP-6a. `loginSrp`, `loginSrpAsync`, `srpEnrollment`,
  `srpAvailable`, the whole `io.axiam.sdk.srp` package, `srp-test-vectors.json`
  and `examples/srp-login` are all gone. AXIAM's server-side SRP endpoints are
  removed in the same release, so keeping the client would leave methods that
  only ever return 404.

### Fixed

- OPAQUE: a refused key-stretching function no longer strands the exchange's
  native state handle. `finish()` spent the handle before building the KSF, so
  an unrecognised function or an out-of-band cost left it out of its one-shot
  slot and unreachable by `close()` or the `Cleaner` — a leaked Rust allocation
  once per login attempt against a misconfigured tenant. The KSF is now built
  first, so a refusal leaves the exchange intact: it is released normally, and a
  caller who fixes the parameters can retry.

## [1.0.0-alpha31] - 2026-08-20

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha30.

## [1.0.0-alpha30] - 2026-08-20

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha29.

## [1.0.0-alpha29] - 2026-08-20

### Added

- SRP-6a login client (CONTRACT §23) (#57)

## [1.0.0-alpha28] - 2026-08-19

### Changed

- Re-vendor openapi.json at 1.0.0-alpha27 (#56)
- Bump org.junit.jupiter:junit-jupiter

## [1.0.0-alpha27] - 2026-08-17

### Added

- ReactorConnections — enforce §8b instead of documenting it
- §22.14 declarative reactor handler binding — ReactorHandlers
- **`ReactorConnections` — CONTRACT.md §8b enforced rather than described.**
  `ReactorServeOptions.builder(channel, …)` takes an already-open channel, and
  §8b's requirements travelled with it as a javadoc sentence: "its connection
  MUST have been opened over `amqps://` with a trusted CA". A javadoc MUST is a
  note to whoever reads the javadoc — a caller who built a `ConnectionFactory`
  from an `amqp://` URI got a working reactor, no warning, and
  signed-but-readable token decisions on the wire.

  `ReactorConnections.connectionFactory(...)` refuses every scheme but
  `amqps://` (rules 1 and 5, with no loopback exception and no pass-through for
  a URI that will not parse), takes a CA bundle for a privately issued broker
  certificate (rule 2), takes a client certificate/key pair for mutual TLS
  (rule 3, all-or-nothing), and enables hostname verification explicitly —
  the RabbitMQ Java client leaves that **off** by default. There is no
  verification-skip argument under any name (rule 4).

  It is deliberately the twin of the Kotlin SDK's `reactorConnectionFactory`:
  two SDKs on the same RabbitMQ client should not disagree about what a reactor
  may connect to. `ReactorServeOptions` still accepts any channel — enforcing at
  construction cannot retroactively constrain one somebody else opened.

- `io.axiam.sdk.internal.TlsSupport`, the PEM-to-`SSLContext` plumbing behind
  the above. Equivalent private copies already exist in `AxiamClient` (§6) and
  `grpc.AuthClientInterceptor`, each with its own nested
  `CompositeX509TrustManager`; adding a third inside the reactor package would
  have been the smaller diff and the worse outcome, since independent
  implementations of certificate verification drift invisibly. Folding the two
  existing transports into it changes established §6/§6.1 behaviour and is left
  to its own change.

### Changed

- Re-vendor CONTRACT.md 1.23 (§8b rules 7 and 8)
- Re-vendor openapi.json for the SCIM provisioning-token endpoints
- Re-vendor CONTRACT.md 1.22 from the server repo
- Re-vendor `openapi.json` at 1.0.0-alpha27 — the copy was pinned at alpha26 and
  failing the cross-repo artifact-drift gate

## [1.0.0-alpha25] - 2026-08-16

### Added

- Adopt CONTRACT §11.2 rule 9 reason accessor (SDK-Q10)
- Ship the §22 reactor runtime (R2.5)
- Extend §10.1 rule 9 for DPoP and implement §21.7.2 (#48)
- SubjectTokenType is required (contract 1.13)
- §15.7 — external-IdP subject tokens at the exchange (X4)
- §20.3 — emit a UMA challenge from the §11 interceptor (#42)
- §20 — UMA 2.0 Protection API and ticket grant
- Report a clamped decision-memo TTL (contract 1.9, §19.2 rule 6)
- §17 memo, §18 close(), §19 telemetry, §16.6 switch (D5)
- Device grant, token exchange, logout helpers; re-vendor (D6)
- **CONTRACT.md §22 — the reactor runtime (`io.axiam.sdk.reactor`).** A reactor is
  an external process subscribed to named hook events on the AMQP bus, answering
  allow / deny / mutate inside a timeout the server declared.
  `ReactorServer.reactorServe(options)` consumes the **server-declared** queue,
  verifies each event under §8 v2 (key version, MAC, freshness, nonce, in that
  order) before the handler sees it, and signs the reply with the same tenant
  subkey.

  The canonicalization difference that costs a day if it is not stated: a reactor
  body is signed with `hmac_signature` **present and set to `null`**, where §8's
  own two message types omit it. `ReactorProtocol` is the only place that rule
  lives, and `ReactorVectorTest` proves it byte-for-byte against the
  server-generated §22.13 vectors — canonical bytes, MAC, the omission of
  `reason`/`patch` when absent and of `require_mfa` when false, the
  `nonce_binding` pair, the `correlation_replay` refusal, and the topology
  strings.

  Four rules are structural rather than documented. The runtime declares no
  exchange, queue or binding (asserted against the AMQP client's own calls); a
  handler that throws produces **no reply** rather than a synthesized `allow`, so
  the operator's `failure_policy` still decides; a patch is sent **unfiltered**,
  because dropping a forbidden key would leave the author believing it was set;
  and a reply is abandoned rather than published after `timeout_ms` has elapsed.
  `ReactorDecision` is a sealed hierarchy in which `allow` cannot carry a patch
  and `mutate` cannot be empty, and `ReactorListener` returns `void`, so a
  listener cannot publish a reply at all.

  §22.7 is honoured as the MUST NOT it is: `authz.check`, `authz.check_batch` and
  `token.introspect` are absent from `ReactorEvents.REGISTRY` and from every
  constant this SDK exposes, asserted against the list rather than a comment, and
  no interceptor equivalent is offered for them anywhere.

  Interacts with the existing D5 surfaces as they already work: `close()` is
  §18-deterministic (cancel, drain, idempotent), §19 emits one
  `RequestStart`/`RequestEnd` pair per dispatch with the event name as the path
  template, the signing key is wrapped in `Sensitive` per §22.12, and §16 retry
  deliberately does **not** apply to a reply — a correlation is single-use, so a
  resend could only add load to a server that has already moved on.

  `io.axiam.sdk.amqp.NonceStore` becomes public (it was package-private): §22
  needs the same replay gate, and two implementations of one security control is
  one too many. Additive; no existing signature moves.

- **CONTRACT.md §10.1 rule 9 extended for DPoP, and §21.7.2 proof verification
  implemented (contract 1.16/1.17).**

  `JwksVerifier.verifyTokenBinding(claims, PresentedProofs)` applies the full
  ten-row rule against a certificate thumbprint, a verified DPoP key thumbprint,
  or **both**. A `cnf` naming both methods is a **conjunction** — satisfying only
  the more convenient one is not compliance — and a `cnf` naming nothing this SDK
  can check (including an *empty* one, which is how proto3 delivers an empty
  `CnfClaim`) is refused rather than read as unbound. `verifyCertificateBinding`
  remains for certificate-only transports and now **refuses** a DPoP-bound or
  both-bound token rather than ignoring the half it cannot check.

  New `DpopVerifier` implements all ten §21.7.2 checks and returns the proof
  key's RFC 7638 thumbprint, so a value passed to `PresentedProofs` could only
  have come from a proof that verified. `DpopVerifier.InMemoryJtiStore` covers
  check 8 for a single JVM; the `JtiStore` argument is required, not optional,
  because there is no safe default that skips replay tracking.

  Two design points: the JWS verifier is chosen from the embedded key's own type
  so an HMAC verifier is never reachable (the test runs the real
  public-key-as-HMAC-secret forgery), and the `jti` is claimed **last**, so a
  stream of invalid proofs cannot burn `jti` values out of the store and deny
  service to valid ones.

  Not a breaking change: an unbound token is still accepted with no certificate
  and no proof, asserted directly by the first test in the new group.

- **CONTRACT.md §10.1 rule 9 — sender-constrained (certificate-bound) access tokens**
  (contract 1.15, RFC 8705 §3 / RFC 7800). A token carrying `cnf` is **not** a bearer
  token; accepting one without proving the caller holds the named key converts it back
  into one.
  - `JwksVerifier.verifySenderConstrained(token, expectedTenantId, presentedThumbprint)`
    — the guard entry point for a resource server that accepts bound tokens.
  - `JwksVerifier.verifyCertificateBinding(claims, presentedThumbprint)` — the rule,
    standalone.
  - `JwksVerifier.certificateThumbprintS256(byte[] der)` — RFC 8705 §3.1 `x5t#S256`:
    base64url, **unpadded**, SHA-256 over the DER certificate. Under a servlet container,
    feed it `X509Certificate.getEncoded()` from
    `jakarta.servlet.request.X509Certificate`.

  **Not a breaking change, and it does not make certificates mandatory.** An *unbound*
  token is still accepted with or without a certificate.

  `verifyAccessToken` deliberately does **not** apply rule 9: it has no transport to ask
  for a peer certificate. The thumbprint must come from the transport, never from a
  caller-settable header. A `cnf` naming an unimplemented method is **rejected**, never
  read as "unconstrained".

- **CONTRACT.md §21** — the FAPI 2.0 posture as an SDK sees it. Only rule 9 is normative
  for this SDK.
- **§15.7 external-IdP subject tokens (X4).** `tokenExchange` can now exchange a token minted by
  a trusted external IdP — a partner's Entra, Okta or Keycloak — for an AXIAM token scoped to
  what the resolved AXIAM user may actually do. No new operation: a new eight-argument
  `OidcOperations.tokenExchange` overload taking `subjectTokenType`, plus the public
  `OidcOperations.ACCESS_TOKEN_TYPE` / `JWT_TOKEN_TYPE` constants.

  (This shipped as a source- and binary-additive overload with an `…:access_token` default;
  contract 1.13 removed both the default and the overload — see *Changed* above.)

  **The type is the caller's to name, never the SDK's to guess.** §15.7 forbids inspecting the
  subject token to pick it, because which kind of token you hold is something only you know and
  a wrong guess is the difference between a request that is refused and one that is silently
  reinterpreted. A JWT-shaped subject token does **not** change what is sent, which is asserted
  by a test.

  Also asserted: an `actorToken` alongside an external subject token surfaces `invalid_request`
  with no retry and no request rewriting; a refused refresh or ID token type is never retried as
  a different type; the one normative description — `the subject token's issuer is not
  configured for token exchange`, meaning *fix the AXIAM trust config* rather than *fix your
  token* — reaches the caller intact; and nothing re-exchanges an exchanged token, which both
  server paths refuse because exchanges do not compose.

  `CONTRACT.md` and `openapi.json` re-synced from `ilpanich/axiam@main` (contract 1.10 → 1.12
  plus §15.7), which also brings contract 1.11's lifted §12.6 deferral, contract 1.12's
  `/oauth2/*` error rows dispatching on the `error` field at any status, and the
  `TokenExchangeTrust` schemas behind the X4 provider configuration.

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

- Re-vendor CONTRACT.md 1.19, openapi.json and proto/ from main (R5.8) (#50)
- R5.7: OIDC/SSO conformance follow-ups (F-12, F-13, F-15, F-17) (#49)
- Contract 1.15 — §10.1 rule 9, sender-constrained access tokens (#47)
- Add the §20.7 required timeout assertion
- Retire the "measured residual" justification (contract 1.14)
- Re-sync to contract 1.14 (#302 closed)
- **Re-sync vendored `CONTRACT.md` / `openapi.json` to contract 1.15.**
- **Re-sync vendored `CONTRACT.md` to contract 1.14** — documentation only, no code change.
  §20.2 rule 6 (a permission ticket MUST NOT be retried) cited a "measured residual
  (ilpanich/axiam#302) … roughly 1 in 640" as its second reason. That residual is closed: the
  server now decides the ticket race with a transaction its storage engine arbitrates plus a
  redemption nonce read back after the commit. **The rule is unchanged, and this SDK's
  behaviour is unchanged** — `uma_exchange_ticket` stays excluded from every automatic retry
  path. What changed is the reasoning: the first reason (a spent ticket makes the retry
  useless) always stood alone, and the second now rests on what an SDK can actually know —
  it is talking to a server whose storage engine it cannot attest, and the guarantee is
  conditional on that engine being persistent.
- **BREAKING (contract 1.13): `tokenExchange`'s `subjectTokenType` is now required**, and the
  seven-argument overload that defaulted it is **removed**.

  It shipped as a `default` method delegating with a `null` type — which satisfied §15.7's
  "never inspect the subject token" while leaving the rule it serves unenforced: an overload
  that fills the argument in *is* a default the SDK applies whenever the caller says nothing.
  §15.1 now makes it required, so the overload had to go rather than be deprecated: it was the
  default, in method form.

  The one-argument convenience `tokenExchange(Sensitive)` becomes
  `tokenExchange(Sensitive, String)` for the same reason — it was the shortest path to the very
  default being removed, since a caller reaching for the convenience form would have had the
  type chosen for them.

  Java cannot demand a non-null argument at compile time, so the demand lands at the call:
  `null` or blank throws `AuthError` **client-side, with no wire call** — not even discovery —
  naming the argument and both constants.

  **Migration** — one argument, naming what you were previously getting by silence:

  ```java
  ExchangedToken exchanged = client.tokenExchange(
          Sensitive.of(userToken),
          OidcOperations.ACCESS_TOKEN_TYPE,   // <- add this
          null, List.of("orders:read"), "orders-service", null, null, null);
  ```

  Implementors of `OidcOperations` other than `AxiamClient` lose an inherited method and must
  implement the eight-argument form.

  This closes a gap rather than opening one: `subject_token_type` has always been required *on
  the wire*, and the SDK was covering for that with a constant which stopped being the only
  legal value when X4 landed.
- Re-vendored `CONTRACT.md` at **1.8.2**. `openapi.json` unchanged — docs-only contract revs.
- `login`, `verifyMfa`, `refresh` and `logout` clear the decision memo (§17.1 rule 9) and
  reject after close (§18.1 rule 4).

### Fixed

- Reattach oidcClockSkew's javadoc, orphaned by the D5 builder methods

### Notes

- §16's arithmetic is **unchanged**: this SDK's policy was already conformant, and of the
  five SDKs that had invented one it was the only one that got both full jitter and
  `Retry-After`-as-a-floor right. The contract adopted its parameters.

## [1.0.0-alpha24] - 2026-08-04

### Added

- Apply the full CONTRACT §10.1 local-verification set
- Add HMAC-SHA256 webhook signature verifier (CONTRACT.md §13)
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

### Changed

- Device (mTLS) tokens now carry aud=axiam:m2m (#36)
- Service accounts can use login_client_credentials (#35)
- Bump the minor-patch group with 5 updates
- Bump actions/setup-java from 5.6.0 to 5.7.0
- Bump coverallsapp/github-action from 2.3.7 to 2.3.8

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

### Fixed

- Clear the SecurityContext when a caller's token is rejected (#37)
- Lower the clock-skew ceiling 300s -> 60s (§13.4 observation 5) (#34)

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

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha9.

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
