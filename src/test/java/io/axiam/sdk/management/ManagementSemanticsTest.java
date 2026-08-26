package io.axiam.sdk.management;

import com.fasterxml.jackson.databind.JsonNode;
import io.axiam.sdk.Sensitive;
import io.axiam.sdk.errors.AuthError;
import io.axiam.sdk.errors.AuthzError;
import io.axiam.sdk.errors.ConflictError;
import io.axiam.sdk.errors.NetworkError;
import io.axiam.sdk.errors.NotFoundError;
import io.axiam.sdk.errors.ValidationError;
import io.axiam.sdk.management.models.CreateRoleRequest;
import io.axiam.sdk.management.models.CreateScimTokenRequest;
import io.axiam.sdk.management.models.CreateUserRequest;
import io.axiam.sdk.management.models.SetMtlsTrustAnchor;
import io.axiam.sdk.management.models.UpdateUserRequest;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CONTRACT §27.4, §27.5 and §27.2 semantics — the §27.9 required tests.
 *
 * <p>Every assertion here exists because the thing it checks is easy to get
 * wrong and silent when wrong. Where §27.9 says to assert on the request
 * <em>path</em> rather than on the arguments, these do.
 */
class ManagementSemanticsTest extends ManagementTestBase {

    /** §27.4 rule 1: a management call with no session fails locally. */
    @Test
    void noSessionMakesNoWireCall() throws Exception {
        Route route = mount("GET", "/api/v1/users", 200, pageOf(null));
        try (io.axiam.sdk.AxiamClient anonymous = io.axiam.sdk.AxiamClient
                .builder(server.url("/").toString().replaceAll("/$", ""), TENANT_SLUG).build()) {
            AuthError thrown = assertThrows(AuthError.class,
                    () -> anonymous.management().users().list(null));
            assertTrue(thrown.getMessage().contains("no active session"),
                    "the refusal should name the missing session, got: " + thrown.getMessage());
        }
        assertEquals(0, route.calls(), "a session-less call must not reach the network");
    }

    /** §27.4 rule 3: the client's org and tenant are interpolated into the path. */
    @Test
    void orgAndTenantComeFromTheClientAndLandInThePath() throws Exception {
        Route org = mount("GET", "/api/v1/organizations/" + ORG_ID, 200,
                "{\"id\":\"" + ORG_ID + "\",\"name\":\"Acme\",\"slug\":\"acme\",\"metadata\":{},"
                        + "\"created_at\":\"2026-08-26T00:00:00Z\","
                        + "\"updated_at\":\"2026-08-26T00:00:00Z\"}");
        Route tenant = mount("GET", "/api/v1/tenants/" + TENANT_ID + "/settings", 200, "{}");

        client.management().organizations().get();
        client.management().settings().getTenantOverride();

        assertEquals("/api/v1/organizations/" + ORG_ID, org.last().path());
        assertEquals("/api/v1/tenants/" + TENANT_ID + "/settings", tenant.last().path());
    }

    /** §27.4 rule 3: an override changes the path and leaves the original handle alone. */
    @Test
    void anExplicitOverrideChangesThePath() throws Exception {
        UUID otherOrg = UUID.fromString("44444444-4444-4444-8444-444444444444");
        UUID otherTenant = UUID.fromString("55555555-5555-4555-8555-555555555555");
        Route org = mount("GET", "/api/v1/organizations/" + otherOrg, 200,
                "{\"id\":\"" + otherOrg + "\",\"name\":\"Other\",\"slug\":\"other\","
                        + "\"metadata\":{},\"created_at\":\"2026-08-26T00:00:00Z\","
                        + "\"updated_at\":\"2026-08-26T00:00:00Z\"}");
        Route tenant = mount("GET", "/api/v1/tenants/" + otherTenant + "/settings", 200, "{}");

        OrganizationsApi base = client.management().organizations();
        OrganizationsApi scoped = base.inOrg(otherOrg);
        assertFalse(base == scoped, "inOrg must return a new handle");

        scoped.get();
        client.management().settings().forTenant(otherTenant).getTenantOverride();

        assertEquals(1, org.calls());
        assertEquals(1, tenant.calls());
    }

    /** §27.4 rule 3: no resolved tenant UUID means a local refusal, not a 404. */
    @Test
    void aClientWithNoResolvedTenantRefusesWithoutCalling() throws Exception {
        Route route = mount("GET", "/api/v1/tenants/" + TENANT_ID + "/settings", 200, "{}");
        try (io.axiam.sdk.AxiamClient anonymous = io.axiam.sdk.AxiamClient
                .builder(server.url("/").toString().replaceAll("/$", ""), TENANT_SLUG).build()) {
            assertThrows(RuntimeException.class,
                    () -> anonymous.management().settings().getTenantOverride());
        }
        assertEquals(0, route.calls());
    }

    /** §5 rule 2 does not lapse on this surface. */
    @Test
    void tenantHeaderIsStillPresent() throws Exception {
        Route route = mount("GET", "/api/v1/users", 200, pageOf(null));
        client.management().users().list(null);
        assertEquals(TENANT_SLUG, route.last().headers().get("X-Tenant-ID"));
    }

    /** §27.4 rule 4: total is the whole set, not the page. */
    @Test
    void totalIsTheWholeSetNotThePage() throws Exception {
        mount("GET", "/api/v1/users", 200,
                "{\"items\":[" + userBody(1) + "," + userBody(2)
                        + "],\"total\":57,\"offset\":0,\"limit\":2}");

        Page<io.axiam.sdk.management.models.UserResponse> page =
                client.management().users().list(PageRequest.of(2));

        assertEquals(2, page.items().size());
        assertEquals(57, page.total(),
                "a Page reporting items.size() passes every single-page fixture");
        assertTrue(page.hasMore());
    }

    /** §27.4 rule 4: the auto-paging walk issues exactly the requests the set needs. */
    @Test
    void listAllWalksEveryPageWithTheExpectedOffsets() throws Exception {
        // Three pages of two out of five, so the walk must ask for 0, 2 and 4.
        mountPaged();
        List<io.axiam.sdk.management.models.UserResponse> everyone =
                client.management().users().listAll(PageRequest.of(2));
        assertEquals(5, everyone.size());
        assertEquals(List.of("0", "2", "4"), pagedOffsets);
    }

    /** The offsets the paged fixture saw, in order. */
    private final List<String> pagedOffsets = new java.util.ArrayList<>();

    private void mountPaged() {
        // MockWebServer's dispatcher is shared, so a varying reply is expressed
        // by mounting once and re-mounting from inside the assertion loop.
        server.setDispatcher(new okhttp3.mockwebserver.Dispatcher() {
            @Override
            public okhttp3.mockwebserver.MockResponse dispatch(
                    okhttp3.mockwebserver.RecordedRequest request) {
                String path = request.getPath() == null ? "" : request.getPath();
                if (path.startsWith("/api/v1/auth/login")) {
                    return new okhttp3.mockwebserver.MockResponse().setResponseCode(200)
                            .setBody("{\"session_id\":\"x\",\"expires_in\":900}");
                }
                String offset = "0";
                if (path.contains("offset=")) {
                    offset = path.substring(path.indexOf("offset=") + 7);
                    if (offset.contains("&")) {
                        offset = offset.substring(0, offset.indexOf('&'));
                    }
                }
                pagedOffsets.add(offset);
                int start = Integer.parseInt(offset);
                StringBuilder items = new StringBuilder();
                for (int i = start; i < Math.min(start + 2, 5); i++) {
                    if (items.length() > 0) {
                        items.append(',');
                    }
                    items.append(userBody(i));
                }
                return new okhttp3.mockwebserver.MockResponse().setResponseCode(200)
                        .setHeader("Content-Type", "application/json")
                        .setBody("{\"items\":[" + items + "],\"total\":5,\"offset\":" + start
                                + ",\"limit\":2}");
            }
        });
    }

    /** §27.4 rule 4: a bare-array read is a list, not a page. */
    @Test
    void aBareArrayOperationIsNotAPage() throws Exception {
        mount("GET", "/api/v1/resources/" + EXAMPLE_ID + "/scopes", 200,
                "[{\"id\":\"" + EXAMPLE_ID + "\",\"name\":\"draft\",\"description\":\"Unpublished\","
                        + "\"resource_id\":\"" + EXAMPLE_ID + "\",\"tenant_id\":\"" + TENANT_ID
                        + "\",\"created_at\":\"2026-08-26T00:00:00Z\","
                        + "\"updated_at\":\"2026-08-26T00:00:00Z\"}]");

        // The compiler is the assertion: a List<Scope> has no total(), and had
        // the generator modelled this as a page this line would not build.
        List<io.axiam.sdk.management.models.Scope> scopes =
                client.management().scopes().list(EXAMPLE_ID);
        assertEquals(1, scopes.size());
    }

    /** §27.4 rule 5: a sparse update sends exactly the key it was given. */
    @Test
    void aSparseUpdateSendsExactlyTheOneKeyItWasGiven() throws Exception {
        Route route = mount("PUT", "/api/v1/users/" + EXAMPLE_ID, 200, userBody(1));

        client.management().users().update(EXAMPLE_ID,
                UpdateUserRequest.builder().email("new@example.test").build());

        assertEquals(List.of("email"), route.last().keys(),
                "asserting the field is present would pass even when every other "
                        + "field went along as null");
    }

    /** §27.4 rule 5: a replacement body's canonical constructor takes every field. */
    @Test
    void aReplacementBodyCannotBeBuiltHalfFilled() throws Exception {
        // The guarantee is the compiler's: SetMtlsTrustAnchor has one required
        // component, and `new SetMtlsTrustAnchor()` does not compile. A record's
        // canonical constructor is the strongest form §27.9's "does not compile
        // with a field omitted" takes in any of the ported languages.
        SetMtlsTrustAnchor anchor = new SetMtlsTrustAnchor(true);
        assertTrue(anchor.enabled());
        assertEquals("{\"enabled\":true}", JSON.writeValueAsString(anchor));
    }

    /** §27.4 rule 7: 404 is a NotFoundError, and still an AuthzError. */
    @Test
    void notFoundIsStillAnAuthzError() throws Exception {
        mount("GET", "/api/v1/users/" + EXAMPLE_ID, 404, "{\"message\":\"gone\"}");

        NotFoundError thrown = assertThrows(NotFoundError.class,
                () -> client.management().users().get(EXAMPLE_ID));
        assertEquals("users.get", thrown.operation());
        assertInstanceOf(AuthzError.class, thrown,
                "code written before §27 catches this as an AuthzError");
    }

    /** §27.4 rules 7 and 8: 409 is a ConflictError, and the write goes out once. */
    @Test
    void conflictIsNotRetried() throws Exception {
        Route route = mount("POST", "/api/v1/roles", 409,
                "{\"message\":\"role name already taken\"}");

        ConflictError thrown = assertThrows(ConflictError.class,
                () -> client.management().roles().create(
                        new CreateRoleRequest("Edits", false, "Editor")));
        assertInstanceOf(AuthzError.class, thrown);
        assertTrue(thrown.getMessage().contains("already taken"));
        assertEquals(1, route.calls(), "a 409 must not be retried");
    }

    /** §27.4 rule 7: 400 is a ValidationError with field detail, and a NetworkError. */
    @Test
    void badRequestCarriesFieldDetail() throws Exception {
        mount("POST", "/api/v1/users", 400,
                "{\"message\":\"invalid\",\"errors\":[{\"field\":\"email\","
                        + "\"message\":\"not an email\"}]}");

        ValidationError thrown = assertThrows(ValidationError.class,
                () -> client.management().users().create(new CreateUserRequest(
                        "nope", null, null, Sensitive.of("hunter2hunter2"), "bob")));
        assertInstanceOf(NetworkError.class, thrown);
        assertEquals(400, thrown.status());
        assertEquals(1, thrown.fields().size());
        assertEquals("email", thrown.fields().get(0).field());
    }

    /** §27.4 rule 7: the object-keyed error shape is understood too. */
    @Test
    void unprocessableCarriesObjectKeyedFieldDetail() throws Exception {
        mount("POST", "/api/v1/users", 422, "{\"errors\":{\"username\":\"already taken\"}}");

        ValidationError thrown = assertThrows(ValidationError.class,
                () -> client.management().users().create(new CreateUserRequest(
                        "b@example.test", null, null, Sensitive.of("hunter2hunter2"), "bob")));
        assertEquals(422, thrown.status());
        assertEquals("username", thrown.fields().get(0).field());
    }

    /** §27 classifies three statuses and widens the taxonomy no further. */
    @Test
    void anOrdinaryForbiddenStaysAPlainAuthzError() throws Exception {
        mount("GET", "/api/v1/users/" + EXAMPLE_ID, 403, "{\"message\":\"nope\"}");

        AuthzError thrown = assertThrows(AuthzError.class,
                () -> client.management().users().get(EXAMPLE_ID));
        assertFalse(thrown instanceof NotFoundError);
        assertFalse(thrown instanceof ConflictError);
    }

    /** A second delete reports the 404 rather than absorbing it. */
    @Test
    void aRepeatedDeleteIsNotSwallowedIntoSuccess() throws Exception {
        mount("DELETE", "/api/v1/users/" + EXAMPLE_ID, 404, "{\"message\":\"gone\"}");
        assertThrows(NotFoundError.class, () -> client.management().users().delete(EXAMPLE_ID));
    }

    /** §27.4 rule 8: a write is issued exactly once, even on a 503. */
    @Test
    void aWriteIsIssuedExactlyOnceOnAServerError() throws Exception {
        Route route = mount("POST", "/api/v1/roles", 503, "{\"message\":\"unavailable\"}");

        assertThrows(NetworkError.class, () -> client.management().roles().create(
                new CreateRoleRequest("Edits", false, "Editor")));
        assertEquals(1, route.calls(),
                "no write on this surface is retried, even one that looks idempotent");
    }

    /** §27.5: a returned one-time secret is redacted from every rendering. */
    @Test
    void aReturnedOneTimeSecretIsRedacted() throws Exception {
        mount("POST", "/api/v1/scim-tokens", 201,
                "{\"id\":\"" + EXAMPLE_ID + "\",\"name\":\"provisioning\",\"created_by\":\""
                        + EXAMPLE_ID + "\",\"user_id\":\"" + EXAMPLE_ID + "\",\"tenant_id\":\""
                        + TENANT_ID + "\",\"status\":\"active\","
                        + "\"created_at\":\"2026-08-26T00:00:00Z\","
                        + "\"expires_at\":\"2026-09-26T00:00:00Z\","
                        + "\"provisioning_token\":\"scim_live_supersecret\"}");

        var created = client.management().scimTokens().create(
                new CreateScimTokenRequest(null, "provisioning", EXAMPLE_ID));

        assertFalse(created.toString().contains("scim_live_supersecret"),
                "the secret leaked into toString()");
        assertFalse(JSON.writeValueAsString(created).contains("scim_live_supersecret"),
                "the secret leaked into JSON");
        assertEquals("scim_live_supersecret", created.provisioningToken().expose());
    }

    /** §27.5: a supplied password is redacted locally but still reaches the wire. */
    @Test
    void aSuppliedPasswordIsRedactedButStillSent() throws Exception {
        Route route = mount("POST", "/api/v1/users", 201, userBody(1));

        CreateUserRequest body = new CreateUserRequest(
                "bob@example.test", null, null, Sensitive.of("hunter2hunter2"), "bob");
        assertFalse(body.toString().contains("hunter2hunter2"),
                "the password leaked into the record's own toString()");
        assertFalse(JSON.writeValueAsString(body).contains("hunter2hunter2"),
                "the password leaked into a default JSON rendering");

        client.management().users().create(body);

        JsonNode sent = route.last().json();
        assertEquals("hunter2hunter2", sent.path("password").asText(),
                "wrapping a secret must not stop it reaching the server");
    }

    /** §27.2 rule 1: acquiring a handle performs no I/O. */
    @Test
    void acquiringAHandlePerformsNoIo() throws Exception {
        int before = totalCalls();
        client.management().users();
        client.management().roles();
        client.management().groups();
        client.management().certificates();
        client.management().platform();
        client.management().manifest();
        assertEquals(before, totalCalls(), "acquiring handles reached the network");
    }

    /** §18.1 rule 4: use-after-close is an error, never a silent reconnect. */
    @Test
    void aClosedClientRejectsEveryOperation() throws Exception {
        Route route = mount("GET", "/api/v1/users", 200, pageOf(null));
        client.close();
        assertThrows(RuntimeException.class, () -> client.management().users().list(null));
        assertEquals(0, route.calls());
    }

    /**
     * A response that does not match its declared schema is a clear error.
     *
     * <p>Jackson's own message names a Java class and a JSON pointer and nothing
     * about which call went wrong; wrapping it in the operation name is the
     * difference between a reportable bug and a stack trace.
     */
    @Test
    void aResponseThatDoesNotMatchItsSchemaNamesTheOperation() throws Exception {
        mount("POST", "/api/v1/roles", 201, "{\"id\":\"not-a-uuid\"}");

        NetworkError thrown = assertThrows(NetworkError.class, () -> client.management().roles()
                .create(new CreateRoleRequest("Edits documents", false, "Editor")));

        assertTrue(thrown.getMessage().contains("roles.create"),
                "the failure should name the operation, got: " + thrown.getMessage());
        assertTrue(thrown.getMessage().contains("Role"),
                "the failure should name the type it could not build, got: " + thrown.getMessage());
    }

    /**
     * A bare-array read that comes back as an object yields nothing, not a crash.
     *
     * <p>An empty list is the honest answer to "what scopes are there" when the
     * server sent something that is not a list of them, and it keeps a
     * malformed read from taking down a plan that was only surveying.
     */
    @Test
    void aBareArrayReadThatIsNotAnArrayIsEmpty() throws Exception {
        mount("GET", "/api/v1/resources/" + EXAMPLE_ID + "/scopes", 200, "{}");
        assertTrue(client.management().scopes().list(EXAMPLE_ID).isEmpty());
    }

    /** A paginated read with no body at all is an empty page, not a null. */
    @Test
    void aPaginatedReadWithNoBodyIsAnEmptyPage() throws Exception {
        mount("GET", "/api/v1/users", 204, "");
        Page<io.axiam.sdk.management.models.UserResponse> page =
                client.management().users().list(null);
        assertTrue(page.items().isEmpty());
        assertEquals(0, page.total());
    }

    /** An unparseable success body names the operation rather than leaking an IOException. */
    @Test
    void anUnparseableSuccessBodyNamesTheOperation() throws Exception {
        mount("GET", "/api/v1/users", 200, "{not json");
        NetworkError thrown = assertThrows(NetworkError.class,
                () -> client.management().users().list(null));
        assertTrue(thrown.getMessage().contains("users.list"),
                "got: " + thrown.getMessage());
    }

    /** A body Jackson cannot serialize is refused before the socket, with the operation named. */
    @Test
    void anUnserializableBodyIsRefusedLocally() {
        NetworkError thrown = assertThrows(NetworkError.class,
                () -> io.axiam.sdk.internal.ManagementTransport.encodeBody(
                        "roles.create", new Object()));
        assertTrue(thrown.getMessage().contains("roles.create"),
                "got: " + thrown.getMessage());
    }

    /**
     * §27.4 rule 3: an org configured on the client is used, claims or not.
     *
     * <p>The precedence is handle override, then client configuration, then the
     * access token's claim. This pins the middle rung: a client built with an
     * explicit {@code orgId} must use it even though the session's token
     * carries a different one, or naming an org would be advisory.
     */
    @Test
    void aConfiguredOrgIdOutranksTheTokenClaim() throws Exception {
        UUID configured = UUID.fromString("dddddddd-dddd-4ddd-8ddd-dddddddddddd");
        Route route = mount("GET", "/api/v1/organizations/" + configured + "/ca-certificates",
                200, pageOf(null));
        try (io.axiam.sdk.AxiamClient scoped = io.axiam.sdk.AxiamClient
                .builder(server.url("/").toString().replaceAll("/$", ""), TENANT_SLUG)
                .orgId(configured).build()) {
            login(scoped);
            scoped.management().caCertificates().list(null);
        }
        assertEquals(1, route.calls(), "the configured org must be the one in the path");
    }

    /**
     * §27.4 rule 3: an unusable org claim refuses locally and says how to fix it.
     *
     * <p>A token whose {@code org_id} is not a UUID is indistinguishable from no
     * claim at all as far as a path is concerned, so it must take the same
     * branch: refuse before calling, and name the three ways to supply one.
     */
    @Test
    void anOrgClaimThatIsNotAUuidRefusesWithoutCalling() throws Exception {
        Route route = mount("GET", "/api/v1/organizations/" + ORG_ID + "/ca-certificates",
                200, pageOf(null));
        mintOrgClaim("not-a-uuid");
        try (io.axiam.sdk.AxiamClient broken = io.axiam.sdk.AxiamClient
                .builder(server.url("/").toString().replaceAll("/$", ""), TENANT_SLUG).build()) {
            login(broken);
            NetworkError thrown = assertThrows(NetworkError.class,
                    () -> broken.management().caCertificates().list(null));
            assertTrue(thrown.getMessage().contains("inOrg("),
                    "the refusal should say how to supply one, got: " + thrown.getMessage());
        }
        assertEquals(0, route.calls());
    }

    /**
     * §27.4 rule 3: the implicits are readable, for the routes that take them explicitly.
     *
     * <p>{@code {tenant_id}} is implicit on most namespaces and an ordinary
     * argument on {@code tenants} and the signing CAs. A caller who cannot read
     * the resolved value has no way to pass the same tenant to the second kind,
     * which is why these are public rather than internal.
     */
    @Test
    void theResolvedOrgAndTenantAreReadable() throws Exception {
        assertEquals(ORG_ID, client.resolvedOrgId().orElseThrow());
        assertEquals(TENANT_ID, client.resolvedTenantId().orElseThrow());
        assertEquals(TENANT_SLUG, client.tenantId(),
                "tenantId() is what the client was built with, not what login resolved");

        try (io.axiam.sdk.AxiamClient anonymous = io.axiam.sdk.AxiamClient
                .builder(server.url("/").toString().replaceAll("/$", ""), TENANT_SLUG).build()) {
            assertTrue(anonymous.resolvedTenantId().isEmpty(),
                    "nothing resolves before a session exists");
            assertTrue(anonymous.resolvedOrgId().isEmpty());
        }
    }
}
