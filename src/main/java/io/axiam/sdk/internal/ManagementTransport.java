package io.axiam.sdk.internal;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.axiam.sdk.Sensitive;
import io.axiam.sdk.errors.AuthError;
import io.axiam.sdk.errors.ConflictError;
import io.axiam.sdk.errors.ErrorMapper;
import io.axiam.sdk.errors.FieldError;
import io.axiam.sdk.errors.NetworkError;
import io.axiam.sdk.errors.NotFoundError;
import io.axiam.sdk.errors.ValidationError;
import io.axiam.sdk.telemetry.TelemetryEvent;
import okhttp3.HttpUrl;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * The one request path every CONTRACT.md &sect;27 management operation goes
 * through.
 *
 * <p>&sect;27.8 is explicit that the generated layer MUST sit on the SDK's
 * existing request path and MUST NOT build its own. That is what this class is:
 * 146 generated operations all funnel into {@link #send}, so they inherit
 * &sect;3 (CSRF), &sect;4 (the cookie jar), &sect;5 ({@code X-Tenant-ID}),
 * &sect;6 (TLS), &sect;16 (retry) and &sect;19 (telemetry) by construction
 * rather than by 146 opportunities to forget one — the first four because every
 * request goes through the same decorated {@link OkHttpClient}.
 *
 * <p>Internal plumbing. It is public only because the generated
 * {@code io.axiam.sdk.management} surface lives in another package; it is not
 * part of this SDK's supported API and may change without notice.
 */
public final class ManagementTransport {

    /** The media type every management request body is sent as. */
    private static final MediaType JSON_MEDIA = MediaType.get("application/json; charset=utf-8");

    /** Reads responses. Secrets deserialize into {@link Sensitive} normally. */
    private static final ObjectMapper READER = new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

    /**
     * The ONE writer that serializes a {@link Sensitive} in the clear.
     *
     * <p>{@code Sensitive} is annotated to serialize as {@code "[SENSITIVE]"},
     * which is exactly right everywhere except the moment a secret is genuinely
     * being sent to the server — serializing a request body with the default
     * mapper would put the placeholder on the wire and the server would reject
     * a password nobody could ever get right.
     *
     * <p>Registering the exposing serializer on a single writer, rather than
     * giving fourteen request types a hand-written wire twin, keeps "a &sect;27
     * secret goes on the socket here" one greppable place (&sect;7 rule 4).
     */
    private static final ObjectMapper WIRE = new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
            .addMixIn(Sensitive.class, ExposeSensitiveMixin.class);

    /**
     * Overrides {@code Sensitive}'s own {@code @JsonSerialize} for this writer.
     *
     * <p>A mixin rather than a module-registered serializer, because a
     * class-level annotation WINS over {@code SimpleModule.addSerializer} — the
     * first cut of this used a module, and the effect was that every password
     * and private key went to the server as the literal string
     * {@code "[SENSITIVE]"}. Jackson resolves a mixin's annotations ahead of the
     * target class's own, which is the documented way to say "not here".
     */
    @JsonSerialize(using = SensitiveExposer.class)
    private abstract static class ExposeSensitiveMixin {
    }

    /**
     * Renders a &sect;27 request body exactly as it goes on the socket.
     *
     * <p>Exposed rather than inlined into {@link #send} so the generated
     * sparse-body conformance test can assert &sect;27.4 rule 5 — a field you
     * did not set is <em>absent</em>, not sent as null — against the writer
     * that actually serializes it, rather than against a second mapper
     * configured to resemble it. A rule proved on a lookalike is not proved.
     *
     * @param operation the canonical {@code namespace.operation} name, for the error message
     * @param body the request body to encode; must not be {@code null}
     * @return the UTF-8 JSON bytes to send
     * @throws NetworkError if the body cannot be encoded
     */
    public static byte[] encodeBody(String operation, Object body) {
        try {
            return WIRE.writeValueAsBytes(body);
        } catch (IOException e) {
            throw new NetworkError(operation + ": could not encode the request body: "
                    + e.getMessage(), e);
        }
    }

    private final OkHttpClient http;
    private final String baseUrl;
    private final SessionState session;
    private final TelemetryDispatcher telemetry;
    private final boolean retryEnabled;
    private final Runnable ensureOpen;

    /**
     * Builds the transport from the pieces its owning client already holds.
     *
     * @param http the client's decorated OkHttp client, which carries the
     *             &sect;3/&sect;4/&sect;5 interceptors every request must go through
     * @param baseUrl the client's base URL
     * @param session the client's session state, for the &sect;27.4 rule 1
     *                authentication precondition and the resolved identifiers
     * @param telemetry the client's &sect;19 dispatcher
     * @param retryEnabled whether the &sect;16 retry policy is on
     * @param ensureOpen the client's use-after-close check (&sect;18.1 rule 4)
     */
    public ManagementTransport(OkHttpClient http, String baseUrl, SessionState session,
                               TelemetryDispatcher telemetry, boolean retryEnabled,
                               Runnable ensureOpen) {
        this.http = http;
        this.baseUrl = baseUrl;
        this.session = session;
        this.telemetry = telemetry;
        this.retryEnabled = retryEnabled;
        this.ensureOpen = ensureOpen;
    }

    /**
     * Returns the session state this transport reads its context from.
     *
     * @return the owning client's session state
     */
    public SessionState session() {
        return session;
    }

    /**
     * Issues one management call and returns its parsed body.
     *
     * <p>Only {@code GET} is routed through the &sect;16 retry runner
     * (&sect;27.4 rule 8). No write here is retriable, not even the ones that
     * look idempotent — generating a certificate twice mints two, and rotating
     * a secret twice invalidates the one the caller already stored.
     *
     * @param operation the registry's namespace-qualified name, e.g. {@code "users.create"}
     * @param method the HTTP verb
     * @param pathTemplate the path with identifiers NOT substituted — the
     *                     &sect;19.1 telemetry label, which must not carry identifiers
     * @param path the same path with identifiers substituted, ready to send
     * @param query the query parameters; entries with a {@code null} value are dropped
     * @param body the request body, or {@code null} for a bodyless request
     * @return the parsed response body, or {@code null} for a 204
     * @throws AuthError when there is no active session (&sect;27.4 rule 1)
     * @throws NotFoundError on 404
     * @throws ConflictError on 409
     * @throws ValidationError on 400 or 422
     * @throws NetworkError on a transport failure or any other unsuccessful status
     */
    public @Nullable JsonNode send(String operation, String method, String pathTemplate,
                                   String path, Map<String, @Nullable String> query,
                                   @Nullable Object body) {
        ensureOpen.run();
        requireSession(operation);

        if (!"GET".equals(method)) {
            return attempt(operation, method, pathTemplate, path, query, body, 1);
        }
        return Retry.withRetry(
                retryEnabled ? Retry.DEFAULT_MAX_ATTEMPTS : 1,
                n -> attempt(operation, method, pathTemplate, path, query, body, n),
                e -> e instanceof NetworkError && !(e instanceof ValidationError),
                telemetry,
                operation);
    }

    /**
     * Refuses a management call with no session (&sect;27.4 rule 1).
     *
     * <p>Letting the request go out trades a clear local error for a 401 the
     * caller must then interpret, two indirections from the actual mistake.
     *
     * @param operation the registry operation being attempted
     * @throws AuthError when no access token is present
     */
    private void requireSession(String operation) {
        if (session.cachedAccessToken() == null) {
            throw new AuthError(operation
                    + ": no active session — call login() before using the management API");
        }
    }

    /** One &sect;16 attempt, with its &sect;19 request pair. */
    private @Nullable JsonNode attempt(String operation, String method, String pathTemplate,
                                       String path, Map<String, @Nullable String> query,
                                       @Nullable Object body, int attemptNumber) {
        HttpUrl.Builder url = HttpUrl.get(baseUrl + path).newBuilder();
        // TreeMap so the encoded query is stable run to run, which makes a
        // failing request reproducible from its telemetry.
        for (Map.Entry<String, @Nullable String> entry : new TreeMap<>(query).entrySet()) {
            if (entry.getValue() != null) {
                url.addQueryParameter(entry.getKey(), entry.getValue());
            }
        }

        Request.Builder request = new Request.Builder().url(url.build());
        if (body == null) {
            request.method(method, "GET".equals(method) || "DELETE".equals(method)
                    ? null : RequestBody.create(new byte[0], JSON_MEDIA));
        } else {
            request.method(method, RequestBody.create(encodeBody(operation, body), JSON_MEDIA));
        }

        // §19.1: the label is the TEMPLATE, never the substituted path — a
        // label carrying a tenant's user identifiers is a cardinality explosion
        // and a disclosure at once.
        TelemetryDispatcher.Span span = telemetry.startRequest(
                operation, method, pathTemplate, attemptNumber);

        try (Response response = execute(operation, request.build())) {
            if (!response.isSuccessful()) {
                span.end(response.code(), TelemetryEvent.Outcome.FAILURE);
                throw mapFailure(operation, response);
            }
            span.end(response.code(), TelemetryEvent.Outcome.SUCCESS);
            return readBody(operation, response);
        }
    }

    private Response execute(String operation, Request request) {
        try {
            return http.newCall(request).execute();
        } catch (IOException e) {
            throw new NetworkError(operation + ": request failed: " + e.getMessage(), e);
        }
    }

    private @Nullable JsonNode readBody(String operation, Response response) {
        if (response.code() == 204) {
            return null;
        }
        try {
            ResponseBody responseBody = response.body();
            if (responseBody == null) {
                return null;
            }
            byte[] raw = responseBody.bytes();
            return raw.length == 0 ? null : READER.readTree(raw);
        } catch (IOException e) {
            throw new NetworkError(operation + ": could not parse the server's response: "
                    + e.getMessage(), e);
        }
    }

    /**
     * Maps a failed management response onto the &sect;2 taxonomy.
     *
     * <p>Delegates to the shared {@link ErrorMapper} for everything &sect;27
     * does not classify, so the two mappers cannot drift: this method's whole
     * job is the three statuses &sect;27.4 rule 7 names, and 404 is the one
     * &sect;2 genuinely lacks.
     */
    private RuntimeException mapFailure(String operation, Response response) {
        String peeked = peek(response);
        String detail = describe(peeked);
        return switch (response.code()) {
            case 404 -> new NotFoundError(operation,
                    operation + ": not found (or not visible to this tenant)" + detail);
            case 409 -> new ConflictError(operation, operation + ": conflict" + detail);
            case 400, 422 -> new ValidationError(operation, response.code(),
                    operation + ": request rejected" + detail, parseFieldErrors(peeked));
            default -> ErrorMapper.fromHttpStatus(response.code(), operation + detail, response);
        };
    }

    /** At most a few KB of an error body is needed to explain the refusal. */
    private static String peek(Response response) {
        try {
            ResponseBody responseBody = response.peekBody(8192);
            return responseBody.string();
        } catch (IOException e) {
            return "";
        }
    }

    private static String describe(String body) {
        if (body.isEmpty()) {
            return "";
        }
        try {
            JsonNode node = READER.readTree(body);
            if (node.hasNonNull("message")) {
                return ": " + node.get("message").asText();
            }
            if (node.hasNonNull("error")) {
                return ": " + node.get("error").asText();
            }
            return "";
        } catch (IOException e) {
            return ": " + (body.length() > 200 ? body.substring(0, 200) : body);
        }
    }

    /**
     * Pulls field-level detail out of an error body, on a best-effort basis.
     *
     * <p>Two shapes are recognised — an array of {@code {field, message}} and
     * an object keyed by field name. A body in neither shape yields no fields
     * rather than an error: failing to parse an error body would replace a
     * useful message with a useless one.
     */
    private static List<FieldError> parseFieldErrors(String body) {
        List<FieldError> out = new ArrayList<>();
        if (body.isEmpty()) {
            return out;
        }
        JsonNode errors;
        try {
            errors = READER.readTree(body).path("errors");
        } catch (IOException e) {
            return out;
        }
        if (errors.isArray()) {
            for (JsonNode item : errors) {
                if (item.hasNonNull("field")) {
                    out.add(new FieldError(item.get("field").asText(),
                            item.path("message").asText("")));
                }
            }
            return out;
        }
        if (errors.isObject()) {
            errors.properties().stream()
                    .filter(e -> e.getValue().isTextual())
                    .sorted(Map.Entry.comparingByKey())
                    .forEach(e -> out.add(new FieldError(e.getKey(), e.getValue().asText())));
        }
        return out;
    }

    /**
     * Returns the mapper used to read management responses.
     *
     * @return the response {@link ObjectMapper}, for the generated layer to
     *         convert a {@link JsonNode} into a model
     */
    public static ObjectMapper reader() {
        return READER;
    }

    /** Serializes a {@link Sensitive} as its raw value, for outbound bodies only. */
    private static final class SensitiveExposer
            extends com.fasterxml.jackson.databind.ser.std.StdSerializer<Sensitive> {

        SensitiveExposer() {
            super(Sensitive.class);
        }

        @Override
        public void serialize(Sensitive value, com.fasterxml.jackson.core.JsonGenerator gen,
                              com.fasterxml.jackson.databind.SerializerProvider provider)
                throws IOException {
            gen.writeString(value.expose());
        }
    }
}
