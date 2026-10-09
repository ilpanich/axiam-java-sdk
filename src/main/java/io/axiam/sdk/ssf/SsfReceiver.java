package io.axiam.sdk.ssf;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetKeyPair;

import io.axiam.sdk.AxiamClient;
import io.axiam.sdk.Sensitive;
import io.axiam.sdk.errors.AuthError;
import io.axiam.sdk.errors.AuthzError;
import io.axiam.sdk.errors.ConflictError;
import io.axiam.sdk.errors.ErrorMapper;
import io.axiam.sdk.errors.NetworkError;
import io.axiam.sdk.errors.NotFoundError;
import io.axiam.sdk.errors.ValidationError;
import io.axiam.sdk.internal.Sessionless;
import io.axiam.sdk.internal.StatusRetry;
import io.axiam.sdk.internal.TelemetryDispatcher;

import okhttp3.HttpUrl;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;

import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/**
 * The SSF receiver helper (CONTRACT.md &sect;32.7): verifies Security Event
 * Tokens and polls a stream.
 *
 * <p>Built over an {@link AxiamClient}: its &sect;6 TLS policy fetches the JWKS,
 * its base URL is the transmitter root {@link #poll} calls, and its &sect;16
 * setting decides whether {@link #poll} retries. Neither operation carries the
 * client's session (no cookie, no SDK access token, no redirect followed).
 *
 * <pre>{@code
 * SsfReceiver receiver = new SsfReceiver(client, SsfReceiverConfig
 *         .builder(issuer, audience, SsfKeySource.jwksUri(issuer + "/oauth2/jwks"))
 *         .accessTokenProvider(() -> client.loginClientCredentials("ssf.manage", null, null).accessToken())
 *         .build());
 * SecurityEvent event = receiver.verifySet(pushedBody);   // push (RFC 8935)
 * SsfPollResult page = receiver.poll(streamId, SsfPollOptions.none());  // poll (RFC 8936)
 * }</pre>
 */
public final class SsfReceiver {

    /** The forced-refetch cooldown for an unknown {@code kid} (&sect;32.7 step 4). */
    private static final long FORCED_REFETCH_INTERVAL_NANOS = TimeUnit.SECONDS.toNanos(60);

    /** How long a fetched JWKS is used before an ordinary refresh. */
    private static final long JWKS_TTL_NANOS = TimeUnit.SECONDS.toNanos(300);

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final MediaType JSON = MediaType.get("application/json; charset=utf-8");

    private final OkHttpClient http;
    private final String baseUrl;
    private final boolean retryEnabled;
    private final TelemetryDispatcher telemetry = new TelemetryDispatcher(null);
    private final SsfReceiverConfig config;

    /** Guards the key cache below. */
    private final Object keyLock = new Object();
    private @Nullable String jwksUri;
    private @Nullable Map<String, OctetKeyPair> keys;
    private long keysFetchedAt;
    private long lastForcedRefetch;
    private boolean forcedRefetchUsed;

    /**
     * Builds a receiver over {@code client}'s transport.
     *
     * @param client the client whose TLS policy, base URL and retry setting are used
     * @param config the receiver configuration
     */
    public SsfReceiver(AxiamClient client, SsfReceiverConfig config) {
        this.http = Sessionless.of(client.okHttpClient());
        this.baseUrl = client.baseUrl();
        this.retryEnabled = client.retryEnabled();
        this.config = Objects.requireNonNull(config, "config");
    }

    @Override
    public String toString() {
        return "SsfReceiver[" + config + "]";
    }

    // ------------------------------------------------------------------
    // verifySet
    // ------------------------------------------------------------------

    /**
     * Verifies one compact SET (CONTRACT.md &sect;32.7), in this order, refusing
     * at the first failure with the {@link SetFailureReason} in brackets:
     *
     * <ol>
     *   <li>three base64url parts, a JSON header and payload object [{@code malformed}];</li>
     *   <li>{@code typ} {@code secevent+jwt} or {@code application/secevent+jwt}, any case [{@code invalid_type}];</li>
     *   <li>{@code alg} exactly {@code EdDSA} [{@code invalid_key}];</li>
     *   <li>the {@code kid} in the configured JWKS &mdash; on a miss, one refetch, at most once a
     *       minute [{@code invalid_key}];</li>
     *   <li>the signature [{@code invalid_key}];</li>
     *   <li>{@code iss} equal to the configured issuer [{@code invalid_issuer}];</li>
     *   <li>{@code aud} equal to, or an array containing, the audience [{@code invalid_audience}];</li>
     *   <li>no {@code exp}, no {@code sub}; a non-empty string {@code jti}, a numeric {@code iat}, an
     *       object {@code sub_id}; exactly one {@code events} member [{@code invalid_request}];</li>
     *   <li>a {@code jti} not seen within the replay window [{@code replayed}] &mdash; recorded only
     *       once steps 1&ndash;8 passed.</li>
     * </ol>
     *
     * <p><strong>A SET that verifies has been recorded</strong>: verifying it again
     * is {@code replayed}. Acknowledge a polled SET once you have processed it. A
     * push endpoint answers a refusal with {@code 400} and
     * {@link SetErr#fromReason(SetFailureReason)}. No {@code jwk} or {@code x5c}
     * header member is ever honoured.
     *
     * @param set the compact SET
     * @return the verified event
     * @throws SetVerificationError when the SET is refused
     * @throws NetworkError when the JWKS (or the configuration document) could not be fetched
     *         &mdash; which is not a verdict on the SET
     */
    public SecurityEvent verifySet(String set) {
        return verify(set, null);
    }

    private static SetVerificationError refuse(SetFailureReason reason, String detail) {
        return new SetVerificationError(reason, detail);
    }

    private static @Nullable ObjectNode b64Json(String part) {
        try {
            JsonNode node = MAPPER.readTree(Base64.getUrlDecoder().decode(part));
            return node instanceof ObjectNode object ? object : null;
        } catch (IllegalArgumentException | IOException e) {
            return null;
        }
    }

    private SecurityEvent verify(String set, @Nullable String expectedJti) {
        // 1.
        String[] parts = set.split("\\.", -1);
        if (parts.length != 3) {
            throw refuse(SetFailureReason.MALFORMED, "not three base64url parts");
        }
        try {
            Base64.getUrlDecoder().decode(parts[2]);
        } catch (IllegalArgumentException e) {
            throw refuse(SetFailureReason.MALFORMED, "the signature part is not base64url");
        }
        ObjectNode header = b64Json(parts[0]);
        ObjectNode claims = b64Json(parts[1]);
        if (header == null || claims == null) {
            throw refuse(SetFailureReason.MALFORMED, "header or payload is not a JSON object");
        }
        // 2.
        String typ = header.path("typ").isTextual() ? header.get("typ").asText() : "";
        if (!typ.equalsIgnoreCase("secevent+jwt") && !typ.equalsIgnoreCase("application/secevent+jwt")) {
            throw refuse(SetFailureReason.INVALID_TYPE, "typ is not secevent+jwt");
        }
        // 3.
        if (!header.path("alg").isTextual() || !"EdDSA".equals(header.get("alg").asText())) {
            throw refuse(SetFailureReason.INVALID_KEY, "alg is not EdDSA");
        }
        // 4.
        if (!header.path("kid").isTextual()) {
            throw refuse(SetFailureReason.INVALID_KEY, "no kid");
        }
        OctetKeyPair key = keyFor(header.get("kid").asText());
        if (key == null) {
            throw refuse(SetFailureReason.INVALID_KEY, "no key for kid in the JWKS");
        }
        // 5.
        boolean valid;
        try {
            valid = JWSObject.parse(set).verify(new Ed25519Verifier(key.toPublicJWK()));
        } catch (ParseException | JOSEException | RuntimeException e) {
            valid = false;
        }
        if (!valid) {
            throw refuse(SetFailureReason.INVALID_KEY, "signature does not verify");
        }
        // 6.
        String iss = claims.path("iss").isTextual() ? claims.get("iss").asText() : "";
        if (!iss.equals(config.issuer())) {
            throw refuse(SetFailureReason.INVALID_ISSUER, "iss is not the configured issuer");
        }
        // 7.
        JsonNode aud = claims.path("aud");
        boolean audOk = false;
        if (aud.isTextual()) {
            audOk = aud.asText().equals(config.audience());
        } else if (aud.isArray()) {
            for (JsonNode a : aud) {
                audOk |= a.isTextual() && a.asText().equals(config.audience());
            }
        }
        if (!audOk) {
            throw refuse(SetFailureReason.INVALID_AUDIENCE, "aud does not name this receiver");
        }
        // 8.
        if (claims.has("exp") || claims.has("sub")) {
            throw refuse(SetFailureReason.INVALID_REQUEST, "a SET carries no exp and no sub");
        }
        JsonNode jtiNode = claims.path("jti");
        if (!jtiNode.isTextual() || jtiNode.asText().isEmpty()) {
            throw refuse(SetFailureReason.INVALID_REQUEST, "no jti");
        }
        JsonNode iat = claims.path("iat");
        if (!iat.isIntegralNumber() || !iat.canConvertToLong()) {
            throw refuse(SetFailureReason.INVALID_REQUEST, "no numeric iat");
        }
        JsonNode subId = claims.path("sub_id");
        if (!subId.isObject()) {
            throw refuse(SetFailureReason.INVALID_REQUEST, "no sub_id object");
        }
        JsonNode events = claims.path("events");
        if (!events.isObject() || events.size() != 1) {
            throw refuse(SetFailureReason.INVALID_REQUEST, "events must have exactly one member");
        }
        String jti = jtiNode.asText();
        if (expectedJti != null && !expectedJti.equals(jti)) {
            throw refuse(SetFailureReason.INVALID_REQUEST, "the poll key is not the SET's jti");
        }
        Map.Entry<String, JsonNode> event = events.properties().iterator().next();
        // 9.
        if (!config.replayStore().checkAndRecord(jti, config.replayWindow())) {
            throw refuse(SetFailureReason.REPLAYED, "jti already seen");
        }
        return new SecurityEvent(jti, iat.asLong(), iss, aud.deepCopy(),
                claims.path("txn").isTextual() ? claims.get("txn").asText() : null,
                event.getKey(), event.getValue().deepCopy(), subId.deepCopy());
    }

    // ------------------------------------------------------------------
    // Keys
    // ------------------------------------------------------------------

    /**
     * The key for {@code kid}: from the cache; on a miss, one forced refetch,
     * at most once per minute across every lookup; {@code null} when still
     * missing.
     */
    private @Nullable OctetKeyPair keyFor(String kid) {
        synchronized (keyLock) {
            long now = System.nanoTime();
            boolean fetchedNow = false;
            if (keys == null || now - keysFetchedAt > JWKS_TTL_NANOS) {
                keys = fetchKeys();
                keysFetchedAt = now;
                fetchedNow = true;
            }
            OctetKeyPair key = keys.get(kid);
            if (key != null || fetchedNow) {
                return key;
            }
            if (forcedRefetchUsed && now - lastForcedRefetch < FORCED_REFETCH_INTERVAL_NANOS) {
                return null;
            }
            forcedRefetchUsed = true;
            lastForcedRefetch = now;
            keys = fetchKeys();
            keysFetchedAt = now;
            return keys.get(kid);
        }
    }

    private Map<String, OctetKeyPair> fetchKeys() {
        if (jwksUri == null) {
            jwksUri = config.keySource().isDiscovery()
                    ? discoverJwksUri(config.keySource().url())
                    : config.keySource().url();
        }
        JsonNode document = getJson(secureUrl("jwks_uri", jwksUri), "JWKS");
        JWKSet set;
        try {
            set = JWKSet.parse(document.toString());
        } catch (ParseException e) {
            throw new NetworkError("the JWKS document could not be parsed: " + e.getMessage(), e);
        }
        Map<String, OctetKeyPair> out = new HashMap<>();
        for (JWK jwk : set.getKeys()) {
            if (jwk instanceof OctetKeyPair okp && Curve.Ed25519.equals(okp.getCurve()) && okp.getKeyID() != null) {
                out.put(okp.getKeyID(), okp);
            }
        }
        return out;
    }

    private String discoverJwksUri(String discoveryUrl) {
        JsonNode doc = getJson(secureUrl("discovery_url", discoveryUrl), "SSF configuration");
        if (!doc.path("issuer").isTextual() || !doc.get("issuer").asText().equals(config.issuer())) {
            throw new NetworkError("the SSF configuration's issuer is not the configured issuer");
        }
        if (!doc.path("jwks_uri").isTextual()) {
            throw new NetworkError("the SSF configuration carries no jwks_uri");
        }
        return doc.get("jwks_uri").asText();
    }

    private JsonNode getJson(HttpUrl url, String what) {
        Request request = new Request.Builder().url(url).get().header("Accept", "application/json").build();
        try (Response response = http.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw ErrorMapper.fromHttpResponse(response.code(), what + " fetch failed", response);
            }
            ResponseBody body = response.body();
            return MAPPER.readTree(body == null ? "{}" : body.string());
        } catch (IOException e) {
            throw new NetworkError(what + " fetch failed: " + e.getMessage(), e);
        }
    }

    /** {@code https}, or {@code http} on a loopback host only &mdash; §6's rule. */
    private static HttpUrl secureUrl(String label, String raw) {
        HttpUrl url = HttpUrl.parse(raw);
        if (url == null) {
            throw new NetworkError(label + " is not an absolute http(s) URL");
        }
        String host = url.host();
        boolean loopback = "localhost".equalsIgnoreCase(host) || "127.0.0.1".equals(host) || "::1".equals(host);
        if (!url.isHttps() && !loopback) {
            throw new NetworkError(label + " must be https (CONTRACT.md §6)");
        }
        return url;
    }

    // ------------------------------------------------------------------
    // poll
    // ------------------------------------------------------------------

    /**
     * Polls the stream's RFC 8936 endpoint, {@code {root}/ssf/v1/poll/{stream_id}}
     * (CONTRACT.md &sect;32.7), with a bearer from the configured
     * {@code accessTokenProvider}, and verifies every SET it returns.
     *
     * <p>{@code ack} and {@code setErrs} are sent exactly as given; a member left
     * unset is not sent, so {@link SsfPollOptions#none()} sends {@code {}}.
     * <strong>Nothing is acknowledged on your behalf</strong>: acknowledge, on the
     * next call, the {@code jti}s you processed, and pass each refused one in
     * {@code setErrs} ({@link SetErr#fromReason(SetFailureReason)}). A SET you
     * neither acknowledge nor refuse is re-offered, and &mdash; having been
     * recorded when it verified &mdash; then reads as {@code replayed}.
     *
     * <p>Retried per &sect;16 on a transport failure, a {@code 5xx}, a
     * {@code 408} or a {@code 429}; never on another {@code 4xx}, which maps as
     * the management surface maps it ({@code 400} &rarr; {@code ValidationError},
     * {@code 404} &rarr; {@code NotFoundError}, {@code 401} &rarr;
     * {@code AuthError}, {@code 403} &rarr; {@code AuthzError}). A SET that is
     * not a string, or whose verified {@code jti} differs from the key it came
     * under, is refused; a JWKS fetch failure aborts the poll with that error
     * rather than refusing SETs it could not judge.
     *
     * @param streamId the stream's id
     * @param options  what to send
     * @return the verified events, whether more are held, and the refused SETs
     * @throws AuthError when no access token provider is configured (no request sent)
     */
    public SsfPollResult poll(String streamId, SsfPollOptions options) {
        Objects.requireNonNull(streamId, "streamId");
        Objects.requireNonNull(options, "options");
        if (config.accessTokenProvider() == null) {
            throw new AuthError("ssf.poll needs an accessTokenProvider (a client-credentials token "
                    + "with ssf.manage; CONTRACT.md §32.7)");
        }
        HttpUrl base = HttpUrl.parse(baseUrl);
        if (base == null) {
            throw new NetworkError("the client's base URL is not a valid URL");
        }
        HttpUrl url = base.newBuilder().addPathSegment("ssf").addPathSegment("v1").addPathSegment("poll")
                .addPathSegment(streamId).build();
        ObjectNode body = MAPPER.createObjectNode();
        if (options.maxEvents() != null) {
            body.put("maxEvents", options.maxEvents());
        }
        if (options.returnImmediately() != null) {
            body.put("returnImmediately", options.returnImmediately());
        }
        if (options.ack() != null) {
            options.ack().forEach(body.putArray("ack")::add);
        }
        if (options.setErrs() != null) {
            body.set("setErrs", MAPPER.valueToTree(options.setErrs()));
        }
        byte[] payload = body.toString().getBytes(StandardCharsets.UTF_8);
        Sensitive token = Objects.requireNonNull(config.accessTokenProvider().get(), "access token");

        JsonNode reply = StatusRetry.run(retryEnabled, telemetry, "ssf.poll", n -> {
            Request request = new Request.Builder().url(url).post(RequestBody.create(payload, JSON))
                    .header("Authorization", "Bearer " + token.expose())
                    .header("Accept", "application/json")
                    .build();
            Response response;
            try {
                response = http.newCall(request).execute();
            } catch (IOException e) {
                throw new StatusRetry.Transient(new NetworkError("ssf.poll request failed: " + e.getMessage(), e), 0);
            }
            try (response) {
                if (!response.isSuccessful()) {
                    RuntimeException err = mapFailure(response);
                    if (StatusRetry.retryableStatus(response.code())) {
                        throw new StatusRetry.Transient(err, StatusRetry.retryAfterMillis(response));
                    }
                    throw err;
                }
                ResponseBody responseBody = response.body();
                try {
                    return MAPPER.readTree(responseBody == null ? "{}" : responseBody.string());
                } catch (IOException e) {
                    throw new NetworkError("ssf.poll: the response could not be parsed", e);
                }
            }
        });

        List<SecurityEvent> events = new ArrayList<>();
        List<RefusedSet> refused = new ArrayList<>();
        JsonNode sets = reply.path("sets");
        if (sets.isObject()) {
            for (Map.Entry<String, JsonNode> entry : sets.properties()) {
                if (!entry.getValue().isTextual()) {
                    refused.add(new RefusedSet(entry.getKey(), SetFailureReason.MALFORMED));
                    continue;
                }
                try {
                    events.add(verify(entry.getValue().asText(), entry.getKey()));
                } catch (SetVerificationError e) {
                    refused.add(new RefusedSet(entry.getKey(), e.failureReason()));
                }
            }
        }
        return new SsfPollResult(events, reply.path("moreAvailable").asBoolean(false), refused);
    }

    /**
     * {@code CompletableFuture} async twin of {@link #poll(String, SsfPollOptions)}.
     *
     * @param streamId the stream's id
     * @param options  what to send
     * @return a future resolving to the poll result
     */
    public CompletableFuture<SsfPollResult> pollAsync(String streamId, SsfPollOptions options) {
        return CompletableFuture.supplyAsync(() -> poll(streamId, options));
    }

    /** The management surface's &sect;2 mapping, for the poll endpoint's answers. */
    private static RuntimeException mapFailure(Response response) {
        String detail = describe(response);
        return switch (response.code()) {
            case 400, 422 -> new ValidationError("ssf.poll", response.code(),
                    "ssf.poll: the transmitter refused the poll" + detail, List.of());
            case 401 -> new AuthError("ssf.poll: the access token was refused" + detail);
            case 403 -> new AuthzError("ssf.poll: forbidden" + detail);
            case 404 -> new NotFoundError("ssf.poll", "ssf.poll: no such stream for this receiver" + detail);
            case 409 -> new ConflictError("ssf.poll", "ssf.poll: conflict" + detail);
            default -> ErrorMapper.fromHttpResponse(response.code(), "ssf.poll failed" + detail, response);
        };
    }

    private static String describe(Response response) {
        try {
            String body = response.peekBody(8192).string();
            if (body.isBlank()) {
                return "";
            }
            JsonNode node = MAPPER.readTree(body);
            for (String member : List.of("message", "error_description", "error")) {
                if (node.path(member).isTextual()) {
                    return ": " + node.get(member).asText();
                }
            }
            return "";
        } catch (IOException | RuntimeException e) {
            return "";
        }
    }
}
