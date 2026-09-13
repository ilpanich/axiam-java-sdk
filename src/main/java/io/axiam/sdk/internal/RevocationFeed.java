package io.axiam.sdk.internal;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.ResponseBody;

import org.jspecify.annotations.Nullable;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.LongSupplier;

/**
 * A poller for one deployment's session-revocation feed (CONTRACT.md
 * &sect;10.4, contract 1.44 &mdash; AXIAM threats T-39 and T-143).
 *
 * <h2>What this narrows, and what it is not</h2>
 *
 * <p>An AXIAM access token is self-contained and valid for up to fifteen
 * minutes, and {@link JwksVerifier} verifies it locally. A logout, a role
 * removal or an account disable therefore does not reach a token already in a
 * caller's hands until it expires &mdash; &sect;10.2 records that, and the
 * documented answer has been "route the decision through gRPC introspection
 * instead", which is correct and costs a round trip <strong>per
 * request</strong>.
 *
 * <p>A deployment may publish {@code GET /oauth2/revocations}: the
 * base64url-unpadded SHA-256 of every session id revoked within the last
 * access-token lifetime. A guard that polls it rejects a revoked session
 * within <strong>one poll interval</strong> instead of one token lifetime, for
 * one cacheable fetch per interval.
 *
 * <p>It is <strong>not a control</strong>, and every rule below follows from
 * that:
 *
 * <ul>
 *   <li><strong>Default off.</strong> Nothing polls unless a caller hands a
 *       feed to a verifier.</li>
 *   <li><strong>Never on the request path.</strong> {@link #isRevoked} answers
 *       from the cached set; a verify never waits on a network fetch it does
 *       not need.</li>
 *   <li><strong>Never fail closed.</strong> An unreachable feed, a non-200, a
 *       body that does not parse, an {@code alg} this build does not know
 *       &mdash; every one of them behaves exactly as no feed at all. Not as an
 *       empty list: an empty list asserts that nothing has been revoked, which
 *       is a guard that silently honours no revocations while appearing to
 *       honour them.</li>
 *   <li><strong>It only ever rejects.</strong> Every &sect;10.1 rule runs first
 *       and still decides. The feed can turn an accept into a reject and never
 *       the reverse.</li>
 *   <li><strong>A token with no {@code sid} is never matched.</strong> There is
 *       no session behind a client-credentials token, an RPT or a token
 *       exchange, and hashing {@code jti} instead would match nothing while
 *       looking like it worked.</li>
 * </ul>
 *
 * <p>Thread-safe, and meant to be shared: several guards built from one feed
 * poll once between them rather than once each.
 */
public final class RevocationFeed {

    /** The published feed's path, appended to a deployment's base URL. */
    public static final String FEED_PATH = "/oauth2/revocations";

    /**
     * The shortest interval a caller may configure (&sect;10.4 rule 2).
     *
     * <p>Bounded because the feed is one deployment-wide document and a fleet
     * of guards polling it at a hundred milliseconds is a load source rather
     * than a security improvement. The floor is applied by clamping, not by
     * refusing: a caller who asked for something faster gets the fastest thing
     * on offer.
     */
    public static final Duration MIN_POLL_INTERVAL = Duration.ofSeconds(15);

    /** The default interval, and the one &sect;10.4 recommends. */
    public static final Duration DEFAULT_POLL_INTERVAL = Duration.ofSeconds(30);

    /**
     * The largest number of entries kept in the cache (&sect;10.4 rule 2).
     *
     * <p>The server bounds the document by its own revocation rate over one
     * token lifetime, so this is defence against a server that stops doing so
     * &mdash; a cache with no ceiling is an allocation an unauthenticated
     * endpoint controls. Overflow drops the <strong>whole</strong> set rather
     * than truncating it: a truncated set is a guard that admits some revoked
     * sessions and reports none, which is worse than a guard that admits all of
     * them and says the feed is unusable.
     */
    public static final int MAX_ENTRIES = 100_000;

    /**
     * The only digest the feed publishes, and the only one this poller accepts.
     *
     * <p>A document naming anything else is treated as unusable &mdash; exactly
     * as an unreachable feed is &mdash; rather than as a list of entries that
     * happen not to match. Silently matching nothing is how a guard ends up
     * reporting that it honours revocations while honouring none.
     */
    private static final String SUPPORTED_ALG = "SHA-256";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final OkHttpClient http;

    private final String feedUrl;

    private final Duration pollInterval;

    /** A testing seam only; wall-clock milliseconds in production. */
    private final LongSupplier clock;

    /**
     * Serializes refreshers, so a burst of guards that all notice the cache is
     * stale produces one fetch rather than one each &mdash; the same shape as
     * {@link JwksVerifier}'s refresh lock, and for the same reason.
     */
    private final ReentrantLock fetchLock = new ReentrantLock();

    /**
     * {@code null} means "never successfully fetched", which is NOT the same as
     * an empty set, and is why this is a nullable reference rather than an
     * always-present collection.
     */
    private volatile @Nullable Set<String> entries;

    /** {@code null} means "never attempted". */
    private volatile @Nullable Long lastAttemptMillis;

    /**
     * Polls {@code {baseUrl}/oauth2/revocations} on
     * {@link #DEFAULT_POLL_INTERVAL}.
     *
     * <p>A deployment that does not publish the feed is not an error here
     * &mdash; that is discovered on the first poll, and behaves as no feed at
     * all from then on.
     *
     * @param http    the client to fetch through, so a caller that pins a
     *                proxy, a timeout or a CA bundle keeps them here too
     * @param baseUrl the AXIAM server base URL (trailing slash tolerated)
     */
    public RevocationFeed(OkHttpClient http, String baseUrl) {
        this(http, baseUrl, DEFAULT_POLL_INTERVAL);
    }

    /**
     * Polls {@code {baseUrl}/oauth2/revocations} on {@code pollInterval},
     * clamped up to {@link #MIN_POLL_INTERVAL}.
     *
     * @param http         the client to fetch through
     * @param baseUrl      the AXIAM server base URL (trailing slash tolerated)
     * @param pollInterval how often a check after this long refetches; anything
     *                     shorter than {@link #MIN_POLL_INTERVAL} is raised to
     *                     it rather than refused
     */
    public RevocationFeed(OkHttpClient http, String baseUrl, Duration pollInterval) {
        this(http, baseUrl, pollInterval, System::currentTimeMillis);
    }

    RevocationFeed(OkHttpClient http, String baseUrl, Duration pollInterval, LongSupplier clock) {
        this.http = http;
        String trimmed = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.feedUrl = trimmed + FEED_PATH;
        this.pollInterval = pollInterval.compareTo(MIN_POLL_INTERVAL) < 0 ? MIN_POLL_INTERVAL : pollInterval;
        this.clock = clock;
    }

    /**
     * The feed entry for a {@code sid}, as the server computes it.
     *
     * <p>Base64url without padding over the claim's <strong>exact
     * string</strong> &mdash; never a parsed-and-re-rendered UUID, or the
     * answer would depend on this SDK's UUID parser rather than on the feed.
     *
     * @param sid the session id, exactly as the {@code sid} claim carries it
     * @return the entry a matching feed document would list
     */
    public static String entryFor(String sid) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(sid.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is mandated by every JRE this SDK supports.
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /**
     * The feed document's URL, as this poller resolved it.
     *
     * @return the URL polled, for diagnostics
     */
    public String feedUrl() {
        return feedUrl;
    }

    /**
     * The poll interval actually in force, after the {@link #MIN_POLL_INTERVAL}
     * clamp.
     *
     * @return the effective interval, which may exceed what the caller
     *         requested and never falls below the floor
     */
    public Duration pollInterval() {
        return pollInterval;
    }

    /**
     * Has this session been revoked, as far as this poller knows?
     *
     * <p>{@code false} whenever the answer is not a confident yes &mdash; a
     * feed never fetched, unreachable, malformed, or simply not listing this
     * session. The caller admits the request in all of those cases, which is
     * &sect;10.4 rule 3 and is the whole reason the feature is safe to turn on.
     *
     * @param sid the session id from the token's {@code sid} claim; a blank one
     *            is never matched, because there is no session behind it
     * @return {@code true} only when the cached document lists this session
     */
    public boolean isRevoked(@Nullable String sid) {
        if (sid == null || sid.isEmpty()) {
            return false;
        }
        refreshIfStale();
        Set<String> cached = entries;
        return cached != null && cached.contains(entryFor(sid));
    }

    /**
     * Fetches now, whatever the interval says. For tests, and for a caller that
     * wants the first poll to have happened before it starts serving.
     */
    public void refresh() {
        fetchLock.lock();
        try {
            Set<String> fetched = fetchOnce();
            lastAttemptMillis = clock.getAsLong();
            if (fetched != null) {
                entries = fetched;
            }
            // On failure the previous set is deliberately left in place: a blip
            // must not un-revoke a session the guard already knows about.
        } finally {
            fetchLock.unlock();
        }
    }

    /**
     * Refetches if the poll interval has elapsed since the last
     * <em>attempt</em>.
     *
     * <p>Attempt, not success: a feed that is down must not be retried on every
     * request, which would put the request path back on the network &mdash; the
     * cost &sect;10.4 exists to avoid.
     */
    private void refreshIfStale() {
        Long last = lastAttemptMillis;
        if (last != null && clock.getAsLong() - last < pollInterval.toMillis()) {
            return;
        }
        refresh();
    }

    /**
     * One fetch. {@code null} for every kind of failure, which the caller
     * treats identically &mdash; see the class documentation on why "unusable"
     * must not collapse into "empty".
     */
    private @Nullable Set<String> fetchOnce() {
        Request request = new Request.Builder().url(feedUrl).get().build();
        try (Response response = http.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                return null;
            }
            ResponseBody body = response.body();
            if (body == null) {
                return null;
            }
            JsonNode document = MAPPER.readTree(body.string());
            if (document == null || !document.isObject()) {
                return null;
            }
            JsonNode alg = document.get("alg");
            if (alg == null || !SUPPORTED_ALG.equals(alg.asText(null))) {
                return null;
            }
            JsonNode revoked = document.get("revoked");
            if (revoked == null || !revoked.isArray() || revoked.size() > MAX_ENTRIES) {
                return null;
            }
            Set<String> parsed = new HashSet<>(revoked.size());
            for (JsonNode entry : revoked) {
                if (entry.isTextual()) {
                    parsed.add(entry.asText());
                }
            }
            return parsed;
        } catch (Exception e) {
            // Every failure mode is the same answer, deliberately: an
            // unreachable host, a truncated body, malformed JSON. Reporting
            // them apart would invite a caller to treat one of them as a denial.
            return null;
        }
    }
}
