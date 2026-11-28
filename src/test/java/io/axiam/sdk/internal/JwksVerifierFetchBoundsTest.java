package io.axiam.sdk.internal;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import io.axiam.sdk.errors.AuthError;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CONTRACT.md &sect;12.4 rule 2 and the fetch-concurrency rules (OI-36 review round 1): every fetch failure counts
 * toward the window, the fetch has a total deadline and runs detached from the caller, a usable held set never waits
 * for a fetch, fetches are single-flight, and only a {@code 200} is a successful fetch.
 */
class JwksVerifierFetchBoundsTest {

    private static final String TENANT = "tenant-a";
    private static final long T0 = 1_000_000_000L;
    private static final long TTL = JwksVerifier.JWKS_TTL.toSeconds();

    private enum Mode { OK, HANG, DRIP, HEADER_DRIP, BIG_BODY, BIG_HEADER, STATUS_203, STATUS_206 }

    /** A raw HTTP/1.1 server whose behaviour is switchable and which counts connections. */
    private static final class RawServer implements AutoCloseable {
        final ServerSocket socket;
        final AtomicInteger connections = new AtomicInteger();
        final AtomicReference<Mode> mode = new AtomicReference<>(Mode.OK);
        final String jwks;
        final List<Socket> open = new ArrayList<>();
        /** Counted down when a streaming response could no longer be written (the client closed the connection). */
        final CountDownLatch streamClosed = new CountDownLatch(1);
        final java.util.concurrent.atomic.AtomicLong bigBytesWritten = new java.util.concurrent.atomic.AtomicLong();

        RawServer(String jwks) throws IOException {
            this.jwks = jwks;
            this.socket = new ServerSocket(0, 50, java.net.InetAddress.getLoopbackAddress());
            Thread t = new Thread(this::loop, "raw-jwks-server");
            t.setDaemon(true);
            t.start();
        }

        String url() {
            return "http://127.0.0.1:" + socket.getLocalPort() + "/";
        }

        private void loop() {
            while (!socket.isClosed()) {
                try {
                    Socket s = socket.accept();
                    connections.incrementAndGet();
                    synchronized (open) {
                        open.add(s);
                    }
                    Thread h = new Thread(() -> handle(s));
                    h.setDaemon(true);
                    h.start();
                } catch (IOException e) {
                    return;
                }
            }
        }

        private void handle(Socket s) {
            try {
                InputStream in = s.getInputStream();
                int state = 0;
                int b;
                while (state < 4 && (b = in.read()) != -1) { // read the request head
                    state = (b == '\r' && (state == 0 || state == 2)) || (b == '\n' && (state == 1 || state == 3))
                            ? state + 1 : (b == '\r' ? 1 : 0);
                }
                OutputStream out = s.getOutputStream();
                switch (mode.get()) {
                    case HANG -> Thread.sleep(60_000);
                    case BIG_BODY -> {
                        out.write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
                                .getBytes(StandardCharsets.US_ASCII)); // no Content-Length: a stream of unknown size
                        byte[] chunk = new byte[64 * 1024];
                        java.util.Arrays.fill(chunk, (byte) ' ');
                        try {
                            for (int i = 0; i < 6000; i++) { // up to ~400 MB
                                out.write(chunk);
                                out.flush();
                                bigBytesWritten.addAndGet(chunk.length);
                            }
                        } catch (IOException closed) {
                            streamClosed.countDown();
                        }
                    }
                    case BIG_HEADER -> {
                        out.write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 10000000\r\n\r\n"
                                .getBytes(StandardCharsets.US_ASCII));
                        out.flush();
                        try {
                            for (int i = 0; i < 600; i++) {
                                Thread.sleep(100);
                                out.write(' ');
                                out.flush();
                            }
                        } catch (IOException closed) {
                            streamClosed.countDown();
                        }
                    }
                    case HEADER_DRIP -> {
                        out.write("HTTP/1.1 200 OK\r\n".getBytes(StandardCharsets.US_ASCII));
                        for (int i = 0; i < 100_000 && !s.isClosed(); i++) {
                            out.write(("X-" + i + ": y\r\n").getBytes(StandardCharsets.US_ASCII));
                            out.flush();
                            Thread.sleep(200);
                        }
                    }
                    case DRIP -> {
                        out.write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100000\r\n\r\n"
                                .getBytes(StandardCharsets.US_ASCII));
                        out.flush();
                        try {
                            for (int i = 0; i < 100_000 && !s.isClosed(); i++) {
                                out.write(' ');
                                out.flush();
                                Thread.sleep(200);
                            }
                        } catch (IOException closed) {
                            streamClosed.countDown();
                        }
                    }
                    default -> {
                        int code = mode.get() == Mode.STATUS_203 ? 203 : mode.get() == Mode.STATUS_206 ? 206 : 200;
                        byte[] body = jwks.getBytes(StandardCharsets.UTF_8);
                        out.write(("HTTP/1.1 " + code + " X\r\nContent-Type: application/json\r\nContent-Length: "
                                + body.length + "\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
                        out.write(body);
                        out.flush();
                        s.close();
                    }
                }
            } catch (Exception ignored) {
                // the client went away
            }
        }

        @Override
        public void close() throws IOException {
            socket.close();
            synchronized (open) {
                for (Socket s : open) {
                    try {
                        s.close();
                    } catch (IOException ignored) {
                        // closing
                    }
                }
            }
        }
    }

    private static String token(OctetKeyPair key, String kid) throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder().subject("user-1").claim("tenant_id", TENANT)
                .expirationTime(new Date(System.currentTimeMillis() + 900_000L)).build();
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.EdDSA).type(new JOSEObjectType("at+jwt"))
                .keyID(kid).build();
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new Ed25519Signer(key));
        return jwt.serialize();
    }

    private static boolean accepts(JwksVerifier v, String token) {
        try {
            v.verifyAccessToken(token, TENANT);
            return true;
        } catch (AuthError e) {
            return false;
        }
    }

    private static OctetKeyPair newKey() throws Exception {
        return new OctetKeyPairGenerator(Curve.Ed25519).keyID("held").generate();
    }

    @Test
    void aNeverAnsweringEndpointCostsOneFetchPerWindow_notOnePerToken() throws Exception {
        OctetKeyPair key = newKey();
        try (RawServer server = new RawServer(new JWKSet(List.of(key.toPublicJWK())).toString())) {
            server.mode.set(Mode.HANG);
            JwksVerifier v = new JwksVerifier(server.url());
            v.setClockForTesting(() -> T0);
            String t = token(key, "held");
            assertTimeoutPreemptively(Duration.ofSeconds(60), () -> {
                for (int i = 0; i < 20; i++) {
                    assertEquals(false, accepts(v, t));
                }
            });
            assertEquals(1, server.connections.get(), "20 tokens on a still clock cost one connection");
        }
    }

    @Test
    void aDripFeedingEndpointIsAbandonedAtTheTotalDeadline() throws Exception {
        OctetKeyPair key = newKey();
        try (RawServer server = new RawServer(new JWKSet(List.of(key.toPublicJWK())).toString())) {
            server.mode.set(Mode.DRIP);
            JwksVerifier v = new JwksVerifier(server.url());
            String t = token(key, "held");
            assertTimeoutPreemptively(Duration.ofSeconds(10), () -> assertEquals(false, accepts(v, t)));
            assertTrue(server.streamClosed.await(3, java.util.concurrent.TimeUnit.SECONDS),
                    "the abandoned exchange must be cancelled: the server sees the connection close shortly after the deadline");
        }
    }

    @Test
    void aBodyLargerThanTheCapIsAFailedRefreshAndItsConnectionIsClosedEarly() throws Exception {
        OctetKeyPair key = newKey();
        try (RawServer server = new RawServer(new JWKSet(List.of(key.toPublicJWK())).toString())) {
            server.mode.set(Mode.BIG_BODY);
            JwksVerifier v = new JwksVerifier(server.url());
            String t = token(key, "held");
            assertTimeoutPreemptively(Duration.ofSeconds(10), () -> assertEquals(false, accepts(v, t)));
            assertTrue(server.streamClosed.await(5, java.util.concurrent.TimeUnit.SECONDS),
                    "the client must stop reading past the cap and close the connection");
            assertTrue(server.bigBytesWritten.get() < 100L * 1024 * 1024,
                    "far less than the whole body was transferred: " + server.bigBytesWritten.get());
        }
    }

    @Test
    void aDeclaredContentLengthAboveTheCapIsRefusedAtOnce() throws Exception {
        OctetKeyPair key = newKey();
        try (RawServer server = new RawServer(new JWKSet(List.of(key.toPublicJWK())).toString())) {
            server.mode.set(Mode.BIG_HEADER);
            JwksVerifier v = new JwksVerifier(server.url());
            String t = token(key, "held");
            assertTimeoutPreemptively(Duration.ofSeconds(3), () -> assertEquals(false, accepts(v, t)));
            assertTrue(server.streamClosed.await(3, java.util.concurrent.TimeUnit.SECONDS));
        }
    }

    @Test
    void aCallersOwnInterruptWhileWaitingIsAnAuthErrorThatRecordsNothingAndKeepsTheFlag() throws Exception {
        OctetKeyPair key = newKey();
        try (RawServer server = new RawServer(new JWKSet(List.of(key.toPublicJWK())).toString())) {
            server.mode.set(Mode.HANG);
            JwksVerifier v = new JwksVerifier(server.url());
            String t = token(key, "held");
            AtomicReference<Throwable> thrown = new AtomicReference<>();
            AtomicReference<Boolean> flag = new AtomicReference<>();
            Thread caller = new Thread(() -> {
                try {
                    v.verifyAccessToken(t, TENANT);
                } catch (Throwable e) {
                    thrown.set(e);
                    flag.set(Thread.currentThread().isInterrupted());
                }
            });
            caller.start();
            long until = System.nanoTime() + Duration.ofSeconds(5).toNanos();
            while (server.connections.get() < 1 && System.nanoTime() < until) {
                Thread.sleep(10);
            }
            caller.interrupt();
            caller.join(3000);
            assertTrue(thrown.get() instanceof AuthError, String.valueOf(thrown.get()));
            assertTrue(thrown.get().getMessage().contains("interrupted"), thrown.get().getMessage());
            assertEquals(true, flag.get(), "the interrupt flag is restored");
        }
    }

    @Test
    void aHeaderDrippingEndpointIsAbandonedAtTheTotalDeadline() throws Exception {
        OctetKeyPair key = newKey();
        try (RawServer server = new RawServer(new JWKSet(List.of(key.toPublicJWK())).toString())) {
            server.mode.set(Mode.HEADER_DRIP);
            JwksVerifier v = new JwksVerifier(server.url());
            String t = token(key, "held");
            assertTimeoutPreemptively(Duration.ofSeconds(10), () -> assertEquals(false, accepts(v, t)));
        }
    }

    @Test
    void aStalledFetchNeverDelaysAVerificationWithAUsableHeldSet() throws Exception {
        OctetKeyPair key = newKey();
        try (RawServer server = new RawServer(new JWKSet(List.of(key.toPublicJWK())).toString())) {
            AtomicLong now = new AtomicLong(T0);
            JwksVerifier v = new JwksVerifier(server.url());
            v.setClockForTesting(now::get);
            String t = token(key, "held");
            assertTrue(accepts(v, t), "cold fetch fills the cache");
            server.mode.set(Mode.DRIP);
            now.set(T0 + Duration.ofSeconds(TTL + 1).toNanos()); // a refresh is due
            long start = System.nanoTime();
            assertTrue(accepts(v, t), "held kid accepted past the TTL");
            assertTrue(Duration.ofNanos(System.nanoTime() - start).toMillis() < 1500,
                    "a held-kid verification must not wait for the fetch");
            // while that fetch is in flight, further held-kid verifications do not wait either
            now.set(T0 + Duration.ofSeconds(TTL + 100).toNanos());
            start = System.nanoTime();
            assertTrue(accepts(v, t));
            assertTrue(Duration.ofNanos(System.nanoTime() - start).toMillis() < 1500);
        }
    }

    @Test
    void eightConcurrentCallersOnAColdCacheCauseOneFetch() throws Exception {
        OctetKeyPair key = newKey();
        try (RawServer server = new RawServer(new JWKSet(List.of(key.toPublicJWK())).toString())) {
            JwksVerifier v = new JwksVerifier(server.url());
            v.setClockForTesting(() -> T0);
            String t = token(key, "held");
            CountDownLatch go = new CountDownLatch(1);
            AtomicInteger ok = new AtomicInteger();
            List<Thread> threads = new ArrayList<>();
            for (int i = 0; i < 8; i++) {
                Thread th = new Thread(() -> {
                    try {
                        go.await();
                        if (accepts(v, t)) {
                            ok.incrementAndGet();
                        }
                    } catch (InterruptedException ignored) {
                        // test over
                    }
                });
                th.start();
                threads.add(th);
            }
            go.countDown();
            for (Thread th : threads) {
                th.join(20_000);
            }
            assertEquals(8, ok.get());
            assertEquals(1, server.connections.get(), "single-flight: one fetch for eight callers");
        }
    }

    @Test
    void onlyA200IsASuccessfulFetch_a203Or206KeepsTheHeldSetAndDoesNotMoveTheAnchor() throws Exception {
        for (Mode status : List.of(Mode.STATUS_203, Mode.STATUS_206)) {
            OctetKeyPair key = newKey();
            try (RawServer server = new RawServer(new JWKSet(List.of(key.toPublicJWK())).toString())) {
                AtomicLong now = new AtomicLong(T0);
                JwksVerifier v = new JwksVerifier(server.url());
                v.setClockForTesting(now::get);
                String t = token(key, "held");
                assertTrue(accepts(v, t));
                server.mode.set(status);
                now.set(T0 + Duration.ofSeconds(TTL + 1).toNanos());
                assertTrue(accepts(v, t), status + ": held kid still accepted after the refused answer");
                now.set(T0 + Duration.ofSeconds(TTL + 301).toNanos());
                assertThrows(AuthError.class, () -> v.verifyAccessToken(t, TENANT),
                        status + ": the anchor did not move, so the held kid is refused at TTL + 301 s");
            }
        }
    }
}
