package io.axiam.sdk.spring;

import org.jspecify.annotations.Nullable;

import org.springframework.http.ResponseCookie;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Locale;

/**
 * The browser binding and {@code return_to} rules of the "Login with AXIAM" glue
 * (CONTRACT.md &sect;12.8, contract 1.68; audit findings C7 and C6), kept in one place so the
 * cookie name, its attributes, the digest and the comparison are decided once and never per
 * route.
 *
 * <p>The login route draws a fresh 32-byte random value, sets it as the {@code __Host-axiam_oidc_bind}
 * cookie and stores its SHA-256 on the state entry; the callback consumes the entry first and
 * then compares, in constant time, the digest of the presented cookie with the stored one. The
 * cookie value is credential-adjacent: it is never logged and appears nowhere but its own
 * {@code Set-Cookie}.
 */
final class OidcLoginBinding {

    /** The cookie name on every deployment except plain-HTTP loopback development. */
    static final String COOKIE_NAME = "__Host-axiam_oidc_bind";

    /** The cookie name used only when {@code redirect_uri} is {@code http:} on a loopback host. */
    static final String LOOPBACK_COOKIE_NAME = "axiam_oidc_bind";

    /** Cookie lifetime: the state store's maximum TTL, ten minutes. */
    static final Duration COOKIE_MAX_AGE = Duration.ofSeconds(600);

    private static final SecureRandom RANDOM = new SecureRandom();

    private OidcLoginBinding() {
    }

    /**
     * The cookie name for a deployment, a pure function of its {@code redirect_uri}: the
     * fallback name only for {@code http:} on {@code localhost}, {@code 127.0.0.1} or
     * {@code [::1]}, the {@code __Host-} name everywhere else.
     */
    static String cookieName(String redirectUri) {
        return usesLoopbackFallback(redirectUri) ? LOOPBACK_COOKIE_NAME : COOKIE_NAME;
    }

    private static boolean usesLoopbackFallback(String redirectUri) {
        try {
            URI uri = URI.create(redirectUri);
            String host = uri.getHost();
            return "http".equalsIgnoreCase(uri.getScheme()) && host != null
                    && ("localhost".equalsIgnoreCase(host) || "127.0.0.1".equals(host) || "[::1]".equals(host));
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /** 32 random bytes, base64url without padding (43 characters). */
    static String newValue() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /** Lower-case hex SHA-256 of the ASCII bytes of {@code value}. */
    static String digest(String value) {
        try {
            return HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.US_ASCII)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }

    /**
     * Constant-time comparison of the presented cookie value against the entry's digest. A missing
     * cookie, a missing digest or a different digest all answer {@code false}.
     */
    static boolean matches(@Nullable String presentedCookieValue, @Nullable String storedDigest) {
        if (presentedCookieValue == null || presentedCookieValue.isEmpty() || storedDigest == null) {
            return false;
        }
        return MessageDigest.isEqual(
                digest(presentedCookieValue).getBytes(StandardCharsets.US_ASCII),
                storedDigest.toLowerCase(Locale.ROOT).getBytes(StandardCharsets.US_ASCII));
    }

    /** The login response's {@code Set-Cookie}: the binding value with the contract's attributes. */
    static String setCookie(String redirectUri, String value) {
        return cookie(redirectUri, value, COOKIE_MAX_AGE).toString();
    }

    /** The clearing {@code Set-Cookie} every callback response carries: same name and attributes, empty, {@code Max-Age=0}. */
    static String clearCookie(String redirectUri) {
        return cookie(redirectUri, "", Duration.ZERO).toString();
    }

    private static ResponseCookie cookie(String redirectUri, String value, Duration maxAge) {
        boolean loopback = usesLoopbackFallback(redirectUri);
        return ResponseCookie.from(loopback ? LOOPBACK_COOKIE_NAME : COOKIE_NAME, value)
                .path("/")
                .httpOnly(true)
                .secure(!loopback)
                .sameSite("Lax")
                .maxAge(maxAge)
                .build();
    }

    /**
     * The default {@code return_to} rule (CONTRACT.md &sect;12.8 rule 3): a same-origin relative
     * path. It starts with a single {@code /}, does not start with {@code //} or {@code /\},
     * contains no backslash anywhere and no control character (U+0000&ndash;U+001F, U+007F).
     */
    static boolean isSafeReturnTo(@Nullable String value) {
        if (value == null || value.isEmpty() || value.charAt(0) != '/') {
            return false;
        }
        if (value.startsWith("//") || value.startsWith("/\\")) {
            return false;
        }
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '\\' || c <= 0x1F || c == 0x7F) {
                return false;
            }
        }
        return true;
    }

    /**
     * The value of the callback's {@code Location} header for {@code destination}: its
     * percent-encoded form (login-glue Decision 7, TYP-R3-1). Written by this adapter, at the point
     * where the header is written; the application is never asked to encode.
     *
     * <p>Characters outside the URL-safe set ({@code A-Z a-z 0-9} and
     * {@code ! # $ % & ' ( ) * + , - . / : ; = ? @ [ \ ] ^ _ | ~}) are UTF-8 percent-encoded with
     * upper-case hex digits; a {@code %} that already starts a well-formed escape is kept, any other
     * {@code %} becomes {@code %25}; a lone surrogate becomes U+FFFD first; a backslash is kept. The
     * result is pure ASCII with no byte below {@code 0x21}, so CR or LF can never split the header.
     */
    static String encodeRedirectLocation(String destination) {
        StringBuilder out = new StringBuilder(destination.length() + 16);
        int n = destination.length();
        for (int i = 0; i < n;) {
            int cp = destination.codePointAt(i);
            int len = Character.charCount(cp);
            if (cp >= 0xD800 && cp <= 0xDFFF) {
                cp = 0xFFFD; // a lone surrogate (a valid pair decodes to a supplementary code point)
            }
            if (cp == '%') {
                if (i + 2 < n && isHex(destination.charAt(i + 1)) && isHex(destination.charAt(i + 2))) {
                    out.append('%');
                } else {
                    out.append("%25");
                }
            } else if (cp < 0x80 && isUrlSafe(cp)) {
                out.append((char) cp);
            } else {
                for (byte b : new String(Character.toChars(cp)).getBytes(StandardCharsets.UTF_8)) {
                    out.append('%').append(Character.toUpperCase(Character.forDigit((b >> 4) & 0xF, 16)))
                            .append(Character.toUpperCase(Character.forDigit(b & 0xF, 16)));
                }
            }
            i += len;
        }
        return out.toString();
    }

    private static boolean isHex(char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }

    private static boolean isUrlSafe(int c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                || "!#$&'()*+,-./:;=?@[\\]^_|~".indexOf(c) >= 0;
    }
}
