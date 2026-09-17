package io.axiam.sdk.spring;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.axiam.sdk.mcp.Mcp;
import io.axiam.sdk.mcp.ProtectedResourceMetadata;

import org.jspecify.annotations.Nullable;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import java.lang.reflect.Method;
import java.util.Objects;

/**
 * {@code @RestController} that serves the CONTRACT.md &sect;28.3 RFC 9728
 * protected-resource metadata document &mdash; {@code serveProtectedResourceMetadata}
 * in every other language's &sect;28.7 naming map, and the second half of this
 * SDK's &sect;28 port (the first is {@link AxiamAuthenticationFilter}'s
 * {@code resourceMetadataUrl} option).
 *
 * <p><strong>The path is derived from the resource, never chosen</strong>
 * (&sect;28.3): {@code metadata} already carries it, computed by
 * {@link Mcp#protectedResourceMetadata}. Because a {@code @GetMapping}
 * annotation's path must be a compile-time constant and this one is only
 * known once {@code metadata} is built, this controller registers its own
 * route programmatically, on {@link RequestMappingHandlerMapping}, in
 * {@link #afterPropertiesSet()} &mdash; the standard Spring MVC seam for a
 * dynamically-derived mapping.
 *
 * <p>The response is {@code 200}, {@code Content-Type: application/json},
 * body exactly the &sect;28.2 document, serialized <strong>once</strong> at
 * construction time since it is identical for every caller (&sect;28.3 rule
 * 4: no {@code Set-Cookie}, nothing read from the request), plus
 * {@code Cache-Control: public, max-age=3600} and
 * {@code Access-Control-Allow-Origin: *} (rules 5 and 6) and no
 * {@code Access-Control-Allow-Credentials}. It answers with
 * <strong>no</strong> authentication required — pair this controller with
 * {@link AxiamAuthenticationFilter}'s {@code resourceMetadataUrl} constructor
 * argument (built from this same {@code metadata}), which is what exempts
 * this one path from that filter's otherwise-global authentication check
 * (&sect;28.3 rule 2).
 */
@RestController
public final class AxiamProtectedResourceMetadataController implements InitializingBean {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final Method SERVE_METHOD;

    static {
        try {
            SERVE_METHOD = AxiamProtectedResourceMetadataController.class.getMethod("serve");
        } catch (NoSuchMethodException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    private final ProtectedResourceMetadata metadata;
    private final RequestMappingHandlerMapping handlerMapping;
    private final String body;

    /**
     * Creates a controller serving {@code metadata} at its derived path, with
     * no cross-check against a paired guard's own configuration.
     *
     * @param metadata       the document to serve, as {@link Mcp#protectedResourceMetadata} built it
     * @param handlerMapping the application's {@code RequestMappingHandlerMapping} bean to register the route on
     */
    public AxiamProtectedResourceMetadataController(
            ProtectedResourceMetadata metadata, RequestMappingHandlerMapping handlerMapping) {
        this(metadata, handlerMapping, null, null);
    }

    /**
     * Creates a controller serving {@code metadata} at its derived path,
     * refusing at construction (&sect;28.5 rule 3) unless it agrees with a
     * paired guard's own {@code resourceMetadataUrl} and expected audience.
     *
     * @param metadata                the document to serve, as {@link Mcp#protectedResourceMetadata} built it
     * @param handlerMapping          the application's {@code RequestMappingHandlerMapping} bean to register the route on
     * @param guardResourceMetadataUrl the paired {@link AxiamAuthenticationFilter}'s
     *                                {@code resourceMetadataUrl}, or {@code null} to skip the cross-check
     *                                (e.g. when the guard is configured in a different process)
     * @param guardExpectedAudience   the paired guard's expected audience, or {@code null} to skip the cross-check
     * @throws io.axiam.sdk.errors.ValidationError if either given value does not match {@code metadata}
     */
    public AxiamProtectedResourceMetadataController(
            ProtectedResourceMetadata metadata,
            RequestMappingHandlerMapping handlerMapping,
            @Nullable String guardResourceMetadataUrl,
            @Nullable String guardExpectedAudience) {
        Mcp.requireMetadataMatchesGuard(metadata, guardResourceMetadataUrl, guardExpectedAudience);
        this.metadata = Objects.requireNonNull(metadata, "metadata");
        this.handlerMapping = Objects.requireNonNull(handlerMapping, "handlerMapping");
        try {
            // §28.3 rule 4: identical for every caller, so there is nothing
            // per-request to (re)build.
            this.body = MAPPER.writeValueAsString(metadata.document());
        } catch (JsonProcessingException e) {
            // Unreachable: ProtectedResourceMetadataDocument is a record of
            // Strings and Lists of Strings, always serializable.
            throw new IllegalStateException(e);
        }
    }

    /**
     * Registers the {@code GET} route at {@link ProtectedResourceMetadata#metadataPath()},
     * once this bean is fully constructed.
     */
    @Override
    public void afterPropertiesSet() {
        RequestMappingInfo mapping =
                RequestMappingInfo.paths(metadata.metadataPath()).methods(RequestMethod.GET).build();
        handlerMapping.registerMapping(mapping, this, SERVE_METHOD);
    }

    /**
     * Serves the RFC 9728 document (CONTRACT.md &sect;28.3): {@code 200},
     * unauthenticated, identical for every caller.
     *
     * <p>Not annotated {@code @GetMapping} — see the class Javadoc for why the
     * route is instead registered programmatically in
     * {@link #afterPropertiesSet()} &mdash; but Spring MVC still treats it as
     * an ordinary handler method once mapped, so the usual content
     * negotiation and exception handling apply exactly as they would to any
     * other {@code @RestController} method.
     *
     * @return the document, with the headers &sect;28.3 pins
     */
    public ResponseEntity<String> serve() {
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .header(HttpHeaders.CACHE_CONTROL, "public, max-age=3600")
                .header(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                .body(body);
    }
}
