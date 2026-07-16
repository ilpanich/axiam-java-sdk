package io.axiam.example.springboot;

import io.axiam.sdk.annotations.AxiamRequireAccess;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

/**
 * Demonstrates CONTRACT.md &sect;11 declarative authorization: the
 * {@link AxiamRequireAccess} annotation guards {@code GET /documents/{id}} so
 * that only a caller authorized for the {@code read} action on the resource
 * whose UUID is the {@code id} path variable reaches the handler.
 *
 * <p>Enforcement is automatic: the AXIAM Spring Boot auto-configuration
 * registers {@link io.axiam.sdk.spring.AxiamAuthorizationInterceptor}, which
 * runs after {@link io.axiam.sdk.spring.AxiamAuthenticationFilter} has
 * authenticated the request and checks the annotated permission for the
 * authenticated user (401 unauthenticated, 403 denied, 400 for a
 * missing/non-UUID {@code id}, 503 if the authz service is unreachable).
 */
@RestController
public class DocumentController {

    /**
     * Returns a document, guarded by a {@code read} access check on the
     * {@code id} path variable (CONTRACT.md &sect;11).
     *
     * @param id             the document's UUID (resolved as the resource id
     *                       for the access check)
     * @param authentication the authenticated caller injected by Spring Security
     * @return a placeholder document representation for the authenticated caller
     */
    @AxiamRequireAccess(action = "read", resourceParam = "id")
    @GetMapping("/documents/{id}")
    public String read(@PathVariable("id") String id, Authentication authentication) {
        return "document " + id + " for " + authentication.getName();
    }
}
