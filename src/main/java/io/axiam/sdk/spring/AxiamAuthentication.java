package io.axiam.sdk.spring;

import org.jspecify.annotations.Nullable;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.List;

/**
 * The identity {@link AxiamAuthenticationFilter} places on the {@code SecurityContext} once a
 * token has passed every CONTRACT.md &sect;10.1 rule.
 *
 * <p>Spring Security keeps one authority list, so the filter keeps roles and scopes apart by
 * name (CONTRACT.md &sect;11.2 rule 11 (c); contract 1.68, N15):
 * <ul>
 *   <li>each entry of the token's {@code roles} claim becomes {@code ROLE_<name>}, which is what
 *       {@code hasRole("<name>")} and {@code @AxiamRequireRole("<name>")} read;</li>
 *   <li>each entry of the token's {@code scope} claim becomes {@code SCOPE_<scope>}, which is what
 *       {@code hasAuthority("SCOPE_<scope>")} and {@code @AxiamRequireScope("<scope>")} read. A
 *       scope named {@code ROLE_admin} therefore becomes {@code SCOPE_ROLE_admin} and can never
 *       satisfy {@code hasRole("admin")}.</li>
 * </ul>
 *
 * <p>A token with <em>no</em> {@code roles} claim and a token whose {@code roles} claim is the
 * empty array both carry no {@code ROLE_} authority, but they are different statements: the first
 * means the application did not request the {@code roles} scope, the second that the user holds
 * none. {@link #roles()} is {@code null} for the first and an empty list for the second.
 */
public final class AxiamAuthentication extends UsernamePasswordAuthenticationToken {

    private static final long serialVersionUID = 1L;

    /** The {@code roles} claim; {@code null} when absent or not an array of strings. */
    private final @Nullable List<String> roles;

    /** The {@code scope} claim, split on single spaces. */
    private final List<String> scopes;

    AxiamAuthentication(
            String subject,
            Collection<? extends GrantedAuthority> authorities,
            @Nullable List<String> roles,
            List<String> scopes) {
        super(subject, null, authorities);
        this.roles = roles == null ? null : List.copyOf(roles);
        this.scopes = List.copyOf(scopes);
    }

    /**
     * The names in the token's {@code roles} claim.
     *
     * @return the role names, an empty list when the claim is the empty array, or {@code null}
     *         when the claim is absent or is not a JSON array of strings
     */
    public @Nullable List<String> roles() {
        return roles;
    }

    /**
     * The entries of the token's {@code scope} claim.
     *
     * @return the scopes, empty when the claim is absent or not a string
     */
    public List<String> scopes() {
        return scopes;
    }
}
