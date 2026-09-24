package io.axiam.sdk.internal;

import java.util.UUID;

/**
 * An OkHttp request tag naming the acting tenant a specific {@code AxiamClient} handle
 * was built or rebound with (CONTRACT.md &sect;5.2 rule 1, contract 1.51).
 *
 * <p>{@code AuthInterceptor} is registered once on a shared {@code OkHttpClient}, and
 * every handle produced by {@code AxiamClient.actingTenant(UUID)} shares that same
 * client and the same {@code SessionState} — only the acting tenant differs between
 * handles. A field on the shared session would let two handles acting on two tenants
 * race to overwrite each other's header between deciding and sending it; a value
 * carried on the immutable {@link okhttp3.Request} itself, tagged by the specific call
 * site that built it, cannot. {@code Request.Builder#tag(Class, Object)} is exactly this
 * mechanism, and this record is the key.
 *
 * @param tenantId the tenant this request acts on
 */
public record ActingTenantTag(UUID tenantId) {
}
