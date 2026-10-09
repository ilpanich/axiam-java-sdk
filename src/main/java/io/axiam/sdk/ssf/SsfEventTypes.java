package io.axiam.sdk.ssf;

/**
 * The event-type URIs AXIAM transmits (CONTRACT.md &sect;32.6): the six CAEP
 * and RISC events, plus the two SSF stream events.
 *
 * <p>Event types are open: a SET whose type is none of these still verifies,
 * and {@link SecurityEvent#eventType()} carries it verbatim.
 */
public final class SsfEventTypes {

    /** CAEP session revoked. */
    public static final String SESSION_REVOKED =
            "https://schemas.openid.net/secevent/caep/event-type/session-revoked";
    /** CAEP credential change. */
    public static final String CREDENTIAL_CHANGE =
            "https://schemas.openid.net/secevent/caep/event-type/credential-change";
    /** CAEP assurance level change. */
    public static final String ASSURANCE_LEVEL_CHANGE =
            "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change";
    /** RISC account disabled. */
    public static final String ACCOUNT_DISABLED =
            "https://schemas.openid.net/secevent/risc/event-type/account-disabled";
    /** RISC account enabled. */
    public static final String ACCOUNT_ENABLED =
            "https://schemas.openid.net/secevent/risc/event-type/account-enabled";
    /** RISC account purged. */
    public static final String ACCOUNT_PURGED =
            "https://schemas.openid.net/secevent/risc/event-type/account-purged";
    /** SSF verification. */
    public static final String VERIFICATION =
            "https://schemas.openid.net/secevent/ssf/event-type/verification";
    /** SSF stream updated. */
    public static final String STREAM_UPDATED =
            "https://schemas.openid.net/secevent/ssf/event-type/stream-updated";

    private SsfEventTypes() {
    }
}
