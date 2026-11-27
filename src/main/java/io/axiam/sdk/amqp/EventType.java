package io.axiam.sdk.amqp;

import java.util.List;

/**
 * The one signed event type an {@link AmqpConsumer} consumes (CONTRACT.md &sect;8 protocol step 2c, "Typed: one
 * configured type", contract 1.69; D-9).
 *
 * <p>A consumer checks the canonical bytes against <em>this</em> type's declared members, in declaration order,
 * and nothing else: a body that has the layout of the other type, or of any other tenant-signed shape, is
 * refused as {@code malformed} before the HMAC is computed. The type is never chosen from the body. An
 * application that consumes both types runs two consumers.
 */
public enum EventType {

    /** {@code AuthzRequest} (asynchronous authorization checks). */
    AUTHZ_REQUEST(List.of(
            Member.req("correlation_id", Kind.UUID), Member.req("tenant_id", Kind.UUID),
            Member.req("subject_id", Kind.UUID), Member.req("action", Kind.STRING),
            Member.req("resource_id", Kind.UUID), Member.opt("scope", Kind.STRING),
            Member.req("key_version", Kind.INT), Member.req("nonce", Kind.UUID),
            Member.req("issued_at", Kind.TIMESTAMP))),

    /** {@code AuditEventMessage} (audit ingestion). */
    AUDIT_EVENT(List.of(
            Member.req("tenant_id", Kind.UUID), Member.req("actor_id", Kind.UUID),
            Member.req("actor_type", Kind.STRING), Member.req("action", Kind.STRING),
            Member.opt("resource_id", Kind.UUID), Member.req("outcome", Kind.STRING),
            Member.opt("ip_address", Kind.STRING), Member.opt("metadata", Kind.OBJECT),
            Member.req("key_version", Kind.INT), Member.req("nonce", Kind.UUID),
            Member.req("issued_at", Kind.TIMESTAMP)));

    /** The JSON type a member must decode as (step 2f). */
    enum Kind { UUID, STRING, INT, TIMESTAMP, OBJECT }

    /** A declared member: wire name, JSON type, and whether the server omits it when absent. */
    record Member(String name, Kind kind, boolean optional) {
        static Member req(String name, Kind kind) {
            return new Member(name, kind, false);
        }

        static Member opt(String name, Kind kind) {
            return new Member(name, kind, true);
        }
    }

    private final List<Member> members;

    EventType(List<Member> members) {
        this.members = members;
    }

    /** The declared members in declaration order ({@code hmac_signature} excluded). */
    List<Member> members() {
        return members;
    }

    /**
     * Whether {@code names} (the canonical bytes' top-level member names, in wire order) are exactly this type's
     * members in declaration order, each optional one present in its place or absent, and nothing else.
     */
    boolean hasLayout(List<String> names) {
        int i = 0;
        for (Member member : members) {
            if (i < names.size() && names.get(i).equals(member.name())) {
                i++;
            } else if (!member.optional()) {
                return false;
            }
        }
        return i == names.size();
    }
}
