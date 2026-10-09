package io.axiam.sdk.management;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.BeanProperty;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.databind.deser.ContextualDeserializer;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;

import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.util.Objects;
import java.util.Optional;

/**
 * A member whose JSON {@code null} means something different from its absence
 * (CONTRACT.md &sect;27.4 rule 5, "null is not absent").
 *
 * <p>A field of this type is three-state: a Java {@code null} field is an
 * <em>absent</em> member (omitted from a request body; not sent by the server),
 * {@link #ofNull()} is a member that is present and JSON {@code null}, and
 * {@link #of(Object)} with a value is a member carrying that value.
 *
 * <p>Used only where the contract names the distinction (the generator's
 * {@code EXPLICIT_NULL_FIELDS}): {@code UpdateDirectoryConfig.group_base_dn} and
 * {@code group_filter}, where {@code null} clears the stored value and absence
 * keeps it (&sect;30.2), and {@code SamlIdpInfo}'s two credential ids, where a
 * {@code null} slot must stay distinguishable from a member the server stopped
 * sending (&sect;29.8 test 8).
 *
 * @param <T> the value type
 */
@JsonSerialize(using = JsonNullable.Writer.class)
@JsonDeserialize(using = JsonNullable.Reader.class)
public final class JsonNullable<T> {

    private static final JsonNullable<?> NULL = new JsonNullable<>(null);

    private final @Nullable T value;

    private JsonNullable(@Nullable T value) {
        this.value = value;
    }

    /**
     * A present member carrying {@code value}; {@code null} gives {@link #ofNull()}.
     *
     * @param <T>   the value type
     * @param value the value, or {@code null} for JSON null
     * @return the member
     */
    @SuppressWarnings("unchecked")
    public static <T> JsonNullable<T> of(@Nullable T value) {
        return value == null ? (JsonNullable<T>) NULL : new JsonNullable<>(value);
    }

    /**
     * A present member whose value is JSON {@code null}.
     *
     * @param <T> the value type
     * @return the member
     */
    @SuppressWarnings("unchecked")
    public static <T> JsonNullable<T> ofNull() {
        return (JsonNullable<T>) NULL;
    }

    /**
     * Whether the member is JSON {@code null}.
     *
     * @return {@code true} for {@link #ofNull()}
     */
    public boolean isNull() {
        return value == null;
    }

    /**
     * The value, or {@code null} when the member is JSON {@code null}.
     *
     * @return the value
     */
    public @Nullable T get() {
        return value;
    }

    /**
     * The value as an {@link Optional}, empty when the member is JSON {@code null}.
     *
     * @return the value, if any
     */
    public Optional<T> asOptional() {
        return Optional.ofNullable(value);
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof JsonNullable<?> that && Objects.equals(value, that.value);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(value);
    }

    @Override
    public String toString() {
        return value == null ? "JsonNullable[null]" : "JsonNullable[" + value + "]";
    }

    /** Writes the value, or JSON {@code null}. */
    static final class Writer extends StdSerializer<JsonNullable<?>> {

        private static final long serialVersionUID = 1L;

        @SuppressWarnings({"unchecked", "rawtypes"})
        Writer() {
            super((Class) JsonNullable.class);
        }

        @Override
        public void serialize(JsonNullable<?> member, JsonGenerator gen, SerializerProvider provider)
                throws IOException {
            if (member.value == null) {
                gen.writeNull();
            } else {
                provider.defaultSerializeValue(member.value, gen);
            }
        }
    }

    /**
     * Reads JSON {@code null} as {@link #ofNull()} and an absent member as a
     * Java {@code null} &mdash; the distinction a default reader erases.
     */
    static final class Reader extends JsonDeserializer<JsonNullable<?>> implements ContextualDeserializer {

        private final @Nullable JavaType valueType;

        Reader() {
            this(null);
        }

        private Reader(@Nullable JavaType valueType) {
            this.valueType = valueType;
        }

        @Override
        public JsonDeserializer<?> createContextual(DeserializationContext ctxt, @Nullable BeanProperty property) {
            JavaType wrapper = property != null ? property.getType() : ctxt.getContextualType();
            JavaType inner = wrapper == null ? null : wrapper.containedType(0);
            return new Reader(inner == null ? ctxt.constructType(Object.class) : inner);
        }

        @Override
        public JsonNullable<?> deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
            JavaType type = valueType != null ? valueType : ctxt.constructType(Object.class);
            return JsonNullable.of(ctxt.readValue(p, type));
        }

        @Override
        public JsonNullable<?> getNullValue(DeserializationContext ctxt) {
            return JsonNullable.ofNull();
        }

        @Override
        public @Nullable Object getAbsentValue(DeserializationContext ctxt) {
            return null;
        }
    }
}
