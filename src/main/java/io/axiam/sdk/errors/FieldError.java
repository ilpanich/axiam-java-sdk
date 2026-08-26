package io.axiam.sdk.errors;

/**
 * One field-level complaint inside a {@link ValidationError}
 * (CONTRACT.md &sect;27.4 rule 7).
 *
 * @param field the offending field's name, as the server names it
 * @param message what is wrong with it
 */
public record FieldError(String field, String message) {
}
