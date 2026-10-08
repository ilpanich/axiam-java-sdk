/**
 * The SSF receiver helper &mdash; CONTRACT.md &sect;32.7 (contract 1.56).
 *
 * <p>AXIAM is a Shared Signals Framework transmitter: it sends CAEP and RISC
 * security events as Security Event Tokens (RFC 8417) to the relying parties a
 * tenant administrator registered through the &sect;27 {@code ssf} management
 * namespace ({@code client.ssf()}). This package is for the <em>relying
 * party</em> that receives them, a different audience from that namespace:
 * {@link io.axiam.sdk.ssf.SsfReceiver#verifySet(String)} verifies one SET
 * &mdash; pushed to your endpoint (RFC 8935) or returned by a poll &mdash; and
 * {@link io.axiam.sdk.ssf.SsfReceiver#poll(String, SsfPollOptions)} calls a
 * stream's RFC 8936 poll endpoint and verifies what it returns.
 *
 * <p>Neither transmits, signs or registers anything, and neither trusts a key
 * it did not fetch from the configured JWKS: no {@code jwk} or {@code x5c}
 * header member is honoured (&sect;32.9).
 */
@NullMarked
package io.axiam.sdk.ssf;

import org.jspecify.annotations.NullMarked;
