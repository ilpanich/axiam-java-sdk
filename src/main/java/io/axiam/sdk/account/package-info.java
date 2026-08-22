/**
 * Account lifecycle and MFA enrolment — CONTRACT.md &sect;25.
 *
 * <p>&sect;1 locked the <em>middle</em> of an account's life: {@code login},
 * {@code verifyMfa}, {@code refresh} and {@code logout} all assume an account
 * that already exists, is verified, and already has its second factor. These
 * nine operations are how an account gets into that state. None of them is new
 * server surface — all nine have been live and unreachable-from-an-SDK since
 * before &sect;1 was written, which meant every application hand-rolled a POST
 * against a path this SDK also knew.
 */
@NullMarked
package io.axiam.sdk.account;

import org.jspecify.annotations.NullMarked;
