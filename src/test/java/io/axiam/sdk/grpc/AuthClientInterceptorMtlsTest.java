package io.axiam.sdk.grpc;

import io.axiam.sdk.errors.NetworkError;
import io.axiam.sdk.testutil.TestCerts;
import io.axiam.sdk.testutil.TestCerts.Identity;

import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * CONTRACT.md &sect;6.1: the gRPC transport's client-identity (mTLS) path —
 * {@link AuthClientInterceptor#channelBuilder(String, byte[], byte[], byte[])}
 * feeds the PEM cert chain + PKCS#8 key into a Netty {@code keyManager},
 * exercising the {@code buildSslContext} client-cert branch. All PKI is
 * generated at test time; nothing is committed.
 */
class AuthClientInterceptorMtlsTest {

    @TempDir
    Path tempDir;

    @Test
    void channelBuilderWithAClientIdentityBuildsANettyChannelBuilder() throws Exception {
        Identity client = TestCerts.selfSignedIdentity(tempDir, "axiam-grpc-mtls-client");
        NettyChannelBuilder builder = AuthClientInterceptor.channelBuilder(
                "dns:///localhost:1", null, client.certPem(), client.keyPem());
        assertNotNull(builder, "the mTLS channel builder (client keyManager path) must build");
    }

    @Test
    void channelBuilderWithClientIdentityAndCustomCaBuildsANettyChannelBuilder() throws Exception {
        Identity client = TestCerts.selfSignedIdentity(tempDir, "axiam-grpc-mtls-client-2");
        byte[] customCa = TestCerts.selfSignedCertPem(tempDir, "axiam-grpc-mtls-ca");
        NettyChannelBuilder builder = AuthClientInterceptor.channelBuilder(
                "dns:///localhost:1", customCa, client.certPem(), client.keyPem());
        assertNotNull(builder);
    }

    @Test
    void channelBuilderWithAMalformedClientKeyThrowsNetworkError() throws Exception {
        Identity client = TestCerts.selfSignedIdentity(tempDir, "axiam-grpc-mtls-badkey");
        assertThrows(NetworkError.class, () -> AuthClientInterceptor.channelBuilder(
                "dns:///localhost:1", null, client.certPem(),
                "-----BEGIN PRIVATE KEY-----\nnotbase64!!\n-----END PRIVATE KEY-----".getBytes()));
    }
}
