/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.repository.encrypted.security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.junit.Before;
import org.opensearch.common.io.PathUtils;
import org.opensearch.test.OpenSearchTestCase;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class RsaKeysReaderTests extends OpenSearchTestCase {

    KeyPair rsaKeyPair;

    Path publicKeyPem;

    Path privateKeyPem;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Before
    public void setupKeys() throws Exception {
        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
        keyPairGenerator.initialize(2048, new SecureRandom());
        rsaKeyPair = keyPairGenerator.generateKeyPair();

        final Path tmpPath = PathUtils.get(randomFrom(tmpPaths()));
        publicKeyPem = tmpPath.resolve("test_public.pem");
        privateKeyPem = tmpPath.resolve("test_private.pem");

        writePemFile(publicKeyPem, new X509EncodedKeySpec(rsaKeyPair.getPublic().getEncoded()));
        writePemFile(privateKeyPem, new PKCS8EncodedKeySpec(rsaKeyPair.getPrivate().getEncoded()));
    }

    static void writePemFile(final Path path, final EncodedKeySpec encodedKeySpec) throws IOException {
        try (PemWriter pemWriter = new PemWriter(Files.newBufferedWriter(path))) {
            final PemObject pemObject = new PemObject("SOME KEY", encodedKeySpec.getEncoded());
            pemWriter.writeObject(pemObject);
            pemWriter.flush();
        }
    }

    public void testThrowsIllegalArgumentExceptionForEmptyBytes() throws IOException {
        Exception e = expectThrows(
                IllegalArgumentException.class,
                () -> RsaKeysReader.readRsaKeyPair(new byte[]{}, new byte[]{})
        );
        assertEquals("Couldn't read public key", e.getMessage());
        e = expectThrows(
                IllegalArgumentException.class,
                () -> RsaKeysReader.readRsaKeyPair(readPemContent(publicKeyPem), new byte[]{})
        );
        assertEquals("Couldn't read private key", e.getMessage());

    }

    public void testThrowsNullPointerExceptionForNullBytes() {
        Exception e = expectThrows(
                NullPointerException.class,
                () -> RsaKeysReader.readRsaKeyPair(null, null)
        );
        assertEquals("Pubic key hasn't been set", e.getMessage());
        e = expectThrows(
                NullPointerException.class,
                () -> RsaKeysReader.readRsaKeyPair(readPemContent(publicKeyPem), null)
        );
        assertEquals("Private key hasn't been set", e.getMessage());
    }


    public void testThrowsIllegalArgumentExceptionUnsupportedKey() throws Exception {
        final Path tmpPath = PathUtils.get(randomFrom(tmpPaths()));
        final Path dsaPublicKeyPem = tmpPath.resolve("dsa_public_key.pem");
        final Path dsaPrivateKeyPem = tmpPath.resolve("dsa_private_key.pem");

        final KeyPair dsaKeyPair = KeyPairGenerator.getInstance("DSA").generateKeyPair();
        writePemFile(dsaPublicKeyPem, new X509EncodedKeySpec(dsaKeyPair.getPublic().getEncoded()));
        writePemFile(dsaPrivateKeyPem, new PKCS8EncodedKeySpec(dsaKeyPair.getPrivate().getEncoded()));

        final Exception e = expectThrows(
                IllegalArgumentException.class,
                () -> RsaKeysReader.readRsaKeyPair(
                        readPemContent(publicKeyPem),
                        readPemContent(dsaPrivateKeyPem))
        );
        assertEquals(
                "Couldn't generate RSA key pair",
                e.getMessage()
        );
    }

    private byte[] readPemContent(final Path path) throws IOException {
        try (InputStream in = Files.newInputStream(path)) {
            return IOUtils.readAllBytes(in);
        }
    }

}
