/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.repository.encrypted.security;

import org.opensearch.common.io.PathUtils;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class RsaKeysReaderTests extends RsaKeyAwareTest {

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
