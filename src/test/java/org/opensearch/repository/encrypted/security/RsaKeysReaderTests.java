/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.repository.encrypted.security;

import org.opensearch.common.io.PathUtils;
import org.opensearch.common.settings.SettingsException;
import org.opensearch.repository.encrypted.RsaKeyAwareTest;

import java.io.IOException;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class RsaKeysReaderTests extends RsaKeyAwareTest {

    public void testThrowsSettingsExceptionForEmptyBytes() throws IOException {
        Exception e = expectThrows(
                SettingsException.class,
                () -> RsaKeysReader.readRsaKeyPair(new byte[]{}, new byte[]{})
        );
        assertEquals("Pubic key hasn't been set", e.getMessage());
        e = expectThrows(
                SettingsException.class,
                () -> RsaKeysReader.readRsaKeyPair(readPemContent(publicKeyPem), new byte[]{})
        );
        assertEquals("Private key hasn't been set", e.getMessage());

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


    public void testThrowsSettingsExceptionForUnsupportedKey() throws Exception {
        final Path tmpPath = PathUtils.get(randomFrom(tmpPaths()));
        final Path dsaPublicKeyPem = tmpPath.resolve("dsa_public_key.pem");
        final Path dsaPrivateKeyPem = tmpPath.resolve("dsa_private_key.pem");

        final KeyPair dsaKeyPair = KeyPairGenerator.getInstance("DSA").generateKeyPair();
        writePemFile(dsaPublicKeyPem, new X509EncodedKeySpec(dsaKeyPair.getPublic().getEncoded()));
        writePemFile(dsaPrivateKeyPem, new PKCS8EncodedKeySpec(dsaKeyPair.getPrivate().getEncoded()));

        final Exception e = expectThrows(
                SettingsException.class,
                () -> RsaKeysReader.readRsaKeyPair(
                        readPemContent(publicKeyPem),
                        readPemContent(dsaPrivateKeyPem))
        );
        assertEquals(
                "Couldn't generate RSA key pair",
                e.getMessage()
        );
    }

}
