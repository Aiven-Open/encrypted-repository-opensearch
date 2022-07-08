/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.repository.encrypted.security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.opensearch.repository.encrypted.IOUtils;
import org.opensearch.test.OpenSearchTestCase;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Security;

public class CryptoIOTests extends OpenSearchTestCase {

    private static final int MAX_BYES_SIZE = 18_192;

    private final EncryptionData encData = new EncryptionDataGenerator().generate();

    @BeforeClass
    static void setupProvider() {
        Security.addProvider(new BouncyCastleProvider());
    }

    public void testEncryptAndDecrypt() throws IOException {
        final CryptoIO cryptoIo = new CryptoIO(BouncyCastleProvider.PROVIDER_NAME, encData);
        final byte [] sequence = randomByteArrayOfLength(randomInt(MAX_BYES_SIZE));

        try (InputStream encIn = cryptoIo.encrypt(new ByteArrayInputStream(sequence))) {
            final byte[] encrypted = IOUtils.readAllBytes(encIn);
            try (InputStream decIn = cryptoIo.decrypt(new ByteArrayInputStream(encrypted))) {
                assertArrayEquals(sequence, IOUtils.readAllBytes(decIn));
            }
        }

    }

    public void testEncryptedStreamSize() throws IOException {
        final CryptoIO cryptoIo = new CryptoIO(BouncyCastleProvider.PROVIDER_NAME, encData);
        final byte [] sequence = randomByteArrayOfLength(randomInt(MAX_BYES_SIZE));

        try (InputStream encIn = cryptoIo.encrypt(new ByteArrayInputStream(sequence))) {
            final byte[] encrypted = IOUtils.readAllBytes(encIn);
            assertEquals(encrypted.length, cryptoIo.encryptedStreamSize(sequence.length));
        }
    }

}