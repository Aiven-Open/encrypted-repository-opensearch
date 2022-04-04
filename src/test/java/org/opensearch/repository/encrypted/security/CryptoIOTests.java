/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.repository.encrypted.security;

import org.opensearch.repository.encrypted.IOUtils;
import org.opensearch.test.OpenSearchTestCase;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

public class CryptoIOTests extends OpenSearchTestCase {

    private static final int BUFFER_SIZE = 8_192;

    public void testEncryptAndDecrypt() throws IOException {
        final EncryptionData encData = new EncryptionDataGenerator().generate();

        final CryptoIO cryptoIo = new CryptoIO(encData);

        final byte [] sequence = randomByteArrayOfLength(BUFFER_SIZE);

        try (InputStream encIn = cryptoIo.encrypt(new ByteArrayInputStream(sequence))) {
            final byte[] encrypted = IOUtils.readAllBytes(encIn);
            try (InputStream decIn = cryptoIo.decrypt(new ByteArrayInputStream(encrypted))) {
                assertArrayEquals(sequence, IOUtils.readAllBytes(decIn));
            }
        }

    }

}