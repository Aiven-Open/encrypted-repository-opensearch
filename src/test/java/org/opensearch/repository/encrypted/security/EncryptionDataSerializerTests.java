/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.repository.encrypted.security;

import java.io.IOException;

public class EncryptionDataSerializerTests extends RsaKeyAwareTest implements Encryptor {

    static final EncryptionDataGenerator encDataGenerator = EncryptionDataGenerator.DEFAULT_GENERATOR;

    public void testSerializeAndDeserializeEncryptionData() throws IOException {
        final EncryptionDataSerializer metadata = new EncryptionDataSerializer(rsaKeyPair);
        final EncryptionDataGenerator.EncryptionData encData = encDataGenerator.generate();

        final byte[] encBytes = metadata.serialize(encData);

        final EncryptionDataGenerator.EncryptionData decData = metadata.deserialize(encBytes);

        assertEquals(encData.encryptionKey(), decData.encryptionKey());
        assertArrayEquals(encData.aad(), decData.aad());
    }

}