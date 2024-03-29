/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.repository.encrypted.security;

import org.opensearch.common.io.PathUtils;
import org.opensearch.repository.encrypted.RsaKeyAwareTest;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;

public class EncryptionDataSerializerTests extends RsaKeyAwareTest implements Encryptor {

	public void testSerializeAndDeserializeEncryptionData() throws IOException {
		EncryptionDataGenerator encryptionDataGenerator = new EncryptionDataGenerator(securityProvider);
		final EncryptionDataSerializer metadata = new EncryptionDataSerializer(rsaKeyPair, securityProvider);
		final EncryptionData encData = encryptionDataGenerator.generate();

		final byte[] encBytes = metadata.serialize(encData);

		final Path tmpPath = PathUtils.get(randomFrom(tmpPaths()));
		final Path key = tmpPath.resolve("enc_key");

		try (OutputStream out = Files.newOutputStream(key)) {
			out.write(encBytes);
			out.flush();
		}

		try (InputStream in = Files.newInputStream(key)) {
			final EncryptionData decData = metadata.deserialize(in.readAllBytes());
			assertEquals(encData.encryptionKey(), decData.encryptionKey());
			assertArrayEquals(encData.aad(), decData.aad());
		}
	}

}