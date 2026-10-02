/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.repository.encrypted.security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.opensearch.repository.encrypted.RsaKeyAwareTest;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Provider;

public class CryptoIOTests extends RsaKeyAwareTest {

	private static final int MAX_BYES_SIZE = 18_192;

	private final Provider securityProvider = new BouncyCastleProvider();

	public void testEncryptAndDecrypt() throws IOException {
		final CryptoIO cryptoIo = new CryptoIO(new EncryptionDataSerializer(rsaKeyPair, securityProvider),
				securityProvider);
		final byte[] sequence = randomByteArrayOfLength(randomInt(MAX_BYES_SIZE));

		try (InputStream encIn = cryptoIo.encrypt(new ByteArrayInputStream(sequence))) {
			final byte[] encrypted = encIn.readAllBytes();
			try (InputStream decIn = cryptoIo.decrypt(new ByteArrayInputStream(encrypted))) {
				assertArrayEquals(sequence, decIn.readAllBytes());
			}
		}

	}

	public void testEncryptedStreamSize() throws IOException {
		final CryptoIO cryptoIo = new CryptoIO(new EncryptionDataSerializer(rsaKeyPair, securityProvider),
				securityProvider);
		final byte[] sequence = randomByteArrayOfLength(randomInt(MAX_BYES_SIZE));

		try (InputStream encIn = cryptoIo.encrypt(new ByteArrayInputStream(sequence))) {
			final byte[] encrypted = encIn.readAllBytes();
			assertEquals(encrypted.length, cryptoIo.encryptedStreamSize(sequence.length));
		}
	}

}