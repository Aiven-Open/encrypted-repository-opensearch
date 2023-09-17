/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.repository.encrypted.security;

import javax.crypto.KeyGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public final class EncryptionDataGenerator {

	private static final int KEY_SIZE = 256;

	private static final int AAD_SIZE = 32;

	private final KeyGenerator aesKeyGenerator;

	private final SecureRandom random;

	public EncryptionDataGenerator() {
		try {
			this.aesKeyGenerator = KeyGenerator.getInstance("AES");
			this.random = new SecureRandom();
			this.aesKeyGenerator.init(KEY_SIZE, this.random);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("Couldn't create AES key generator", e);
		}
	}

	public EncryptionData generate() {
		final byte[] aad = new byte[AAD_SIZE];
		random.nextBytes(aad);
		return new EncryptionData(aesKeyGenerator.generateKey(), aad);
	}

}
