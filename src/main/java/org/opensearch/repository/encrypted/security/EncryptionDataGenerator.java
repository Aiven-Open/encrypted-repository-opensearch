/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.repository.encrypted.security;

import org.opensearch.repository.encrypted.Permissions;

import javax.crypto.KeyGenerator;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;

public final class EncryptionDataGenerator {

	private static final int KEY_SIZE = 256;

	private static final int AAD_SIZE = 32;

	public static final int GCM_IV_LENGTH = 12;

	private final KeyGenerator aesKeyGenerator;

	private final SecureRandom random = new SecureRandom();

	public EncryptionDataGenerator(final Provider securityProvider) {
		try {
			this.aesKeyGenerator = Permissions.doPrivileged(() -> {
				try {
					final var aesKeyGenerator = KeyGenerator.getInstance("AES", securityProvider);
					aesKeyGenerator.init(KEY_SIZE, this.random);
					return aesKeyGenerator;
				} catch (NoSuchAlgorithmException e) {
					throw new RuntimeException("Couldn't create AES key generator", e);
				}
			});
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	public EncryptionData generate() {
		final byte[] aad = new byte[AAD_SIZE];
		random.nextBytes(aad);
		final byte[] iv = new byte[GCM_IV_LENGTH];
		random.nextBytes(iv);
		return new EncryptionData(aesKeyGenerator.generateKey(), aad, iv);
	}

}
