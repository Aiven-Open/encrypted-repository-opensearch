/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.repository.encrypted.security;

import org.opensearch.repository.encrypted.Permissions;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.SequenceInputStream;
import java.security.Provider;
import java.security.SecureRandom;

public class CryptoIO implements Encryptor, Decryptor {

	public static final int BUFFER_SIZE = 128 * 1024; // 128KB default mark/reset buffer size

	public static final int GCM_TAG_LENGTH = 16;

	public static final int GCM_ENCRYPTED_BLOCK_LENGTH = 128;

	public static final int GCM_IV_LENGTH = 12;

	public static final String CIPHER_TRANSFORMATION = "AES/GCM/NoPadding";

	private final SecretKey secretKey;

	private final byte[] aad;

	private final SecureRandom secureRandom;

	private final Provider securityProvider;

	public CryptoIO(final EncryptionData encryptionData, final Provider securityProvider) {
		this.secretKey = encryptionData.encryptionKey();
		this.aad = encryptionData.aad();
		this.secureRandom = new SecureRandom();
		this.securityProvider = securityProvider;
	}

	public InputStream encrypt(final InputStream in) throws IOException {
		return Permissions.doPrivileged(() -> {
			final byte[] iv = new byte[GCM_IV_LENGTH];
			secureRandom.nextBytes(iv);
			final Cipher cipher = createEncryptingCipher(secretKey,
					new GCMParameterSpec(GCM_ENCRYPTED_BLOCK_LENGTH, iv), CIPHER_TRANSFORMATION, securityProvider);
			cipher.updateAAD(aad);
			return new BufferedInputStream(
					new SequenceInputStream(new ByteArrayInputStream(iv), new CipherInputStream(in, cipher)),
					BUFFER_SIZE);
		});
	}

	public InputStream decrypt(final InputStream in) throws IOException {
		return Permissions.doPrivileged(() -> {
			final Cipher cipher = createDecryptingCipher(secretKey,
					new GCMParameterSpec(GCM_ENCRYPTED_BLOCK_LENGTH, in.readNBytes(GCM_IV_LENGTH)),
					CIPHER_TRANSFORMATION, securityProvider);
			cipher.updateAAD(aad);
			return new BufferedInputStream(new CipherInputStream(in, cipher), BUFFER_SIZE);
		});
	}

	public long encryptedStreamSize(final long originSize) {
		return originSize + GCM_TAG_LENGTH + GCM_IV_LENGTH;
	}

}
