/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.repository.encrypted.security;

import org.opensearch.repository.encrypted.Permissions;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.spec.GCMParameterSpec;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.SequenceInputStream;
import java.security.Provider;

public class CryptoIO implements Encryptor, Decryptor {

	public static final int BUFFER_SIZE = 128 * 1024; // 128KB default mark/reset buffer size

	public static final int GCM_TAG_LENGTH = 16;

	public static final int GCM_ENCRYPTED_BLOCK_LENGTH = 128;

	public static final String CIPHER_TRANSFORMATION = "AES/GCM/NoPadding";

	private final Provider securityProvider;

	private final EncryptionDataGenerator encryptionDataGenerator;

	private final EncryptionDataSerializer encryptionDataSerializer;

	public CryptoIO(final EncryptionDataSerializer encryptionDataSerializer, final Provider securityProvider) {
		this.encryptionDataSerializer = encryptionDataSerializer;
		this.encryptionDataGenerator = new EncryptionDataGenerator(securityProvider);
		this.securityProvider = securityProvider;
	}

	public InputStream encrypt(final InputStream in) throws IOException {
		return Permissions.doPrivileged(() -> {
			final EncryptionData encryptionData = encryptionDataGenerator.generate();
			final Cipher cipher = createEncryptingCipher(encryptionData.encryptionKey(),
					new GCMParameterSpec(GCM_ENCRYPTED_BLOCK_LENGTH, encryptionData.iv()), CIPHER_TRANSFORMATION,
					securityProvider);
			cipher.updateAAD(encryptionData.aad());
			return new BufferedInputStream(new SequenceInputStream(
					new ByteArrayInputStream(encryptionDataSerializer.serialize(encryptionData)),
					new CipherInputStream(in, cipher)), BUFFER_SIZE);
		});
	}

	public InputStream decrypt(final InputStream in) throws IOException {
		return Permissions.doPrivileged(() -> {
			final EncryptionData encryptionData = encryptionDataSerializer
					.deserialize(in.readNBytes(EncryptionDataSerializer.ENC_DATA_SIZE));
			final Cipher cipher = createDecryptingCipher(encryptionData.encryptionKey(),
					new GCMParameterSpec(GCM_ENCRYPTED_BLOCK_LENGTH, encryptionData.iv()), CIPHER_TRANSFORMATION,
					securityProvider);
			cipher.updateAAD(encryptionData.aad());
			return new BufferedInputStream(new CipherInputStream(in, cipher), BUFFER_SIZE);
		});
	}

	public long encryptedStreamSize(final long originSize) {
		return originSize + GCM_TAG_LENGTH + EncryptionDataSerializer.ENC_DATA_SIZE;
	}

}
