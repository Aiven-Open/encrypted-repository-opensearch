/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.repository.encrypted.security;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.SequenceInputStream;
import java.security.SecureRandom;

public class CryptoIO implements Encryptor, Decryptor {

    public static final int GCM_TAG_LENGTH = 16;

    public static final int GCM_ENCRYPTED_BLOCK_LENGTH = 128;

    public static final int GCM_IV_LENGTH = 12;

    public static final String CIPHER_TRANSFORMATION = "AES/GCM/NoPadding";

    private final SecretKey secretKey;

    private final byte[] aad;

    private final SecureRandom secureRandom;

    public CryptoIO(final EncryptionData encryptionData) {
        this.secretKey = encryptionData.encryptionKey();
        this.aad = encryptionData.aad();
        this.secureRandom = new SecureRandom();
    }

    public InputStream encrypt(final InputStream in) throws IOException {
        final byte[] iv = new byte[GCM_IV_LENGTH];
        secureRandom.nextBytes(iv);
        final Cipher cipher = createEncryptingCipher(
                secretKey,
                new GCMParameterSpec(GCM_ENCRYPTED_BLOCK_LENGTH, iv),
                CIPHER_TRANSFORMATION);
        cipher.updateAAD(aad);
        return new SequenceInputStream(new ByteArrayInputStream(iv), new CipherInputStream(in, cipher));
    }

    public InputStream decrypt(final InputStream in) throws IOException {
        final Cipher cipher = createDecryptingCipher(
                secretKey,
                new GCMParameterSpec(GCM_ENCRYPTED_BLOCK_LENGTH, in.readNBytes(GCM_IV_LENGTH)),
                CIPHER_TRANSFORMATION);
        cipher.updateAAD(aad);
        return new CipherInputStream(in, cipher);
    }

    public long encryptedStreamSize(final long originSize) {
        return originSize + GCM_TAG_LENGTH + GCM_IV_LENGTH;
    }

}
