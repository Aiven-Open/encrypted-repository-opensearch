/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.repository.encrypted.security;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.KeyPair;

public class EncryptionDataSerializer implements Encryptor, Decryptor {

    private static final String CIPHER_TRANSFORMATION = "RSA/NONE/OAEPWithSHA3-512AndMGF1Padding";

    static final int VERSION = 1;

    private final KeyPair rsaKeyPair;

    public static final int ENC_DATA_SIZE = 512 + Integer.BYTES;

    public EncryptionDataSerializer(final KeyPair rsaKeyPair) {
        this.rsaKeyPair = rsaKeyPair;
    }

    public byte[] serialize(final EncryptionData encryptionData) throws IOException {
        if (encryptionData.encryptionKey().getAlgorithm().equals("AES") == false) {
            throw new IllegalArgumentException("Couldn't encrypt non AES key");
        }
        return ByteBuffer.allocate(ENC_DATA_SIZE)
                .put(encrypt(encryptionData.encryptionKey().getEncoded()))
                .put(encrypt(encryptionData.aad()))
                .putInt(VERSION)
                .array();
    }

    public EncryptionData deserialize(final byte[] metadata) throws IOException {
        final ByteBuffer buffer = ByteBuffer.wrap(metadata);
        final byte[] encryptedKey = new byte[256];
        final byte[] aad = new byte[256];
        buffer.get(encryptedKey);
        buffer.get(aad);
        buffer.getInt(); //skip version
        return new EncryptionData(
                new SecretKeySpec(decrypt(encryptedKey), "AES"),
                decrypt(aad)
        );
    }

    private byte[] encrypt(final byte[] bytes) {
        try {
            final Cipher cipher = createEncryptingCipher(rsaKeyPair.getPublic(), CIPHER_TRANSFORMATION);
            return cipher.doFinal(bytes);
        } catch (final IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException("Couldn't encrypt AES key", e);
        }
    }

    private byte[] decrypt(final byte[] bytes) {
        try {
            final Cipher cipher = createDecryptingCipher(rsaKeyPair.getPrivate(), CIPHER_TRANSFORMATION);
            return cipher.doFinal(bytes);
        } catch (final IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException("Couldn't decrypt AES key", e);
        }
    }


}
