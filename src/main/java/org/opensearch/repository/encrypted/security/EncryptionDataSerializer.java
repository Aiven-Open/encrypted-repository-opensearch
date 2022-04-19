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
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;

public class EncryptionDataSerializer implements Encryptor, Decryptor {

    private static final String CIPHER_TRANSFORMATION = "RSA/NONE/OAEPWithSHA3-512AndMGF1Padding";

    static final int VERSION = 1;

    private final KeyPair rsaKeyPair;

    public static final int SIGNATURE_SIZE = 256;

    public static final int ENCRYPTED_KEY_SIZE = 256;

    public static final int ENCRYPTED_AAD_SIZE = 256;

    public static final int ENC_DATA_SIZE = ENCRYPTED_KEY_SIZE + ENCRYPTED_AAD_SIZE + SIGNATURE_SIZE + Integer.BYTES;

    public EncryptionDataSerializer(final KeyPair rsaKeyPair) {
        this.rsaKeyPair = rsaKeyPair;
    }

    public byte[] serialize(final EncryptionData encryptionData) throws IOException {
        if (encryptionData.encryptionKey().getAlgorithm().equals("AES") == false) {
            throw new IllegalArgumentException("Couldn't encrypt non AES key");
        }
        final byte[] key = encryptionData.encryptionKey().getEncoded();
        final byte[] aad = encryptionData.aad();
        final byte[] signature = sign(
                ByteBuffer.allocate(key.length + aad.length)
                        .put(key)
                        .put(aad)
                        .array()
        );
        final byte[] encryptedKey = encrypt(key);
        final byte[] encryptedAad = encrypt(aad);
        return ByteBuffer.allocate(ENC_DATA_SIZE)
                .put(encryptedKey)
                .put(encryptedAad)
                .put(signature)
                .putInt(VERSION)
                .array();
    }

    public EncryptionData deserialize(final byte[] metadata) throws IOException {
        final ByteBuffer buffer = ByteBuffer.wrap(metadata);
        final byte[] encryptedKey = new byte[256];
        final byte[] encryptedAad = new byte[256];
        final byte[] signature = new byte[256];
        buffer.get(encryptedKey);
        buffer.get(encryptedAad);
        buffer.get(signature);
        buffer.getInt(); //skip version
        final byte[] decryptedKey = decrypt(encryptedKey);
        final byte[] decryptedAdd = decrypt(encryptedAad);
        verifySignature(
                signature,
                ByteBuffer.allocate(decryptedKey.length + decryptedAdd.length)
                        .put(decryptedKey)
                        .put(decryptedAdd)
                        .array()
        );
        return new EncryptionData(new SecretKeySpec(decryptedKey, "AES"), decryptedAdd);
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

    private byte[] sign(final byte[] bytes) {
        try {
            final Signature signature = Signature.getInstance("SHA512withRSA");
            signature.initSign(rsaKeyPair.getPrivate());
            signature.update(bytes);
            return signature.sign();
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new RuntimeException(e);
        }
    }

    private void verifySignature(final byte[] expectedSignature, final byte[] data) {
        try {
            final Signature signature = Signature.getInstance("SHA512withRSA");
            signature.initVerify(rsaKeyPair.getPublic());
            signature.update(data);
            if (signature.verify(expectedSignature) == false) {
                throw new RuntimeException("Couldn't verify signature for encryption data");
            }
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }


}
