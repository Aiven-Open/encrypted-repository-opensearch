/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.repository.encrypted.security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.SignatureException;

public class EncryptionDataSerializer implements Encryptor, Decryptor {

    private static final String CIPHER_TRANSFORMATION = "RSA/NONE/OAEPWithSHA3-512AndMGF1Padding";

    private static final String SIGNATURE_ALGORITHM = "SHA512withRSA";

    private static final String KEY_ALGORITHM = "AES";

    static final int VERSION = 1;

    private final KeyPair rsaKeyPair;

    public static final int SIGNATURE_SIZE = 256;

    public static final int ENCRYPTED_KEY_SIZE = 256;

    public static final int ENCRYPTED_AAD_SIZE = 256;

    public static final int ENC_DATA_SIZE = ENCRYPTED_KEY_SIZE + ENCRYPTED_AAD_SIZE + SIGNATURE_SIZE + Integer.BYTES;

    private final String encryptionProviderName;

    public EncryptionDataSerializer(final String encryptionProviderName, final KeyPair rsaKeyPair) {
        this.encryptionProviderName = encryptionProviderName;
        this.rsaKeyPair = rsaKeyPair;
    }

    public byte[] serialize(final EncryptionData encryptionData) throws IOException {
        if (encryptionData.encryptionKey().getAlgorithm().equals(KEY_ALGORITHM) == false) {
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
        final byte[] encryptedKey = encrypt(key, "Couldn't encrypt " + KEY_ALGORITHM + " key");
        final byte[] encryptedAad = encrypt(aad, "Couldn't encrypt AAD");
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
        final byte[] decryptedKey = decrypt(encryptedKey, "Couldn't decrypt " + KEY_ALGORITHM + " key");
        final byte[] decryptedAdd = decrypt(encryptedAad, "Couldn't decrypt AAD");
        verifySignature(
                signature,
                ByteBuffer.allocate(decryptedKey.length + decryptedAdd.length)
                        .put(decryptedKey)
                        .put(decryptedAdd)
                        .array()
        );
        return new EncryptionData(new SecretKeySpec(decryptedKey, KEY_ALGORITHM), decryptedAdd);
    }

    private byte[] encrypt(final byte[] bytes, final String errMessage) {
        try {
            final Cipher cipher =
                    createEncryptingCipher(
                            BouncyCastleProvider.PROVIDER_NAME,
                            rsaKeyPair.getPublic(), CIPHER_TRANSFORMATION
                    );
            return cipher.doFinal(bytes);
        } catch (final IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException(errMessage, e);
        }
    }

    private byte[] decrypt(final byte[] bytes, final String errMessage) {
        try {
            final Cipher cipher =
                    createDecryptingCipher(
                            BouncyCastleProvider.PROVIDER_NAME,
                            rsaKeyPair.getPrivate(), CIPHER_TRANSFORMATION
                    );
            return cipher.doFinal(bytes);
        } catch (final IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException(errMessage, e);
        }
    }

    private byte[] sign(final byte[] bytes) {
        try {
            final Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM, encryptionProviderName);
            signature.initSign(rsaKeyPair.getPrivate());
            signature.update(bytes);
            return signature.sign();
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }

    private void verifySignature(final byte[] expectedSignature, final byte[] data) {
        try {
            final Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM, encryptionProviderName);
            signature.initVerify(rsaKeyPair.getPublic());
            signature.update(data);
            if (signature.verify(expectedSignature) == false) {
                throw new RuntimeException("Couldn't verify signature for encryption data");
            }
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }


}
