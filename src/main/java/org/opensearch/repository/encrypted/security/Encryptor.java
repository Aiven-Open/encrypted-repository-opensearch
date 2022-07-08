/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.repository.encrypted.security;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Objects;

public interface Encryptor {

    default Cipher createEncryptingCipher(final String encryptionProviderName,
                                          final Key key,
                                          final String transformation) {
        return createEncryptingCipher(encryptionProviderName, key, null, transformation);
    }

    default Cipher createEncryptingCipher(final String encryptionProviderName,
                                          final Key key,
                                          final AlgorithmParameterSpec algorithmParameterSpec,
                                          final String transformation) {
        Objects.requireNonNull(key, "key hasn't been set");
        Objects.requireNonNull(transformation, "transformation hasn't been set");
        try {
            final Cipher cipher = Cipher.getInstance(transformation, encryptionProviderName);
            if (Objects.nonNull(algorithmParameterSpec)) {
                cipher.init(
                        Cipher.ENCRYPT_MODE,
                        key,
                        algorithmParameterSpec,
                        new SecureRandom());
            } else {
                cipher.init(Cipher.ENCRYPT_MODE, key, new SecureRandom());
            }
            return cipher;
        } catch (final NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                       InvalidAlgorithmParameterException | NoSuchProviderException e) {
            throw new RuntimeException("Couldn't create encrypt cipher", e);
        }
    }

}
